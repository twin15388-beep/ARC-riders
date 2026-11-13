#ifdef _WIN32

#include <windows.h>

#include <cstdint>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

[[noreturn]] void ThrowWin32(const std::string& operation, const DWORD error = ::GetLastError()) {
    throw std::runtime_error(operation + ": Win32 error " + std::to_string(error));
}

class Handle {
public:
    explicit Handle(HANDLE value = nullptr) : value_(value) {}
    ~Handle() {
        if (value_ != nullptr && value_ != INVALID_HANDLE_VALUE) {
            ::CloseHandle(value_);
        }
    }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    [[nodiscard]] HANDLE Get() const noexcept { return value_; }
private:
    HANDLE value_{};
};

class RemoteMemory {
public:
    RemoteMemory(HANDLE process, void* address) : process_(process), address_(address) {}
    ~RemoteMemory() {
        if (address_ != nullptr) {
            ::VirtualFreeEx(process_, address_, 0, MEM_RELEASE);
        }
    }
    RemoteMemory(const RemoteMemory&) = delete;
    RemoteMemory& operator=(const RemoteMemory&) = delete;
    [[nodiscard]] void* Get() const noexcept { return address_; }
    void Release() noexcept { address_ = nullptr; }
private:
    HANDLE process_{};
    void* address_{};
};

std::uint32_t ParsePid(const char* text) {
    std::size_t consumed = 0;
    const std::string value(text);
    const auto pid = std::stoull(value, &consumed, 10);
    if (consumed != value.size() || pid == 0 || pid > UINT32_MAX) {
        throw std::invalid_argument("PID must be a decimal integer in range 1..4294967295");
    }
    return static_cast<std::uint32_t>(pid);
}

// The rights a protected game process grants usually depend on the caller holding SeDebugPrivilege,
// which is *present but disabled* in an elevated shell by default. arc_tool probe reported all eight
// rights with the privilege enabled and injection previously failed at VirtualAllocEx error 5 without
// it, so enabling it here is part of the measurement rather than a convenience.
void EnableDebugPrivilege() {
    HANDLE token = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        std::cout << "se_debug_privilege=open_token_failed win32_error=" << ::GetLastError() << '\n';
        return;
    }
    LUID luid{};
    if (!::LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid)) {
        std::cout << "se_debug_privilege=lookup_failed win32_error=" << ::GetLastError() << '\n';
        ::CloseHandle(token);
        return;
    }
    TOKEN_PRIVILEGES privileges{};
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Luid = luid;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!::AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), nullptr, nullptr)) {
        std::cout << "se_debug_privilege=adjust_failed win32_error=" << ::GetLastError() << '\n';
    } else if (::GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        std::cout << "se_debug_privilege=not_assigned (the shell is not elevated; run PowerShell as "
                     "administrator)\n";
    } else {
        std::cout << "se_debug_privilege=enabled\n";
    }
    ::CloseHandle(token);
}

// VirtualAllocEx was measured as denied on this build even with SeDebugPrivilege enabled, which is
// what a memory-protection callback filtering remote allocation looks like. The native syscall is the
// same operation through a different entry point, so it is tried first: if only the Win32 wrapper is
// hooked, injection is still possible, and the report then says which path worked.
void* AllocateRemote(const HANDLE process, const std::size_t size, std::string& how) {
    using NtAllocateVirtualMemoryFn = NTSTATUS(NTAPI*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    const auto allocate = reinterpret_cast<NtAllocateVirtualMemoryFn>(
        ::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"), "NtAllocateVirtualMemory"));
    if (allocate != nullptr) {
        PVOID address = nullptr;
        SIZE_T region = size;
        const NTSTATUS status = allocate(process, &address, 0, &region, MEM_RESERVE | MEM_COMMIT,
                                         PAGE_READWRITE);
        if (status == 0 && address != nullptr) {
            how = "ntdll!NtAllocateVirtualMemory";
            return address;
        }
        std::cout << "nt_allocate_virtual_memory=status=0x" << std::hex << static_cast<std::uint32_t>(status)
                  << std::dec << " (falling back to VirtualAllocEx)\n";
    }
    void* address = ::VirtualAllocEx(process, nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    how = "kernel32!VirtualAllocEx";
    return address;
}

void Inject(const std::uint32_t pid, const std::filesystem::path& dll_path) {
    EnableDebugPrivilege();
    const auto full_path = std::filesystem::canonical(dll_path);
    if (!std::filesystem::is_regular_file(full_path) || std::filesystem::file_size(full_path) == 0) {
        throw std::runtime_error("DLL path is not a nonempty regular file");
    }
    const auto native = full_path.wstring();
    const auto bytes = (native.size() + 1) * sizeof(wchar_t);
    if (bytes > 32768 * sizeof(wchar_t)) {
        throw std::runtime_error("DLL path is too long");
    }

    Handle process(::OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid));
    if (process.Get() == nullptr) {
        ThrowWin32("OpenProcess injector failed for PID " + std::to_string(pid));
    }
    BOOL wow64 = FALSE;
    if (!::IsWow64Process(process.Get(), &wow64)) {
        ThrowWin32("IsWow64Process failed");
    }
    if (wow64) {
        throw std::runtime_error("32-bit targets are not supported");
    }

    std::string allocator;
    RemoteMemory remote_memory(process.Get(), AllocateRemote(process.Get(), bytes, allocator));
    if (remote_memory.Get() == nullptr) {
        const DWORD error = ::GetLastError();
        std::string hint;
        if (error == ERROR_ACCESS_DENIED) {
            hint = " - both the native syscall and VirtualAllocEx were refused, so the target denies "
                   "remote allocation outright (se_debug_privilege line above says whether the shell was "
                   "elevated). This is the end of the injection path for this protection: no Dumper-7, no "
                   "in-process tool. Use arc_tool probe-write <pid> to confirm, then build the external "
                   "reader + overlay and analyse dumps offline.";
        }
        ThrowWin32("VirtualAllocEx failed" + hint, error);
    }
    SIZE_T written = 0;
    if (!::WriteProcessMemory(process.Get(), remote_memory.Get(), native.c_str(), bytes, &written) || written != bytes) {
        ThrowWin32("WriteProcessMemory DLL path failed");
    }

    const auto kernel = ::GetModuleHandleW(L"kernel32.dll");
    if (kernel == nullptr) {
        ThrowWin32("GetModuleHandleW kernel32 failed");
    }
    const auto load_library = ::GetProcAddress(kernel, "LoadLibraryW");
    if (load_library == nullptr) {
        ThrowWin32("GetProcAddress LoadLibraryW failed");
    }

    Handle thread(::CreateRemoteThread(
        process.Get(), nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(load_library),
        remote_memory.Get(), 0, nullptr));
    if (thread.Get() == nullptr) {
        ThrowWin32("CreateRemoteThread LoadLibraryW failed");
    }
    if (::WaitForSingleObject(thread.Get(), 60000) != WAIT_OBJECT_0) {
        remote_memory.Release(); // LoadLibraryW may still be reading the path.
        ThrowWin32("WaitForSingleObject LoadLibraryW failed or timed out");
    }
    DWORD module_handle = 0;
    if (!::GetExitCodeThread(thread.Get(), &module_handle)) {
        ThrowWin32("GetExitCodeThread LoadLibraryW failed");
    }
    if (!::VirtualFreeEx(process.Get(), remote_memory.Get(), 0, MEM_RELEASE)) {
        ThrowWin32("VirtualFreeEx DLL path failed");
    }
    remote_memory.Release();
    if (module_handle == 0) {
        throw std::runtime_error("LoadLibraryW returned null in the target process");
    }
    std::cout << "LoadLibraryW succeeded via " << allocator
              << "; remote module handle=0x" << std::hex << module_handle << std::dec << '\n';
}

} // namespace

int main(int argc, char** argv) {
    try {
        if (argc != 3) {
            std::cout << "arc_inject <pid> <Dumper-7.dll>\n";
            return 2;
        }
        Inject(ParsePid(argv[1]), argv[2]);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}

#else

#include <iostream>

int main() {
    std::cerr << "arc_inject must be built for Windows\n";
    return 1;
}

#endif
