#ifdef _WIN32

#include "Process.h"

#include "Version.h"

#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace arc {
namespace {

[[noreturn]] void ThrowWin32(const std::string& operation, const DWORD error = ::GetLastError()) {
    throw std::runtime_error(operation + ": Win32 error " + std::to_string(error));
}

std::uint32_t LoadU32(const std::uint8_t* bytes) {
    return static_cast<std::uint32_t>(bytes[0]) |
        (static_cast<std::uint32_t>(bytes[1]) << 8) |
        (static_cast<std::uint32_t>(bytes[2]) << 16) |
        (static_cast<std::uint32_t>(bytes[3]) << 24);
}

} // namespace

Process Process::Open(const std::uint32_t pid) {
    if (pid == 0) {
        throw std::invalid_argument("PID must be nonzero");
    }
    HANDLE handle = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (handle == nullptr) {
        ThrowWin32("OpenProcess failed for PID " + std::to_string(pid));
    }
    BOOL wow64 = FALSE;
    if (!::IsWow64Process(handle, &wow64)) {
        const DWORD error = ::GetLastError();
        ::CloseHandle(handle);
        ThrowWin32("IsWow64Process failed", error);
    }
    if (wow64) {
        ::CloseHandle(handle);
        throw std::runtime_error("32-bit targets are not supported; this tool expects an x64 process");
    }
    return Process(handle, pid);
}

Process::~Process() {
    if (handle_ != nullptr) {
        ::CloseHandle(handle_);
    }
}

Process::Process(Process&& other) noexcept : handle_(other.handle_), pid_(other.pid_) {
    other.handle_ = nullptr;
    other.pid_ = 0;
}

Process& Process::operator=(Process&& other) noexcept {
    if (this != &other) {
        if (handle_ != nullptr) {
            ::CloseHandle(handle_);
        }
        handle_ = other.handle_;
        pid_ = other.pid_;
        other.handle_ = nullptr;
        other.pid_ = 0;
    }
    return *this;
}

std::vector<ModuleInfo> Process::Modules() const {
    HANDLE snapshot = INVALID_HANDLE_VALUE;
    for (int attempt = 0; attempt < 3; ++attempt) {
        snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid_);
        if (snapshot != INVALID_HANDLE_VALUE) {
            break;
        }
        if (::GetLastError() != ERROR_BAD_LENGTH || attempt == 2) {
            ThrowWin32("CreateToolhelp32Snapshot modules failed");
        }
    }
    struct SnapshotGuard {
        HANDLE handle;
        ~SnapshotGuard() { ::CloseHandle(handle); }
    } guard{snapshot};

    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!::Module32FirstW(snapshot, &entry)) {
        ThrowWin32("Module32FirstW failed");
    }
    std::vector<ModuleInfo> result;
    do {
        if (result.size() == 1024) {
            throw std::runtime_error("target has more than 1024 modules; refusing an unbounded enumeration");
        }
        result.push_back({
            reinterpret_cast<std::uintptr_t>(entry.modBaseAddr),
            static_cast<std::size_t>(entry.modBaseSize),
            entry.szModule,
            std::filesystem::path(entry.szExePath),
        });
    } while (::Module32NextW(snapshot, &entry));
    if (::GetLastError() != ERROR_NO_MORE_FILES) {
        ThrowWin32("Module32NextW failed");
    }
    return result;
}

void Process::ReadExact(const std::uintptr_t address, void* output, const std::size_t size) const {
    if (size == 0) {
        return;
    }
    if (address == 0 || output == nullptr) {
        throw std::invalid_argument("read address and output must be nonzero");
    }
    if (size - 1 > std::numeric_limits<std::uintptr_t>::max() - address) {
        throw std::overflow_error("read address range overflows uintptr_t");
    }
    SIZE_T bytes_read = 0;
    if (!::ReadProcessMemory(
            handle_,
            reinterpret_cast<const void*>(address),
            output,
            size,
            &bytes_read)) {
        ThrowWin32("ReadProcessMemory failed at 0x" + std::to_string(address));
    }
    if (bytes_read != size) {
        throw std::runtime_error("partial process read at 0x" + std::to_string(address));
    }
}

std::vector<std::uint8_t> Process::Read(const std::uintptr_t address, const std::size_t size) const {
    if (size > 16 * 1024 * 1024) {
        throw std::invalid_argument("single process read exceeds the 16 MiB limit");
    }
    std::vector<std::uint8_t> result(size);
    ReadExact(address, result.data(), result.size());
    return result;
}

std::uint64_t Process::ReadU64(const std::uintptr_t address) const {
    std::uint64_t value{};
    ReadExact(address, &value, sizeof(value));
    return value;
}

namespace {

using NtQueryInformationProcessFn = NTSTATUS(NTAPI*)(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

std::uint16_t LoadLe16(const std::uint8_t* const bytes) {
    return static_cast<std::uint16_t>(bytes[0]) | (static_cast<std::uint16_t>(bytes[1]) << 8);
}

std::uint64_t LoadLe64(const std::uint8_t* const bytes) {
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < 8; ++i) {
        value |= static_cast<std::uint64_t>(bytes[i]) << (i * 8);
    }
    return value;
}

bool ReadRaw(const HANDLE handle, const std::uint64_t address, void* const output, const std::size_t size) {
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE || address == 0 || output == nullptr || size == 0) {
        return false;
    }
    SIZE_T transferred = 0;
    const BOOL ok = ::ReadProcessMemory(
        handle, reinterpret_cast<const void*>(static_cast<std::uintptr_t>(address)), output, size, &transferred);
    return ok != FALSE && transferred == size;
}

// Documented Windows 10/11 x64 structure offsets, read through ReadRaw and range-checked per entry.
// They are OS layout facts, not game data; a wrong offset shows up as an implausible walk.
constexpr std::size_t kPebImageBase = 0x10;
constexpr std::size_t kPebLdr = 0x18;
constexpr std::size_t kLdrInMemoryOrderList = 0x20;
constexpr std::size_t kEntryLinksOffset = 0x10;
constexpr std::size_t kEntryDllBase = 0x30;
constexpr std::size_t kEntrySizeOfImage = 0x40;
constexpr std::size_t kEntryBaseDllName = 0x58;
constexpr std::size_t kEntryEntrySize = 0x70;

void PrintSelfTokenState() {
    HANDLE token = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token)) {
        std::cout << "  token=unavailable win32_error=" << ::GetLastError() << '\n';
        return;
    }
    struct TokenGuard {
        HANDLE handle;
        ~TokenGuard() { ::CloseHandle(handle); }
    } guard{token};

    DWORD elevated = 0;
    DWORD returned = 0;
    if (::GetTokenInformation(token, TokenElevation, &elevated, sizeof(elevated), &returned)) {
        std::cout << "  current_process_elevated=" << (elevated != 0 ? "yes" : "no") << '\n';
    } else {
        std::cout << "  current_process_elevated=unknown win32_error=" << ::GetLastError() << '\n';
    }
    std::array<std::uint8_t, 8192> buffer{};
    if (!::GetTokenInformation(token, TokenPrivileges, buffer.data(),
            static_cast<DWORD>(buffer.size()), &returned) ||
        returned < sizeof(TOKEN_PRIVILEGES)) {
        std::cout << "  se_debug_privilege=unknown win32_error=" << ::GetLastError() << '\n';
        return;
    }
    const auto* privileges = reinterpret_cast<const TOKEN_PRIVILEGES*>(buffer.data());
    LUID debug_luid{};
    bool debug_present = false;
    bool debug_enabled = false;
    const bool found_debug = ::LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &debug_luid) != FALSE;
    const auto count = std::min<DWORD>(privileges->PrivilegeCount, 1024);
    for (DWORD i = 0; found_debug && i < count; ++i) {
        const auto& entry = privileges->Privileges[i];
        if (entry.Luid.LowPart == debug_luid.LowPart && entry.Luid.HighPart == debug_luid.HighPart) {
            debug_present = true;
            debug_enabled = (entry.Attributes & SE_PRIVILEGE_ENABLED) != 0;
        }
    }
    std::cout << "  se_debug_privilege=" << (debug_present ? (debug_enabled ? "enabled" : "present_not_enabled") : "absent")
              << " privileges_reported=" << privileges->PrivilegeCount << '\n';
}

void PrintPebModules(const HANDLE handle, const NtQueryInformationProcessFn query) {
    PROCESS_BASIC_INFORMATION basic{};
    const NTSTATUS status = query(
        handle, ProcessBasicInformation, &basic, static_cast<ULONG>(sizeof(basic)), nullptr);
    if (status < 0 || basic.PebBaseAddress == nullptr) {
        std::cout << "  NtQueryInformationProcess(ProcessBasicInformation) failed status=0x"
                  << std::hex << static_cast<std::uint32_t>(status) << std::dec << '\n';
        return;
    }
    std::array<std::uint8_t, 0x20> peb{};
    if (!ReadRaw(handle, reinterpret_cast<std::uint64_t>(basic.PebBaseAddress), peb.data(), peb.size())) {
        std::cout << "  PEB read failed win32_error=" << ::GetLastError() << '\n';
        return;
    }
    const auto image_base = LoadLe64(peb.data() + kPebImageBase);
    const auto ldr = LoadLe64(peb.data() + kPebLdr);
    std::cout << "  peb=0x" << std::hex << reinterpret_cast<std::uint64_t>(basic.PebBaseAddress)
              << " image_base=0x" << image_base << " ldr=0x" << ldr << std::dec << '\n';
    std::array<std::uint8_t, 2> signature{};
    if (ReadRaw(handle, image_base, signature.data(), signature.size())) {
        std::cout << "  vm_read_at_image_base=" << (signature[0] == 'M' && signature[1] == 'Z' ? "MZ ok" : "not MZ")
                  << '\n';
    } else {
        std::cout << "  vm_read_at_image_base=failed win32_error=" << ::GetLastError() << '\n';
    }
    if (ldr == 0) {
        return;
    }
    std::array<std::uint8_t, kLdrInMemoryOrderList + 8> ldr_header{};
    if (!ReadRaw(handle, ldr, ldr_header.data(), ldr_header.size())) {
        std::cout << "  PEB_LDR_DATA read failed win32_error=" << ::GetLastError() << '\n';
        return;
    }
    const auto list_head = ldr + kLdrInMemoryOrderList;
    auto entry = LoadLe64(ldr_header.data() + kLdrInMemoryOrderList);
    std::cout << "  modules_via_peb:\n";
    for (std::size_t index = 0;
         entry != 0 && entry != list_head && entry > kEntryLinksOffset && index < 2048; ++index) {
        const auto entry_va = entry - kEntryLinksOffset;
        std::array<std::uint8_t, kEntryEntrySize> record{};
        if (!ReadRaw(handle, entry_va, record.data(), record.size())) {
            std::cout << "    module record read failed at 0x" << std::hex << entry_va << std::dec
                      << " win32_error=" << ::GetLastError() << '\n';
            break;
        }
        const auto module_base = LoadLe64(record.data() + kEntryDllBase);
        const auto module_size = static_cast<std::uint32_t>(LoadLe64(record.data() + kEntrySizeOfImage) & 0xFFFFFFFFULL);
        const auto name_length = LoadLe16(record.data() + kEntryBaseDllName);
        const auto name_buffer = LoadLe64(record.data() + kEntryBaseDllName + 8);
        std::string name = "<unreadable>";
        if (name_buffer != 0 && name_length != 0 && name_length <= 1024 && name_length % 2 == 0) {
            std::vector<wchar_t> wide(name_length / 2, L'\0');
            if (ReadRaw(handle, name_buffer, wide.data(), name_length)) {
                name = WideToUtf8(std::wstring_view(wide.data(), wide.size()));
            }
        }
        std::cout << "    " << name << " base=0x" << std::hex << module_base
                  << " size=0x" << module_size << std::dec << '\n';
        entry = LoadLe64(record.data());
    }
}

void PrintPrivateReadProbe(const HANDLE handle) {
    struct Region {
        std::uint64_t base{};
        std::size_t size{};
    };
    std::vector<Region> regions;
    MEMORY_BASIC_INFORMATION info{};
    std::uint64_t address = 0x10000;
    std::size_t walked = 0;
    while (regions.size() < 5 && address < 0x7FFFFFFF0000ULL && walked < 200000) {
        if (::VirtualQueryEx(handle, reinterpret_cast<const void*>(static_cast<std::uintptr_t>(address)),
                &info, sizeof(info)) == 0) {
            std::cout << "  virtualquery=failed win32_error=" << ::GetLastError() << '\n';
            return;
        }
        ++walked;
        const auto protection = info.Protect & 0xFFU;
        const bool readable = protection == PAGE_READONLY || protection == PAGE_READWRITE ||
            protection == PAGE_EXECUTE_READ || protection == PAGE_EXECUTE_READWRITE ||
            protection == PAGE_EXECUTE_WRITECOPY;
        if (readable && info.State == MEM_COMMIT && info.Type == MEM_PRIVATE && info.RegionSize >= 0x1000) {
            regions.push_back({reinterpret_cast<std::uint64_t>(info.BaseAddress),
                static_cast<std::size_t>(std::min<SIZE_T>(info.RegionSize, 0x1000))});
        }
        const auto next = reinterpret_cast<std::uint64_t>(info.BaseAddress) + info.RegionSize;
        if (next <= address) {
            break;
        }
        address = next;
    }
    std::cout << "  virtualquery=ok regions_walked=" << walked << " private_samples=" << regions.size() << '\n';
    std::size_t readable_count = 0;
    for (const auto& region : regions) {
        std::array<std::uint8_t, 16> buffer{};
        const bool ok = ReadRaw(handle, region.base, buffer.data(), buffer.size());
        readable_count += ok ? 1U : 0U;
        std::cout << "    read 0x" << std::hex << region.base << std::dec << " size=0x" << std::hex
                  << region.size << std::dec << " -> " << (ok ? "readable" : "denied");
        if (!ok) {
            std::cout << " win32_error=" << ::GetLastError();
        }
        std::cout << '\n';
    }
    std::cout << "  private_region_reads=" << readable_count << " of " << regions.size()
              << (regions.empty() ? " (no private committed regions walked)" : "") << '\n';
}

} // namespace

void PrintProcessProbe(const std::uint32_t pid) {
    if (pid == 0) {
        throw std::invalid_argument("PID must be nonzero");
    }
    struct Access {
        std::uint32_t mask;
        std::string_view name;
    };
    constexpr std::array<Access, 8> accesses{{
        {PROCESS_QUERY_LIMITED_INFORMATION, "PROCESS_QUERY_LIMITED_INFORMATION"},
        {PROCESS_QUERY_INFORMATION, "PROCESS_QUERY_INFORMATION"},
        {PROCESS_VM_READ, "PROCESS_VM_READ"},
        {PROCESS_VM_WRITE, "PROCESS_VM_WRITE"},
        {PROCESS_VM_OPERATION, "PROCESS_VM_OPERATION"},
        {PROCESS_CREATE_THREAD, "PROCESS_CREATE_THREAD"},
        {PROCESS_SUSPEND_RESUME, "PROCESS_SUSPEND_RESUME"},
        {SYNCHRONIZE, "SYNCHRONIZE"},
    }};
    std::cout << "build=" << kBuildStamp << "\nprobe pid=" << pid << '\n';
    PrintSelfTokenState();
    std::cout << "access_rights:\n";
    for (const auto& access : accesses) {
        const HANDLE handle = ::OpenProcess(access.mask, FALSE, pid);
        std::cout << "  " << access.name << "=" << (handle != nullptr ? "granted" : "denied");
        if (handle == nullptr) {
            std::cout << " win32_error=" << ::GetLastError();
        }
        std::cout << '\n';
        if (handle != nullptr) {
            ::CloseHandle(handle);
        }
    }

    const auto reader_mask = static_cast<DWORD>(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
    const HANDLE reader = ::OpenProcess(reader_mask, FALSE, pid);
    std::cout << "reader_handle=" << (reader != nullptr ? "open" : "failed") << '\n';
    if (reader != nullptr) {
        struct HandleGuard {
            HANDLE handle;
            ~HandleGuard() { ::CloseHandle(handle); }
        } guard{reader};
        const auto ntdll = ::GetModuleHandleW(L"ntdll.dll");
        const auto query = reinterpret_cast<NtQueryInformationProcessFn>(
            ntdll == nullptr ? nullptr : ::GetProcAddress(ntdll, "NtQueryInformationProcess"));
        if (query == nullptr) {
            std::cout << "  NtQueryInformationProcess unavailable\n";
        } else {
            PrintPebModules(reader, query);
        }
        // A handle can be granted with PROCESS_VM_READ silently stripped by a protection callback, so
        // the only meaningful test is an actual read. One address is one point; sample several.
        PrintPrivateReadProbe(reader);
    }

    const HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::cout << "toolhelp_snapshot=failed win32_error=" << ::GetLastError() << '\n';
    } else {
        MODULEENTRY32W entry{};
        entry.dwSize = sizeof(entry);
        std::size_t count = 0;
        for (BOOL more = ::Module32FirstW(snapshot, &entry); more != FALSE; more = ::Module32NextW(snapshot, &entry)) {
            ++count;
            if (count >= 2048) {
                break;
            }
        }
        std::cout << "toolhelp_snapshot=ok modules=" << count << '\n';
        ::CloseHandle(snapshot);
    }
}

std::string WideToUtf8(const std::wstring_view value) {
    if (value.empty()) {
        return {};
    }
    const int size = ::WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (size <= 0) {
        ThrowWin32("WideCharToMultiByte size query failed");
    }
    std::string result(static_cast<std::size_t>(size), '\0');
    if (::WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), result.data(), size, nullptr, nullptr) != size) {
        ThrowWin32("WideCharToMultiByte conversion failed");
    }
    return result;
}

std::wstring Utf8ToWide(const std::string_view value) {
    if (value.empty()) {
        return {};
    }
    const int size = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0);
    if (size <= 0) {
        ThrowWin32("MultiByteToWideChar size query failed");
    }
    std::wstring result(static_cast<std::size_t>(size), L'\0');
    if (::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), result.data(), size) != size) {
        ThrowWin32("MultiByteToWideChar conversion failed");
    }
    return result;
}

std::uint32_t ReadPeTimestamp(const Process& process, const ModuleInfo& module) {
    const auto dos = process.Read(module.base, 0x40);
    if (dos[0] != 'M' || dos[1] != 'Z') {
        throw std::runtime_error("module has no MZ header: " + WideToUtf8(module.name));
    }
    const std::int32_t lfanew = static_cast<std::int32_t>(LoadU32(dos.data() + 0x3C));
    if (lfanew < 0 || lfanew > 1024 * 1024) {
        throw std::runtime_error("module has an implausible e_lfanew: " + WideToUtf8(module.name));
    }
    const auto nt_address = module.base + static_cast<std::uintptr_t>(lfanew);
    const auto nt = process.Read(nt_address, 24);
    if (!(nt[0] == 'P' && nt[1] == 'E' && nt[2] == 0 && nt[3] == 0)) {
        throw std::runtime_error("module has no PE header: " + WideToUtf8(module.name));
    }
    if (nt[4] != 0x64 || nt[5] != 0x86) {
        throw std::runtime_error("module is not AMD64 PE: " + WideToUtf8(module.name));
    }
    return LoadU32(nt.data() + 8);
}

std::uint32_t ReadPeFileTimestamp(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("cannot open PE file: " + path.string());
    }
    std::array<std::uint8_t, 0x40> dos{};
    input.read(reinterpret_cast<char*>(dos.data()), dos.size());
    if (!input || dos[0] != 'M' || dos[1] != 'Z') {
        throw std::runtime_error("file has no readable MZ header: " + path.string());
    }
    const std::int32_t lfanew = static_cast<std::int32_t>(LoadU32(dos.data() + 0x3C));
    if (lfanew < 0 || lfanew > 1024 * 1024) {
        throw std::runtime_error("file has an implausible e_lfanew: " + path.string());
    }
    input.seekg(lfanew);
    std::array<std::uint8_t, 24> nt{};
    input.read(reinterpret_cast<char*>(nt.data()), nt.size());
    if (!input || !(nt[0] == 'P' && nt[1] == 'E' && nt[2] == 0 && nt[3] == 0)) {
        throw std::runtime_error("file has no readable PE header: " + path.string());
    }
    if (nt[4] != 0x64 || nt[5] != 0x86) {
        throw std::runtime_error("file is not AMD64 PE: " + path.string());
    }
    return LoadU32(nt.data() + 8);
}

const ModuleInfo& FindModule(const std::vector<ModuleInfo>& modules, const std::string_view utf8_name) {
    const std::wstring expected = Utf8ToWide(utf8_name);
    const auto found = std::find_if(modules.begin(), modules.end(), [&](const ModuleInfo& module) {
        return ::CompareStringOrdinal(module.name.c_str(), -1, expected.c_str(), -1, TRUE) == CSTR_EQUAL;
    });
    if (found == modules.end()) {
        throw std::runtime_error("configured module is not loaded: " + std::string(utf8_name));
    }
    return *found;
}

} // namespace arc

#endif
