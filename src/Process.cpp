#ifdef _WIN32

#include "Process.h"

#include <tlhelp32.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <limits>
#include <stdexcept>

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
