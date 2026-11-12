#pragma once

#ifdef _WIN32

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include <windows.h>

namespace arc {

struct ModuleInfo {
    std::uintptr_t base{};
    std::size_t size{};
    std::wstring name;
    std::filesystem::path path;
};

class Process {
public:
    static Process Open(std::uint32_t pid);
    ~Process();

    Process(const Process&) = delete;
    Process& operator=(const Process&) = delete;
    Process(Process&& other) noexcept;
    Process& operator=(Process&& other) noexcept;

    [[nodiscard]] std::uint32_t Pid() const noexcept { return pid_; }
    [[nodiscard]] std::vector<ModuleInfo> Modules() const;
    void ReadExact(std::uintptr_t address, void* output, std::size_t size) const;
    [[nodiscard]] std::vector<std::uint8_t> Read(std::uintptr_t address, std::size_t size) const;
    [[nodiscard]] std::uint64_t ReadU64(std::uintptr_t address) const;

private:
    Process(HANDLE handle, std::uint32_t pid) noexcept : handle_(handle), pid_(pid) {}

    HANDLE handle_{};
    std::uint32_t pid_{};
};

[[nodiscard]] std::string WideToUtf8(std::wstring_view value);
[[nodiscard]] std::wstring Utf8ToWide(std::string_view value);
[[nodiscard]] std::uint32_t ReadPeTimestamp(const Process& process, const ModuleInfo& module);
[[nodiscard]] std::uint32_t ReadPeFileTimestamp(const std::filesystem::path& path);
[[nodiscard]] const ModuleInfo& FindModule(const std::vector<ModuleInfo>& modules, std::string_view utf8_name);

} // namespace arc

#endif
