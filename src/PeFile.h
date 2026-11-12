#pragma once

#ifdef _WIN32

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <vector>

#include <windows.h>

namespace arc {

class MappedFile {
public:
    explicit MappedFile(const std::filesystem::path& path);
    ~MappedFile();

    MappedFile(const MappedFile&) = delete;
    MappedFile& operator=(const MappedFile&) = delete;

    [[nodiscard]] std::span<const std::uint8_t> Bytes() const noexcept {
        return {view_, size_};
    }

private:
    HANDLE file_{};
    HANDLE mapping_{};
    const std::uint8_t* view_{};
    std::size_t size_{};
};

void PrintPeFileInfo(const std::filesystem::path& path);
void PrintPeRtti(
    const std::filesystem::path& path,
    std::uint64_t image_base,
    const std::vector<std::uint64_t>& vtables);

} // namespace arc

#endif
