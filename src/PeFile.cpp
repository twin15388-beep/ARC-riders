#ifdef _WIN32

#include "PeFile.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <iomanip>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace arc {
namespace {

[[noreturn]] void ThrowWin32(const std::string& operation, const DWORD error = ::GetLastError()) {
    throw std::runtime_error(operation + ": Win32 error " + std::to_string(error));
}

std::uint16_t U16(const std::uint8_t* p) {
    return static_cast<std::uint16_t>(p[0]) | (static_cast<std::uint16_t>(p[1]) << 8);
}

std::uint32_t U32(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0]) |
        (static_cast<std::uint32_t>(p[1]) << 8) |
        (static_cast<std::uint32_t>(p[2]) << 16) |
        (static_cast<std::uint32_t>(p[3]) << 24);
}

void Require(const std::size_t offset, const std::size_t amount, const std::size_t size) {
    if (offset > size || amount > size - offset) {
        throw std::runtime_error("PE structure points outside the file");
    }
}

std::string PrintableString(const std::span<const std::uint8_t> bytes, const std::size_t start) {
    constexpr std::size_t max_length = 240;
    std::string result;
    for (std::size_t i = start; i < bytes.size() && result.size() < max_length; ++i) {
        const auto c = bytes[i];
        if (c == 0) {
            break;
        }
        result.push_back(c >= 0x20 && c <= 0x7e ? static_cast<char>(c) : '.');
    }
    return result;
}

void PrintStringHits(const std::span<const std::uint8_t> bytes, const std::string_view needle) {
    constexpr std::size_t max_hits = 16;
    std::size_t hits = 0;
    auto lower = [](const unsigned char c) { return static_cast<unsigned char>(std::tolower(c)); };
    auto current = bytes.begin();
    while (current != bytes.end() && hits < max_hits) {
        const auto found = std::search(current, bytes.end(), needle.begin(), needle.end(), [&](const char a, const char b) {
            return lower(static_cast<unsigned char>(a)) == lower(static_cast<unsigned char>(b));
        });
        if (found == bytes.end()) {
            break;
        }
        const auto offset = static_cast<std::size_t>(found - bytes.begin());
        std::cout << "    file_offset=0x" << std::hex << offset << std::dec << " \""
                  << PrintableString(bytes, offset) << "\"\n";
        ++hits;
        current = found + 1;
    }
    std::cout << "  hits=" << hits << (hits == max_hits ? " (cap reached)" : "") << '\n';
}

} // namespace

MappedFile::MappedFile(const std::filesystem::path& path) {
    file_ = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file_ == INVALID_HANDLE_VALUE) {
        ThrowWin32("CreateFileW failed for " + path.string());
    }
    LARGE_INTEGER size{};
    if (!::GetFileSizeEx(file_, &size)) {
        const auto error = ::GetLastError();
        ::CloseHandle(file_);
        ThrowWin32("GetFileSizeEx failed", error);
    }
    if (size.QuadPart <= 0 || static_cast<std::uint64_t>(size.QuadPart) > std::numeric_limits<std::size_t>::max()) {
        ::CloseHandle(file_);
        throw std::runtime_error("file is empty or too large to map");
    }
    size_ = static_cast<std::size_t>(size.QuadPart);
    mapping_ = ::CreateFileMappingW(file_, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (mapping_ == nullptr) {
        const auto error = ::GetLastError();
        ::CloseHandle(file_);
        ThrowWin32("CreateFileMappingW failed", error);
    }
    view_ = static_cast<const std::uint8_t*>(::MapViewOfFile(mapping_, FILE_MAP_READ, 0, 0, 0));
    if (view_ == nullptr) {
        const auto error = ::GetLastError();
        ::CloseHandle(mapping_);
        ::CloseHandle(file_);
        ThrowWin32("MapViewOfFile failed", error);
    }
}

MappedFile::~MappedFile() {
    if (view_ != nullptr) {
        ::UnmapViewOfFile(view_);
    }
    if (mapping_ != nullptr) {
        ::CloseHandle(mapping_);
    }
    if (file_ != nullptr && file_ != INVALID_HANDLE_VALUE) {
        ::CloseHandle(file_);
    }
}

void PrintPeFileInfo(const std::filesystem::path& path) {
    const MappedFile file(path);
    const auto bytes = file.Bytes();
    Require(0, 0x40, bytes.size());
    if (bytes[0] != 'M' || bytes[1] != 'Z') {
        throw std::runtime_error("not an MZ executable");
    }
    const auto nt = static_cast<std::size_t>(U32(bytes.data() + 0x3C));
    Require(nt, 24, bytes.size());
    if (!(bytes[nt] == 'P' && bytes[nt + 1] == 'E' && bytes[nt + 2] == 0 && bytes[nt + 3] == 0)) {
        throw std::runtime_error("not a PE executable");
    }
    const auto machine = U16(bytes.data() + nt + 4);
    const auto section_count = static_cast<std::size_t>(U16(bytes.data() + nt + 6));
    const auto timestamp = U32(bytes.data() + nt + 8);
    const auto optional_size = static_cast<std::size_t>(U16(bytes.data() + nt + 20));
    const auto optional = nt + 24;
    Require(optional, optional_size, bytes.size());
    if (optional_size < 64 || U16(bytes.data() + optional) != 0x20B) {
        throw std::runtime_error("expected a PE32+ optional header");
    }
    const auto image_size = U32(bytes.data() + optional + 56);
    const auto headers_size = U32(bytes.data() + optional + 60);
    std::cout << "file=" << path.string() << "\nfile_size=" << bytes.size()
              << "\nmachine=0x" << std::hex << machine
              << "\npe_timestamp=0x" << timestamp
              << "\nsize_of_image=0x" << image_size
              << "\nsize_of_headers=0x" << headers_size << std::dec << '\n';

    const auto sections = optional + optional_size;
    Require(sections, section_count * 40, bytes.size());
    for (std::size_t i = 0; i < section_count; ++i) {
        const auto section = sections + i * 40;
        std::string name;
        for (std::size_t j = 0; j < 8 && bytes[section + j] != 0; ++j) {
            name.push_back(static_cast<char>(bytes[section + j]));
        }
        std::cout << "section " << name
                  << " RVA=0x" << std::hex << U32(bytes.data() + section + 12)
                  << " virtual_size=0x" << U32(bytes.data() + section + 8)
                  << " raw_offset=0x" << U32(bytes.data() + section + 20)
                  << " raw_size=0x" << U32(bytes.data() + section + 16)
                  << " characteristics=0x" << U32(bytes.data() + section + 36)
                  << std::dec << '\n';
    }

    constexpr std::array<std::string_view, 8> needles{
        "++UE", "Unreal Engine", "FNamePool", "GUObjectArray",
        "GWorld", "Pioneer", "EasyAntiCheat", "EOS",
    };
    for (const auto& needle : needles) {
        std::cout << "string \"" << needle << "\":\n";
        PrintStringHits(bytes, needle);
    }
}

} // namespace arc

#endif
