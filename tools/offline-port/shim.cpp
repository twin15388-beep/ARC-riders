// POSIX stand-in for the Windows-only pieces the offline dump code needs, so that src/DumpFile.cpp can be
// compiled and run on Linux against a synthetic .dmp. Build it with -D_WIN32 and this directory first on
// the include path; see build.sh. Nothing here ships in the Windows binary.
#include "PeFile.h"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <string>
#include <stdexcept>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

namespace arc {

MappedFile::MappedFile(const std::filesystem::path& path) {
    const std::string name = path.string();  // value_type is wchar_t under _WIN32, so ask for UTF-8
    const int fd = ::open(name.c_str(), O_RDONLY);
    if (fd < 0) {
        throw std::runtime_error("cannot open " + path.string() + ": " + std::strerror(errno));
    }
    struct stat status {};
    if (::fstat(fd, &status) != 0 || status.st_size <= 0) {
        ::close(fd);
        throw std::runtime_error("cannot stat " + path.string());
    }
    void* view = ::mmap(nullptr, static_cast<std::size_t>(status.st_size), PROT_READ, MAP_PRIVATE, fd, 0);
    if (view == MAP_FAILED) {
        const int error = errno;
        ::close(fd);
        throw std::runtime_error("cannot map " + path.string() + ": " + std::strerror(error));
    }
    file_ = reinterpret_cast<HANDLE>(static_cast<std::intptr_t>(fd));
    view_ = static_cast<const std::uint8_t*>(view);
    size_ = static_cast<std::size_t>(status.st_size);
}

MappedFile::~MappedFile() {
    if (view_ != nullptr) {
        ::munmap(const_cast<std::uint8_t*>(view_), size_);
    }
    if (file_ != nullptr) {
        ::close(static_cast<int>(reinterpret_cast<std::intptr_t>(file_)));
    }
}

// Process.h declares this for the Windows build (Process.cpp defines it there); the offline paths in this
// harness come from a minidump, where module names are wide strings.
std::string WideToUtf8(std::wstring_view value) {
    std::string out;
    for (const auto code : value) {
        const auto point = static_cast<std::uint32_t>(code);
        if (point < 0x80) {
            out.push_back(static_cast<char>(point));
        } else if (point < 0x800) {
            out.push_back(static_cast<char>(0xC0U | (point >> 6)));
            out.push_back(static_cast<char>(0x80U | (point & 0x3FU)));
        } else if (point < 0x10000) {
            out.push_back(static_cast<char>(0xE0U | (point >> 12)));
            out.push_back(static_cast<char>(0x80U | ((point >> 6) & 0x3FU)));
            out.push_back(static_cast<char>(0x80U | (point & 0x3FU)));
        } else {
            out.push_back(static_cast<char>(0xF0U | (point >> 18)));
            out.push_back(static_cast<char>(0x80U | ((point >> 12) & 0x3FU)));
            out.push_back(static_cast<char>(0x80U | ((point >> 6) & 0x3FU)));
            out.push_back(static_cast<char>(0x80U | (point & 0x3FU)));
        }
    }
    return out;
}

} // namespace arc
