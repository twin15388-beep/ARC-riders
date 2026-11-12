#pragma once

#ifdef _WIN32

#include "Pattern.h"

#include <cstdint>
#include <filesystem>
#include <string_view>
#include <vector>

namespace arc {

void PrintDumpInfo(const std::filesystem::path& path);
void PrintDumpStrings(const std::filesystem::path& path, std::string_view needle);
void PrintDumpXrefs(const std::filesystem::path& path, std::uint64_t target_va);
void PrintDumpScan(const std::filesystem::path& path, const Pattern& pattern);
void PrintDumpRead(const std::filesystem::path& path, std::uint64_t va, std::size_t size);
void PrintDumpRtti(
    const std::filesystem::path& path,
    std::uint64_t image_base,
    const std::vector<std::uint64_t>& vtables);
void PrintDumpPointerChain(
    const std::filesystem::path& path,
    std::uint64_t pointer_va,
    const std::vector<std::uint64_t>& offsets);
void PrintDumpPointerChainScan(
    const std::filesystem::path& path,
    std::uint64_t image_base,
    std::uint64_t image_size,
    const std::vector<std::uint64_t>& offsets);
void PrintDumpGNamesCandidates(
    const std::filesystem::path& path,
    std::uint64_t image_base,
    std::uint64_t image_size);
void PrintDumpGObjectsCandidates(
    const std::filesystem::path& path,
    std::uint64_t data_va,
    std::uint64_t data_size);
void PrintDumpGObjectsCheck(const std::filesystem::path& path, std::uint64_t objects);
void PrintDumpGNamesLazyCandidates(
    const std::filesystem::path& path,
    std::uint64_t image_base,
    std::uint64_t image_size);

} // namespace arc

#endif
