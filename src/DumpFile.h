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
void PrintDumpRipXrefs(const std::filesystem::path& path, std::uint64_t target_va);
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
void PrintDumpFNamePool(
    const std::filesystem::path& path,
    std::uint64_t image_base,
    std::uint64_t image_size);
// Anchor-driven FName pool recovery: finds the block that starts with a known first name, follows the
// block chain, and reports every captured pointer to that block (in-image hits are GNames RVAs).
// Prints the observed name-entry layout of one region: every position whose header decodes as a
// printable null-terminated string, the gaps between them, and the raw bytes. Used to measure the
// entry stride instead of assuming it.
void PrintDumpFNameLayout(
    const std::filesystem::path& path,
    std::uint64_t va,
    std::uint32_t window_size,
    std::size_t max_hits);
// Recovers FName pool blocks without assuming where the pool lives. `anchor_data_va` is the data VA of
// a block already known to hold names, when one is known; if it is 0, or if that VA is not captured in
// this dump, every captured range is searched for the start of a dense NUL-terminated name stream whose
// first entry is one of `marker_list` (comma separated, defaults to engine-core names beginning with
// "None"). The point of the marker list is that "no block starts with None" was already measured, so a
// single-marker search cannot tell a wrong codec apart from a region the dump never captured.
void PrintDumpFNameBlocks(
    const std::filesystem::path& path,
    std::uint64_t image_base,
    std::uint64_t image_size,
    std::uint64_t anchor_data_va,
    std::uint32_t block_size,
    std::uint32_t min_entries,
    std::size_t max_blocks,
    std::string_view marker_list = {});

} // namespace arc

#endif
