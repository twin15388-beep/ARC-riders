#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace arc {

// Encoding of the 16-bit FName entry header and the payload that follows it. length_shift and
// length_bits say where the character count sits inside the header, wide_bit selects the character
// width, string_offset is the distance from the entry start to the first character.
//
// These are hypotheses to test against captured bytes, not claims about a build. DetectNameBlock()
// decides which one actually decodes the block that was found in the dump, and the caller reports the
// winner, so a passing codec is a measurement.
struct NameCodec {
    std::string_view label;
    std::uint32_t length_shift{};
    std::uint32_t length_bits{};
    std::uint32_t wide_bit{};
    std::uint32_t string_offset{};
};

// Measured on the plaintext FName block at 0xA6A00000 of gameplay dump (2): header immediately
// precedes the string, length = header >> 6, bit 0 marks a wide entry.
inline constexpr NameCodec kNameCodecMeasured{
    "measured_shift6_wide0_str2", 6, 10, 0, 2};

// Stock-looking alternative kept only so a real block can reject or accept it: length in bits 0..9,
// wide flag in bit 10.
inline constexpr NameCodec kNameCodecLenLowBits{
    "alt_len_bits_0_9_wide10", 0, 10, 10, 2};

inline constexpr std::array<NameCodec, 2> kNameCodecCandidates{
    kNameCodecMeasured, kNameCodecLenLowBits};

struct NameEntry {
    std::uint32_t offset{};  // from block data start; the low bits of an FName pool index
    std::uint32_t length{};  // characters, excluding the terminator
    bool wide{};
    std::string text;        // UTF-8 copy of the stored characters
};

// Forward decode of one FName pool block. The walk stops at the first entry whose header or payload
// does not fit, whose length is out of range, whose terminator is missing, or whose characters are not
// name-like; that density requirement is what makes a block recognizable.
struct NameBlockWalk {
    const NameCodec* codec{};
    std::vector<NameEntry> entries;
    std::uint32_t consumed{};  // bytes of the block used by accepted entries
    bool cap_reached{};        // stopped on max_entries, block may continue
    bool span_exhausted{};     // stopped because the captured span ended
};

[[nodiscard]] NameBlockWalk WalkNameBlock(
    std::span<const std::uint8_t> block,
    const NameCodec& codec,
    std::size_t max_entries,
    std::uint32_t start_offset = 0);

// Returns the walk of the codec that decodes the most entries. When expected_first is non-empty a
// codec only qualifies if its first entry matches it (FName pool block 0 begins with "None").
// min_entries is the density requirement that separates a name block from arbitrary heap data.
[[nodiscard]] NameBlockWalk DetectNameBlock(
    std::span<const std::uint8_t> block,
    std::span<const NameCodec> codecs,
    std::string_view expected_first,
    std::uint32_t min_entries,
    std::size_t max_entries = 8192);

// Summary form used when only the shape of a block matters, so no entry strings are kept.
struct NameBlockStats {
    std::uint32_t entries{};
    std::uint32_t consumed{};  // block bytes used by accepted entries
    bool cap_reached{};        // entries beyond max_entries were not counted
    bool span_exhausted{};
    std::string first_name;
    std::string last_name;
};

[[nodiscard]] NameBlockStats MeasureNameBlock(
    std::span<const std::uint8_t> block,
    const NameCodec& codec,
    std::size_t max_entries);

// Memory access injected so the block walk can be checked without a dump. The returned span is the
// longest contiguous captured run starting at va, capped at size, and must stay valid for the
// duration of the call; nullopt means nothing is captured at va.
using CapturedRead =
    std::function<std::optional<std::span<const std::uint8_t>>(std::uint64_t va, std::uint64_t size)>;

// Per-candidate result of looking for the block header that precedes a block's entry data.
struct HeaderProbe {
    std::uint32_t header_size{};
    std::uint64_t header_va{};
    std::uint64_t next{};
    bool header_captured{};
    bool next_is_null{};
    bool next_is_block{};     // next + header_size decodes as a name block
    std::uint32_t next_entries{};
    std::vector<std::uint8_t> window;  // raw bytes of the candidate header
};

[[nodiscard]] std::vector<HeaderProbe> ProbeBlockHeaders(
    const CapturedRead& read,
    std::uint64_t first_data_va,
    std::uint32_t block_size,
    const NameCodec& codec,
    std::uint32_t min_entries,
    std::span<const std::uint32_t> header_size_candidates);

struct NameBlockNode {
    std::uint64_t header_va{};
    std::uint64_t data_va{};
    std::uint64_t next{};
    NameBlockStats stats;
    bool data_captured{};
    bool header_captured{};
};

// FName pool blocks are separate allocations chained through a pointer in each block header. Walking
// the chain recovers every block, and therefore every name, without knowing any global address.
struct NameBlockChain {
    std::uint32_t header_size{};
    std::uint32_t block_size{};
    std::vector<NameBlockNode> blocks;
    std::uint64_t total_entries{};
    bool total_capped{};      // at least one block stopped on max_entries_per_block
    std::string stop_reason;
};

[[nodiscard]] NameBlockChain FollowNameBlocks(
    const CapturedRead& read,
    std::uint64_t first_data_va,
    std::uint32_t header_size,
    std::uint32_t block_size,
    const NameCodec& codec,
    std::uint32_t min_entries,
    std::size_t max_entries_per_block,
    std::size_t max_blocks);

// A position where the measured header encoding announces a printable, null-terminated string that
// starts right there. This makes no assumption about how entries are chained, so the gaps between hits
// are what reveal the real stride.
struct NameHit {
    std::uint32_t offset{};
    std::uint32_t length{};
    bool wide{};
    std::string text;
    // The measurement that matters: bytes between one entry start and the next decoded position, and how
    // many zero bytes sit between the terminator and the following header. A constant entry_size across a
    // region means fixed-size records; entry_size == 2 + payload + pad with a varying pad means the
    // entries are packed back to back and the record size comes from the length field alone.
    std::uint32_t entry_size{};
    std::uint32_t pad_after{};
};

[[nodiscard]] std::vector<NameHit> FindNameLikeEntries(
    std::span<const std::uint8_t> window,
    const NameCodec& codec,
    std::size_t max_hits);

// Format-agnostic fallback: every maximal run of printable ASCII terminated by a NUL byte. Works
// even when the entry header itself is encrypted, so the stride between strings is still measurable.
[[nodiscard]] std::vector<NameHit> FindAsciiRuns(
    std::span<const std::uint8_t> window,
    std::uint32_t min_length,
    std::size_t max_hits);

// Walks the packed name stream backwards from `stop` by requiring each predecessor to end exactly at
// `stop` (allowing zero padding). This is how the start of a block is recovered from an anchor found in
// the middle of it, which is the normal case: a marker search lands on whatever name matched, not on
// entry 0.
[[nodiscard]] std::vector<NameHit> BackwardNameStream(
    std::span<const std::uint8_t> window,
    const NameCodec& codec,
    std::uint32_t stop,
    std::size_t max_entries);

// Distinct byte gaps between consecutive hits, with how often each one occurs. A single gap value
// across the whole block means a fixed stride model; alternating values mean extra per-entry fields.
[[nodiscard]] std::vector<std::pair<std::uint32_t, std::uint32_t>> GapHistogram(
    std::span<const NameHit> hits);

// Reads `window` bytes at `va` through `read` and prints what the bytes actually say about the entry
// layout: every header-shaped position whose string decodes, the stride between them, the raw hex.
// Shared by dump analysis and the live process, because the same question needs the same measurement.
void PrintNameLayout(
    std::ostream& out,
    std::string_view label,
    const CapturedRead& read,
    std::uint64_t va,
    std::uint32_t window,
    std::size_t max_hits);

// True for characters allowed in an FName: printable ASCII, no space, no control bytes.
[[nodiscard]] bool IsNameCharacter(char value) noexcept;

} // namespace arc
