#include "Chain.h"
#include "Esp.h"
#include "Config.h"
#include "Pattern.h"
#include "Names.h"
#include "Usmap.h"
#include "ArcDecrypt.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <array>
#include <exception>
#include <optional>
#include <span>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

namespace {

void Check(const bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void ExpectThrow(const std::function<void()>& action, const char* message) {
    try {
        action();
    } catch (const std::exception&) {
        return;
    }
    throw std::runtime_error(message);
}

void TestPattern() {
    const auto pattern = arc::Pattern::Parse("48 8B 05 ?? ?? ?? 48 85");
    Check(pattern.Size() == 8, "pattern size");
    const std::vector<std::uint8_t> bytes{
        0x48, 0x8B, 0x05, 0x11, 0x22, 0x33, 0x48, 0x85,
        0x48, 0x8B, 0x05, 0x44, 0x55, 0x66, 0x48, 0x85,
    };
    const auto matches = arc::FindPattern(bytes, pattern);
    Check(matches.size() == 2 && matches[0] == 0 && matches[1] == 8, "wildcard matches");
    Check(arc::FindPattern(bytes, pattern, 1).size() == 1, "match limit");

    const auto nibble = arc::Pattern::Parse("4? ?B");
    Check(arc::FindPattern(bytes, nibble).size() == 2, "nibble wildcards");
    const auto wild = arc::Pattern::Parse("?? ??");
    Check(arc::FindPattern(bytes, wild, 5).size() == 5, "all-wildcard limit");
    Check(arc::FindPattern(std::vector<std::uint8_t>{1, 2}, arc::Pattern::Parse("01 02 03")).empty(), "short haystack");

    ExpectThrow([] { (void)arc::Pattern::Parse(""); }, "empty pattern accepted");
    ExpectThrow([] { (void)arc::Pattern::Parse("A"); }, "odd pattern accepted");
    ExpectThrow([] { (void)arc::Pattern::Parse("GG"); }, "invalid hex accepted");
    ExpectThrow([] { (void)arc::Pattern::Parse("?"); }, "single wildcard accepted");
}

void TestNumbersAndChains() {
    Check(arc::ParseUnsigned(" 0x1000 ") == 0x1000, "hex number");
    Check(arc::ParseUnsigned("4096") == 4096, "decimal number");
    ExpectThrow([] { (void)arc::ParseUnsigned("-1"); }, "negative number accepted");
    ExpectThrow([] { (void)arc::ParseUnsigned("0x"); }, "empty hex accepted");
    ExpectThrow([] { (void)arc::ParseUnsigned("12junk"); }, "numeric suffix accepted");
    Check(arc::CheckedAdd(10, 20).value() == 30, "checked addition");
    Check(!arc::CheckedAdd(std::numeric_limits<std::uint64_t>::max(), 1), "overflow accepted");

    const auto chain = arc::ParsePointerChain("g_world+0x20, 0x30, 0x120,8");
    Check(chain.base_kind == arc::ChainBaseKind::Signature, "chain base kind");
    Check(chain.signature_name == "g_world" && chain.base_offset == 0x20, "chain base");
    Check(chain.offsets.size() == 3 && chain.offsets[0] == 0x30 && chain.offsets[1] == 0x120 && chain.offsets[2] == 8, "chain offsets");
    const auto direct = arc::ParsePointerChain("module+0x1234");
    Check(direct.base_kind == arc::ChainBaseKind::Module && direct.offsets.empty(), "direct module chain");
    ExpectThrow([] { (void)arc::ParsePointerChain("module"); }, "base without offset accepted");
    ExpectThrow([] { (void)arc::ParsePointerChain("module+0,,"); }, "empty chain offset accepted");
}

void TestConfig() {
    const auto config = arc::Config::Parse(R"(
[build]
process_name = Game.exe
module_name = Game.exe
file_size = 0x1000
pe_timestamp = 0x65000000
[signatures]
world = 48 8B ?? ??
unused =
[chains]
player = world+0x3,0x10,0x20
)");
    Check(config.build.process_name == "Game.exe", "config process");
    Check(config.build.file_size.value() == 0x1000, "config size");
    Check(config.build.pe_timestamp.value() == 0x65000000, "config timestamp");
    Check(config.signatures.size() == 1 && config.chains.size() == 1, "config maps");
    Check(config.chains.at("player").offsets.size() == 2, "config chain");

    const auto unset = arc::Config::Parse("[build]\nfile_size =\npe_timestamp =\n");
    Check(!unset.build.file_size && !unset.build.pe_timestamp, "unset values became zero");
    ExpectThrow([] { (void)arc::Config::Parse("[unknown]\na=b\n"); }, "unknown section accepted");
    ExpectThrow([] { (void)arc::Config::Parse("[build]\npe_timestamp=0x100000000\n"); }, "large timestamp accepted");
    ExpectThrow([] { (void)arc::Config::Parse("[build]\nunknown=1\n"); }, "unknown build key accepted");
    ExpectThrow([] { (void)arc::Config::Parse("[signatures]\na=48\na=48\n"); }, "duplicate signature accepted");
}

template<typename T>
void Append(std::vector<std::uint8_t>& bytes, const T value) {
    const auto* first = reinterpret_cast<const std::uint8_t*>(&value);
    bytes.insert(bytes.end(), first, first + sizeof(T));
}

void TestUsmap() {
    std::vector<std::uint8_t> payload;
    Append<std::uint32_t>(payload, 2);
    Append<std::uint16_t>(payload, 6);
    payload.insert(payload.end(), {'V', 'e', 'c', 't', 'o', 'r'});
    Append<std::uint16_t>(payload, 1);
    payload.push_back('X');
    Append<std::uint32_t>(payload, 0);
    Append<std::uint32_t>(payload, 1);
    Append<std::uint32_t>(payload, 0);
    Append<std::uint32_t>(payload, UINT32_MAX);
    Append<std::uint16_t>(payload, 1);
    Append<std::uint16_t>(payload, 1);
    Append<std::uint16_t>(payload, 0);
    Append<std::uint8_t>(payload, 1);
    Append<std::uint32_t>(payload, 1);
    Append<std::uint8_t>(payload, 7);
    payload.insert(payload.end(), {'C', 'E', 'X', 'T'});
    Append<std::uint8_t>(payload, 0);
    Append<std::uint32_t>(payload, 0);

    std::vector<std::uint8_t> file;
    Append<std::uint16_t>(file, 0x30C4);
    Append<std::uint8_t>(file, 4);
    Append<std::int32_t>(file, 0);
    Append<std::uint8_t>(file, 0);
    Append<std::uint32_t>(file, static_cast<std::uint32_t>(payload.size()));
    Append<std::uint32_t>(file, static_cast<std::uint32_t>(payload.size()));
    file.insert(file.end(), payload.begin(), payload.end());

    const auto path = std::filesystem::temp_directory_path() / "arc_core_test.usmap";
    {
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        output.write(reinterpret_cast<const char*>(file.data()), static_cast<std::streamsize>(file.size()));
    }
    const auto data = arc::LoadUsmap(path);
    Check(data.version == 4 && data.name_count == 2 && data.structs.size() == 1, "usmap summary");
    const auto& item = arc::FindUsmapStruct(data, "Vector");
    Check(!item.super && item.properties.size() == 1 && item.properties[0].name == "X" &&
          item.properties[0].type == "Double", "usmap struct");
    Check(data.extensions.size() == 1 && data.extensions[0] == "CEXT", "usmap extension");
    ExpectThrow([&] { (void)arc::FindUsmapStruct(data, "Missing"); }, "missing usmap struct accepted");

    file.pop_back();
    {
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        output.write(reinterpret_cast<const char*>(file.data()), static_cast<std::streamsize>(file.size()));
    }
    ExpectThrow([&] { (void)arc::LoadUsmap(path); }, "truncated usmap accepted");
    std::error_code error;
    std::filesystem::remove(path, error);
}


void PutU16At(std::vector<std::uint8_t>& bytes, const std::size_t offset, const std::uint16_t value) {
    bytes[offset] = static_cast<std::uint8_t>(value);
    bytes[offset + 1] = static_cast<std::uint8_t>(value >> 8);
}

void PutU32At(std::vector<std::uint8_t>& bytes, const std::size_t offset, const std::uint32_t value) {
    for (std::size_t i = 0; i < 4; ++i) {
        bytes[offset + i] = static_cast<std::uint8_t>(value >> (i * 8));
    }
}

void PutU64At(std::vector<std::uint8_t>& bytes, const std::size_t offset, const std::uint64_t value) {
    for (std::size_t i = 0; i < 8; ++i) {
        bytes[offset + i] = static_cast<std::uint8_t>(value >> (i * 8));
    }
}

// FName entry in the measured encoding: header (length << 6), characters, null, padded to an even offset.
void PutNameEntry(std::vector<std::uint8_t>& bytes, std::string_view name) {
    const auto start = bytes.size();
    bytes.resize(start + 2);
    PutU16At(bytes, start, static_cast<std::uint16_t>(name.size() << 6));
    bytes.insert(bytes.end(), name.begin(), name.end());
    bytes.push_back(0);
    if (bytes.size() % 2 != 0) {
        bytes.push_back(0);
    }
}

std::vector<std::uint8_t> MakeNameBlock(const std::vector<std::string>& names, std::size_t block_size) {
    std::vector<std::uint8_t> bytes;
    for (const auto& name : names) {
        PutNameEntry(bytes, name);
    }
    bytes.resize(block_size, 0);
    return bytes;
}

// Reads return the longest contiguous run inside one synthetic captured region.
arc::CapturedRead MakeMapReader(std::vector<std::uint8_t>& map, std::uint64_t map_base) {
    return [&map, map_base](std::uint64_t va, std::uint64_t size)
               -> std::optional<std::span<const std::uint8_t>> {
        if (va < map_base || va - map_base >= map.size()) {
            return std::nullopt;
        }
        const auto available = map_base + map.size() - va;
        const auto length = std::min<std::uint64_t>(size, available);
        return std::span<const std::uint8_t>(
            map.data() + (va - map_base), static_cast<std::size_t>(length));
    };
}

void TestNameEntries() {
    const auto block = MakeNameBlock(
        {"None", "ByteProperty", "World", "Actor", "PioneerPlayerCharacter"}, 0x20000);
    const auto walk = arc::WalkNameBlock(block, arc::kNameCodecMeasured, 16);
    Check(walk.entries.size() == 5, "measured codec entry count");
    Check(walk.entries.front().text == "None", "first entry is None");
    Check(walk.entries[4].text == "PioneerPlayerCharacter", "last entry text");
    // 8 + 16 + 8 + 8 + 26: header, characters, terminator, even padding.
    Check(walk.consumed == 66, "block bytes consumed");
    Check(!walk.span_exhausted, "block span not exhausted");
    const auto stats = arc::MeasureNameBlock(block, arc::kNameCodecMeasured, 8192);
    Check(stats.entries == 5 && stats.last_name == "PioneerPlayerCharacter", "measured block summary");

    std::vector<std::uint8_t> wide_bytes(0x100, 0);
    PutU16At(wide_bytes, 0, static_cast<std::uint16_t>((5 << 6) | 1));
    const char16_t wide[5] = {u'W', u'o', u'r', u'l', u'd'};
    for (std::size_t i = 0; i < 5; ++i) {
        PutU16At(wide_bytes, 2 + i * 2, static_cast<std::uint16_t>(wide[i]));
    }
    const auto wide_walk = arc::WalkNameBlock(wide_bytes, arc::kNameCodecMeasured, 8);
    Check(wide_walk.entries.size() == 1 && wide_walk.entries[0].wide &&
              wide_walk.entries[0].text == "World", "wide entry decodes");

    std::vector<std::uint8_t> noise(0x400);
    for (std::size_t i = 0; i < noise.size(); ++i) {
        noise[i] = static_cast<std::uint8_t>(i * 7 + 3);
    }
    Check(arc::MeasureNameBlock(noise, arc::kNameCodecMeasured, 8192).entries < 8,
        "random bytes decoded as a name stream");

    std::vector<std::uint8_t> broken(0x40, 0);
    PutU16At(broken, 0, static_cast<std::uint16_t>(4 << 6));
    std::memcpy(broken.data() + 2, "NonXX", 5);  // no terminator after four characters
    Check(arc::MeasureNameBlock(broken, arc::kNameCodecMeasured, 8).entries == 0,
        "entry without a terminator accepted");
    PutU16At(broken, 0, static_cast<std::uint16_t>(4 << 6));
    std::memcpy(broken.data() + 2, "No\x01X", 4);  // control byte inside the name
    Check(arc::MeasureNameBlock(broken, arc::kNameCodecMeasured, 8).entries == 0,
        "control byte accepted as a name");

    const auto best = arc::DetectNameBlock(block, arc::kNameCodecCandidates, "None", 2, 64);
    Check(best.codec != nullptr && best.entries.size() == 5, "codec detection picked a codec");
    Check(best.codec->label == arc::kNameCodecMeasured.label, "codec detection result");
    Check(arc::DetectNameBlock(block, arc::kNameCodecCandidates, "Missing", 2, 64).codec == nullptr,
        "wrong expected first name accepted");
    Check(arc::DetectNameBlock(block, arc::kNameCodecCandidates, "None", 6, 64).codec == nullptr,
        "min_entries gate ignored");
}

void TestNameBlockChain() {
    constexpr std::uint64_t map_base = 0x1000000;
    constexpr std::size_t block_size = 0x20000;
    constexpr std::uint32_t header_size = 0x10;
    std::vector<std::uint8_t> map(3 * block_size + 0x100, 0);
    const auto block0 = MakeNameBlock({"None", "World", "Actor"}, block_size);
    const auto block1 = MakeNameBlock({"Pawn", "PlayerController"}, block_size);
    const auto block2 = MakeNameBlock({"UWorld", "Level"}, block_size);
    std::memcpy(map.data() + 0x100, block0.data(), block_size);
    std::memcpy(map.data() + 0x100 + block_size, block1.data(), block_size);
    std::memcpy(map.data() + 0x100 + 2 * block_size, block2.data(), block_size);
    const auto data0 = map_base + 0x100;
    const auto data1 = data0 + block_size;
    const auto data2 = data1 + block_size;
    PutU64At(map, 0x100 - header_size, data1 - header_size);
    PutU32At(map, 0x100 - header_size + 8, 0);
    PutU32At(map, 0x100 - header_size + 0xC, 0x18);
    PutU64At(map, 0x100 + block_size - header_size, data2 - header_size);
    PutU64At(map, 0x100 + 2 * block_size - header_size, 0);

    auto read = MakeMapReader(map, map_base);
    const std::uint32_t candidates[] = {header_size, 0x18, 0x20};
    const auto probes = arc::ProbeBlockHeaders(
        read, data0, block_size, arc::kNameCodecMeasured, 2, candidates);
    Check(probes.size() == 3, "probe count");
    Check(probes[0].header_captured && probes[0].next_is_block && probes[0].next_entries == 2,
        "correct header size identified");
    Check(!probes[1].next_is_block && !probes[2].next_is_block, "wrong header sizes rejected");
    Check(probes[0].window.size() == header_size, "header window bytes captured");

    const auto chain = arc::FollowNameBlocks(
        read, data0, header_size, block_size, arc::kNameCodecMeasured, 2, 8192, 16);
    Check(chain.blocks.size() == 3, "chain block count");
    Check(chain.total_entries == 7 && !chain.total_capped, "chain entry total");
    Check(chain.blocks[0].stats.consumed == 0x18, "block consumed bytes");
    Check(chain.blocks[2].next == 0 && chain.stop_reason == "end of chain: null next pointer",
        "chain stop reason");

    const auto missing = [](std::uint64_t, std::uint64_t) -> std::optional<std::span<const std::uint8_t>> {
        return std::nullopt;
    };
    const std::uint32_t one_candidate[] = {0x10};
    Check(!arc::ProbeBlockHeaders(missing, 0x2000, 0x200, arc::kNameCodecMeasured, 2, one_candidate)
               .front()
               .header_captured,
        "uncaptured header reported as captured");
    const auto absent = arc::FollowNameBlocks(
        missing, 0x2000, 0x10, 0x20000, arc::kNameCodecMeasured, 2, 64, 8);
    Check(absent.blocks.size() == 1 && absent.stop_reason == "block data is not captured",
        "uncaptured block stop reason");
    std::vector<std::uint8_t> partial(0x10, 0);
    const auto partial_block = MakeNameBlock({"None", "World"}, 0xF0);
    partial.insert(partial.end(), partial_block.begin(), partial_block.end());
    auto partial_read = MakeMapReader(partial, 0);
    const auto short_chain = arc::FollowNameBlocks(
        partial_read, 0, 0x10, 0x100, arc::kNameCodecMeasured, 4, 64, 8);
    Check(short_chain.blocks.empty() && short_chain.stop_reason == "invalid block data VA or header size",
        "anchor VA below the header size not rejected");
    const auto last_partial = arc::FollowNameBlocks(
        partial_read, 0x10, 0x10, 0x100, arc::kNameCodecMeasured, 4, 64, 8);
    Check(last_partial.blocks.size() == 1 &&
        last_partial.stop_reason == "short block: fewer entries than min_entries, typically the partially filled last block",
        "partially filled last block reason");

    std::vector<std::uint8_t> loop(0x220, 0);
    const auto self_block = MakeNameBlock({"None", "World"}, 0x100);
    std::memcpy(loop.data() + 0x10, self_block.data(), 0x100);
    PutU64At(loop, 0, 0x1000);  // Next points at its own header
    auto loop_read = MakeMapReader(loop, 0x1000);
    const auto cyclic = arc::FollowNameBlocks(
        loop_read, 0x1010, 0x10, 0x20000, arc::kNameCodecMeasured, 2, 64, 8);
    Check(cyclic.blocks.size() == 1 && cyclic.stop_reason == "cycle in the block chain",
        "cycle not detected");
    const auto underflow = arc::FollowNameBlocks(
        loop_read, 0x8, 0x10, 0x20000, arc::kNameCodecMeasured, 2, 64, 8);
    Check(underflow.blocks.empty() && !underflow.stop_reason.empty(), "underflow guard missing");
}


// One entry with a fixed tail after the string: the strict chained walk stops after the first entry,
// while the local predicate still finds every name and the gap histogram shows the real stride.
void PutNameEntryWithTail(std::vector<std::uint8_t>& bytes, std::string_view name, std::size_t tail) {
    const auto start = bytes.size();
    bytes.resize(start + 2);
    PutU16At(bytes, start, static_cast<std::uint16_t>(name.size() << 6));
    bytes.insert(bytes.end(), name.begin(), name.end());
    bytes.push_back(0);
    if (bytes.size() % 2 != 0) {
        bytes.push_back(0);
    }
    bytes.resize(bytes.size() + tail, 0xAA);
}

void TestNameLayoutProbe() {
    std::vector<std::uint8_t> block;
    for (const auto* name : {"None", "World", "Actor", "Pawn"}) {
        PutNameEntryWithTail(block, name, 8);
    }
    block.resize(0x20000, 0);
    const auto strict = arc::WalkNameBlock(block, arc::kNameCodecMeasured, 64);
    Check(strict.entries.size() == 1, "chained walk tolerated a tail between entries");

    const auto hits = arc::FindNameLikeEntries(block, arc::kNameCodecMeasured, 512);
    Check(hits.size() == 4, "local predicate missed entries");
    Check(hits[0].text == "None" && hits[3].text == "Pawn", "local predicate text");
    Check(hits[1].offset - hits[0].offset == 0x10, "entry stride");
    const auto gaps = arc::GapHistogram(hits);
    Check(gaps.size() == 1 && gaps[0].first == 0x10 && gaps[0].second == 3, "gap histogram");

    // Wide entries are reported as wide, and the header word is available for the caller to print.
    std::vector<std::uint8_t> wide(0x40, 0);
    PutU16At(wide, 0, static_cast<std::uint16_t>((4 << 6) | 1));
    const char16_t text[4] = {u'N', u'o', u'n', u'e'};
    for (std::size_t i = 0; i < 4; ++i) {
        PutU16At(wide, 2 + i * 2, static_cast<std::uint16_t>(text[i]));
    }
    const auto wide_hits = arc::FindNameLikeEntries(wide, arc::kNameCodecMeasured, 8);
    Check(wide_hits.size() == 1 && wide_hits[0].wide && wide_hits[0].text == "None", "wide hit decode");
    Check(arc::GapHistogram(wide_hits).empty(), "gap histogram with a single hit");
    Check(arc::FindNameLikeEntries(std::span<const std::uint8_t>{}, arc::kNameCodecMeasured, 8).empty(),
        "empty window produced hits");
}

void TestBackwardChain() {
    // Zero padding, unlike the 0xAA tail of PutNameEntryWithTail: the backward chain only accepts a
    // predecessor when everything between its last name byte and the next entry is zero.
    std::vector<std::uint8_t> block;
    for (const auto* name : {"None", "World", "Actor", "Pawn", "PlayerController"}) {
        const auto start = block.size();
        block.resize(start + 2 + std::string_view(name).size() + 1, 0);
        PutU16At(block, start, static_cast<std::uint16_t>(std::string_view(name).size() << 6));
        std::memcpy(block.data() + start + 2, name, std::string_view(name).size());
        while (block.size() % 8 != 0) {
            block.push_back(0);
        }
    }
    const std::span<const std::uint8_t> view{block};
    const auto back = arc::BackwardNameStream(view, arc::kNameCodecMeasured, 3 * 8, 16);
    Check(back.size() == 3, "backward chain length");
    Check(back.size() == 3 && back.front().offset == 0 && back.front().text == "None",
        "backward chain reached entry 0");
    Check(back.size() == 3 && back.back().text == "Actor", "backward chain order");
    Check(back.size() == 3 && back[1].entry_size == 8 && back[1].pad_after == 0,
        "backward entry size and pad");
    Check(arc::BackwardNameStream(view, arc::kNameCodecMeasured, 5, 16).empty(),
        "backward chain accepted an unexplained gap");
}

void PutPackedEntry(std::vector<std::uint8_t>& bytes, std::string_view name, std::uint16_t low_bits) {
    const auto start = bytes.size();
    bytes.resize(start + 2 + name.size(), 0);
    PutU16At(bytes, start, static_cast<std::uint16_t>((name.size() << 6) | low_bits));
    std::memcpy(bytes.data() + start + 2, name.data(), name.size());
    if ((2 + name.size()) % 2 != 0) {
        bytes.push_back(0);  // even-alignment pad, not a terminator
    }
}

void TestPackedCodec() {
    // Byte layout copied from the real pool at 0xa6f10000 of gameplay dump (3): 1e 01 "None" 10 03
    // "ByteProperty" c0 02 "IntProperty" 00 - no terminators, one zero pad after odd lengths.
    std::vector<std::uint8_t> block;
    PutPackedEntry(block, "None", 0x1e);
    PutPackedEntry(block, "ByteProperty", 0x10);
    PutPackedEntry(block, "IntProperty", 0x00);
    PutPackedEntry(block, "BoolProperty", 0x34);
    PutPackedEntry(block, "FloatProperty", 0x36);
    Check(block.size() == 0x40, "packed synthetic size");

    const auto walk = arc::WalkNameBlock(block, arc::kNameCodecPacked, 64);
    Check(walk.entries.size() == 5, "packed walk entries");
    Check(walk.consumed == block.size(), "packed walk consumed whole block");
    Check(walk.entries.front().text == "None" && walk.entries.back().text == "FloatProperty",
        "packed walk texts");

    // The NUL-terminated codec must stop at the first entry, which is exactly why the pool was missed.
    const auto legacy = arc::WalkNameBlock(block, arc::kNameCodecMeasured, 64);
    Check(legacy.entries.empty(), "NUL codec accepted a terminator-less entry");

    const auto hits = arc::FindNameLikeEntries(block, arc::kNameCodecPacked, 64);
    Check(hits.size() == 5, "packed scatter count");
    Check(hits[2].offset == 0x14 && hits[2].entry_size == 0xe, "packed scatter offsets");

    // Backward chaining from the last entry reaches offset 0; a predecessor with any other size is
    // rejected, so a mid-block anchor cannot drift.
    const auto back = arc::BackwardNameStream(block, arc::kNameCodecPacked, hits[4].offset, 16);
    Check(back.size() == 4 && back.front().offset == 0, "packed backward chain");
    Check(back.size() == 4 && back.back().text == "BoolProperty", "packed backward texts");
    const auto drift = arc::BackwardNameStream(block, arc::kNameCodecPacked, hits[4].offset + 2, 4);
    Check(drift.empty(), "packed backward accepted an off-entry stop");

    // A zero run between blocks stops the walk: real pool blocks end in padding, not names.
    auto padded = block;
    padded.resize(0x4000, 0);
    const auto padded_walk = arc::WalkNameBlock(padded, arc::kNameCodecPacked, 64);
    Check(padded_walk.entries.size() == 5 && !padded_walk.cap_reached, "packed walk stopped at padding");
}

void TestViewportDecrypt() {
    std::array<std::uint8_t, 0x100> bank{};
    const std::uint64_t lo = 0xF7149774B727E060ULL, hi = 0x642BFE20256AF201ULL;
    std::memcpy(bank.data() + 0x40, &lo, 8);
    std::memcpy(bank.data() + 0x48, &hi, 8);
    const auto value = arc::DecryptViewport1450810(0x1DBCF5730, 0x140000000, bank);
    Check(value.slot == 2, "viewport hash slot");
    Check(value.key == 0xA74474574EF90345ULL, "viewport key");
    Check(value.address == 0x1DBDA3550, "viewport decrypted pointer");
    ExpectThrow([&] {
        (void)arc::DecryptViewport1450810(0x1DBCF5730, 0x140000000,
            std::span<const std::uint8_t>(bank.data(), 0xFF));
    }, "short viewport bank accepted");
}


[[nodiscard]] bool Near(const double value, const double expected, const double tolerance = 1.0e-6) {
    return std::fabs(value - expected) <= tolerance;
}

// The exporter's memory is an interface, so the whole read-project-serialise path is testable without a
// dump, a process, or Windows. This fake is the same shape a minidump reader has: VA in, bytes out.
struct FakeMemory final : arc::IMemory {
    std::uint64_t base{};
    std::vector<std::uint8_t> bytes;

    template <typename T>
    void Put(const std::uint64_t va, const T value) {
        const auto offset = va - base;
        if (offset + sizeof(T) > bytes.size()) {
            bytes.resize(static_cast<std::size_t>(offset + sizeof(T)));
        }
        std::memcpy(bytes.data() + offset, &value, sizeof(T));
    }

    [[nodiscard]] std::optional<std::uint64_t> Qword(const std::uint64_t va) const override {
        return Read<std::uint64_t>(va);
    }
    [[nodiscard]] std::optional<double> Double(const std::uint64_t va) const override {
        return Read<double>(va);
    }
    [[nodiscard]] std::optional<float> Float(const std::uint64_t va) const override {
        return Read<float>(va);
    }
    [[nodiscard]] std::optional<std::uint32_t> Dword(const std::uint64_t va) const override {
        return Read<std::uint32_t>(va);
    }

private:
    template <typename T>
    [[nodiscard]] std::optional<T> Read(const std::uint64_t va) const {
        const auto offset = va - base;
        if (va < base || offset + sizeof(T) > bytes.size()) {
            return std::nullopt;
        }
        T value{};
        std::memcpy(&value, bytes.data() + offset, sizeof(T));
        return value;
    }
};

void TestEspMath() {
    Check(arc::IsPlausiblePosition(arc::FVector{100.0, -200.0, 300.0}), "plain position rejected");
    Check(arc::IsPlausiblePosition(arc::FVector{0.0, 0.0, 1200.0}), "zero axis rejected as a position");
    Check(!arc::IsPlausiblePosition(arc::FVector{0.0, 0.0, 0.0 / 0.0}), "NaN accepted as a position");
    Check(!arc::IsPlausiblePosition(arc::FVector{1.0e30, 1.0, 1.0}), "infinite magnitude accepted");
    // The measured failure: a 64-bit pointer read as two floats gives denormals like this, and the sweep
    // on a real dump voted for exactly that field.
    Check(!arc::IsPlausiblePosition(arc::FVector{1.4e-45, 2.0, 3.0}), "denormal axis accepted as a position");
    Check(!arc::IsPositionCandidate(arc::FVector{0.0, 200.0, 300.0}), "zero axis accepted as a candidate");
    Check(arc::IsPositionCandidate(arc::FVector{1000.0, -2000.0, 100.0}), "candidate rejected");

    Check(Near(arc::DistanceMetres(arc::FVector{}, arc::FVector{100.0, 0.0, 0.0}), 1.0), "distance metres");
    Check(Near(arc::DistanceMetres(arc::FVector{0.0, 0.0, 0.0}, arc::FVector{300.0, 400.0, 0.0}), 5.0),
        "3-4-5 distance");

    arc::FVector forward{};
    arc::FVector right{};
    arc::FVector up{};
    arc::CameraBasis(arc::FRotator{0.0, 0.0, 0.0}, &forward, &right, &up);
    Check(Near(forward.x, 1.0) && Near(forward.y, 0.0) && Near(up.z, 1.0), "zero rotation basis");
    arc::CameraBasis(arc::FRotator{0.0, 90.0, 0.0}, &forward, &right, &up);
    Check(Near(forward.x, 0.0, 1.0e-9) && Near(forward.y, 1.0, 1.0e-9), "yaw 90 basis");
    arc::CameraBasis(arc::FRotator{90.0, 0.0, 0.0}, &forward, &right, &up);
    Check(Near(forward.z, 1.0, 1.0e-9), "pitch 90 looks up");

    arc::Viewport view;
    view.fov_degrees = 90.0;
    view.width = 1920;
    view.height = 1080;
    Check(Near(std::tan(view.VerticalFovDegrees() * 3.14159265358979323846 / 360.0), 9.0 / 16.0, 1.0e-9),
        "vertical fov from aspect");

    double x = -1.0;
    double y = -1.0;
    double depth = -1.0;
    Check(arc::WorldToScreen(arc::FVector{100.0, 0.0, 0.0}, view, &x, &y, &depth), "in front failed");
    Check(Near(x, 960.0, 1.0e-6) && Near(y, 540.0, 1.0e-6) && Near(depth, 100.0), "centre projection");
    // Straight up by tan(half vertical fov) * depth lands on the top edge, which is the projection test
    // that would notice a swapped or missing aspect correction.
    Check(arc::WorldToScreen(arc::FVector{100.0, 0.0, 56.25}, view, &x, &y, &depth), "top edge failed");
    Check(Near(x, 960.0, 1.0e-6) && Near(y, 0.0, 1.0e-6), "aspect-corrected vertical projection");
    Check(!arc::WorldToScreen(arc::FVector{-100.0, 0.0, 0.0}, view, &x, &y, &depth),
        "behind the camera projected");
    Check(!arc::WorldToScreen(arc::FVector{5.0, 0.0, 0.0}, view, &x, &y, &depth), "inside near plane projected");
    Check(arc::WorldToScreen(arc::FVector{0.0, 100.0, 0.0}, view, &x, &y, &depth) == false ||
              Near(x, 960.0 + 100.0 / 100.0 * 960.0, 1.0e-3),
        "lateral offset projection");

    // A box has to shrink with distance and scale with the viewport, or the overlay looks wrong at 400 m.
    const double near_px = arc::ScreenRadiusPixels(1000.0, 100.0, view);
    const double far_px = arc::ScreenRadiusPixels(2000.0, 100.0, view);
    // (100 cm / 1000 cm) / tan(vertical half fov = 9/16) * half the screen height
    Check(Near(near_px, 0.1 / (9.0 / 16.0) * 540.0, 1.0e-6), "screen radius");
    Check(Near(far_px, near_px * 0.5, 1.0e-6), "radius does not halve with depth");
    Check(arc::ScreenRadiusPixels(1.0, 100.0, view) == 0.0, "radius inside the near plane");
}

void TestEspConfigAndRows() {
    const auto offsets = arc::ParseEspConfig(
        "[build]\nmodule_name = PioneerGame.exe\n"
        "[esp]\n# a comment and a blank line\n\n"
        "actor_array_data = 0x1000\nactor_array_num = 3\n"
        "root_component_off = 0x130\nrelative_location_off = 0x11C\n"
        "level_actors_off = 0xa0\npersistent_level_off = 0xe8\n"
        "local_x = 0\nlocal_y = 0\nlocal_z = 0\nview_yaw_degrees = 0\nfov_degrees = 90\n"
        "screen_width = 1920\nscreen_height = 1080\nactor_radius_cm = 100\n"
        "health_off = 0x200\nteam_off = 0x208\n");
    Check(offsets.actor_array_data == 0x1000 && offsets.actor_array_num == 3, "actor list keys");
    Check(offsets.root_component_off == 0x130 && offsets.relative_location_off == 0x11C, "position keys");
    Check(offsets.screen_width == 1920 && Near(offsets.fov_degrees, 90.0), "screen keys");
    Check(offsets.HasActorList() && offsets.HasPositions(), "resolved config reported as incomplete");
    Check(arc::ParseEspConfig("[esp]\nrelative_location_off = 0\n").relative_location_off == 0,
        "unset key got a default");

    FakeMemory memory;
    memory.base = 0x1000;
    memory.Put<std::uint64_t>(0x1000, 0x2000);  // actors[0]
    memory.Put<std::uint64_t>(0x1008, 0x2100);  // actors[1]
    memory.Put<std::uint64_t>(0x1010, 0x2200);  // actors[2]: has a NaN position
    memory.Put<std::uint64_t>(0x2000 + 0x130, 0x3000);
    memory.Put<std::uint64_t>(0x2100 + 0x130, 0x3100);
    memory.Put<std::uint64_t>(0x2200 + 0x130, 0x3200);
    memory.Put<float>(0x3000 + 0x11C, 1000.0F);
    memory.Put<float>(0x3000 + 0x11C + 4, -2000.0F);
    memory.Put<float>(0x3000 + 0x11C + 8, 100.0F);
    memory.Put<float>(0x3100 + 0x11C, 2000.0F);
    memory.Put<float>(0x3100 + 0x11C + 4, -1000.0F);
    memory.Put<float>(0x3100 + 0x11C + 8, 50.0F);
    memory.Put<float>(0x3200 + 0x11C, 0.0F / 0.0F);
    memory.Put<float>(0x3200 + 0x11C + 4, 1.0F);
    memory.Put<float>(0x3200 + 0x11C + 8, 1.0F);
    memory.Put<float>(0x2000 + 0x200, 73.0F);   // health
    memory.Put<std::uint32_t>(0x2000 + 0x208, 2U);  // team

    const auto rows = arc::ReadActors(memory, offsets, 16);
    Check(rows.size() == 2, "rows read from the fake memory");
    Check(rows[0].address == 0x2000, "row address");
    Check(Near(rows[0].distance_m, std::sqrt(1000.0 * 1000.0 + 2000.0 * 2000.0 + 100.0 * 100.0) / 100.0,
            1.0e-9),
        "row distance");
    Check(rows[0].projected, "row not projected");
    Check(Near(rows[0].screen_x, 960.0 + (-2000.0 / 1000.0) * 960.0, 1.0e-3), "row screen x");
    Check(rows[0].box_half_height > 0.0, "box has no height");
    Check(rows[0].has_health && Near(rows[0].health, 73.0, 1.0e-6), "health not read");
    Check(rows[0].has_team && rows[0].team == 2U, "team not read");

    const auto json = arc::ToJson(rows, offsets, 3, true, "test note");
    Check(json.rfind("window.ARC = ", 0) == 0, "js wrapper missing");
    Check(json.find("\"actors_with_position\": 2") != std::string::npos, "row count missing");
    Check(json.find("\"actors_total\": 3") != std::string::npos, "actor total missing");
    Check(json.find("\"id\": \"0x2000\"") != std::string::npos, "row id missing");
    Check(json.find("\"hp\": 73.00") != std::string::npos, "health missing from json");
    Check(json.find("\"hp\": null") != std::string::npos, "missing health was invented");
    Check(json.find("test note") != std::string::npos, "note missing");
    Check(arc::ToJson(rows, offsets, 3, false, "").rfind("{", 0) == 0, "json wrapper wrong");

    // Aim and trigger rules, on the projected rows only.
    const auto pick = arc::SelectAimTarget(rows, 960.0, 540.0, 4000.0);
    Check(pick.has_value(), "no aim target although rows are projected");
    Check(rows[pick->index].address == rows[0].address || rows[pick->index].address == rows[1].address,
        "aim pick is not one of the rows");
    Check(pick->offset_px <= 4000.0, "aim pick ignores the cone");
    Check(!arc::SelectAimTarget(rows, 960.0, 540.0, 0.5).has_value(), "aim cone of half a pixel widened");
    Check(!arc::SelectAimTarget({}, 960.0, 540.0, 500.0).has_value(), "empty row set picked a target");
    Check(arc::IsOnAimPoint(rows[0], rows[0].screen_x, rows[0].screen_y, 0.0),
        "centre of the actor's own box is not on the aim point");
    Check(!arc::IsOnAimPoint(rows[0], rows[0].screen_x + 5.0e5, rows[0].screen_y, 0.0),
        "trigger fires far outside the box");
    Check(!rows[1].projected || !arc::IsOnAimPoint(rows[1], -1.0, -1.0, 0.0), "trigger fires off-screen");

    // Argument handling, which is the part a Windows-only main() cannot be tested in.
    const auto overlay_one = arc::ParseOverlayArgs({"page.html"});
    Check(overlay_one && overlay_one->html == "page.html" && !overlay_one->demo, "overlay: single arg");
    const auto overlay_demo = arc::ParseOverlayArgs({"page.html", "demo"});
    Check(overlay_demo && overlay_demo->demo, "overlay: demo flag rejected");
    Check(!arc::ParseOverlayArgs({"page.html", "Demo"}).has_value(), "overlay: unknown flag accepted");
    Check(!arc::ParseOverlayArgs({}).has_value(), "overlay: no argument accepted");
    Check(!arc::ParseOverlayArgs({"a.html", "demo", "extra"}).has_value(), "overlay: extra argument accepted");
    Check(arc::ParseConfigArgs({"esp.ini"}).has_value() && !arc::ParseConfigArgs({}).has_value(),
        "config: argument count");
    const auto export_full = arc::ParseExportArgs(
        {"game.dmp", "0x140000000", "0x139F9000", "esp.ini", "esp-data.js"});
    Check(export_full && export_full->base == 0x140000000ULL && export_full->image_size == 0x139F9000ULL &&
        export_full->config == "esp.ini" && export_full->out == "esp-data.js" && export_full->rows == 4096,
        "export: full form");
    const auto export_min = arc::ParseExportArgs({"game.dmp", "0x1000", "0x2000", "esp.ini"});
    Check(export_min && export_min->out.empty() && export_min->rows == 4096, "export: minimal form");
    const auto export_rows = arc::ParseExportArgs({"g.dmp", "0x1000", "0x2000", "c.ini", "o.js", "25"});
    Check(export_rows && export_rows->rows == 25, "export: row limit ignored");
    Check(!arc::ParseExportArgs({"g.dmp", "0x1000", "0x2000"}).has_value(), "export: missing config accepted");
    Check(!arc::ParseExportArgs({"g.dmp", "notanumber", "0x2000", "c.ini"}).has_value(),
        "export: unparsable base accepted");
    Check(!arc::ParseExportArgs({"g.dmp", "0x1000", "0", "c.ini"}).has_value(),
        "export: zero image size accepted");

    const auto demo = arc::DemoOverlayData();
    Check(demo.rfind("window.ARC = ", 0) == 0, "demo data is not a js assignment");
    Check(demo.find("\"actors_with_position\": 12") != std::string::npos, "demo rows missing");
    Check(demo.find("\"hp\": ") != std::string::npos && demo.find("\"team\": ") != std::string::npos,
        "demo rows carry no health or team");

    const auto page = arc::OverlayHtml();
    Check(page.find("window.ARC") != std::string::npos, "overlay does not read the exported data");
    Check(page.find("<canvas") != std::string::npos, "overlay has no canvas");
    Check(page.find("esp-data.js") != std::string::npos, "overlay ignores the exporter's file name");

    // An unset position offset must produce no rows at all rather than reading from address 0x11c.
    arc::EspOffsetSet partial;
    partial.actor_array_data = 0x1000;
    partial.actor_array_num = 3;
    Check(arc::ReadActors(memory, partial, 8).empty(), "rows produced without position offsets");
}

} // namespace

int main() {
    try {
        TestPattern();
        TestNumbersAndChains();
        TestConfig();
        TestUsmap();
        TestNameEntries();
        TestNameBlockChain();
        TestNameLayoutProbe();
        TestBackwardChain();
        TestPackedCodec();
        TestViewportDecrypt();
        TestEspMath();
        TestEspConfigAndRows();
        std::cout << "All core checks passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Core check failed: " << error.what() << '\n';
        return 1;
    }
}
