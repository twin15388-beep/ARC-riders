#include "Chain.h"
#include "Config.h"
#include "Pattern.h"
#include "Names.h"
#include "Usmap.h"
#include "ArcDecrypt.h"

#include <algorithm>
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

} // namespace

int main() {
    try {
        TestPattern();
        TestNumbersAndChains();
        TestConfig();
        TestUsmap();
        TestNameEntries();
        TestNameBlockChain();
        TestViewportDecrypt();
        std::cout << "All core checks passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Core check failed: " << error.what() << '\n';
        return 1;
    }
}
