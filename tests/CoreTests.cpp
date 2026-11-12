#include "Chain.h"
#include "Config.h"
#include "Pattern.h"
#include "Usmap.h"
#include "ArcDecrypt.h"

#include <cstdint>
#include <cstring>
#include <array>
#include <exception>
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
        TestViewportDecrypt();
        std::cout << "All core checks passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Core check failed: " << error.what() << '\n';
        return 1;
    }
}
