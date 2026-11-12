#include "ArcDecrypt.h"

#include <bit>
#include <cstring>
#include <stdexcept>

namespace arc {
namespace {
std::uint64_t Load64(std::span<const std::uint8_t> bytes, std::size_t offset) {
    std::uint64_t value{};
    std::memcpy(&value, bytes.data() + offset, sizeof(value));
    return value;
}
std::uint64_t Rotl(std::uint64_t value, unsigned count) {
    return (value << count) | (value >> (64U - count));
}
}

ViewportCandidate DecryptViewport1450810(
    const std::uint64_t local_player,
    const std::uint64_t module_base,
    const std::span<const std::uint8_t> bank) {
    if (bank.size() < 0x100) throw std::invalid_argument("viewport bank requires 0x100 bytes");
    // This seed is the address of module+0x10421C80, not a qword read from it.
    const std::uint64_t seed = module_base + 0x10421C80ULL;
    std::uint64_t key = (local_player ^ (seed + 0x41C64E6DULL)) + 0x9E3779B97F4A7C15ULL;
    key = (key ^ (key >> 30)) * 0xBF58476D1CE4E5B9ULL;
    key = (key ^ (key >> 27)) * 0x94D049BB133111EBULL;
    key ^= key >> 31;
    const std::uint32_t slot = ((static_cast<std::uint32_t>(local_player >> 3)) * 0x9E3779B1U) >> 29;
    const std::size_t offset = static_cast<std::size_t>(slot) * 0x20;
    const std::uint64_t a = Load64(bank, offset);
    const std::uint64_t b = Load64(bank, offset + 8);
    const std::uint64_t c = Load64(bank, offset + 0x10);
    const std::uint64_t d = Load64(bank, offset + 0x18);
    const std::uint64_t first = a ^ key ^ Rotl(key, 13);
    const std::uint64_t second = b ^ std::rotr(key, 17) ^ key;
    const std::uint64_t combined = first + second;
    const std::uint64_t address = combined ^ Rotl(c ^ key, combined & 63U) ^ std::rotr(d ^ key, 29);
    return {slot, key, address};
}
}
