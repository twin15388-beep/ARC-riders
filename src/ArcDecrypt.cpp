#include "ArcDecrypt.h"

#include <bit>
#include <cstring>
#include <stdexcept>

namespace arc {

ViewportCandidate DecryptViewport1450810(
    const std::uint64_t local_player,
    const std::uint64_t module_base,
    const std::span<const std::uint8_t> bank) {
    if (bank.size() < 0x100) throw std::invalid_argument("viewport bank requires 0x100 bytes");

    std::uint32_t hash = static_cast<std::uint32_t>(local_player + 0xF0);
    for (const unsigned rotation : {0x12U, 0x0DU, 0x12U, 0x0DU}) {
        hash = std::rotl(hash, static_cast<int>(rotation)) * 0x01000193U + 0x3DF4F4F9U;
    }
    hash ^= hash >> 16;
    const std::uint32_t slot = hash & 7U;

    const std::uint64_t seed = module_base + 0x10421C80ULL;
    const std::uint64_t key = 0x96E1893DE50C3EC5ULL +
        ((0xCA5DE8DA8DAF0350ULL ^ seed) | 1ULL) * seed;
    std::uint64_t lo{};
    std::uint64_t hi{};
    std::memcpy(&lo, bank.data() + slot * 0x20U, sizeof(lo));
    std::memcpy(&hi, bank.data() + slot * 0x20U + 8, sizeof(hi));

    std::uint64_t value = lo + 0x672ADC2992A10C8BULL;
    value = std::rotl(value, 0xB);
    value *= 0x32B8790980D8F375ULL;
    value += 0x691E76C372AC9E1FULL;
    value ^= hi;
    value += 0x98D5F1EA80D8F374ULL;
    value = std::rotl(value, 0x35);
    value *= 0x32B8790980D8F375ULL;
    value += 0x691E76C372AC9E1FULL;
    value ^= lo;
    value ^= key;
    return {slot, key, value};
}

} // namespace arc
