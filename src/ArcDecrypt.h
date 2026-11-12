#pragma once

#include <cstdint>
#include <span>

namespace arc {

struct ViewportCandidate {
    std::uint32_t slot{};
    std::uint64_t key{};
    std::uint64_t address{};
};

// Exact-build CL-1450810 candidate transform; bank must contain eight 0x20-byte cells.
ViewportCandidate DecryptViewport1450810(
    std::uint64_t local_player,
    std::uint64_t module_base,
    std::span<const std::uint8_t> bank);

} // namespace arc
