#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace arc {

struct PatternByte {
    std::uint8_t value{};
    bool wildcard{};
};

class Pattern {
public:
    static Pattern Parse(std::string_view text);

    [[nodiscard]] std::size_t Size() const noexcept { return bytes_.size(); }
    [[nodiscard]] const std::vector<PatternByte>& Bytes() const noexcept { return bytes_; }

private:
    std::vector<PatternByte> bytes_;
};

// Returned positions are relative to haystack. Overlapping matches are included.
[[nodiscard]] std::vector<std::size_t> FindPattern(
    std::span<const std::uint8_t> haystack,
    const Pattern& pattern,
    std::size_t max_results = 128);

} // namespace arc
