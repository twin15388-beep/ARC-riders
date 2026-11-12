#include "Pattern.h"

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace arc {
namespace {

int HexDigit(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

} // namespace

Pattern Pattern::Parse(std::string_view text) {
    Pattern result;
    std::size_t position = 0;
    while (position < text.size()) {
        while (position < text.size() && (text[position] == ' ' || text[position] == '\t' || text[position] == '\r' || text[position] == '\n')) {
            ++position;
        }
        if (position == text.size()) {
            break;
        }
        if (position + 1 < text.size() && (text[position] == '?' || text[position + 1] == '?')) {
            if (!((text[position] == '?' && text[position + 1] == '?') ||
                  (text[position] == '?' && HexDigit(text[position + 1]) >= 0) ||
                  (HexDigit(text[position]) >= 0 && text[position + 1] == '?'))) {
                throw std::invalid_argument("invalid wildcard token at character " + std::to_string(position));
            }
            if (text[position] == '?' && text[position + 1] == '?') {
                result.bytes_.push_back({0, true});
            } else if (text[position] == '?') {
                result.bytes_.push_back({static_cast<std::uint8_t>(HexDigit(text[position + 1])), true});
            } else {
                result.bytes_.push_back({static_cast<std::uint8_t>(HexDigit(text[position]) << 4), true});
            }
            position += 2;
            continue;
        }
        if (position + 1 >= text.size()) {
            throw std::invalid_argument("odd number of hexadecimal digits at character " + std::to_string(position));
        }
        const int high = HexDigit(text[position]);
        const int low = HexDigit(text[position + 1]);
        if (high < 0 || low < 0) {
            throw std::invalid_argument("invalid byte token at character " + std::to_string(position));
        }
        result.bytes_.push_back({static_cast<std::uint8_t>((high << 4) | low), false});
        position += 2;
    }
    if (result.bytes_.empty()) {
        throw std::invalid_argument("pattern is empty");
    }
    if (result.bytes_.size() > 4096) {
        throw std::invalid_argument("pattern exceeds the 4096-byte limit");
    }
    return result;
}

std::vector<std::size_t> FindPattern(
    std::span<const std::uint8_t> haystack,
    const Pattern& pattern,
    const std::size_t max_results) {
    if (max_results == 0) {
        throw std::invalid_argument("max_results must be greater than zero");
    }
    std::vector<std::size_t> results;
    const auto& bytes = pattern.Bytes();
    if (bytes.empty() || haystack.size() < bytes.size()) {
        return results;
    }

    const auto anchor = std::find_if(bytes.begin(), bytes.end(), [](const PatternByte& byte) {
        return !byte.wildcard;
    });
    if (anchor == bytes.end()) {
        for (std::size_t i = 0; i <= haystack.size() - bytes.size() && results.size() < max_results; ++i) {
            bool match = true;
            for (std::size_t j = 0; j < bytes.size(); ++j) {
                if ((haystack[i + j] & bytes[j].value) != bytes[j].value) {
                    match = false;
                    break;
                }
            }
            if (match) {
                results.push_back(i);
            }
        }
        return results;
    }

    const std::size_t anchor_offset = static_cast<std::size_t>(anchor - bytes.begin());
    for (std::size_t i = 0; i <= haystack.size() - bytes.size() && results.size() < max_results;) {
        const auto begin = haystack.begin() + static_cast<std::ptrdiff_t>(i + anchor_offset);
        const auto end = haystack.end() - static_cast<std::ptrdiff_t>(bytes.size() - anchor_offset - 1);
        const auto found = std::find(begin, end, static_cast<std::uint8_t>(anchor->value));
        if (found == end) {
            break;
        }
        i = static_cast<std::size_t>(found - haystack.begin()) - anchor_offset;
        bool match = true;
        for (std::size_t j = 0; j < bytes.size(); ++j) {
            const auto& expected = bytes[j];
            const auto actual = haystack[i + j];
            const bool equal = expected.wildcard
                ? ((actual & expected.value) == expected.value)
                : actual == expected.value;
            if (!equal) {
                match = false;
                break;
            }
        }
        if (match) {
            results.push_back(i);
        }
        ++i;
    }
    return results;
}

} // namespace arc
