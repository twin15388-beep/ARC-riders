#include "Chain.h"

#include <charconv>
#include <limits>
#include <stdexcept>

namespace arc {
namespace {

std::string_view Trim(std::string_view value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string_view::npos) {
        return {};
    }
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

} // namespace

std::uint64_t ParseUnsigned(std::string_view text) {
    text = Trim(text);
    int base = 10;
    if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        text.remove_prefix(2);
        base = 16;
    }
    if (text.empty()) {
        throw std::invalid_argument("empty unsigned integer");
    }
    std::uint64_t value{};
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value, base);
    if (error != std::errc{} || end != text.data() + text.size()) {
        throw std::invalid_argument("invalid unsigned integer: " + std::string(text));
    }
    return value;
}

std::optional<std::uint64_t> CheckedAdd(const std::uint64_t left, const std::uint64_t right) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        return std::nullopt;
    }
    return left + right;
}

PointerChainSpec ParsePointerChain(std::string_view text) {
    const auto comma = text.find(',');
    const auto base_text = Trim(text.substr(0, comma));
    const auto plus = base_text.find('+');
    if (plus == std::string_view::npos) {
        throw std::invalid_argument("chain base must be module+OFFSET or SIGNATURE+OFFSET");
    }

    PointerChainSpec result;
    const auto base_name = Trim(base_text.substr(0, plus));
    if (base_name == "module") {
        result.base_kind = ChainBaseKind::Module;
    } else {
        if (base_name.empty()) {
            throw std::invalid_argument("chain signature name is empty");
        }
        result.base_kind = ChainBaseKind::Signature;
        result.signature_name = std::string(base_name);
    }
    result.base_offset = ParseUnsigned(base_text.substr(plus + 1));

    auto position = comma;
    while (position != std::string_view::npos) {
        const auto next = text.find(',', position + 1);
        const auto offset = Trim(text.substr(position + 1, next - position - 1));
        if (offset.empty()) {
            throw std::invalid_argument("chain contains an empty offset");
        }
        result.offsets.push_back(ParseUnsigned(offset));
        position = next;
    }
    return result;
}

} // namespace arc
