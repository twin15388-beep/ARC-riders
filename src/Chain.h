#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace arc {

enum class ChainBaseKind {
    Module,
    Signature,
};

struct PointerChainSpec {
    ChainBaseKind base_kind{};
    std::string signature_name;
    std::uint64_t base_offset{};
    std::vector<std::uint64_t> offsets;
};

[[nodiscard]] std::uint64_t ParseUnsigned(std::string_view text);
[[nodiscard]] std::optional<std::uint64_t> CheckedAdd(std::uint64_t left, std::uint64_t right);
[[nodiscard]] PointerChainSpec ParsePointerChain(std::string_view text);

} // namespace arc
