#include "Names.h"

#include <algorithm>
#include <cstring>
#include <limits>

namespace arc {
namespace {

constexpr std::uint32_t kHeaderBytes = 2;
constexpr std::uint32_t kMaxNameLength = 1024;

std::uint16_t LoadU16(const std::uint8_t* const bytes) {
    return static_cast<std::uint16_t>(bytes[0] | (bytes[1] << 8));
}

std::uint64_t LoadU64(const std::uint8_t* const bytes) {
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < 8; ++i) {
        value |= static_cast<std::uint64_t>(bytes[i]) << (i * 8);
    }
    return value;
}

bool IsWideNameCharacter(const std::uint16_t value) {
    if (value >= 0xD800 && value <= 0xDFFF) {
        return false;
    }
    return (value >= 0x21 && value <= 0x7e) || value >= 0x100;
}

void AppendUtf8(std::string& output, const std::uint32_t code_point) {
    if (code_point < 0x80) {
        output.push_back(static_cast<char>(code_point));
    } else if (code_point < 0x800) {
        output.push_back(static_cast<char>(0xC0U | (code_point >> 6)));
        output.push_back(static_cast<char>(0x80U | (code_point & 0x3FU)));
    } else {
        output.push_back(static_cast<char>(0xE0U | (code_point >> 12)));
        output.push_back(static_cast<char>(0x80U | ((code_point >> 6) & 0x3FU)));
        output.push_back(static_cast<char>(0x80U | (code_point & 0x3FU)));
    }
}

// One decoded entry, relative to the block start.
struct ParsedEntry {
    std::uint32_t offset{};
    std::uint32_t length{};
    bool wide{};
    std::uint32_t next{};  // start of the following entry
};

// Reads the header at entry_offset and checks that the payload it announces is present, null
// terminated and name-like. Returns false when the stream cannot continue here.
bool ReadEntry(
    const std::span<const std::uint8_t> block,
    const NameCodec& codec,
    const std::uint32_t entry_offset,
    ParsedEntry& entry) {
    if (codec.string_offset < kHeaderBytes || codec.length_bits == 0 || codec.length_bits > 16 ||
        codec.length_shift + codec.length_bits > 16) {
        return false;
    }
    if (entry_offset > block.size() || entry_offset + codec.string_offset > block.size()) {
        return false;
    }
    const auto header = LoadU16(block.data() + entry_offset);
    const std::uint32_t mask = (1U << codec.length_bits) - 1U;
    const auto length = (header >> codec.length_shift) & mask;
    const bool wide = ((header >> codec.wide_bit) & 1U) != 0;
    if (length == 0 || length > kMaxNameLength) {
        return false;
    }
    const std::uint32_t char_width = wide ? 2U : 1U;
    const std::uint64_t payload = static_cast<std::uint64_t>(length + 1U) * char_width;
    const std::uint64_t end = codec.string_offset + payload;
    if (end > block.size() - entry_offset) {
        return false;
    }
    const auto* text = block.data() + entry_offset + codec.string_offset;
    for (std::uint32_t i = 0; i < length; ++i) {
        if (wide) {
            if (!IsWideNameCharacter(LoadU16(text + i * 2))) {
                return false;
            }
        } else if (!IsNameCharacter(static_cast<char>(text[i]))) {
            return false;
        }
    }
    if (wide ? LoadU16(text + length * 2) != 0 : text[length] != 0) {
        return false;
    }
    auto next = static_cast<std::uint64_t>(entry_offset) + end;
    next = (next + 1U) & ~std::uint64_t{1};  // pool offsets are stored divided by two
    if (next > block.size()) {
        return false;
    }
    entry = {entry_offset, length, wide, static_cast<std::uint32_t>(next)};
    return true;
}

std::string EntryText(const std::span<const std::uint8_t> block, const NameCodec& codec, const ParsedEntry& entry) {
    const auto* text = block.data() + entry.offset + codec.string_offset;
    std::string result;
    result.reserve(entry.length);
    for (std::uint32_t i = 0; i < entry.length; ++i) {
        if (entry.wide) {
            AppendUtf8(result, LoadU16(text + i * 2));
        } else {
            result.push_back(static_cast<char>(text[i]));
        }
    }
    return result;
}

} // namespace

bool IsNameCharacter(const char value) noexcept {
    const auto byte = static_cast<unsigned char>(value);
    return byte >= 0x21 && byte <= 0x7e;
}

NameBlockWalk WalkNameBlock(
    const std::span<const std::uint8_t> block,
    const NameCodec& codec,
    const std::size_t max_entries,
    const std::uint32_t start_offset) {
    NameBlockWalk walk;
    walk.codec = &codec;
    auto offset = start_offset;
    while (walk.entries.size() < max_entries) {
        ParsedEntry parsed;
        if (!ReadEntry(block, codec, offset, parsed)) {
            walk.span_exhausted = offset + kHeaderBytes >= block.size();
            break;
        }
        walk.entries.push_back({parsed.offset, parsed.length, parsed.wide, EntryText(block, codec, parsed)});
        walk.consumed = parsed.next;
        offset = parsed.next;
    }
    walk.cap_reached = max_entries != 0 && walk.entries.size() == max_entries;
    return walk;
}

NameBlockStats MeasureNameBlock(
    const std::span<const std::uint8_t> block,
    const NameCodec& codec,
    const std::size_t max_entries) {
    const auto walk = WalkNameBlock(block, codec, max_entries);
    NameBlockStats stats;
    stats.entries = static_cast<std::uint32_t>(walk.entries.size());
    stats.consumed = walk.consumed;
    stats.cap_reached = walk.cap_reached;
    stats.span_exhausted = walk.span_exhausted;
    if (!walk.entries.empty()) {
        stats.first_name = walk.entries.front().text;
        stats.last_name = walk.entries.back().text;
    }
    return stats;
}

NameBlockWalk DetectNameBlock(
    const std::span<const std::uint8_t> block,
    const std::span<const NameCodec> codecs,
    const std::string_view expected_first,
    const std::uint32_t min_entries,
    const std::size_t max_entries) {
    NameBlockWalk best;
    for (const auto& codec : codecs) {
        auto walk = WalkNameBlock(block, codec, max_entries);
        if (walk.entries.size() < min_entries) {
            continue;
        }
        if (!expected_first.empty() && walk.entries.front().text != expected_first) {
            continue;
        }
        if (best.entries.size() < walk.entries.size()) {
            best = std::move(walk);
        }
    }
    return best;
}

std::vector<HeaderProbe> ProbeBlockHeaders(
    const CapturedRead& read,
    const std::uint64_t first_data_va,
    const std::uint32_t block_size,
    const NameCodec& codec,
    const std::uint32_t min_entries,
    const std::span<const std::uint32_t> header_size_candidates) {
    std::vector<HeaderProbe> probes;
    probes.reserve(header_size_candidates.size());
    for (const auto header_size : header_size_candidates) {
        HeaderProbe probe;
        probe.header_size = header_size;
        if (header_size < 8 || header_size > 0x100 || first_data_va < header_size) {
            probes.push_back(std::move(probe));
            continue;
        }
        probe.header_va = first_data_va - header_size;
        const auto window = read(probe.header_va, header_size);
        if (!window || window->size() < 8) {
            probes.push_back(std::move(probe));
            continue;
        }
        probe.header_captured = true;
        probe.window.assign(window->begin(), window->end());
        probe.next = LoadU64(window->data());
        probe.next_is_null = probe.next == 0;
        if (probe.next != 0 && probe.next <= std::numeric_limits<std::uint64_t>::max() - header_size) {
            if (const auto next_block = read(probe.next + header_size, block_size)) {
                probe.next_entries = MeasureNameBlock(*next_block, codec, 8192).entries;
                probe.next_is_block = probe.next_entries >= min_entries;
            }
        }
        probes.push_back(std::move(probe));
    }
    return probes;
}

NameBlockChain FollowNameBlocks(
    const CapturedRead& read,
    const std::uint64_t first_data_va,
    const std::uint32_t header_size,
    const std::uint32_t block_size,
    const NameCodec& codec,
    const std::uint32_t min_entries,
    const std::size_t max_entries_per_block,
    const std::size_t max_blocks) {
    NameBlockChain chain;
    chain.header_size = header_size;
    chain.block_size = block_size;
    if (header_size < 8 || header_size > 0x100 || first_data_va < header_size) {
        chain.stop_reason = "invalid block data VA or header size";
        return chain;
    }
    std::vector<std::uint64_t> visited;
    auto data_va = first_data_va;
    for (std::size_t index = 0; index < max_blocks; ++index) {
        if (std::find(visited.begin(), visited.end(), data_va) != visited.end()) {
            chain.stop_reason = "cycle in the block chain";
            break;
        }
        visited.push_back(data_va);
        NameBlockNode node;
        node.data_va = data_va;
        node.header_va = data_va - header_size;
        const auto block = read(data_va, block_size);
        const auto header = read(node.header_va, header_size);
        node.data_captured = block.has_value();
        node.header_captured = header.has_value() && header->size() >= 8;
        if (block) {
            node.stats = MeasureNameBlock(*block, codec, max_entries_per_block);
        }
        if (node.header_captured) {
            node.next = LoadU64(header->data());
        }
        chain.total_entries += node.stats.entries;
        chain.total_capped = chain.total_capped || node.stats.cap_reached;
        chain.blocks.push_back(std::move(node));
        const auto& added = chain.blocks.back();
        if (!added.data_captured) {
            chain.stop_reason = "block data is not captured";
            break;
        }
        if (added.stats.entries < min_entries) {
            chain.stop_reason = added.stats.entries > 0
                ? "short block: fewer entries than min_entries, typically the partially filled last block"
                : "block did not decode as a name stream";
            break;
        }
        if (!added.header_captured) {
            chain.stop_reason = "block header is not captured";
            break;
        }
        if (added.next == 0) {
            chain.stop_reason = "end of chain: null next pointer";
            break;
        }
        if (added.next < header_size ||
            added.next > std::numeric_limits<std::uint64_t>::max() - header_size) {
            chain.stop_reason = "implausible next pointer";
            break;
        }
        data_va = added.next + header_size;
        if (index + 1 == max_blocks) {
            chain.stop_reason = "block limit reached; chain may continue";
        }
    }
    if (chain.blocks.empty() && chain.stop_reason.empty()) {
        chain.stop_reason = "no blocks";
    }
    return chain;
}

} // namespace arc
