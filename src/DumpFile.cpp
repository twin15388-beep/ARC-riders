#ifdef _WIN32

#include "DumpFile.h"

#include "PeFile.h"
#include "Process.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iomanip>
#include <iostream>
#include <limits>
#include <optional>
#include <span>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace arc {
namespace {

struct Stream {
    std::uint32_t type{};
    std::uint32_t size{};
    std::uint32_t offset{};
};

struct MemoryRange {
    std::uint64_t va{};
    std::uint64_t size{};
    std::uint64_t file_offset{};
};

std::uint16_t U16(const std::uint8_t* p) {
    return static_cast<std::uint16_t>(p[0]) | (static_cast<std::uint16_t>(p[1]) << 8);
}

std::uint32_t U32(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0]) |
        (static_cast<std::uint32_t>(p[1]) << 8) |
        (static_cast<std::uint32_t>(p[2]) << 16) |
        (static_cast<std::uint32_t>(p[3]) << 24);
}

std::uint64_t U64(const std::uint8_t* p) {
    return static_cast<std::uint64_t>(U32(p)) | (static_cast<std::uint64_t>(U32(p + 4)) << 32);
}

void Require(const std::uint64_t offset, const std::uint64_t amount, const std::size_t file_size) {
    if (offset > file_size || amount > static_cast<std::uint64_t>(file_size) - offset) {
        throw std::runtime_error("minidump structure points outside the file");
    }
}

const Stream* FindStream(const std::vector<Stream>& streams, const std::uint32_t type) {
    const auto found = std::find_if(streams.begin(), streams.end(), [&](const Stream& stream) {
        return stream.type == type;
    });
    return found == streams.end() ? nullptr : &*found;
}

std::string DumpString(const std::span<const std::uint8_t> bytes, const std::uint32_t offset) {
    Require(offset, 4, bytes.size());
    const auto length = static_cast<std::size_t>(U32(bytes.data() + offset));
    if (length > 1024 * 1024 || length % 2 != 0) {
        throw std::runtime_error("implausible minidump string length");
    }
    Require(static_cast<std::uint64_t>(offset) + 4, length, bytes.size());
    std::wstring text(length / 2, L'\0');
    for (std::size_t i = 0; i < text.size(); ++i) {
        text[i] = static_cast<wchar_t>(U16(bytes.data() + offset + 4 + i * 2));
    }
    return WideToUtf8(text);
}

std::optional<std::uint64_t> FileOffsetToVa(
    const std::vector<MemoryRange>& ranges,
    const std::uint64_t offset) {
    for (const auto& range : ranges) {
        if (offset >= range.file_offset && offset - range.file_offset < range.size) {
            return range.va + (offset - range.file_offset);
        }
    }
    return std::nullopt;
}

std::optional<std::span<const std::uint8_t>> ReadVa(
    const std::span<const std::uint8_t> bytes,
    const std::vector<MemoryRange>& ranges,
    const std::uint64_t va,
    const std::uint64_t size) {
    const auto next = std::upper_bound(ranges.begin(), ranges.end(), va,
        [](const std::uint64_t address, const MemoryRange& range) { return address < range.va; });
    if (next == ranges.begin()) {
        return std::nullopt;
    }
    const auto& range = *std::prev(next);
    if (va < range.va || va - range.va > range.size || size > range.size - (va - range.va)) {
        return std::nullopt;
    }
    const auto offset = static_cast<std::size_t>(range.file_offset + (va - range.va));
    return bytes.subspan(offset, static_cast<std::size_t>(size));
}

std::string PrintableString(const std::span<const std::uint8_t> bytes, const std::size_t start) {
    std::string result;
    for (std::size_t i = start; i < bytes.size() && result.size() < 240; ++i) {
        const auto c = bytes[i];
        if (c == 0) {
            break;
        }
        result.push_back(c >= 0x20 && c <= 0x7e ? static_cast<char>(c) : '.');
    }
    return result;
}

void PrintStringHits(
    const std::span<const std::uint8_t> bytes,
    const std::vector<MemoryRange>& ranges,
    const std::string_view needle) {
    constexpr std::size_t max_hits = 16;
    const std::vector<std::uint8_t> pattern(needle.begin(), needle.end());
    const auto searcher = std::boyer_moore_searcher(pattern.begin(), pattern.end());
    auto current = bytes.begin();
    std::size_t hits = 0;
    while (current != bytes.end() && hits < max_hits) {
        const auto found = std::search(current, bytes.end(), searcher);
        if (found == bytes.end()) {
            break;
        }
        const auto offset = static_cast<std::size_t>(found - bytes.begin());
        std::cout << "    dump_offset=0x" << std::hex << offset;
        if (const auto va = FileOffsetToVa(ranges, offset)) {
            std::cout << " VA=0x" << *va;
        } else {
            std::cout << " VA=unmapped";
        }
        std::cout << std::dec << " \"" << PrintableString(bytes, offset) << "\"\n";
        ++hits;
        current = found + 1;
    }
    std::cout << "  hits=" << hits << (hits == max_hits ? " (cap reached)" : "") << '\n';
}

std::vector<MemoryRange> ReadMemoryRanges(
    const std::span<const std::uint8_t> bytes,
    const std::vector<Stream>& streams) {
    std::vector<MemoryRange> ranges;
    if (const auto* stream = FindStream(streams, 9)) {
        Require(stream->offset, stream->size, bytes.size());
        if (stream->size < 16) {
            throw std::runtime_error("truncated Memory64List header");
        }
        Require(stream->offset, 16, bytes.size());
        const auto count = U64(bytes.data() + stream->offset);
        const auto base = U64(bytes.data() + stream->offset + 8);
        if (count > 1024 * 1024 || count > (stream->size - 16) / 16) {
            throw std::runtime_error("invalid Memory64List range count");
        }
        std::uint64_t file_offset = base;
        for (std::uint64_t i = 0; i < count; ++i) {
            const auto entry = static_cast<std::uint64_t>(stream->offset) + 16 + i * 16;
            const auto va = U64(bytes.data() + entry);
            const auto size = U64(bytes.data() + entry + 8);
            Require(file_offset, size, bytes.size());
            ranges.push_back({va, size, file_offset});
            if (size > std::numeric_limits<std::uint64_t>::max() - file_offset) {
                throw std::runtime_error("Memory64List file offset overflow");
            }
            file_offset += size;
        }
    } else if (const auto* stream = FindStream(streams, 5)) {
        Require(stream->offset, stream->size, bytes.size());
        if (stream->size < 4) {
            throw std::runtime_error("truncated MemoryList header");
        }
        Require(stream->offset, 4, bytes.size());
        const auto count = static_cast<std::uint64_t>(U32(bytes.data() + stream->offset));
        if (count > 1024 * 1024 || count > (stream->size - 4) / 16) {
            throw std::runtime_error("invalid MemoryList range count");
        }
        for (std::uint64_t i = 0; i < count; ++i) {
            const auto entry = static_cast<std::uint64_t>(stream->offset) + 4 + i * 16;
            const auto va = U64(bytes.data() + entry);
            const auto size = U32(bytes.data() + entry + 8);
            const auto file_offset = U32(bytes.data() + entry + 12);
            Require(file_offset, size, bytes.size());
            ranges.push_back({va, size, file_offset});
        }
    }
    std::sort(ranges.begin(), ranges.end(), [](const MemoryRange& left, const MemoryRange& right) {
        return left.va < right.va;
    });
    return ranges;
}

std::vector<Stream> ReadStreams(const std::span<const std::uint8_t> bytes) {
    Require(0, 32, bytes.size());
    if (U32(bytes.data()) != 0x504D444D) {
        throw std::runtime_error("not an MDMP minidump");
    }
    const auto stream_count = static_cast<std::size_t>(U32(bytes.data() + 8));
    const auto directory = static_cast<std::size_t>(U32(bytes.data() + 12));
    if (stream_count == 0 || stream_count > 4096) {
        throw std::runtime_error("implausible minidump stream count");
    }
    Require(directory, stream_count * 12, bytes.size());
    std::vector<Stream> streams;
    streams.reserve(stream_count);
    for (std::size_t i = 0; i < stream_count; ++i) {
        const auto entry = directory + i * 12;
        const auto type = U32(bytes.data() + entry);
        const auto size = U32(bytes.data() + entry + 4);
        const auto offset = U32(bytes.data() + entry + 8);
        Require(offset, size, bytes.size());
        streams.push_back({type, size, offset});
    }
    return streams;
}

void PrintModules(const std::span<const std::uint8_t> bytes, const std::vector<Stream>& streams) {
    const auto* stream = FindStream(streams, 4);
    if (stream == nullptr) {
        std::cout << "modules=unavailable\n";
        return;
    }
    Require(stream->offset, stream->size, bytes.size());
    if (stream->size < 4) {
        throw std::runtime_error("truncated ModuleList header");
    }
    Require(stream->offset, 4, bytes.size());
    const auto count = static_cast<std::size_t>(U32(bytes.data() + stream->offset));
    if (count > 16384 || count > (stream->size - 4) / 108) {
        throw std::runtime_error("invalid ModuleList count");
    }
    std::cout << "modules=" << count << '\n';
    for (std::size_t i = 0; i < count; ++i) {
        const auto module = static_cast<std::size_t>(stream->offset) + 4 + i * 108;
        const auto base = U64(bytes.data() + module);
        const auto size = U32(bytes.data() + module + 8);
        const auto timestamp = U32(bytes.data() + module + 16);
        const auto name_rva = U32(bytes.data() + module + 20);
        std::cout << "  " << DumpString(bytes, name_rva)
                  << " base=0x" << std::hex << base
                  << " image_size=0x" << size
                  << " pe_timestamp=0x" << timestamp << std::dec << '\n';
    }
}

} // namespace

void PrintDumpInfo(const std::filesystem::path& path) {
    const MappedFile file(path);
    const auto bytes = file.Bytes();
    const auto streams = ReadStreams(bytes);
    std::cout << "dump=" << path.string() << "\ndump_file_size=" << bytes.size()
              << "\nstreams=" << streams.size() << '\n';
    PrintModules(bytes, streams);
    const auto ranges = ReadMemoryRanges(bytes, streams);
    std::uint64_t total_memory = 0;
    for (const auto& range : ranges) {
        if (range.size > std::numeric_limits<std::uint64_t>::max() - total_memory) {
            throw std::runtime_error("total dump memory size overflow");
        }
        total_memory += range.size;
    }
    std::cout << "memory_ranges=" << ranges.size() << " captured_memory=" << total_memory << '\n';

    constexpr std::array<std::string_view, 11> needles{
        "++UE", "Unreal Engine", "FNamePool", "GUObjectArray", "GWorld", "Pioneer",
        "EasyAntiCheat", "/Script/Engine", "PersistentLevel", "PlayerCameraManager", "RootComponent",
    };
    for (const auto& needle : needles) {
        std::cout << "string \"" << needle << "\":\n";
        PrintStringHits(bytes, ranges, needle);
    }
}

void PrintDumpStrings(const std::filesystem::path& path, const std::string_view needle) {
    if (needle.empty() || needle.size() > 256) {
        throw std::invalid_argument("string needle length must be 1..256 bytes");
    }
    const MappedFile file(path);
    const auto bytes = file.Bytes();
    const auto streams = ReadStreams(bytes);
    const auto ranges = ReadMemoryRanges(bytes, streams);
    std::cout << "string \"" << needle << "\":\n";
    PrintStringHits(bytes, ranges, needle);
}

void PrintDumpXrefs(const std::filesystem::path& path, const std::uint64_t target_va) {
    if (target_va == 0) {
        throw std::invalid_argument("target VA must be nonzero");
    }
    const MappedFile file(path);
    const auto bytes = file.Bytes();
    const auto streams = ReadStreams(bytes);
    const auto ranges = ReadMemoryRanges(bytes, streams);
    std::vector<std::uint8_t> pointer(8);
    for (std::size_t i = 0; i < pointer.size(); ++i) {
        pointer[i] = static_cast<std::uint8_t>(target_va >> (i * 8));
    }
    const auto searcher = std::boyer_moore_searcher(pointer.begin(), pointer.end());
    auto current = bytes.begin();
    std::size_t hits = 0;
    std::cout << "xrefs_to VA=0x" << std::hex << target_va << std::dec << ":\n";
    while (current != bytes.end() && hits < 128) {
        const auto found = std::search(current, bytes.end(), searcher);
        if (found == bytes.end()) {
            break;
        }
        const auto offset = static_cast<std::size_t>(found - bytes.begin());
        std::cout << "  dump_offset=0x" << std::hex << offset;
        if (const auto va = FileOffsetToVa(ranges, offset)) {
            std::cout << " VA=0x" << *va;
        } else {
            std::cout << " VA=unmapped";
        }
        std::cout << std::dec << '\n';
        ++hits;
        current = found + 1;
    }
    std::cout << "hits=" << hits << (hits == 128 ? " (cap reached)" : "") << '\n';
}

void PrintDumpRipXrefs(const std::filesystem::path& path, const std::uint64_t target_va) {
    if (target_va == 0) throw std::invalid_argument("RIP xref target VA must be nonzero");
    const MappedFile file(path);
    const auto bytes = file.Bytes();
    const auto ranges = ReadMemoryRanges(bytes, ReadStreams(bytes));
    std::size_t hits = 0;
    std::cout << "RIP-relative LEA xrefs to VA=0x" << std::hex << target_va << std::dec << ":\n";
    for (const auto& range : ranges) {
        if (range.size < 7) continue;
        const auto data = bytes.subspan(
            static_cast<std::size_t>(range.file_offset), static_cast<std::size_t>(range.size));
        for (std::size_t position = 0; position + 7 <= data.size() && hits < 128; ++position) {
            if ((data[position] != 0x48 && data[position] != 0x4C) ||
                data[position + 1] != 0x8D || (data[position + 2] & 0xC7) != 0x05) {
                continue;
            }
            const auto displacement = static_cast<std::int64_t>(
                static_cast<std::int32_t>(U32(data.data() + position + 3)));
            const auto instruction_va = range.va + position;
            const auto next_va = instruction_va + 7;
            if ((displacement >= 0 && static_cast<std::uint64_t>(displacement) > UINT64_MAX - next_va) ||
                (displacement < 0 && static_cast<std::uint64_t>(-displacement) > next_va)) {
                continue;
            }
            const auto computed = displacement >= 0
                ? next_va + static_cast<std::uint64_t>(displacement)
                : next_va - static_cast<std::uint64_t>(-displacement);
            if (computed != target_va) continue;
            std::cout << "  instruction=0x" << std::hex << instruction_va
                      << " bytes=" << static_cast<unsigned>(data[position]) << ' '
                      << static_cast<unsigned>(data[position + 1]) << ' '
                      << static_cast<unsigned>(data[position + 2]) << std::dec << '\n';
            ++hits;
        }
        if (hits == 128) break;
    }
    std::cout << "hits=" << hits << (hits == 128 ? " (cap reached)" : "") << '\n';
}

void PrintDumpScan(const std::filesystem::path& path, const Pattern& pattern) {
    const MappedFile file(path);
    const auto bytes = file.Bytes();
    const auto streams = ReadStreams(bytes);
    const auto ranges = ReadMemoryRanges(bytes, streams);
    std::size_t hits = 0;
    std::cout << "dump AOB scan:\n";
    for (const auto& range : ranges) {
        if (range.size == 0 || hits == 128) {
            continue;
        }
        const auto offset = static_cast<std::size_t>(range.file_offset);
        const auto size = static_cast<std::size_t>(range.size);
        const auto matches = FindPattern(bytes.subspan(offset, size), pattern, 128 - hits);
        for (const auto position : matches) {
            std::cout << "  VA=0x" << std::hex << range.va + position
                      << " dump_offset=0x" << range.file_offset + position << std::dec << '\n';
            ++hits;
        }
    }
    std::cout << "hits=" << hits << (hits == 128 ? " (cap reached)" : "") << '\n';
}

void PrintDumpRead(const std::filesystem::path& path, const std::uint64_t va, const std::size_t size) {
    if (va == 0 || size == 0 || size > 4096) {
        throw std::invalid_argument("dump read requires nonzero VA and size 1..4096");
    }
    const MappedFile file(path);
    const auto bytes = file.Bytes();
    const auto streams = ReadStreams(bytes);
    const auto ranges = ReadMemoryRanges(bytes, streams);
    for (const auto& range : ranges) {
        if (va < range.va || va - range.va > range.size || size > range.size - (va - range.va)) {
            continue;
        }
        const auto offset = static_cast<std::size_t>(range.file_offset + (va - range.va));
        for (std::size_t row = 0; row < size; row += 16) {
            std::cout << "0x" << std::hex << std::setw(16) << std::setfill('0') << va + row << "  ";
            const auto amount = std::min<std::size_t>(16, size - row);
            for (std::size_t i = 0; i < 16; ++i) {
                if (i < amount) {
                    std::cout << std::setw(2) << static_cast<unsigned>(bytes[offset + row + i]) << ' ';
                } else {
                    std::cout << "   ";
                }
            }
            std::cout << " ";
            for (std::size_t i = 0; i < amount; ++i) {
                const auto c = bytes[offset + row + i];
                std::cout << (c >= 0x20 && c <= 0x7e ? static_cast<char>(c) : '.');
            }
            std::cout << '\n';
        }
        std::cout << std::dec << std::setfill(' ');
        return;
    }
    throw std::runtime_error("requested VA range is not captured in the dump");
}

void PrintDumpRtti(
    const std::filesystem::path& path,
    const std::uint64_t image_base,
    const std::vector<std::uint64_t>& vtables) {
    if (image_base == 0 || vtables.empty() || vtables.size() > 32) {
        throw std::invalid_argument("dump RTTI requires an image base and 1..32 vtables");
    }
    const MappedFile file(path);
    const auto bytes = file.Bytes();
    const auto ranges = ReadMemoryRanges(bytes, ReadStreams(bytes));
    for (const auto vtable : vtables) {
        std::cout << "vtable=0x" << std::hex << vtable << std::dec << '\n';
        if (vtable < 8) throw std::invalid_argument("vtable address underflow");
        const auto locator_pointer = ReadVa(bytes, ranges, vtable - 8, 8);
        if (!locator_pointer) {
            std::cout << "  locator pointer is not captured\n";
            continue;
        }
        const auto locator_va = U64(locator_pointer->data());
        std::cout << "  locator pointer=0x" << std::hex << locator_va << std::dec << '\n';
        const auto locator = ReadVa(bytes, ranges, locator_va, 20);
        if (!locator) {
            std::cout << "  CompleteObjectLocator is not captured\n";
            continue;
        }
        const auto signature = U32(locator->data());
        const auto type_rva = U32(locator->data() + 12);
        if (signature != 1 || type_rva == 0 || image_base > std::numeric_limits<std::uint64_t>::max() - type_rva) {
            std::cout << "  no valid x64 RTTI locator (signature=0x" << std::hex << signature
                      << ", typeRVA=0x" << type_rva << std::dec << ")\n";
            continue;
        }
        const auto type_va = image_base + type_rva;
        const auto descriptor = ReadVa(bytes, ranges, type_va, 16 + 256);
        if (!descriptor) {
            std::cout << "  TypeDescriptor is not fully captured at VA=0x" << std::hex << type_va << std::dec << '\n';
            continue;
        }
        const std::string name = PrintableString(*descriptor, 16);
        if (!name.starts_with(".?AV") && !name.starts_with(".?AU")) {
            std::cout << "  unexpected TypeDescriptor at VA=0x" << std::hex << type_va
                      << ": " << name << std::dec << '\n';
            continue;
        }
        std::cout << "  locator=0x" << std::hex << locator_va << " type=0x" << type_va
                  << std::dec << "\n  name=" << name << '\n';
    }
}

void PrintDumpPointerChain(
    const std::filesystem::path& path,
    const std::uint64_t pointer_va,
    const std::vector<std::uint64_t>& offsets) {
    if (pointer_va == 0) {
        throw std::invalid_argument("dump chain pointer VA must be nonzero");
    }
    const MappedFile file(path);
    const auto bytes = file.Bytes();
    const auto ranges = ReadMemoryRanges(bytes, ReadStreams(bytes));
    auto read_address = pointer_va;
    for (std::size_t step = 0; step <= offsets.size(); ++step) {
        const auto data = ReadVa(bytes, ranges, read_address, 8);
        if (!data) {
            throw std::runtime_error("dump chain read is not captured at step " + std::to_string(step));
        }
        const auto value = U64(data->data());
        std::cout << "step=" << step << " read_VA=0x" << std::hex << read_address
                  << " value=0x" << value << std::dec << '\n';
        if (step == offsets.size()) {
            break;
        }
        if (value == 0 || offsets[step] > std::numeric_limits<std::uint64_t>::max() - value) {
            throw std::runtime_error("dump chain pointer is null or overflows at step " + std::to_string(step));
        }
        read_address = value + offsets[step];
    }
}

void PrintDumpPointerChainScan(
    const std::filesystem::path& path,
    const std::uint64_t image_base,
    const std::uint64_t image_size,
    const std::vector<std::uint64_t>& offsets) {
    if (image_base == 0 || image_size == 0 || offsets.empty() || offsets.size() > 8 ||
        image_size > std::numeric_limits<std::uint64_t>::max() - image_base) {
        throw std::invalid_argument("dump chain scan requires a valid image range and 1..8 offsets");
    }
    const MappedFile file(path);
    const auto bytes = file.Bytes();
    const auto ranges = ReadMemoryRanges(bytes, ReadStreams(bytes));
    const auto image_end = image_base + image_size;
    std::size_t hits = 0;
    std::uint64_t duplicates = 0;
    std::uint64_t pointer_chains = 0;
    std::uint64_t scanned = 0;
    std::set<std::vector<std::uint64_t>> unique_chains;
    for (const auto& range : ranges) {
        if (range.size == 0 || range.va >= image_end || image_base >= range.va + range.size) {
            continue;
        }
        auto current = std::max(image_base, range.va);
        current = (current + 7) & ~std::uint64_t{7};
        const auto end = std::min(image_end, range.va + range.size);
        for (; current <= end && end - current >= 8 && hits < 128; current += 8) {
            ++scanned;
            auto read_address = current;
            std::vector<std::uint64_t> values;
            values.reserve(offsets.size() + 1);
            bool valid = true;
            for (std::size_t step = 0; step <= offsets.size(); ++step) {
                const auto data = ReadVa(bytes, ranges, read_address, 8);
                if (!data) {
                    valid = false;
                    break;
                }
                const auto value = U64(data->data());
                if (value < 0x10000 || value > 0x7FFFFFFFFFFF || (value & 7) != 0 ||
                    (value >= image_base && value < image_end)) {
                    valid = false;
                    break;
                }
                values.push_back(value);
                if (step < offsets.size()) {
                    if (offsets[step] > std::numeric_limits<std::uint64_t>::max() - value) {
                        valid = false;
                        break;
                    }
                    read_address = value + offsets[step];
                }
            }
            if (!valid) {
                continue;
            }
            ++pointer_chains;
            for (const auto value : values) {
                const auto object_header = ReadVa(bytes, ranges, value, 8);
                if (!object_header) {
                    valid = false;
                    break;
                }
                const auto vtable = U64(object_header->data());
                if (vtable < image_base || vtable >= image_end) {
                    valid = false;
                    break;
                }
            }
            if (!valid) {
                continue;
            }
            if (!unique_chains.insert(values).second) {
                ++duplicates;
                continue;
            }
            std::cout << "candidate global_VA=0x" << std::hex << current;
            for (std::size_t i = 0; i < values.size(); ++i) {
                std::cout << " step" << i << "=0x" << values[i];
            }
            std::cout << std::dec << '\n';
            ++hits;
        }
    }
    std::cout << "scanned_qwords=" << scanned << " pointer_chains=" << pointer_chains
              << " unique_uobject_candidates=" << hits << " duplicates_suppressed=" << duplicates
              << (hits == 128 ? " (cap reached)" : "") << '\n';
}

void PrintDumpGNamesCandidates(
    const std::filesystem::path& path,
    const std::uint64_t image_base,
    const std::uint64_t image_size) {
    if (image_base == 0 || image_size == 0 || image_size > std::numeric_limits<std::uint64_t>::max() - image_base) {
        throw std::invalid_argument("invalid image range for GNames scan");
    }
    const MappedFile file(path);
    const auto bytes = file.Bytes();
    const auto streams = ReadStreams(bytes);
    const auto ranges = ReadMemoryRanges(bytes, streams);
    const auto pattern = Pattern::Parse("48 8D 0D ?? ?? ?? ?? E8");
    constexpr std::uint64_t core_uobject = 0x6A624F5565726F43;
    constexpr std::uint32_t none = 0x656E6F4E;
    std::size_t candidates = 0;
    std::size_t scanned_matches = 0;
    for (const auto& range : ranges) {
        if (range.size == 0) {
            continue;
        }
        const auto data = bytes.subspan(
            static_cast<std::size_t>(range.file_offset), static_cast<std::size_t>(range.size));
        const auto matches = FindPattern(data, pattern, 4096);
        for (const auto position : matches) {
            const auto instruction = range.va + position;
            if (instruction < image_base || instruction >= image_base + image_size) {
                continue;
            }
            ++scanned_matches;
            const auto displacement = static_cast<std::int32_t>(U32(data.data() + position + 3));
            const auto target = static_cast<std::uint64_t>(
                static_cast<std::int64_t>(instruction + 7) + displacement);
            const auto header = ReadVa(bytes, ranges, target, 0x20);
            if (!header) {
                continue;
            }
            for (std::size_t i = 0; i < 0x20; i += 4) {
                const auto max_chunk = static_cast<std::int32_t>(U32(header->data() + i));
                if (max_chunk <= 0 || max_chunk > 0x10000) {
                    continue;
                }
                const auto chunks_start = static_cast<std::uint64_t>(i + 8 + (i % 8));
                const auto pointers_size = (static_cast<std::uint64_t>(max_chunk) + 1) * 8;
                const auto pointers = ReadVa(bytes, ranges, target + chunks_start, pointers_size);
                if (!pointers) {
                    continue;
                }
                bool all_nonnull = true;
                for (std::int32_t chunk = 0; chunk <= max_chunk; ++chunk) {
                    if (U64(pointers->data() + static_cast<std::size_t>(chunk) * 8) == 0) {
                        all_nonnull = false;
                        break;
                    }
                }
                if (!all_nonnull) {
                    continue;
                }
                const auto first_chunk = U64(pointers->data());
                const auto names = ReadVa(bytes, ranges, first_chunk, 0x1000);
                if (!names) {
                    continue;
                }
                bool found_none = false;
                bool found_core = false;
                for (std::size_t j = 0; j <= names->size() - 8; ++j) {
                    found_none |= U32(names->data() + j) == none;
                    found_core |= U64(names->data() + j) == core_uobject;
                }
                if (!found_none || !found_core) {
                    continue;
                }
                std::cout << "GNames candidate instruction=0x" << std::hex << instruction
                          << " instruction_RVA=0x" << instruction - image_base
                          << " pool=0x" << target;
                if (target >= image_base && target < image_base + image_size) {
                    std::cout << " pool_RVA=0x" << target - image_base;
                } else {
                    std::cout << " pool_RVA=outside_image";
                }
                std::cout << " max_chunk=" << std::dec << max_chunk
                          << " chunks_start=0x" << std::hex << chunks_start
                          << " first_chunk=0x" << first_chunk << std::dec << '\n';
                ++candidates;
            }
        }
    }
    std::cout << "instruction_matches=" << scanned_matches
              << " validated_candidates=" << candidates << '\n';
}

void PrintDumpFNamePool(
    const std::filesystem::path& path,
    const std::uint64_t image_base,
    const std::uint64_t image_size) {
    if (image_base == 0 || image_size == 0 || image_size > UINT64_MAX - image_base) {
        throw std::invalid_argument("invalid image range for FName pool scan");
    }
    static constexpr std::array<std::string_view, 10> names{{
        "World", "Actor", "Pawn", "GameInstance", "LocalPlayer",
        "PlayerController", "PlayerCameraManager", "PersistentLevel",
        "RootComponent", "/Script/Engine",
    }};
    struct Hit {
        std::uint64_t entry;
        std::uint64_t block;
        std::uint32_t offset;
        std::string_view name;
    };
    struct ChunksCandidate {
        std::uint64_t address;
        std::vector<std::uint64_t> blocks;
    };
    const auto heap = [&](const std::uint64_t address) {
        return address >= 0x10000 && address <= 0x7FFFFFFFFFFF &&
            (address < image_base || address >= image_base + image_size);
    };
    const MappedFile file(path);
    const auto bytes = file.Bytes();
    const auto ranges = ReadMemoryRanges(bytes, ReadStreams(bytes));
    std::uint64_t scanned = 0;
    std::uint64_t raw_hits = 0;
    std::uint64_t filtered = 0;
    std::vector<Hit> hits;
    std::set<std::pair<std::uint64_t, std::string_view>> unique;
    for (const auto& range : ranges) {
        scanned += range.size;
        if (range.size < 4) continue;
        const auto data = bytes.subspan(
            static_cast<std::size_t>(range.file_offset), static_cast<std::size_t>(range.size));
        for (std::size_t position = 2; position < data.size(); ++position) {
            for (const auto name : names) {
                if (name.size() > 63 || position + name.size() > data.size() ||
                    data[position] != static_cast<std::uint8_t>(name.front()) ||
                    std::memcmp(data.data() + position, name.data(), name.size()) != 0) {
                    continue;
                }
                ++raw_hits;
                const auto header = U16(data.data() + position - 2);
                if ((header & 1U) != 0 || (header >> 6) != name.size()) {
                    ++filtered;
                    continue;
                }
                const auto entry = range.va + position - 2;
                const auto block = entry & ~std::uint64_t{0x1FFFF};
                if (!heap(block) || !unique.emplace(entry, name).second ||
                    !ReadVa(bytes, ranges, block, 0x20000)) {
                    ++filtered;
                    continue;
                }
                hits.push_back({entry, block, static_cast<std::uint32_t>(entry - block), name});
            }
        }
    }
    std::cout << "name scan bytes=" << scanned << " raw_hits=" << raw_hits
              << " filtered=" << filtered << " unique_entries=" << hits.size() << '\n';
    std::set<std::uint64_t> named_blocks;
    for (const auto& hit : hits) named_blocks.insert(hit.block);
    std::cout << "named_aligned_blocks=" << named_blocks.size() << '\n';

    std::vector<ChunksCandidate> candidates;
    std::uint64_t rejected_runs = 0;
    for (const auto& range : ranges) {
        if (range.size < 8 * 8) continue;
        const auto data = bytes.subspan(
            static_cast<std::size_t>(range.file_offset), static_cast<std::size_t>(range.size));
        for (std::size_t position = 0; position + 8 * 8 <= data.size(); position += 8) {
            const auto address = range.va + position;
            if (!heap(address) || !named_blocks.contains(U64(data.data() + position))) continue;
            if (position >= 8 && named_blocks.contains(U64(data.data() + position - 8))) continue;
            std::vector<std::uint64_t> blocks;
            while (position + blocks.size() * 8 + 8 <= data.size() && blocks.size() < 8192) {
                const auto value = U64(data.data() + position + blocks.size() * 8);
                if (!named_blocks.contains(value) || !ReadVa(bytes, ranges, value, 0x20000)) break;
                blocks.push_back(value);
            }
            if (blocks.size() >= 8) candidates.push_back({address, std::move(blocks)});
            else ++rejected_runs;
        }
    }
    std::cout << "chunk runs rejected=" << rejected_runs
              << " candidates_with_8plus_blocks=" << candidates.size() << '\n';

    std::size_t validated_pools = 0;
    for (const auto& candidate : candidates) {
        for (const auto& range : ranges) {
            if (range.size < 8) continue;
            const auto data = bytes.subspan(
                static_cast<std::size_t>(range.file_offset), static_cast<std::size_t>(range.size));
            for (std::size_t position = 0; position + 8 <= data.size(); position += 8) {
                if (U64(data.data() + position) != candidate.address) continue;
                const auto pool = range.va + position;
                if (!heap(pool)) {
                    ++filtered;
                    continue;
                }
                std::cout << "POOL CANDIDATE pool=0x" << std::hex << pool
                          << " chunks=0x" << candidate.address << std::dec
                          << " valid_blocks=" << candidate.blocks.size() << '\n';
                std::size_t decoded = 0;
                for (const auto& hit : hits) {
                    const auto found = std::find(candidate.blocks.begin(), candidate.blocks.end(), hit.block);
                    if (found == candidate.blocks.end()) continue;
                    const auto block_index = static_cast<std::uint32_t>(found - candidate.blocks.begin());
                    if ((hit.offset & 1U) != 0) continue;
                    const auto index = (block_index << 16) | (hit.offset / 2);
                    const auto entry = ReadVa(bytes, ranges, hit.block + hit.offset, 2 + hit.name.size());
                    if (!entry) continue;
                    const auto length = U16(entry->data()) >> 6;
                    const bool match = static_cast<std::size_t>(length) == hit.name.size() &&
                        std::memcmp(entry->data() + 2, hit.name.data(), hit.name.size()) == 0;
                    std::cout << "  index=0x" << std::hex << index << std::dec
                              << " expected=" << hit.name << " decoded=";
                    std::cout.write(reinterpret_cast<const char*>(entry->data() + 2),
                        static_cast<std::streamsize>(match ? length : 0));
                    std::cout << (match ? " MATCH" : " FAIL") << '\n';
                    decoded += match ? 1U : 0U;
                }
                if (decoded != 0) {
                    ++validated_pools;
                    std::cout << "PREDICATE PASS pool=0x" << std::hex << pool << std::dec
                              << " decoded_names=" << decoded << '\n';
                } else {
                    std::cout << "PREDICATE FAIL: no USMAP name decoded\n";
                }
            }
        }
    }
    std::cout << "SUMMARY scanned_bytes=" << scanned << " raw_hits=" << raw_hits
              << " filtered=" << filtered << " chunk_candidates=" << candidates.size()
              << " validated_pools=" << validated_pools << '\n';
}

void PrintDumpGObjectsCandidates(
    const std::filesystem::path& path,
    const std::uint64_t data_va,
    const std::uint64_t data_size) {
    const bool scan_all = data_va == 0 && data_size == 0;
    if (!scan_all && (data_va == 0 || data_size < 0x30 || data_size > 1024 * 1024 * 1024 ||
        data_size > std::numeric_limits<std::uint64_t>::max() - data_va)) {
        throw std::invalid_argument("invalid data range for GObjects scan; use 0 0 for all captured memory");
    }
    struct Layout {
        std::uint32_t objects;
        std::uint32_t max_elements;
        std::uint32_t num_elements;
        std::uint32_t max_chunks;
        std::uint32_t num_chunks;
    };
    constexpr std::array<Layout, 6> layouts{{
        {0x00, 0x10, 0x14, 0x18, 0x1C},
        {0x00, 0x0C, 0x08, 0x14, 0x10},
        {0x10, 0x00, 0x04, 0x08, 0x0C},
        {0x18, 0x10, 0x00, 0x14, 0x20},
        {0x18, 0x00, 0x14, 0x10, 0x04},
        {0x10, 0x20, 0x24, 0x04, 0x08},
    }};

    const MappedFile file(path);
    const auto bytes = file.Bytes();
    const auto streams = ReadStreams(bytes);
    const auto ranges = ReadMemoryRanges(bytes, streams);
    std::size_t candidates = 0;
    for (const auto& range : ranges) {
        if (!scan_all && (range.va >= data_va + data_size || range.va + range.size <= data_va)) {
            continue;
        }
        if (range.size < 0x30) {
            continue;
        }
        const auto data = bytes.subspan(
            static_cast<std::size_t>(range.file_offset), static_cast<std::size_t>(range.size));
        for (std::size_t position = 0; position + 0x30 <= data.size(); position += 4) {
            const auto address = range.va + position;
            if (!scan_all && (address < data_va || address >= data_va + data_size)) {
                continue;
            }
            for (std::size_t layout_index = 0; layout_index < layouts.size(); ++layout_index) {
                const auto& layout = layouts[layout_index];
                const auto objects = U64(data.data() + position + layout.objects);
                const auto max_elements = static_cast<std::int32_t>(U32(data.data() + position + layout.max_elements));
                const auto num_elements = static_cast<std::int32_t>(U32(data.data() + position + layout.num_elements));
                const auto max_chunks = static_cast<std::int32_t>(U32(data.data() + position + layout.max_chunks));
                const auto num_chunks = static_cast<std::int32_t>(U32(data.data() + position + layout.num_chunks));
                if (num_chunks > 0x14 || num_chunks < 1 || max_chunks > 0x5FF || max_chunks < 6 ||
                    num_elements <= 0x800 || max_elements <= 0x10000 || num_elements > max_elements ||
                    num_chunks > max_chunks || (max_elements % 0x10) != 0) {
                    continue;
                }
                const auto elements_per_chunk = max_elements / max_chunks;
                if ((elements_per_chunk % 0x10) != 0 || elements_per_chunk < 0x8000 || elements_per_chunk > 0x80000 ||
                    (num_elements / elements_per_chunk) + 1 != num_chunks ||
                    max_elements / elements_per_chunk != max_chunks) {
                    continue;
                }
                const auto pointers = ReadVa(bytes, ranges, objects, static_cast<std::uint64_t>(num_chunks) * 8);
                if (!pointers) {
                    continue;
                }
                bool chunks_valid = true;
                for (std::int32_t chunk = 0; chunk < num_chunks; ++chunk) {
                    const auto chunk_pointer = U64(pointers->data() + static_cast<std::size_t>(chunk) * 8);
                    if (chunk_pointer == 0 || !ReadVa(bytes, ranges, chunk_pointer, 0x80)) {
                        chunks_valid = false;
                        break;
                    }
                }
                if (!chunks_valid) {
                    continue;
                }
                const auto first_chunk = U64(pointers->data());
                const auto first_items = ReadVa(bytes, ranges, first_chunk, 6 * 0x18);
                bool index5_valid = false;
                if (first_items) {
                    const auto fifth_object = U64(first_items->data() + 5 * 0x18);
                    const auto object = ReadVa(bytes, ranges, fifth_object, 0x10);
                    index5_valid = object && static_cast<std::int32_t>(U32(object->data() + 0xC)) == 5;
                }
                std::cout << "GObjects candidate address=0x" << std::hex << address
                          << " data_RVA=0x" << address - data_va
                          << " layout=" << std::dec << layout_index
                          << " objects=0x" << std::hex << objects
                          << " first_chunk=0x" << first_chunk
                          << " max_elements=" << std::dec << max_elements
                          << " num_elements=" << num_elements
                          << " max_chunks=" << max_chunks
                          << " num_chunks=" << num_chunks
                          << " elements_per_chunk=" << elements_per_chunk
                          << " index5_valid=" << index5_valid << '\n';
                if (++candidates == 128) {
                    std::cout << "candidate cap reached\n";
                    return;
                }
            }
        }
    }
    std::cout << "validated_candidates=" << candidates << '\n';
}

void PrintDumpGObjectsCheck(const std::filesystem::path& path, const std::uint64_t objects) {
    const MappedFile file(path);
    const auto bytes = file.Bytes();
    const auto streams = ReadStreams(bytes);
    const auto ranges = ReadMemoryRanges(bytes, streams);
    const auto first = ReadVa(bytes, ranges, objects, 8);
    if (!first) {
        throw std::runtime_error("objects pointer is not captured");
    }
    const auto first_chunk = U64(first->data());
    std::cout << "objects=0x" << std::hex << objects << " first_chunk=0x" << first_chunk << std::dec << '\n';
    constexpr std::array<std::size_t, 3> strides{0x10, 0x18, 0x20};
    for (const auto stride : strides) {
        const auto items = ReadVa(bytes, ranges, first_chunk, 16 * stride);
        if (!items) {
            continue;
        }
        std::size_t valid = 0;
        std::size_t nonnull = 0;
        std::cout << "stride=0x" << std::hex << stride << std::dec << '\n';
        for (std::size_t i = 0; i < 16; ++i) {
            const auto object_pointer = U64(items->data() + i * stride);
            if (object_pointer == 0) {
                continue;
            }
            ++nonnull;
            const auto object = ReadVa(bytes, ranges, object_pointer, 0x10);
            if (!object) {
                std::cout << "  [" << i << "] object=0x" << std::hex << object_pointer << std::dec << " unreadable\n";
                continue;
            }
            const auto internal_index = static_cast<std::int32_t>(U32(object->data() + 0xC));
            valid += internal_index == static_cast<std::int32_t>(i) ? 1 : 0;
            std::cout << "  [" << i << "] object=0x" << std::hex << object_pointer
                      << " vtable=0x" << U64(object->data()) << std::dec
                      << " internal_index=" << internal_index << '\n';
        }
        std::cout << "nonnull=" << nonnull << " matching_indices=" << valid << '\n';
    }
}

void PrintDumpGNamesLazyCandidates(
    const std::filesystem::path& path,
    const std::uint64_t image_base,
    const std::uint64_t image_size) {
    if (image_base == 0 || image_size == 0 || image_size > std::numeric_limits<std::uint64_t>::max() - image_base) {
        throw std::invalid_argument("invalid image range for lazy GNames scan");
    }
    const MappedFile file(path);
    const auto bytes = file.Bytes();
    const auto streams = ReadStreams(bytes);
    const auto ranges = ReadMemoryRanges(bytes, streams);
    std::size_t pairs = 0;
    std::size_t candidates = 0;
    for (const auto& range : ranges) {
        if (range.size < 0x27) {
            continue;
        }
        const auto data = bytes.subspan(
            static_cast<std::size_t>(range.file_offset), static_cast<std::size_t>(range.size));
        for (std::size_t position = 0; position + 0x27 <= data.size(); ++position) {
            const bool r8 = data[position] == 0x4C && data[position + 1] == 0x8D && data[position + 2] == 0x05;
            const bool rcx = data[position] == 0x48 && data[position + 1] == 0x8D && data[position + 2] == 0x0D;
            if (!r8 && !rcx) {
                continue;
            }
            const auto instruction = range.va + position;
            if (instruction < image_base || instruction >= image_base + image_size) {
                continue;
            }
            const auto displacement = static_cast<std::int32_t>(U32(data.data() + position + 3));
            const auto target = static_cast<std::uint64_t>(
                static_cast<std::int64_t>(instruction + 7) + displacement);
            for (std::size_t i = 7; i <= 0x20; ++i) {
                const auto pair = position + i;
                const bool pair_match = r8
                    ? data[pair] == 0x48 && data[pair + 1] == 0x8D && data[pair + 2] == 0x0D
                    : data[pair] == 0x4C && data[pair + 1] == 0x8D && data[pair + 2] == 0x05;
                if (!pair_match) {
                    continue;
                }
                const auto pair_displacement = static_cast<std::int32_t>(U32(data.data() + pair + 3));
                const auto pair_target = static_cast<std::uint64_t>(
                    static_cast<std::int64_t>(instruction + i + 7) + pair_displacement);
                if (pair_target != target) {
                    continue;
                }
                ++pairs;
                const auto header = ReadVa(bytes, ranges, target, 0x20);
                if (!header) {
                    continue;
                }
                for (std::size_t field = 0; field < 0x20; field += 4) {
                    const auto max_chunk = static_cast<std::int32_t>(U32(header->data() + field));
                    if (max_chunk <= 0 || max_chunk > 0x10000) {
                        continue;
                    }
                    const auto chunks_start = static_cast<std::uint64_t>(field + 8 + (field % 8));
                    const auto first = ReadVa(bytes, ranges, target + chunks_start, 8);
                    if (!first) {
                        continue;
                    }
                    const auto first_chunk = U64(first->data());
                    const auto names = ReadVa(bytes, ranges, first_chunk, 20);
                    if (!names || (U16(names->data()) >> 6) != 4 ||
                        std::memcmp(names->data() + 2, "None", 4) != 0 ||
                        (U16(names->data() + 6) >> 6) != 12 ||
                        std::memcmp(names->data() + 8, "ByteProperty", 12) != 0) {
                        continue;
                    }
                    std::cout << "lazy GNames candidate instruction=0x" << std::hex << instruction
                              << " instruction_RVA=0x" << instruction - image_base
                              << " pool=0x" << target
                              << " first_chunk=0x" << first_chunk
                              << " chunks_start=0x" << chunks_start
                              << " max_chunk=" << std::dec << max_chunk << '\n';
                    ++candidates;
                }
            }
        }
    }
    std::cout << "matching_lea_pairs=" << pairs << " validated_candidates=" << candidates << '\n';
}

} // namespace arc

#endif
