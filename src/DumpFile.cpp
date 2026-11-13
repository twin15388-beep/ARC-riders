#ifdef _WIN32

#include "DumpFile.h"

#include "Names.h"
#include "PeFile.h"
#include "Process.h"
#include "Version.h"

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
#include <fstream>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
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

namespace {

// Longest contiguous captured run starting at va, capped at size. nullopt means nothing is captured at
// va; a span shorter than size means the dump only captured part of the region.
[[nodiscard]] std::optional<std::span<const std::uint8_t>> ReadCaptured(
    const std::span<const std::uint8_t> bytes,
    const std::vector<MemoryRange>& ranges,
    const std::uint64_t va,
    const std::uint64_t size) {
    if (va == 0 || size == 0 || size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        return std::nullopt;
    }
    const auto next = std::upper_bound(ranges.begin(), ranges.end(), va,
        [](const std::uint64_t address, const MemoryRange& range) { return address < range.va; });
    if (next == ranges.begin()) {
        return std::nullopt;
    }
    const auto& range = *std::prev(next);
    if (va < range.va || va - range.va >= range.size) {
        return std::nullopt;
    }
    const auto available = range.size - (va - range.va);
    const auto length = std::min(size, available);
    return std::span<const std::uint8_t>(
        bytes.data() + static_cast<std::size_t>(range.file_offset + (va - range.va)),
        static_cast<std::size_t>(length));
}

void PrintHexWindow(std::string_view label, const std::optional<std::span<const std::uint8_t>>& data) {
    std::cout << "  " << label << '=';
    if (!data) {
        std::cout << "uncaptured\n";
        return;
    }
    for (const auto byte : *data) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<std::uint32_t>(byte)
                  << std::dec << std::setfill(' ');
    }
    std::cout << " (" << data->size() << " bytes)\n";
}

struct RunHit {
    std::uint64_t base{};
    std::uint32_t runs{};
    std::vector<std::pair<std::uint32_t, std::uint32_t>> gaps;
    std::string first_text;
    std::vector<std::uint8_t> head;
};

struct PartialHit {
    std::uint64_t base{};
    std::uint32_t name_like{};
    std::vector<NameHit> hits;
    std::vector<std::pair<std::uint32_t, std::uint32_t>> gaps;
};

struct AnchorHit {
    std::uint64_t data_va{};      // first FName entry of the block
    const NameCodec* codec{};
    std::uint32_t entries{};
    std::uint32_t consumed{};
    bool capped{};
    // name -> (block 0 pool index), filled only when the block starts with the empty name. The pool
    // index is what a UObject's FName comparison field stores: (block << 16) | (entry_offset / 2).
    struct NamedIndex {
        std::string name;
        std::uint32_t ordinal{};       // pool insertion order; the usmap name index
        std::uint32_t half_offset{};   // offset / 2, the low bits of a block-0 FName number
        std::uint32_t block{};         // block index relative to the anchor (0 for the anchor block)
    };
    std::vector<NamedIndex> wanted_indices;
    // True when the region was accepted on local entry density alone, without claiming that the entries
    // follow each other back to back or that a block chain was found.
    bool dense_table{};
};

constexpr std::array<std::string_view, 9> kWantedNames{{
    "World", "Actor", "Pawn", "GameInstance", "LocalPlayer", "PlayerController",
    "PlayerCameraManager", "PersistentLevel", "RootComponent",
}};

// Hunt needles. Chosen because they are registered dynamically (not part of the engine's static EName
// table, so they cannot be reached from block 0) and because every shipped UE build registers them: if
// the pool's later blocks are present in a dump at all, one of these names lives in one of them.
constexpr std::array<std::string_view, 6> kHuntNames{{
    "PersistentLevel", "PlayerController", "RootComponent", "SceneComponent", "SkeletalMeshComponent",
    "CharacterMovementComponent",
}};

struct BackwardChain {
    std::uint32_t entries{};      // well-formed names reached in front of the start position
    std::uint32_t padding{};      // empty-name slots skipped, deliberately not counted as proof
    std::uint64_t start_va{};     // where the walk stopped, padding included
    std::uint64_t first_entry_va{};  // header of the oldest real name reached - the block start guess
    bool hit_window{};            // the walk was cut off by a bound, so start_va is only a lower bound
};

// Walks the packed FName stream backwards from one entry header. Every name in a pool block is preceded
// by a long run of entries whose declared length puts their last byte exactly at the next header (a
// single pad byte is allowed), so depth is a strong test of "is this pool content or a string literal".
// A 0x0000 header decodes as an empty name - the pool really does leave those in unused slots - so
// padding is stepped over without being counted; otherwise the zero tail of a half-used block would look
// like an infinitely deep chain.
[[nodiscard]] BackwardChain WalkBackward(
    const std::span<const std::uint8_t> win,
    const std::uint64_t win_va,
    const std::uint64_t at_header,
    const std::uint32_t cap) {
    BackwardChain out;
    out.start_va = at_header;
    if (at_header <= win_va + 3 || at_header - win_va >= win.size()) {
        return out;
    }
    const auto at_end = win_va + win.size();
    const auto header_at = [&](const std::uint64_t va) {
        return va >= win_va && va + 2 <= at_end ? U16(win.data() + (va - win_va)) : 0U;
    };
    auto at = at_header;
    out.first_entry_va = at;
    while (out.entries + out.padding < cap) {
        // Both bounds below assume `at` is inside the window; without this the candidate scan
        // underflows past win_va and "walks" through a wrapped address.
        if (at < win_va + 8) {
            out.hit_window = true;
            break;
        }
        // Long zero runs are the pool's unused slots, not a chain. Stepping over kilometres of padding
        // would let a hit claim a block start in an unrelated region, so stop and say so instead.
        if (out.padding >= 0x400) {
            out.hit_window = true;
            break;
        }
        const auto floor_va = std::max<std::uint64_t>(win_va + 4, at - 0x804);
        bool stepped = false;
        for (auto q = at - 2; q > floor_va; q -= 2) {
            const auto header = header_at(q);
            const std::uint64_t len = header >> 6;
            if (len == 0) {
                if (q + 2 == at) {
                    at = q;
                    ++out.padding;
                    stepped = true;
                    break;
                }
                continue;
            }
            // The entry spans [q + 2, q + 2 + len); the next header starts at that end or one byte
            // later. kNameCodecPacked has no wide form for this build (its wide bit position is outside
            // the 16-bit header), and accepting a 2*len variant instead lets the walk chain through random
            // bytes - measured: a junk region produced 600 "entries". Strictness is the point here.
            const auto entry_end = q + 2 + len;
            if (entry_end != at && entry_end + 1 != at) {
                continue;
            }
            const auto name_va = q + 2;
            const auto name_end = std::min<std::uint64_t>(at, name_va + len);
            if (name_va >= at_end || name_end > at_end) {
                continue;
            }
            bool printable = true;
            for (auto b = name_va; b < name_end; ++b) {
                if (!IsNameCharacter(static_cast<char>(win[b - win_va]))) {
                    printable = false;
                    break;
                }
            }
            if (!printable) {
                continue;
            }
            at = q;
            ++out.entries;
            out.first_entry_va = at;  // overwritten each step, so it ends up at the oldest name
            stepped = true;
            break;
        }
        if (!stepped) {
            break;
        }
    }
    out.start_va = at;
    return out;
}

} // namespace

// Recovers the FName pool from a block whose entry stream can actually be decoded, instead of searching
// for a global by shape. Block 0 starts with the empty name, so locating that string and walking
// forward is enough to identify the block; the block chain then yields every name.
void PrintDumpFNameBlocks(
    const std::filesystem::path& path,
    const std::uint64_t image_base,
    const std::uint64_t image_size,
    const std::uint64_t anchor_data_va,
    const std::uint32_t block_size,
    const std::uint32_t min_entries,
    const std::size_t max_blocks,
    const std::string_view marker_list,
    const std::filesystem::path& names_out) {
    if (image_base == 0 || image_size == 0 || image_size > std::numeric_limits<std::uint64_t>::max() - image_base) {
        throw std::invalid_argument("invalid image range for FName block scan");
    }
    if (block_size < 0x1000 || block_size > 0x1000000) {
        throw std::invalid_argument("block_size must be 0x1000..0x1000000");
    }
    if (min_entries < 4) {
        throw std::invalid_argument("min_entries must be at least 4");
    }
    if (max_blocks == 0 || max_blocks > 4096) {
        throw std::invalid_argument("max_blocks must be 1..4096");
    }
    // One marker is not a search: the previous run proved that no captured region begins with "None"
    // under either carried codec, so a single-marker scan cannot tell a wrong entry header apart from a
    // pool this dump never captured. Every hit of every marker is checked, and the per-marker counts are
    // reported, because "0 hits for all six engine-core names" is a coverage fact, not a codec fact.
    std::vector<std::string> markers;
    {
        std::string current;
        for (const char character : marker_list) {
            if (character == ',' || character == ' ' || character == ';') {
                if (!current.empty()) {
                    markers.push_back(current);
                    current.clear();
                }
            } else {
                current.push_back(character);
            }
        }
        if (!current.empty()) {
            markers.push_back(current);
        }
    }
    if (markers.empty()) {
        markers = {"None", "ByteProperty", "IntProperty", "FloatProperty", "ObjectProperty", "Class"};
    }
    std::vector<std::uint64_t> marker_hits_for(markers.size(), 0);
    constexpr std::array<std::uint32_t, 6> kProbeSizes{{0x8, 0x10, 0x18, 0x20, 0x28, 0x30}};
    constexpr std::size_t max_anchors = 16;
    constexpr std::size_t entry_cap = 8192;
    constexpr std::size_t referrer_cap = 128;

    const MappedFile file(path);
    const auto bytes = file.Bytes();
    const auto ranges = ReadMemoryRanges(bytes, ReadStreams(bytes));
    const auto read = [&](const std::uint64_t va, const std::uint64_t size) {
        return ReadCaptured(bytes, ranges, va, size);
    };
    const auto image_end = image_base + image_size;
    const auto in_image = [&](const std::uint64_t va) { return va >= image_base && va < image_end; };

    std::cout << "build=" << kBuildStamp << "\nblock_size=0x" << std::hex << block_size
              << std::dec << " min_entries=" << min_entries << " markers=";
    for (std::size_t index = 0; index < markers.size(); ++index) {
        std::cout << (index == 0 ? "\"" : "\",\"") << markers[index];
    }
    std::cout << "\" captured_ranges=" << ranges.size() << '\n';

    std::vector<AnchorHit> anchors;
    // A supplied anchor that decodes nothing is still worth reporting (it is evidence about that VA),
    // but it must not suppress marker discovery or the layout fallback: only a dense stream does that.
    std::size_t validated_anchors = 0;
    std::vector<PartialHit> partials;  // best decoders that missed the strict gate, for layout reading
    std::vector<RunHit> run_hits;      // header-format independent candidates, ranked by string density
    std::vector<AnchorHit> dense_tables;
    constexpr std::size_t max_tables = 8;
    constexpr std::size_t max_partials = 8;
    constexpr std::uint32_t layout_window = 0x400;
    std::set<std::uint64_t> seen_bases;
    std::uint64_t scanned_bytes = 0;
    std::uint64_t marker_hits = 0;
    std::uint64_t region_probes = 0;
    if (anchor_data_va != 0) {
        const auto block = read(anchor_data_va, block_size);
        if (!block) {
            std::cout << "anchor=0x" << std::hex << anchor_data_va << std::dec
                      << " captured=no (this dump does not contain the region; falling back to marker"
                      << " discovery)\n";
        } else {
        const auto walk = DetectNameBlock(*block, kNameCodecCandidates, "", min_entries, entry_cap);
        if (walk.codec == nullptr) {
            std::cout << "note: the supplied VA does not decode as a dense name stream from offset 0;"
                         " continuing with the measured codec for the chain only\n";
        }
        AnchorHit anchor{
            anchor_data_va,
            walk.codec ? walk.codec : &kNameCodecMeasured,
            static_cast<std::uint32_t>(walk.entries.size()),
            walk.consumed,
            walk.cap_reached,
            {},
        };
        if (!walk.entries.empty()) {
            std::uint32_t ordinal = 0;
            for (const auto& entry : walk.entries) {
                for (const auto wanted : kWantedNames) {
                    if (entry.text == wanted) {
                        anchor.wanted_indices.push_back(
                            {std::string(wanted), ordinal, entry.offset / 2U, 0});
                    }
                }
                ++ordinal;
            }
        }
        if (anchor.entries >= min_entries) {
            ++validated_anchors;
        }
        anchors.push_back(std::move(anchor));
        }
    }
    const std::size_t supplied_anchors = anchors.size();
    if (validated_anchors == 0) {
        // Each engine-core name is searched separately, so "the pool is not captured here" and "the
        // entry header is different" produce different reports.
        for (std::size_t marker_index = 0; marker_index < markers.size() && validated_anchors == 0; ++marker_index) {
            const std::string& expected_first = markers[marker_index];
            // The raw name is searched without a trailing zero: the pool's packed entries have no
            // terminator at all, and demanding one is what made the last two full passes miss the pool
            // that dump-read shows in plaintext at 0xa6f10000. Candidates pay for the looser needle
            // through the chain validation below, which is the actual gate.
            std::vector<std::uint8_t> needle;
            needle.assign(expected_first.begin(), expected_first.end());
            const auto searcher = std::boyer_moore_searcher(needle.begin(), needle.end());
            for (const auto& range : ranges) {

                scanned_bytes += range.size;
                if (range.size < needle.size()) {
                    continue;
                }
                const auto data = bytes.subspan(
                    static_cast<std::size_t>(range.file_offset), static_cast<std::size_t>(range.size));
                for (auto current = data.begin(); current != data.end();) {
                    const auto found = std::search(current, data.end(), searcher);
                    if (found == data.end()) {
                        break;
                    }
                    ++marker_hits;
                    ++marker_hits_for[marker_index];
                    const auto string_at = static_cast<std::size_t>(found - data.begin());
                    // All three codecs read the string at offset 2 from the header, so one base is
                    // computed per hit and every codec is tried on that base. Deduplicating the base
                    // before probing let the first codec's failure swallow the second codec's success.
                    constexpr std::size_t kStringOff = 2;
                    if (string_at >= kStringOff) {
                        const auto base = range.va + string_at - kStringOff;
                        if (base >= 0x10000 && seen_bases.insert(base).second) {
                            const auto block = read(base, block_size);
                            if (block && block->size() >= block_size / 2) {
                                ++region_probes;
                                const NameCodec* winner = nullptr;
                                NameBlockWalk best_walk;
                                for (const auto& codec : kNameCodecCandidates) {
                                    auto walk = WalkNameBlock(*block, codec, entry_cap);
                                    if (walk.entries.empty() ||
                                        walk.entries.front().text != expected_first ||
                                        walk.entries.size() < min_entries) {
                                        continue;
                                    }
                                    winner = &codec;
                                    best_walk = std::move(walk);
                                    break;
                                }
                                if (winner != nullptr) {
                                    AnchorHit anchor{
                                        base, winner, static_cast<std::uint32_t>(best_walk.entries.size()),
                                        best_walk.consumed, best_walk.cap_reached, {},
                                    };
                                    std::uint32_t ordinal = 0;
                                    for (const auto& entry : best_walk.entries) {
                                        for (const auto wanted : kWantedNames) {
                                            if (entry.text == wanted) {
                                                anchor.wanted_indices.push_back(
                                                    {std::string(wanted), ordinal, entry.offset / 2U, 0});
                                            }
                                        }
                                        ++ordinal;
                                    }
                                    if (anchor.entries >= min_entries) {
                                        ++validated_anchors;
                                    }
                                    anchors.push_back(std::move(anchor));
                                } else {
                                    const std::size_t span =
                                        std::min<std::size_t>(layout_window, block->size());
                                    auto hits = FindAsciiRuns(block->first(span), 3, 512);
                                    if (hits.size() >= 8) {
                                        RunHit candidate;
                                        candidate.base = base;
                                        candidate.runs = static_cast<std::uint32_t>(hits.size());
                                        candidate.gaps = GapHistogram(hits);
                                        candidate.first_text = hits.front().text;
                                        const auto head_span = std::min<std::size_t>(0x40, block->size());
                                        candidate.head.assign(block->begin(), block->begin() + head_span);
                                        const auto place = std::find_if(run_hits.begin(), run_hits.end(),
                                            [&candidate](const RunHit& other) {
                                                return other.base == candidate.base;
                                            });
                                        if (place == run_hits.end()) {
                                            run_hits.push_back(std::move(candidate));
                                        } else if (candidate.runs > place->runs) {
                                            *place = std::move(candidate);
                                        }
                                        std::sort(run_hits.begin(), run_hits.end(),
                                            [](const RunHit& left, const RunHit& right) {
                                                return left.runs > right.runs;
                                            });
                                        if (run_hits.size() > max_partials) {
                                            run_hits.pop_back();
                                        }
                                    }
                                    // A region that chains hundreds of packed entries is a name table even
                                    // when the searched marker is not its first entry. Acceptance is the
                                    // chained walk, never a scatter count: the NUL-codec scatter produced
                                    // 257 "tables" in random module code, which is pure noise.
                                    const auto dense = MeasureNameBlock(*block, kNameCodecPacked, 8192);
                                    if (dense.entries >= min_entries) {
                                        AnchorHit table;
                                        table.data_va = base;
                                        table.codec = &kNameCodecPacked;
                                        table.entries = dense.entries;
                                        table.consumed = dense.consumed;
                                        table.capped = dense.cap_reached;
                                        table.dense_table = true;
                                        const auto wanted_walk =
                                            WalkNameBlock(*block, kNameCodecPacked, 8192);
                                        std::uint32_t ordinal = 0;
                                        for (const auto& entry : wanted_walk.entries) {
                                            for (const auto wanted : kWantedNames) {
                                                if (entry.text == wanted) {
                                                    table.wanted_indices.push_back(
                                                        {std::string(wanted), ordinal, entry.offset / 2U, 0});
                                                }
                                            }
                                            ++ordinal;
                                        }
                                        const auto place = std::find_if(dense_tables.begin(),
                                            dense_tables.end(), [&table](const AnchorHit& other) {
                                                return other.data_va == table.data_va;
                                            });
                                        if (place == dense_tables.end()) {
                                            dense_tables.push_back(std::move(table));
                                        } else if (table.entries > place->entries) {
                                            *place = std::move(table);
                                        }
                                    }
                                    hits = FindNameLikeEntries(block->first(span), kNameCodecPacked, 512);
                                    if (hits.size() >= 4) {
                                        PartialHit partial;
                                        partial.base = base;
                                        partial.name_like = static_cast<std::uint32_t>(hits.size());
                                        partial.gaps = GapHistogram(hits);
                                        if (hits.size() > 12) {
                                            hits.resize(12);
                                        }
                                        partial.hits = std::move(hits);
                                        const auto place = std::find_if(partials.begin(), partials.end(),
                                            [&partial](const PartialHit& other) {
                                                return other.base == partial.base;
                                            });
                                        if (place == partials.end()) {
                                            partials.push_back(std::move(partial));
                                            std::sort(partials.begin(), partials.end(),
                                                [](const PartialHit& left, const PartialHit& right) {
                                                    return left.name_like > right.name_like;
                                                });
                                            if (partials.size() > max_partials) {
                                                partials.pop_back();
                                            }
                                        } else if (partial.name_like > place->name_like) {
                                            *place = std::move(partial);
                                            std::sort(partials.begin(), partials.end(),
                                                [](const PartialHit& left, const PartialHit& right) {
                                                    return left.name_like > right.name_like;
                                                });
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if (anchors.size() >= max_anchors + supplied_anchors) {
                        break;
                    }
                    current = found + 1;
                }
                if (anchors.size() >= max_anchors + supplied_anchors) {
                    break;
                }
            }
        }

        std::cout << "discovery scanned_bytes=" << scanned_bytes << " marker_hits=" << marker_hits << " (";
        for (std::size_t index = 0; index < markers.size(); ++index) {
            std::cout << (index == 0 ? "" : ",") << markers[index] << "=" << marker_hits_for[index];
        }
        std::cout << ") region_probes=" << region_probes
                  << " discovered_anchors=" << anchors.size() - supplied_anchors
                  << " dense=" << validated_anchors
                  << (anchors.size() >= max_anchors + supplied_anchors ? " (anchor cap reached)" : "")
                  << '\n';
    }
    // Every captured pointer to a candidate region: an in-image hit is a GNames candidate with a stable
    // RVA, a heap hit is only useful inside this dump.
    const auto SweepReferrers = [&](const std::vector<std::uint64_t>& wanted,
                                    std::vector<std::uint64_t>* out_vas = nullptr) {
        auto targets = wanted;
        std::sort(targets.begin(), targets.end());
        targets.erase(std::unique(targets.begin(), targets.end()), targets.end());
        if (targets.empty()) {
            return std::pair<std::size_t, std::size_t>{0, 0};
        }
        const auto target_lo = targets.front();
        const auto target_hi = targets.back();
        std::size_t image_hits = 0;
        std::size_t heap_hits = 0;
        for (const auto& range : ranges) {
            if (range.size < 8) {
                continue;
            }
            const auto data = bytes.subspan(
                static_cast<std::size_t>(range.file_offset), static_cast<std::size_t>(range.size));
            for (std::size_t position = 0; position + 8 <= data.size(); position += 8) {
                const auto value = U64(data.data() + position);
                if (value < target_lo || value > target_hi) {
                    continue;
                }
                if (!std::binary_search(targets.begin(), targets.end(), value)) {
                    continue;
                }
                const auto va = range.va + position;
                std::cout << "  referrer=0x" << std::hex << va << " -> 0x" << value << std::dec
                          << (in_image(va) ? " [image]" : " [heap]");
                if (out_vas != nullptr) {
                    out_vas->push_back(va);
                }
                if (in_image(va)) {
                    std::cout << " RVA=0x" << std::hex << (va - image_base) << std::dec;
                    ++image_hits;
                } else {
                    ++heap_hits;
                }
                std::cout << '\n';
                if (image_hits + heap_hits >= referrer_cap) {
                    return std::pair{image_hits, heap_hits};
                }
            }
        }
        return std::pair{image_hits, heap_hits};
    };

    for (const auto& anchor : anchors) {
        std::cout << "anchor block_data=0x" << std::hex << anchor.data_va << std::dec
                  << " codec=" << anchor.codec->label << " entries=" << anchor.entries
                  << (anchor.capped ? "+" : "") << " consumed=0x" << std::hex << anchor.consumed
                  << std::dec << '\n';
    }
    if (!dense_tables.empty()) {
        std::cout << "\ndense name tables accepted on local entry density (" << dense_tables.size()
                  << "): the entries decode, but they are not back to back, so no block chain is claimed"
                  " and only the pointers below are offered as candidates\n";
        std::sort(dense_tables.begin(), dense_tables.end(), [](const AnchorHit& left, const AnchorHit& right) {
            return left.entries > right.entries;
        });
        // Several markers hit inside one region, so the candidates overlap. Keep the widest span of each
        // region only, otherwise the report repeats the same table with different offsets and the reader
        // cannot tell how many distinct tables the dump really holds.
        {
            std::vector<AnchorHit> kept;
            for (const auto& table : dense_tables) {
                const auto lo = table.data_va;
                const auto hi = table.data_va + (table.consumed != 0 ? table.consumed : 1U);
                const auto overlaps = [lo, hi](const AnchorHit& other) {
                    const auto other_lo = other.data_va;
                    const auto other_hi = other.data_va + (other.consumed != 0 ? other.consumed : 1U);
                    return lo < other_hi && other_lo < hi;
                };
                if (std::none_of(kept.begin(), kept.end(), overlaps)) {
                    kept.push_back(table);
                }
            }
            dense_tables.swap(kept);
        }
        if (dense_tables.size() > max_tables) {
            dense_tables.resize(max_tables);
        }
        // One merged pointer pass for every table: a full sweep of the captured ranges is the single
        // most expensive operation in this command, so per-table sweeps would multiply the runtime.
        std::vector<std::uint64_t> targets;
        std::unordered_map<std::uint64_t, std::size_t> owner;
        for (std::size_t i = 0; i < dense_tables.size(); ++i) {
            targets.push_back(dense_tables[i].data_va);
            owner.emplace(dense_tables[i].data_va, i);
            for (const auto size : kProbeSizes) {
                if (dense_tables[i].data_va > size) {
                    targets.push_back(dense_tables[i].data_va - size);
                    owner.emplace(dense_tables[i].data_va - size, i);
                }
            }
        }
        std::sort(targets.begin(), targets.end());
        targets.erase(std::unique(targets.begin(), targets.end()), targets.end());
        std::vector<std::pair<std::size_t, std::size_t>> ref_counts(dense_tables.size(), {0, 0});
        if (!targets.empty()) {
            const auto target_lo = targets.front();
            const auto target_hi = targets.back();
            std::size_t total = 0;
            for (const auto& range : ranges) {
                if (range.size < 8 || total >= referrer_cap) {
                    continue;
                }
                const auto data = bytes.subspan(
                    static_cast<std::size_t>(range.file_offset), static_cast<std::size_t>(range.size));
                for (std::size_t position = 0; position + 8 <= data.size(); position += 8) {
                    const auto value = U64(data.data() + position);
                    if (value < target_lo || value > target_hi ||
                        !std::binary_search(targets.begin(), targets.end(), value)) {
                        continue;
                    }
                    const auto va = range.va + position;
                    const auto which = owner.find(value);
                    if (which != owner.end()) {
                        std::cout << "  table[" << which->second << "] referrer=0x" << std::hex << va
                                  << " -> 0x" << value << std::dec
                                  << (in_image(va) ? " [image]" : " [heap]");
                        if (in_image(va)) {
                            std::cout << " RVA=0x" << std::hex << (va - image_base) << std::dec;
                            ++ref_counts[which->second].first;
                        } else {
                            ++ref_counts[which->second].second;
                        }
                        std::cout << '\n';
                    }
                    if (++total >= referrer_cap) {
                        break;
                    }
                }
            }
        }
        for (std::size_t i = 0; i < dense_tables.size(); ++i) {
            const auto& table = dense_tables[i];
            std::cout << "  table[" << i << "] base=0x" << std::hex << table.data_va << std::dec
                      << " entries=" << table.entries << (table.capped ? "+" : "") << " span=0x"
                      << std::hex << table.consumed << std::dec << " referrers image="
                      << ref_counts[i].first << " heap=" << ref_counts[i].second << '\n';
            for (const auto& wi : table.wanted_indices) {
                std::cout << "    wanted name \"" << wi.name << "\" ordinal=" << wi.ordinal
                          << " entry_offset=0x" << std::hex << (wi.half_offset * 2U) << std::dec << '\n';
            }
            std::cout << "  measure it: dump-fname-layout <dmp> 0x" << std::hex << table.data_va
                      << std::dec << " 0x800 512\n";
        }
    }
    if (validated_anchors == 0) {
        for (const auto& run : run_hits) {
            std::cout << "  ascii_run block_base=0x" << std::hex << run.base << std::dec << " runs="
                      << run.runs << " string_to_string=";
            for (std::size_t i = 0; i < run.gaps.size() && i < 4; ++i) {
                std::cout << (i == 0 ? "0x" : ",0x") << run.gaps[i].first << "x" << run.gaps[i].second;
            }
            std::cout << " first=\"" << run.first_text << "\"\n";
            PrintHexWindow("    head", std::span<const std::uint8_t>(run.head));
        }
        std::cout << "\nlayout of the best " << partials.size()
                  << " regions (strict walk rejected, so the entry stride differs from the model):\n";
        for (const auto& partial : partials) {
            std::cout << "  partial block_base=0x" << std::hex << partial.base << std::dec
                      << " name_like_entries=" << partial.name_like << " gaps=";
            for (std::size_t i = 0; i < partial.gaps.size() && i < 6; ++i) {
                std::cout << (i == 0 ? "" : ",") << "0x" << std::hex << partial.gaps[i].first << std::dec
                          << "x" << partial.gaps[i].second;
            }
            std::cout << "\n";
            for (const auto& hit : partial.hits) {
                std::cout << "    entry=0x" << std::hex << hit.offset << std::dec << " len=" << hit.length
                          << (hit.wide ? " wide" : " ansi") << " \"" << hit.text << "\"\n";
            }
        }
        std::cout << "  read one of these regions in full with: dump-fname-layout <dmp> <block_base> "
                  << layout_window << " 512\n";
        std::cout << "SUMMARY build=" << kBuildStamp << " anchors=" << anchors.size() - supplied_anchors
                  << " validated_pools=0 (supplied anchor: " << (supplied_anchors ? "decoded no dense stream" : "not searched")
                  << ")\n";
        std::cout << "next: no block whose first entry decodes as \"" << markers.front() << "\" with "
                  << min_entries << "+ entries exists in the captured memory. Dump the bytes around a"
                     " known name (dump-read on the block VA from the previous notes) to read the real"
                     " entry header instead of assuming shift 6 or the stock layout.\n";
        return;
    }

    std::size_t validated_pools = 0;
    for (auto& anchor : anchors) {
        std::cout << "\n=== anchor block_data=0x" << std::hex << anchor.data_va << std::dec << " ===\n";
        if (anchor.data_va > 0x40) {
            PrintHexWindow("bytes_before_block", read(anchor.data_va - 0x40, 0x40));
        }
        std::vector<std::uint32_t> header_candidates;
        header_candidates.assign(kProbeSizes.begin(), kProbeSizes.end());
        const auto probes = ProbeBlockHeaders(
            read, anchor.data_va, block_size, *anchor.codec, min_entries, header_candidates);
        std::uint32_t header_size = 0;
        for (const auto& probe : probes) {
            std::cout << "  probe header=0x" << std::hex << probe.header_va << std::dec
                      << " header_size=0x" << std::hex << probe.header_size << std::dec
                      << " captured=" << probe.header_captured << " next=0x" << std::hex << probe.next
                      << std::dec << " next_is_block=" << probe.next_is_block
                      << " next_entries=" << probe.next_entries << '\n';
            if (header_size == 0 && probe.next_is_block) {
                header_size = probe.header_size;
            }
        }

        NameBlockChain chain;
        if (header_size != 0) {
            chain = FollowNameBlocks(read, anchor.data_va, header_size, block_size, *anchor.codec,
                min_entries, entry_cap, max_blocks);
            std::cout << "  chain header_size=0x" << std::hex << chain.header_size << std::dec
                      << " blocks=" << chain.blocks.size() << " entries=" << chain.total_entries
                      << (chain.total_capped ? "+" : "") << " stop=\"" << chain.stop_reason << "\"\n";
            for (std::size_t i = 0; i < chain.blocks.size() && i < 32; ++i) {
                const auto& node = chain.blocks[i];
                std::cout << "    block[" << i << "] data=0x" << std::hex << node.data_va << " header=0x"
                          << node.header_va << " next=0x" << node.next << std::dec << " entries="
                          << node.stats.entries << " consumed=0x" << std::hex << node.stats.consumed
                          << std::dec << " first=\"" << node.stats.first_name << "\" last=\""
                          << node.stats.last_name << "\"\n";
            }
            if (chain.blocks.size() > 32) {
                std::cout << "    ... " << (chain.blocks.size() - 32) << " more blocks\n";
            }
        } else {
            std::cout << "  no captured qword in front of the block points at another decodable block;"
                         " the pool is not a plain FBlockInfo chain in this build\n";
        }

        // Why the chained walk stopped inside a half-empty block is the one fact that decides the
        // rest of the layout work. Print the exact bytes at the stop, then look forward for the next
        // position from which at least four entries chain - the distance and the skipped bytes name
        // whatever entry form the codec does not model yet (a wide name is the prime suspect).
        std::size_t resync_gap = 0;
        std::vector<std::pair<std::uint32_t, std::string>> resync_names;
        {
            const auto win = read(anchor.data_va, block_size);
            if (win && anchor.entries != 0 && anchor.consumed != 0 && anchor.consumed < win->size()) {
                const std::size_t stop = anchor.consumed;
                const auto from = stop > 0x20 ? stop - 0x20 : std::size_t{0};
                const auto to = std::min<std::size_t>(stop + 0x60, win->size());
                std::cout << "  stop context (walk ended at +" << std::hex << stop << std::dec
                          << "; bytes before/after):\n";
                PrintHexWindow("stop", std::span<const std::uint8_t>(win->data() + from, to - from));
                for (std::size_t off = stop + 2; off + 0x40 <= win->size(); off += 2) {
                    const auto probe = WalkNameBlock({win->data() + off, win->size() - off}, *anchor.codec, 8);
                    if (probe.entries.size() < 4) {
                        continue;
                    }
                    resync_gap = off - stop;
                    for (const auto& entry : probe.entries) {
                        resync_names.emplace_back(entry.offset, entry.text);
                    }
                    break;
                }
                if (resync_names.empty()) {
                    std::cout << "  resync: no 4-entry chain restarts within this block after the stop -"
                                 " the rest of the block is not packed names, so block 0 ends here and"
                                 " later blocks live elsewhere\n";
                } else {
                    std::cout << "  resync at +" << std::hex << (stop + resync_gap) << " skipped=0x"
                              << resync_gap << std::dec << " names:";
                    for (const auto& [name_off, name] : resync_names) {
                        std::cout << " \"" << name << "\"";
                    }
                    std::cout << "\n  the skipped bytes are one or more entries in a form the packed"
                                 " codec does not model; ordinals past the stop are lower bounds\n";
                }
            }
        }

        // Second allocator shape: blocks laid out back to back instead of chained through headers.
        // When the winning codec is the packed pool form, also test half the configured step: real
        // FNamePool blocks are 0x10000 apart while the scan probes a coarser grid.
        std::uint64_t stride_entries = 0;
        std::size_t stride_blocks = 0;
        std::uint64_t stride_step = block_size;
        if (anchor.codec == &kNameCodecPacked && block_size >= 0x20000) {
            stride_step = 0x10000;
        }
        std::uint32_t running_ordinal = anchor.entries;  // block 0 is walked fully for the anchor
        for (std::size_t index = 1; index < max_blocks; ++index) {
            const auto step = stride_step;
            if (anchor.data_va > std::numeric_limits<std::uint64_t>::max() - index * step) {
                break;
            }
            const auto data_va = anchor.data_va + index * step;
            const auto block = read(data_va, block_size);
            if (!block || block->size() < block_size) {
                break;
            }
            const auto walk = DetectNameBlock(*block, kNameCodecCandidates, "", min_entries, entry_cap);
            if (walk.codec == nullptr) {
                break;
            }
            // Pool ordinals are insertion order across blocks, so the wanted names found in a stride
            // block get anchor.entries + everything counted before it. The USMAP stores exactly these
            // numbers as name indices.
            std::uint32_t local = 0;
            for (const auto& entry : walk.entries) {
                for (const auto wanted : kWantedNames) {
                    if (entry.text == wanted) {
                        anchor.wanted_indices.push_back(
                            {std::string(wanted), running_ordinal + local, entry.offset / 2U,
                             static_cast<std::uint32_t>(index)});
                    }
                }
                ++local;
            }
            ++stride_blocks;
            stride_entries += walk.entries.size();
            running_ordinal += walk.entries.size();
        }
        if (!anchor.wanted_indices.empty()) {
            std::cout << "  wanted names with pool ordinals (ordinal is the usmap name index; "
                          "half_offset is the low 16 bits of the FName number, (block << 16) | half):\n";
            std::sort(anchor.wanted_indices.begin(), anchor.wanted_indices.end(),
                [](const AnchorHit::NamedIndex& l, const AnchorHit::NamedIndex& r) {
                    return l.ordinal < r.ordinal;
                });
            for (const auto& wi : anchor.wanted_indices) {
                std::cout << "    " << wi.name << " block=" << wi.block << " ordinal=" << wi.ordinal
                          << " half_offset=0x" << std::hex << wi.half_offset << std::dec << '\n';
            }
        }
        std::cout << "  stride_blocks=" << stride_blocks << " stride_entries=" << stride_entries
                  << " (further blocks at block_size intervals that still decode as name streams)\n";

        // "stride_blocks=0" has three very different causes, and only one of them is about the allocator:
        // the dump never captured the page, the page is zero-filled (a region the writer skipped or that
        // was never written), or the pool continues with something the codec does not model. Printing the
        // cause per page turns the negative result into a statement about the dump.
        std::cout << "  page map around the anchor (each 0x10000 slot: uncaptured / zero-filled /"
                     " non-zero):\n";
        for (int k = -4; k <= 24; ++k) {
            if (k == 0) {
                continue;
            }
            const auto page_va = static_cast<std::uint64_t>(
                static_cast<std::int64_t>(anchor.data_va) + static_cast<std::int64_t>(k) * 0x10000);
            const auto head = read(page_va, 0x1000);
            std::cout << "    " << (k < 0 ? "-" : "+") << (k < 0 ? -k : k) << "] 0x" << std::hex
                      << page_va << std::dec << (in_image(page_va) ? " [image]" : " [heap]") << " ";
            if (!head || head->size() < 0x1000) {
                std::cout << "uncaptured\n";
                continue;
            }
            std::uint64_t nonzero = 0;
            for (const auto byte : *head) {
                nonzero += byte != 0 ? 1 : 0;
            }
            if (nonzero == 0) {
                std::cout << "zero-filled (first 4 KiB)\n";
                continue;
            }
            std::cout << "non-zero " << nonzero << "/0x1000";
            const auto block = read(page_va, block_size);
            if (block) {
                const auto walk = DetectNameBlock(*block, kNameCodecCandidates, "", min_entries, entry_cap);
                if (walk.codec != nullptr) {
                    std::cout << " NAME STREAM entries=" << walk.entries.size() << " first=\""
                              << (walk.entries.empty() ? "" : walk.entries.front().text) << "\"";
                } else {
                    std::cout << " no name stream; bytes=";
                    for (std::size_t b = 0; b < 24 && b < block->size(); ++b) {
                        std::cout << std::hex << std::setw(2) << std::setfill('0')
                                  << static_cast<int>((*block)[b]);
                    }
                    std::cout << std::setfill(' ') << std::dec;
                }
            }
            std::cout << '\n';
        }

        // Every captured pointer to the block: an in-image hit is a GNames candidate with a stable RVA,
        // a heap hit is only useful inside this dump.
        std::size_t image_refs = 0;
        std::size_t heap_refs = 0;
        std::vector<std::uint64_t> referrer_vas;
        {
            std::vector<std::uint64_t> targets{anchor.data_va};
            for (const auto size : kProbeSizes) {
                if (anchor.data_va > size) {
                    targets.push_back(anchor.data_va - size);
                }
            }
            for (const auto& node : chain.blocks) {
                targets.push_back(node.header_va);
                targets.push_back(node.data_va);
            }
            std::tie(image_refs, heap_refs) = SweepReferrers(targets, &referrer_vas);
        }

        // The full sweep printed one pointer per referrer line; the pool's block table sits right
        // around those pointers. Every qword in a window around each referrer that opens a 4+ entry
        // packed stream is a block pointer; a maximal run of such qwords at stride 0x8 IS the block
        // array, and walking it in array order is the only ordinal-correct way to cover the pool.
        std::vector<std::uint64_t> pool_blocks;
        if (!referrer_vas.empty() && anchor.codec != nullptr) {
            std::cout << "  pointer-array hunt around " << referrer_vas.size() << " referrer(s):\n";
            std::set<std::uint64_t> probed;
            for (std::size_t ri = 0; ri < referrer_vas.size() && ri < 8; ++ri) {
                const auto r = referrer_vas[ri];
                if (r < 0x1000) {
                    continue;
                }
                const auto win = read(r - 0x100, 0x1000);
                if (!win || win->size() < 0x200) {
                    std::cout << "    referrer=0x" << std::hex << r << std::dec << " window uncaptured\n";
                    continue;
                }
                std::vector<std::pair<std::size_t, std::uint64_t>> good;
                for (std::size_t pos = 0; pos + 8 <= win->size(); pos += 8) {
                    const auto q = U64(win->data() + pos);
                    if (q < 0x10000 || !probed.insert(q).second) {
                        continue;
                    }
                    const auto probe = read(q, 0x100);
                    if (!probe || probe->size() < 0x40) {
                        continue;
                    }
                    const auto w = WalkNameBlock(*probe, *anchor.codec, 8);
                    if (w.entries.size() >= 4) {
                        good.emplace_back(pos, q);
                    }
                }
                std::size_t best_len = 0;
                std::size_t best_at = 0;
                for (std::size_t i = 0; i < good.size();) {
                    std::size_t j = i + 1;
                    while (j < good.size() && good[j].first == good[i].first + (j - i) * 8) {
                        ++j;
                    }
                    if (j - i > best_len) {
                        best_len = j - i;
                        best_at = i;
                    }
                    i = j == i ? i + 1 : j;
                }
                const auto rv = r - 0x100;
                std::cout << "    referrer=0x" << std::hex << r << " window=0x" << rv << std::dec
                          << " block_like_ptrs=" << good.size() << " longest_stride8_run=" << best_len
                          << '\n';
                if (best_len < 2) {
                    continue;
                }
                const auto array_va = rv + good[best_at].first;
                std::cout << "    block_array=0x" << std::hex << array_va << std::dec << " count="
                          << best_len << (in_image(array_va)
                                              ? " [image] - RVA candidate for the FNamePool block table"
                                              : " [heap]")
                          << '\n';
                pool_blocks.clear();
                for (std::size_t i = 0; i < best_len; ++i) {
                    pool_blocks.push_back(good[best_at + i].second);
                }
                std::uint32_t running = 0;
                std::vector<std::pair<std::string, std::uint32_t>> pool_wanted;
                for (std::size_t i = 0; i < pool_blocks.size() && i < 64; ++i) {
                    const auto blk = read(pool_blocks[i], block_size);
                    if (!blk) {
                        std::cout << "      block[" << i << "] at 0x" << std::hex << pool_blocks[i]
                                  << std::dec << " uncaptured\n";
                        break;
                    }
                    const auto walk = WalkNameBlock(*blk, *anchor.codec, entry_cap);
                    std::uint32_t local = 0;
                    for (const auto& entry : walk.entries) {
                        for (const auto wanted : kWantedNames) {
                            if (entry.text == wanted) {
                                pool_wanted.emplace_back(std::string(wanted), running + local);
                            }
                        }
                        ++local;
                    }
                    std::cout << "      block[" << i << "]=0x" << std::hex << pool_blocks[i] << std::dec
                              << " entries=" << walk.entries.size() << " first=\""
                              << (walk.entries.empty() ? "" : walk.entries.front().text) << "\" last=\""
                              << (walk.entries.empty() ? "" : walk.entries.back().text) << "\"\n";
                    running += static_cast<std::uint32_t>(walk.entries.size());
                }
                std::cout << "      pool_names>=" << running << " (array order, lower bound where a"
                          << " block stops mid-window)\n";
                for (const auto& [name, ordinal] : pool_wanted) {
                    std::cout << "      " << name << " ordinal=" << ordinal << '\n';
                }
                break;
            }
        }

        // Page-aligned chain sweep. Block 0 was found through the "None" marker, but later blocks are
        // not: they start at no known name, they are not adjacent (the +0x10000 stride found nothing),
        // and no block table shows up in memory around the referrers. So every 0x1000-aligned position
        // that opens at least min_entries chained packed entries is a block data start. The test is
        // the chain itself, which random module code cannot satisfy at 64+ consecutive entries.
        struct PageBlock {
            std::uint64_t va{};
            std::uint32_t entries{};
            std::string first;
            std::string last;
            std::vector<std::pair<std::string, std::uint32_t>> wanted;  // name, ordinal inside sweep
            // Chains that stop with block bytes left over carry the only diagnostic that matters: the
            // raw bytes at the stop and where (and how far away) the chain restarts. Every sweep block
            // gets it, not just the anchor, so one run explains the whole pool.
            std::string stop_hex;
            std::uint32_t stop_at{};
            std::uint32_t resync_gap{};
            std::vector<std::string> resync_names;
            // Set when a wanted name was found inside this stream, which proves it is pool content
            // regardless of how deep the chain happens to be.
            bool proven{};
        };
        std::vector<PageBlock> sweep_blocks;
        std::uint32_t gate_dropped = 0;
        {
            std::vector<PageBlock> hits;
            for (const auto& range : ranges) {
                const auto first_aligned = (range.va + 0xfffULL) & ~0xfffULL;
                if (first_aligned < range.va) {
                    continue;
                }
                for (auto pos = first_aligned - range.va; pos + 0x40 <= range.size; pos += 0x1000) {
                    const auto view = bytes.subspan(static_cast<std::size_t>(range.file_offset + pos),
                        std::min<std::uint64_t>(0x1000, range.size - pos));
                    const auto quick = WalkNameBlock(view, *anchor.codec, min_entries + 1);
                    if (quick.entries.size() < min_entries) {
                        continue;
                    }
                    PageBlock h;
                    h.va = range.va + pos;
                    h.entries = static_cast<std::uint32_t>(quick.entries.size());
                    h.first = quick.entries.front().text;
                    h.last = quick.entries.back().text;
                    hits.push_back(std::move(h));
                }
            }
            // Alignment-agnostic name hunt. The page pass above only tests 0x1000-aligned stream
            // starts - which is how block 0 was found - so a pool block whose first entry is not page
            // aligned (a block from the general allocator, for instance) is invisible to it. Hunting the
            // bytes of names that must be in the pool answers two different questions at once, and the
            // previous run could only answer one of them:
            //   raw hits            - is the string in the captured memory at all? (coverage question:
            //                         "the dump is missing the pool" and "the codec is wrong" look the
            //                         same when only header-validated hits are counted)
            //   header_ok + depth   - is it a packed pool entry, and how deep does the chain go back?
            // Raw hits inside the module are string literals and mean nothing; raw hits *outside* it with
            // no packed header in front are the interesting case, so a few of those get their bytes
            // printed - that hex is what would show a different entry header.
            struct HuntStat {
                std::string_view needle;
                std::uint64_t raw = 0;
                std::uint64_t raw_in_image = 0;
                std::uint64_t header_ok = 0;
                std::uint32_t best_depth = 0;
                std::uint64_t best_va = 0;
                std::vector<std::uint64_t> outside_samples;
            };
            std::vector<HuntStat> stats;
            for (const auto& needle : kHuntNames) {
                stats.push_back(HuntStat{needle, 0, 0, 0, 0, 0, {}});
            }
            std::uint64_t hunt_printed = 0;
            std::set<std::uint64_t> hunt_starts;
            bool hunt_capped = false;
            for (auto& stat : stats) {
                const auto& needle = stat.needle;
                for (const auto& range : ranges) {
                    const std::string_view span(
                        reinterpret_cast<const char*>(bytes.data() + range.file_offset),
                        static_cast<std::size_t>(std::min<std::uint64_t>(
                            range.size, static_cast<std::uint64_t>(
                                std::numeric_limits<std::size_t>::max()))));
                    std::size_t from = 0;
                    while (from + needle.size() <= span.size()) {
                        const auto pos = span.find(needle, from);
                        if (pos == std::string_view::npos) {
                            break;
                        }
                        from = pos + 1;
                        const auto name_va = range.va + pos;
                        ++stat.raw;
                        if (in_image(name_va)) {
                            ++stat.raw_in_image;
                        } else if (stat.outside_samples.size() < 4) {
                            stat.outside_samples.push_back(name_va);
                        }
                        if (name_va < 4) {
                            continue;
                        }
                        // The entry header must sit immediately in front and declare exactly this length.
                        // Read it straight out of the mapped range: a big dump holds plenty of these names
                        // inside longer strings, and the header test is what throws them away.
                        const std::uint16_t header_before = [&]() {
                            if (pos >= 2) {
                                return U16(reinterpret_cast<const std::uint8_t*>(span.data()) + pos - 2);
                            }
                            const auto pre = read(name_va - 2, 2);
                            return pre ? U16(pre->data()) : std::uint16_t{0};
                        }();
                        if ((header_before >> 6) != needle.size()) {
                            continue;
                        }
                        ++stat.header_ok;
                        // The window is clamped into the range the hit sits in: a block near the start of
                        // a captured region has nothing in front of it *in the dump*, and shrinking is
                        // what tells a short chain apart from an uncaptured one.
                        std::optional<std::span<const std::uint8_t>> win;
                        std::uint64_t win_va = 0;
                        for (std::uint64_t want = 0x10000; want >= 0x40; want /= 4) {
                            const auto room = name_va > range.va + want ? want : name_va - range.va;
                            if (room < 0x40) {
                                continue;
                            }
                            auto probe = read(name_va - room, room + needle.size() + 8);
                            if (probe) {
                                win = std::move(probe);
                                win_va = name_va - room;
                                break;
                            }
                        }
                        if (!win) {
                            std::cout << "    hunt \"" << needle << "\" at 0x" << std::hex
                                      << name_va << std::dec << ": header ok, bytes before it uncaptured\n";
                            continue;
                        }
                        const auto back =
                            WalkBackward({win->data(), win->size()}, win_va, name_va - 2, 0x4000);
                        if (back.entries > stat.best_depth) {
                            stat.best_depth = back.entries;
                            stat.best_va = name_va;
                        }
                        if (hunt_printed < 24) {
                            ++hunt_printed;
                            std::cout << "    hunt \"" << needle << "\" at 0x" << std::hex << name_va
                                      << std::dec << " back_entries=" << back.entries << " pad="
                                      << back.padding << " chain_start=0x" << std::hex << back.start_va
                                      << " first_entry=0x" << back.first_entry_va << std::dec
                                      << (back.first_entry_va % 0x1000 == 0 ? " page-aligned"
                                                                            : " NOT page-aligned")
                                      << (back.hit_window ? " (window edge, start is a lower bound)" : "")
                                      << '\n';
                        }
                        const auto hunt_min_depth = std::max<std::uint32_t>(8U, min_entries / 4U);
                        if (back.entries < hunt_min_depth) {
                            continue;
                        }
                        // Padding is not proof of a boundary: a block preceded by another block's zero
                        // tail would otherwise claim a start in the middle of that tail. The oldest real
                        // name the walk reached is the honest candidate.
                        if (!hunt_starts.insert(back.first_entry_va).second) {
                            continue;
                        }
                        if (hunt_starts.size() >= 256) {
                            if (!hunt_capped) {
                                hunt_capped = true;
                                std::cout << "    hunt: 256 distinct starts reached, further hits"
                                             " ignored\n";
                            }
                            continue;
                        }
                        PageBlock h;
                        h.va = back.first_entry_va;
                        h.proven = true;
                        h.first = std::string(needle);
                        hits.push_back(std::move(h));
                    }
                }
            }
            std::uint64_t hunt_total = 0;
            std::uint64_t hunt_raw_outside = 0;
            std::uint32_t hunt_best_depth = 0;
            for (const auto& stat : stats) {
                hunt_total += stat.header_ok;
                hunt_raw_outside += stat.raw - stat.raw_in_image;
                if (stat.best_depth > hunt_best_depth) {
                    hunt_best_depth = stat.best_depth;
                }
                std::cout << "  hunt \"" << stat.needle << "\": raw=" << stat.raw << " (in module "
                          << stat.raw_in_image << ", outside " << stat.raw - stat.raw_in_image
                          << ") packed_header=" << stat.header_ok << " deepest_chain=" << stat.best_depth;
                if (stat.best_depth != 0) {
                    std::cout << " (0x" << std::hex << stat.best_va << std::dec << ")";
                }
                std::cout << '\n';
                for (std::size_t i = 0; i < stat.outside_samples.size(); ++i) {
                    const auto sample = stat.outside_samples[i];
                    const auto around = read(sample - 16, 16 + stat.needle.size() + 16);
                    if (!around) {
                        continue;
                    }
                    std::cout << "    raw[" << i << "] 0x" << std::hex << sample - 16 << std::dec
                              << " before=";
                    for (std::size_t b = 0; b < 16; ++b) {
                        std::cout << std::hex << std::setw(2) << std::setfill('0')
                                  << static_cast<int>((*around)[b]);
                    }
                    std::cout << std::setfill(' ') << std::dec << " after=";
                    for (std::size_t b = 16 + stat.needle.size(); b < around->size(); ++b) {
                        std::cout << std::hex << std::setw(2) << std::setfill('0')
                                  << static_cast<int>((*around)[b]);
                    }
                    std::cout << std::setfill(' ') << std::dec << '\n';
                }
            }
            std::cout << "  hunt: " << hunt_total << " packed-header candidate(s) examined, "
                      << hunt_raw_outside << " raw occurrence(s) outside the module, deepest chain in"
                         " front of a hit = "
                      << hunt_best_depth << '\n';
            if (hunt_starts.empty()) {
                if (hunt_raw_outside == 0) {
                    std::cout << "  verdict: none of these name strings occurs anywhere in the captured"
                                 " memory outside the module, so the dump does not hold the rest of the"
                                 " pool. No codec change can recover what is not there: capture a full"
                                 " memory dump (procdump -ma <pid> out.dmp) and rerun this command.\n";
                } else if (hunt_total == 0) {
                    std::cout << "  verdict: the names ARE in the captured memory outside the module but"
                                 " never with a length-prefixed header in front, so blocks beyond the"
                                 " anchor use a different entry format. The raw[] lines above show the"
                                 " bytes in front of real occurrences - that is the header to model.\n";
                } else {
                    std::cout << "  verdict: packed headers were found outside the module but no chain of "
                              << min_entries << "+ entries stands behind them, so the stream is either"
                                 " interrupted by an entry form this codec does not model (the raw[] lines"
                                 " show what is in front) or the block is not contiguous in the dump.\n";
                }
            }
            // Expand each page hit over the whole block window, then drop any hit that sits inside an
            // earlier hit's chain: pages in the middle of a block chain too, and adjacent blocks are
            // legitimately absorbed into one continuous stream (the order is unchanged by that).
            std::sort(hits.begin(), hits.end(),
                [](const PageBlock& left, const PageBlock& right) { return left.va < right.va; });
            std::vector<std::pair<std::uint64_t, std::uint64_t>> covered;
            std::uint32_t running_ordinal = 0;
            for (auto& h : hits) {
                const auto blk = read(h.va, block_size * 8);
                std::uint64_t end = h.va + 1;
                if (blk) {
                    auto walk = WalkNameBlock(*blk, *anchor.codec, entry_cap);
                    if (!walk.entries.empty()) {
                        h.entries = static_cast<std::uint32_t>(walk.entries.size());
                        h.first = walk.entries.front().text;
                        h.last = walk.entries.back().text;
                        end = h.va + walk.consumed;
                        std::uint32_t local = 0;
                        for (const auto& entry : walk.entries) {
                            for (const auto wanted : kWantedNames) {
                                if (entry.text == wanted) {
                                    h.wanted.emplace_back(std::string(wanted), running_ordinal + local);
                                }
                            }
                            ++local;
                        }
                        if (walk.consumed != 0 && walk.consumed + 0x40 < blk->size()) {
                            h.stop_at = walk.consumed;
                            const auto from = walk.consumed > 0x10 ? walk.consumed - 0x10 : 0U;
                            static constexpr char kHexDigits[] = "0123456789abcdef";
                            for (std::size_t b = from; b < walk.consumed + 0x40 && b < blk->size(); ++b) {
                                h.stop_hex.push_back(kHexDigits[(*blk)[b] >> 4]);
                                h.stop_hex.push_back(kHexDigits[(*blk)[b] & 0xf]);
                            }
                            for (std::size_t off = walk.consumed + 2; off + 0x40 <= blk->size(); off += 2) {
                                const auto probe =
                                    WalkNameBlock({blk->data() + off, blk->size() - off}, *anchor.codec, 8);
                                if (probe.entries.size() < 4) {
                                    continue;
                                }
                                h.resync_gap = static_cast<std::uint32_t>(off - walk.consumed);
                                for (const auto& entry : probe.entries) {
                                    h.resync_names.push_back(entry.text);
                                }
                                break;
                            }
                        }
                    }
                }
                // Density gate. Without it the chain test also accepts executable and rodata regions:
                // an earlier run reported 20 "blocks", 19 of them 60-90 single-character names, and their
                // entries shifted every ordinal in the names file. A real pool block is thousands of
                // entries deep (block 0 holds 536 because it only carries the static EName table), so
                // require depth, a wanted name inside the stream, or the anchor itself.
                if (!h.proven && h.va != anchor.data_va && h.entries < 512) {
                    ++gate_dropped;
                    continue;
                }
                const auto inside = std::any_of(covered.begin(), covered.end(),
                    [&](const std::pair<std::uint64_t, std::uint64_t>& span) {
                        return h.va >= span.first && h.va < span.second;
                    });
                if (inside) {
                    continue;
                }
                covered.emplace_back(h.va, std::max(end, h.va + 1));
                running_ordinal += h.entries;
                sweep_blocks.push_back(std::move(h));
            }
        }
        std::uint64_t sweep_names = 0;
        for (const auto& block : sweep_blocks) {
            sweep_names += block.entries;
        }
        std::cout << "  sweep: " << gate_dropped << " candidate stream(s) below 512 entries dropped\n";
        std::cout << "  page sweep: " << sweep_blocks.size() << " chain-validated block(s), total_names>="
                  << sweep_names << " (a block contained in another's chain was absorbed, which keeps"
                  " order but hides boundaries)\n";
        for (std::size_t i = 0; i < sweep_blocks.size() && i < 64; ++i) {
            std::cout << "    block[" << i << "] data=0x" << std::hex << sweep_blocks[i].va << std::dec
                      << " entries=" << sweep_blocks[i].entries << " first=\"" << sweep_blocks[i].first
                      << "\" last=\"" << sweep_blocks[i].last << "\"\n";
            for (const auto& [name, ordinal] : sweep_blocks[i].wanted) {
                std::cout << "      " << name << " ordinal=" << ordinal << '\n';
            }
            if (!sweep_blocks[i].stop_hex.empty()) {
                std::cout << "      stop=+" << std::hex << sweep_blocks[i].stop_at << std::dec
                          << " bytes=" << sweep_blocks[i].stop_hex << '\n';
                if (!sweep_blocks[i].resync_names.empty()) {
                    std::cout << "      resync=+0x" << std::hex << sweep_blocks[i].resync_gap << std::dec
                              << " next=\"";
                    for (std::size_t n = 0; n < sweep_blocks[i].resync_names.size(); ++n) {
                        std::cout << (n ? "," : "") << sweep_blocks[i].resync_names[n];
                    }
                    std::cout << "\"\n";
                } else {
                    std::cout << "      resync=none-before-window-end\n";
                }
            }
        }
        if (sweep_blocks.size() > 64) {
            std::cout << "    ... " << (sweep_blocks.size() - 64) << " more block(s)\n";
        }
        if (sweep_blocks.size() > 1) {
            std::cout << "  note: cross-block ordinals assume VA order equals insertion order. Adjacent"
                         " absorbed blocks are certainly in order; separated blocks are provisional"
                         " until the pool's block array or the usmap name table confirms it.\n";
        }
        // Ordinals count from the anchor block: the anchor starts at the pool's first name, so every
        // sweep block at a lower VA is some other stream that merely satisfies the chain rule (shader
        // source, CRT data) and must not shift the numbering. Re-walk from the anchor forward once.
        std::size_t pool_start = 0;
        for (std::size_t i = 0; i < sweep_blocks.size(); ++i) {
            if (sweep_blocks[i].va == anchor.data_va) {
                pool_start = i;
                break;
            }
        }
        if (pool_start != 0) {
            std::cout << "  ordinals counted from block[" << pool_start << "] at 0x" << std::hex
                      << anchor.data_va << std::dec << "; " << pool_start
                      << " lower-VA stream(s) excluded from numbering\n";
        }
        std::vector<std::pair<std::uint32_t, std::string>> pool_names;
        {
            std::uint32_t pool_ordinal = 0;
            for (std::size_t i = pool_start; i < sweep_blocks.size(); ++i) {
                sweep_blocks[i].wanted.clear();
                const auto blk = read(sweep_blocks[i].va, block_size * 8);
                if (!blk) {
                    continue;
                }
                const auto walk = WalkNameBlock(*blk, *anchor.codec, entry_cap);
                std::uint32_t local = 0;
                for (const auto& entry : walk.entries) {
                    for (const auto wanted : kWantedNames) {
                        if (entry.text == wanted) {
                            sweep_blocks[i].wanted.emplace_back(std::string(wanted), pool_ordinal + local);
                        }
                    }
                    if (!names_out.empty()) {
                        pool_names.emplace_back(pool_ordinal + local, entry.text);
                    }
                    ++local;
                }
                pool_ordinal += static_cast<std::uint32_t>(walk.entries.size());
            }
            if (pool_start == 0 && sweep_blocks.size() > 1) {
                std::cout << "  note: the anchor block was not among the sweep blocks; ordinals start at"
                             " the lowest sweep VA\n";
            }
        }
        if (!names_out.empty() && !pool_names.empty()) {
            std::ofstream out(names_out.string());
            if (out) {
                for (const auto& [ordinal, name] : pool_names) {
                    out << ordinal << '\t' << name << '\n';
                }
                std::cout << "  names written to " << names_out << " (" << pool_names.size()
                          << " entries)\n";
            } else {
                std::cout << "  could not write names file " << names_out << '\n';
            }
        }

        const auto block_count = std::max<std::size_t>(
            std::max(chain.blocks.size(), stride_blocks + 1), sweep_blocks.size());
        const auto names = chain.total_entries != 0 ? chain.total_entries : stride_entries + anchor.entries;
        if (block_count > 1) {
            ++validated_pools;
            std::cout << "PREDICATE PASS blocks=" << block_count << " names="
                      << (sweep_names != 0 ? sweep_names : names)
                      << (chain.total_capped ? " (capped)" : "") << " pool_referrers_image=" << image_refs
                      << " heap=" << heap_refs << '\n';
            if (image_refs == 0) {
                std::cout << "  no in-image pointer to the block: the pool is reached through heap memory."
                             " Run dump-xrefs on the block VA and disassemble the function that loads it to"
                             " recover the stable global RVA.\n";
            }
        } else {
            std::cout << "PREDICATE FAIL: single block only, " << anchor.entries
                      << " names decoded from the anchor. The chain walk found no second block, so the"
                         " block-linking assumption is wrong for this build.\n";
        }
    }
    std::cout << "\nSUMMARY build=" << kBuildStamp
              << " anchors_found=" << anchors.size() - supplied_anchors
              << " dense=" << validated_anchors
              << " chain_validated=" << validated_pools
              << " scanned_bytes=" << scanned_bytes << " marker_hits=" << marker_hits << " (";
    for (std::size_t index = 0; index < markers.size(); ++index) {
        std::cout << (index == 0 ? "" : ",") << markers[index] << "=" << marker_hits_for[index];
    }
    std::cout << ") region_probes=" << region_probes << '\n';
    if (supplied_anchors != 0 && validated_anchors == 0) {
        std::cout << "note: the supplied anchor VA decoded no dense name stream, so marker discovery ran"
                     " in the same pass. A heap VA from another session's dump is not expected to hold"
                     " the pool here; a hit list of zero for every marker is what says the pool is"
                     " absent or encoded.\n";
    }
    std::cout << "note: an in-image referrer gives an RVA that survives restarts, a heap referrer does"
                 " not. Decoded names prove the pool layout only; no object header field is implied.\n";
}

void PrintDumpFNameLayout(
    const std::filesystem::path& path,
    const std::uint64_t va,
    const std::uint32_t window_size,
    const std::size_t max_hits) {
    if (va == 0) {
        throw std::invalid_argument("region VA must be nonzero");
    }
    const MappedFile file(path);
    const auto bytes = file.Bytes();
    const auto ranges = ReadMemoryRanges(bytes, ReadStreams(bytes));
    const auto read = [&](const std::uint64_t address, const std::uint64_t size) {
        return ReadCaptured(bytes, ranges, address, size);
    };
    std::cout << "build=" << kBuildStamp << "\n";
    PrintNameLayout(std::cout, "dump layout", read, va, window_size, max_hits);
}

namespace {

// Structural predicates for the object graph, used instead of class names. A name is only a label; every
// test below is something a wrong offset cannot satisfy, which is what makes this route independent of
// the FName pool (measured: this build's pool beyond block 0 is not in any of the three dumps).
struct EspReader {
    const std::span<const std::uint8_t> bytes;
    const std::vector<MemoryRange>& ranges;
    std::uint64_t image_base{};
    std::uint64_t image_size{};

    [[nodiscard]] std::optional<std::uint64_t> Qword(const std::uint64_t va) const {
        const auto span = ReadCaptured(bytes, ranges, va, 8);
        if (!span || span->size() < 8) {
            return std::nullopt;
        }
        return U64(span->data());
    }
    [[nodiscard]] std::optional<std::uint32_t> Dword(const std::uint64_t va) const {
        const auto span = ReadCaptured(bytes, ranges, va, 4);
        if (!span || span->size() < 4) {
            return std::nullopt;
        }
        return U32(span->data());
    }
    [[nodiscard]] bool InImage(const std::uint64_t va) const {
        return va >= image_base && va - image_base < image_size;
    }
    // An object header is a pointer to a vtable inside the module: true for every UObject and for the
    // components, and essentially never true by accident for a float field or a stale value.
    [[nodiscard]] bool LooksLikeObject(const std::uint64_t va, std::uint64_t* vtable = nullptr) const {
        if (va < 0x1000) {
            return false;
        }
        const auto head = Qword(va);
        if (!head || *head < 0x1000) {
            return false;
        }
        if (!InImage(*head)) {
            return false;
        }
        // The vtable slot itself must be readable and point back into the module's code.
        const auto entry = Qword(*head);
        if (!entry || !InImage(*entry)) {
            return false;
        }
        if (vtable != nullptr) {
            *vtable = *head;
        }
        return true;
    }
    // A world position: three finite floats, at least one non-trivial, magnitudes inside what a level
    // blueprint uses. Zero triples (components at the origin) and NaN/inf garbage are both rejected.
    [[nodiscard]] bool FloatTriple(const std::uint64_t va, float out[3]) const {
        const auto span = ReadCaptured(bytes, ranges, va, 12);
        if (!span || span->size() < 12) {
            return false;
        }
        float values[3];
        std::memcpy(values, span->data(), sizeof(values));
        for (const auto value : values) {
            const auto absolute = value < 0.0F ? -value : value;
            if (absolute == 0.0F) {
                return false;  // a zero axis makes the read ambiguous by one float
            }
            // The halves of a 64-bit pointer read as floats come out denormal or tiny, so this band is
            // what stops the next object's vtable from being accepted as a coordinate - measured on the
            // synthetic, where components sit 0x100 apart and the lowest offset was exactly that.
            if (absolute < 1.0e-2F || absolute > 1.0e6F) {
                return false;  // NaN, denormal, rotation-sized noise, or an impossible coordinate
            }
        }
        std::memcpy(out, values, sizeof(values));
        return true;
    }
};

// TArray<T> in a UE container is { void* Data; int32 Num; int32 Max; }. The count and the capacity have
// to agree with the data pointer, and for a pointer array every element has to be a real object.
bool LooksLikeObjectArray(const EspReader& mem, const std::uint64_t data_va, const std::uint32_t num,
    const std::uint32_t max, const std::uint32_t probe_limit, std::uint32_t* good) {
    if (num == 0 || num > 200000U || max < num || data_va < 0x1000) {
        return false;
    }
    const auto probes = std::min<std::uint32_t>(num, probe_limit);
    std::uint32_t hits = 0;
    for (std::uint32_t i = 0; i < probes; ++i) {
        const auto element = mem.Qword(data_va + i * 8);
        if (element && mem.LooksLikeObject(*element)) {
            ++hits;
        }
    }
    if (good != nullptr) {
        *good = hits;
    }
    return hits == probes && probes > 0;
}

// AActor -> RootComponent -> USceneComponent::RelativeLocation, derived from the dump rather than
// assumed: for every object-pointer slot of every actor, does that component hold a float triple that
// looks like a position. The offset that most actors agree on is the field.
struct FieldHits {
    std::uint32_t offset{};
    std::uint32_t count{};
};

}  // namespace

void PrintDumpEspChain(
    const std::filesystem::path& path,
    const std::uint64_t image_base,
    const std::uint64_t image_size,
    const std::uint64_t global_rva,
    const std::string_view chain_list,
    const std::filesystem::path& ini_out) {
    if (image_base == 0 || image_size == 0 || global_rva > image_size) {
        throw std::invalid_argument(
            "esp-chain needs the module base and size, and a global RVA inside the image");
    }
    // The chain arrives as a comma separated list of offsets, each applied after one pointer read. The
    // default is the sequence found by the structural chain scan and re-confirmed on two gameplay dumps
    // (global 0x108FEEC0 -> +0xA0 -> +0x250 -> +0x160); a build that moved the fields needs a new list,
    // and the FAIL lines below say which step broke.
    std::vector<std::uint64_t> chain;
    {
        std::string current;
        for (const char character : chain_list) {
            if (character == ',' || character == ' ' || character == ';') {
                if (!current.empty()) {
                    chain.push_back(std::stoull(current, nullptr, 0));
                    current.clear();
                }
            } else {
                current.push_back(character);
            }
        }
        if (!current.empty()) {
            chain.push_back(std::stoull(current, nullptr, 0));
        }
    }
    if (chain.empty() && chain_list.empty()) {
        chain = {0xA0, 0x250, 0x160};
    }

    const MappedFile file(path);
    const auto bytes = file.Bytes();
    const auto streams = ReadStreams(bytes);
    const auto ranges = ReadMemoryRanges(bytes, streams);
    const EspReader mem{bytes, ranges, image_base, image_size};

    std::cout << "build=" << kBuildStamp << "\n";
    std::cout << "image=0x" << std::hex << image_base << " size=0x" << image_size << " global=0x"
              << image_base + global_rva << std::dec << "\n";
    std::cout << "captured_ranges=" << ranges.size() << "\n";

    std::vector<std::uint64_t> objects;
    auto cursor = image_base + global_rva;
    const auto first = mem.Qword(cursor);
    if (!first) {
        std::cout << "FAIL: the global at base+0x" << std::hex << global_rva
                  << std::dec << " is not captured in this dump. Rerun with the base this dump actually"
                                  " uses (PrintDumpInfo shows the module list) or pass a different RVA.\n";
        return;
    }
    cursor = *first;
    objects.push_back(cursor);
    for (const auto offset : chain) {
        const auto next = mem.Qword(cursor + offset);
        if (!next || *next == 0) {
            std::cout << "FAIL: chain step +0x" << std::hex << offset << std::dec
                      << " from 0x" << cursor << " is null or uncaptured; the chain belongs to another"
                                     " build. Re-run with the offsets of this build as the [chain]"
                                     " argument (5th positional, comma separated).\n";
            return;
        }
        cursor = *next;
        objects.push_back(cursor);
    }
    std::cout << "\n[chain] start global=0x" << std::hex << image_base + global_rva << std::dec << "\n";
    for (std::size_t i = 0; i < objects.size(); ++i) {
        std::uint64_t vtable = 0;
        const auto ok = mem.LooksLikeObject(objects[i], &vtable);
        std::cout << "  obj[" << i << "]=0x" << std::hex << objects[i] << " vtable=0x" << vtable
                  << std::dec << " object_header=" << (ok ? "yes" : "NO") << "\n";
    }

    // UWorld and ULevel recognise each other: the level stores a pointer back to its own world. Testing
    // the round trip at one offset on both sides identifies the pair without knowing either class name.
    static constexpr std::array<std::uint32_t, 14> kLevelOffsets{{
        0x28, 0x30, 0x38, 0x40, 0x98, 0xA0, 0xE8, 0xF0, 0xF8, 0x100, 0x108, 0x110, 0x140, 0x160,
    }};
    struct LevelHit {
        std::uint64_t world{};
        std::uint64_t level{};
        std::uint32_t world_off{};
        std::uint32_t level_off{};
    };
    std::vector<LevelHit> level_hits;
    std::cout << "\n[uworld/level] round trip [world+a]=level and [level+b]=world\n";
    for (const auto world : objects) {
        for (const auto a : kLevelOffsets) {
            const auto level = mem.Qword(world + a);
            if (!level || *level < 0x1000) {
                continue;
            }
            for (const auto b : kLevelOffsets) {
                const auto back = mem.Qword(*level + b);
                if (!back || *back != world) {
                    continue;
                }
                std::cout << "  HIT world=0x" << std::hex << world << " +0x" << a << std::dec << " -> level=0x"
                          << std::hex << *level << " +0x" << b << std::dec << " -> world  (world_off=0x"
                          << std::hex << a << " level_off=0x" << b << std::dec << ")\n";
                level_hits.push_back({world, *level, a, b});
            }
        }
    }
    if (level_hits.empty()) {
        std::cout << "  no round trip in 0x28..0x160 on any chain object: either the chain does not end at"
                     " UWorld, or the level pointer is obfuscated in this build. Both are answers - the"
                     " second means the ESP has to start from an object whose level link is plaintext.\n";
    }

    // The actor array of the level, derived by the same kind of test: TArray of object pointers.
    std::cout << "\n[level] actor array search (TArray of UObject*)\n";
    std::uint64_t actors_va = 0;
    std::uint32_t actor_count = 0;
    std::uint32_t actors_off = 0;
    for (const auto& hit : level_hits) {
        for (std::uint32_t off = 0x20; off + 16 <= 0x400; off += 8) {
            const auto data = mem.Qword(hit.level + off);
            if (!data) {
                continue;
            }
            const auto num = mem.Dword(hit.level + off + 8);
            const auto max = mem.Dword(hit.level + off + 0xC);
            if (!num || !max) {
                continue;
            }
            std::uint32_t good = 0;
            if (!LooksLikeObjectArray(mem, *data, *num, *max, 6, &good)) {
                continue;
            }
            std::cout << "  HIT level=0x" << std::hex << hit.level << " +0x" << off << " data=0x"
                      << *data << std::dec << " num=" << *num << " max=" << *max
                      << " (all 6 sampled elements are objects with in-image vtables)\n";
            if (actor_count == 0 || *num > actor_count) {
                actor_count = *num;
                actors_va = *data;
                actors_off = off;
            }
        }
    }
    if (actors_va == 0) {
        std::cout << "  no TArray of objects in the first 0x400 bytes of any level candidate.\n";
    }

    // Positions, derived over the whole actor array and voted on, so the reported offset is the one the
    // actors agree on instead of one copied from another build.
    std::vector<FieldHits> root_hits;
    std::vector<FieldHits> loc_hits;
    std::uint32_t sampled = 0;
    if (actors_va != 0) {
        constexpr std::uint32_t kActorProbe = 48;
        const auto probes = std::min<std::uint32_t>(actor_count, kActorProbe);
        std::cout << "\n[actors] sampling " << probes << " of " << actor_count << "\n";
        for (std::uint32_t i = 0; i < probes; ++i) {
            const auto actor = mem.Qword(actors_va + i * 8);
            if (!actor || !mem.LooksLikeObject(*actor)) {
                continue;
            }
            ++sampled;
            // Record every candidate instead of the first one: the field is the offset the majority of
            // actors agree on, and a first-match scan would report whichever low offset holds bytes that
            // happen to look like floats.
            std::set<std::pair<std::uint32_t, std::uint32_t>> pairs;
            for (std::uint32_t off = 0x100; off + 8 <= 0x400 && pairs.size() < 64; off += 8) {
                const auto component = mem.Qword(*actor + off);
                if (!component || !mem.LooksLikeObject(*component)) {
                    continue;
                }
                for (std::uint32_t lo = 0x100; lo + 12 <= 0x240 && pairs.size() < 64; lo += 4) {
                    float triple[3];
                    if (!mem.FloatTriple(*component + lo, triple)) {
                        continue;
                    }
                    if (!pairs.insert({off, lo}).second) {
                        continue;
                    }
                    for (auto* table : {&root_hits, &loc_hits}) {
                        const auto want = table == &root_hits ? off : lo;
                        const auto hit = std::find_if(table->begin(), table->end(),
                            [want](const FieldHits& item) { return item.offset == want; });
                        if (hit == table->end()) {
                            table->push_back({want, 1});
                        } else {
                            ++hit->count;
                        }
                    }
                }
            }
        }
        const auto rank = [](std::vector<FieldHits> hits) {
            std::sort(hits.begin(), hits.end(),
                [](const FieldHits& l, const FieldHits& r) { return l.count > r.count; });
            return hits;
        };
        root_hits = rank(std::move(root_hits));
        loc_hits = rank(std::move(loc_hits));
        std::cout << "  component-offset votes:";
        for (std::size_t i = 0; i < root_hits.size() && i < 6; ++i) {
            std::cout << " +0x" << std::hex << root_hits[i].offset << std::dec << "="
                      << root_hits[i].count << "/" << sampled;
        }
        std::cout << "\n  location-offset votes:";
        for (std::size_t i = 0; i < loc_hits.size() && i < 6; ++i) {
            std::cout << " +0x" << std::hex << loc_hits[i].offset << std::dec << "="
                      << loc_hits[i].count << "/" << sampled;
        }
        std::cout << "\n";
        for (std::size_t i = 0; i < root_hits.size() && i < 3; ++i) {
            std::cout << "    candidate component +0x" << std::hex << root_hits[i].offset << std::dec
                      << "=" << root_hits[i].count << "\n";
        }
        for (std::size_t i = 0; i < loc_hits.size() && i < 3; ++i) {
            std::cout << "    candidate location +0x" << std::hex << loc_hits[i].offset << std::dec << "="
                      << loc_hits[i].count << "\n";
        }
        if (!root_hits.empty() && !loc_hits.empty()) {
            const auto root_off = root_hits.front().offset;
            const auto loc_off = loc_hits.front().offset;
            std::cout << "  winner: [actor+0x" << std::hex << root_off
                      << "] -> component, [component+0x" << loc_off << std::dec
                      << "] -> FVector\n";
            std::uint32_t with_position = 0;
            std::array<std::array<float, 2>, 3> bounds{{
                {{1.0e30F, -1.0e30F}}, {{1.0e30F, -1.0e30F}}, {{1.0e30F, -1.0e30F}}}};
            for (std::uint32_t i = 0; i < probes; ++i) {
                const auto actor = mem.Qword(actors_va + i * 8);
                if (!actor || !mem.LooksLikeObject(*actor)) {
                    continue;
                }
                const auto component = mem.Qword(*actor + root_off);
                float triple[3];
                if (!component || !mem.FloatTriple(*component + loc_off, triple)) {
                    continue;
                }
                ++with_position;
                for (std::size_t axis = 0; axis < 3; ++axis) {
                    bounds[axis][0] = std::min(bounds[axis][0], triple[axis]);
                    bounds[axis][1] = std::max(bounds[axis][1], triple[axis]);
                }
                if (i < 8) {
                    std::cout << "    actor[" << i << "]=0x" << std::hex << *actor << std::dec << " pos=("
                              << triple[0] << ", " << triple[1] << ", " << triple[2] << ")\n";
                }
            }
            std::cout << "  positions at the winning offsets: " << with_position << "/" << sampled << "\n";
            if (with_position != 0) {
                std::cout << "  spread X=[" << bounds[0][0] << ".." << bounds[0][1] << "] Y=[" << bounds[1][0]
                          << ".." << bounds[1][1] << "] Z=[" << bounds[2][0] << ".." << bounds[2][1]
                          << "] (a real level spreads over thousands of units on X/Y)\n";
            }
            if (with_position * 2 < sampled) {
                std::cout << "  note: fewer than half the actors agree on this pair, so it is a candidate"
                             " and not a measurement - print a wider sample before trusting it.\n";
            }
        }
    }

    // One line that spells the whole read out, so it can be pasted into a config without recomputation.
    std::cout << "\n[read path]\n  ";
    std::cout << "[base+0x" << std::hex << global_rva << "]";
    for (const auto offset : chain) {
        std::cout << " -> [+0x" << offset << "]";
    }
    if (!level_hits.empty()) {
        std::cout << " = world -> [world+0x" << level_hits[0].world_off << std::dec << "]";
        if (actors_va != 0) {
            std::cout << " = level -> [level+0x" << std::hex << actors_off << std::dec << "]";
        }
    }
    if (!root_hits.empty()) {
        std::cout << " = actor -> [actor+0x" << std::hex << root_hits[0].offset << std::dec << "]";
    }
    if (!loc_hits.empty()) {
        std::cout << " = component -> [component+0x" << std::hex << loc_hits[0].offset << std::dec
                  << "] = FVector";
    }
    std::cout << "\n  (a step in this line that was not found is simply absent; the section above it says"
                 " why)\n";

    std::cout << "\nSUMMARY sampled_objects=" << objects.size() << " level_hits=" << level_hits.size()
              << " actors=" << actor_count << " position_actors=" << sampled << "\n";
    if (!ini_out.empty()) {
        std::ofstream out(ini_out.string());
        if (!out) {
            std::cout << "  could not write " << ini_out << "\n";
        } else {
            out << "# derived offline from this dump by structural predicates; not validated in a live"
                   " process\n";
            out << "[esp]\n";
            out << "image_base = 0x" << std::hex << image_base << std::dec << "\n";
            out << "global_rva = 0x" << std::hex << global_rva << std::dec << "\n";
            out << "chain =";
            for (std::size_t i = 0; i < chain.size(); ++i) {
                out << (i == 0 ? " " : ",") << "0x" << std::hex << chain[i] << std::dec;
            }
            out << "\n";
            if (!level_hits.empty()) {
                out << "world = 0x" << std::hex << level_hits[0].world << "\n";
                out << "persistent_level_off = 0x" << level_hits[0].world_off << "\n";
                out << "level = 0x" << std::hex << level_hits[0].level << "\n";
                out << "level_owning_world_off = 0x" << level_hits[0].level_off << "\n";
            }
            if (actors_va != 0) {
                out << "level_actors_off = 0x" << std::hex << actors_off << std::dec << "\n";
            }
            if (!root_hits.empty()) {
                out << "root_component_off = 0x" << std::hex << root_hits[0].offset << std::dec << "\n";
            }
            if (!loc_hits.empty()) {
                out << "relative_location_off = 0x" << std::hex << loc_hits[0].offset << std::dec << "\n";
            }
            std::cout << "  ini written to " << ini_out << "\n";
        }
    }
}

} // namespace arc

#endif
