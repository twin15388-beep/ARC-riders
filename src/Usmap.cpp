#include "Usmap.h"

#include <array>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <type_traits>

namespace arc {
namespace {

constexpr std::uint16_t kMagic = 0x30C4;
constexpr std::uint32_t kNoName = UINT32_MAX;

class Reader {
public:
    Reader(const std::vector<std::uint8_t>& bytes, std::size_t begin, std::size_t end)
        : bytes_(bytes), position_(begin), end_(end) {
        if (begin > end || end > bytes.size()) {
            throw std::runtime_error("usmap reader range is invalid");
        }
    }

    std::size_t Position() const { return position_; }
    std::size_t Remaining() const { return end_ - position_; }

    template<typename T>
    T Read() {
        static_assert(std::is_trivially_copyable_v<T>);
        Require(sizeof(T));
        T value{};
        std::memcpy(&value, bytes_.data() + position_, sizeof(T));
        position_ += sizeof(T);
        return value;
    }

    std::string Bytes(const std::size_t size) {
        Require(size);
        const auto* first = reinterpret_cast<const char*>(bytes_.data() + position_);
        std::string result(first, size);
        position_ += size;
        return result;
    }

    void Skip(const std::size_t size) {
        Require(size);
        position_ += size;
    }

private:
    void Require(const std::size_t size) const {
        if (size > end_ - position_) {
            throw std::runtime_error("usmap ends unexpectedly at payload offset " + std::to_string(position_));
        }
    }

    const std::vector<std::uint8_t>& bytes_;
    std::size_t position_;
    std::size_t end_;
};

std::vector<std::uint8_t> ReadFile(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input) {
        throw std::runtime_error("cannot open usmap: " + path.string());
    }
    const auto length = input.tellg();
    if (length < 0 || static_cast<unsigned long long>(length) > SIZE_MAX) {
        throw std::runtime_error("usmap size is invalid");
    }
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(length));
    input.seekg(0);
    if (!bytes.empty() && !input.read(reinterpret_cast<char*>(bytes.data()), length)) {
        throw std::runtime_error("cannot read complete usmap: " + path.string());
    }
    return bytes;
}

std::string Name(const std::vector<std::string>& names, const std::uint32_t index, const bool nullable = false) {
    if (index == kNoName && nullable) {
        return {};
    }
    if (index >= names.size()) {
        throw std::runtime_error("usmap name index is outside the name table");
    }
    return names[index];
}

std::string TypeName(const std::uint8_t type) {
    static constexpr std::array<std::string_view, 31> names{
        "Byte", "Bool", "Int", "Float", "Object", "Name", "Delegate", "Double",
        "Array", "Struct", "Str", "Text", "Interface", "MulticastDelegate", "WeakObject",
        "LazyObject", "AssetObject", "SoftObject", "UInt64", "UInt32", "UInt16", "Int64",
        "Int16", "Int8", "Map", "Set", "Enum", "FieldPath", "Optional", "Utf8Str", "AnsiStr"
    };
    return type < names.size() ? std::string(names[type]) : "Unknown(" + std::to_string(type) + ")";
}

std::string ReadType(Reader& reader, const std::vector<std::string>& names, const unsigned depth = 0) {
    if (depth > 16) {
        throw std::runtime_error("usmap property type nesting exceeds 16");
    }
    const auto type = reader.Read<std::uint8_t>();
    const auto label = TypeName(type);
    switch (type) {
    case 8:
    case 25:
    case 28:
        return label + "<" + ReadType(reader, names, depth + 1) + ">";
    case 9:
        return label + "<" + Name(names, reader.Read<std::uint32_t>()) + ">";
    case 24:
        return label + "<" + ReadType(reader, names, depth + 1) + ", " +
            ReadType(reader, names, depth + 1) + ">";
    case 26: {
        const auto inner = ReadType(reader, names, depth + 1);
        return label + "<" + inner + ", " + Name(names, reader.Read<std::uint32_t>()) + ">";
    }
    default:
        return label;
    }
}

void RequireCount(const std::uint64_t count, const std::size_t remaining, const std::size_t minimum_size,
                  const char* what) {
    if (count > remaining / minimum_size) {
        throw std::runtime_error(std::string("usmap ") + what + " count exceeds the remaining payload");
    }
}

} // namespace

UsmapData LoadUsmap(const std::filesystem::path& path) {
    const auto bytes = ReadFile(path);
    Reader header(bytes, 0, bytes.size());
    if (header.Read<std::uint16_t>() != kMagic) {
        throw std::runtime_error("usmap magic is not 0x30C4");
    }

    UsmapData result;
    result.version = header.Read<std::uint8_t>();
    if (result.version > 4) {
        throw std::runtime_error("unsupported usmap version: " + std::to_string(result.version));
    }
    if (result.version >= 1) {
        const auto has_versioning = header.Read<std::int32_t>();
        if (has_versioning != 0 && has_versioning != 1) {
            throw std::runtime_error("usmap versioning flag is not an FArchive Boolean");
        }
        if (has_versioning == 1) {
            header.Skip(8);
            const auto custom_count = header.Read<std::uint32_t>();
            RequireCount(custom_count, header.Remaining(), 20, "custom version");
            header.Skip(static_cast<std::size_t>(custom_count) * 20 + 4);
        }
    }
    result.compression = header.Read<std::uint8_t>();
    const auto compressed_size = header.Read<std::uint32_t>();
    const auto uncompressed_size = header.Read<std::uint32_t>();
    if (result.compression != 0) {
        throw std::runtime_error("compressed usmap is unsupported by this build; compression=" +
                                 std::to_string(result.compression));
    }
    if (compressed_size != uncompressed_size) {
        throw std::runtime_error("uncompressed usmap has different compressed/decompressed sizes");
    }
    if (compressed_size != header.Remaining()) {
        throw std::runtime_error("usmap payload size does not match its header");
    }

    Reader reader(bytes, header.Position(), bytes.size());
    const auto name_count = reader.Read<std::uint32_t>();
    RequireCount(name_count, reader.Remaining(), result.version >= 2 ? 2 : 1, "name");
    std::vector<std::string> names;
    names.reserve(name_count);
    for (std::uint32_t i = 0; i < name_count; ++i) {
        const auto length = result.version >= 2
            ? reader.Read<std::uint16_t>()
            : reader.Read<std::uint8_t>();
        names.push_back(reader.Bytes(static_cast<std::size_t>(length)));
    }
    result.name_count = name_count;

    result.enum_count = reader.Read<std::uint32_t>();
    RequireCount(result.enum_count, reader.Remaining(), 6, "enum");
    for (std::uint32_t i = 0; i < result.enum_count; ++i) {
        static_cast<void>(Name(names, reader.Read<std::uint32_t>()));
        const auto count = static_cast<std::uint32_t>(result.version >= 3
            ? reader.Read<std::uint16_t>()
            : reader.Read<std::uint8_t>());
        for (std::uint32_t j = 0; j < count; ++j) {
            if (result.version >= 4) {
                reader.Skip(8);
            }
            static_cast<void>(Name(names, reader.Read<std::uint32_t>()));
        }
    }

    const auto struct_count = reader.Read<std::uint32_t>();
    RequireCount(struct_count, reader.Remaining(), 12, "struct");
    result.structs.reserve(struct_count);
    for (std::uint32_t i = 0; i < struct_count; ++i) {
        UsmapStruct item;
        item.name = Name(names, reader.Read<std::uint32_t>());
        const auto super = reader.Read<std::uint32_t>();
        if (super != kNoName) {
            item.super = Name(names, super);
        }
        item.property_count = reader.Read<std::uint16_t>();
        const auto serializable_count = reader.Read<std::uint16_t>();
        RequireCount(serializable_count, reader.Remaining(), 8, "property");
        item.properties.reserve(serializable_count);
        for (std::uint32_t j = 0; j < serializable_count; ++j) {
            UsmapProperty property;
            property.schema_index = reader.Read<std::uint16_t>();
            property.array_dim = reader.Read<std::uint8_t>();
            property.name = Name(names, reader.Read<std::uint32_t>());
            property.type = ReadType(reader, names);
            item.properties.push_back(std::move(property));
        }
        result.structs.push_back(std::move(item));
    }

    while (reader.Remaining() != 0) {
        const auto tag = reader.Bytes(4);
        result.extensions.push_back(tag);
        if (tag == "CEXT") {
            reader.Skip(1);
            const auto extension_count = reader.Read<std::uint32_t>();
            if (extension_count > 1024) {
                throw std::runtime_error("usmap CEXT extension count is unreasonable");
            }
            continue;
        }
        const auto size = reader.Read<std::uint32_t>();
        if (size > reader.Remaining()) {
            throw std::runtime_error("usmap extension " + tag + " exceeds the payload");
        }
        const auto end = reader.Position() + size;
        if (tag == "PPTH") {
            const auto extension_version = reader.Read<std::uint8_t>();
            if (extension_version != 0) {
                throw std::runtime_error("unsupported PPTH extension version");
            }
            const auto enum_paths = reader.Read<std::uint32_t>();
            RequireCount(enum_paths, reader.Remaining(), 4, "enum path");
            for (std::uint32_t i = 0; i < enum_paths; ++i) {
                static_cast<void>(Name(names, reader.Read<std::uint32_t>()));
            }
            const auto struct_paths = reader.Read<std::uint32_t>();
            RequireCount(struct_paths, reader.Remaining(), 4, "struct path");
            if (struct_paths != result.structs.size()) {
                throw std::runtime_error("PPTH struct path count differs from the struct count");
            }
            for (auto& item : result.structs) {
                item.package_path = Name(names, reader.Read<std::uint32_t>());
            }
        }
        if (reader.Position() > end) {
            throw std::runtime_error("usmap extension " + tag + " overreads its declared size");
        }
        reader.Skip(end - reader.Position());
    }
    return result;
}

const UsmapStruct& FindUsmapStruct(const UsmapData& data, const std::string_view name) {
    for (const auto& item : data.structs) {
        if (item.name == name) {
            return item;
        }
    }
    throw std::runtime_error("usmap struct not found: " + std::string(name));
}

void PrintUsmapInfo(const UsmapData& data) {
    std::cout << "usmap version=" << static_cast<unsigned>(data.version)
              << " compression=" << static_cast<unsigned>(data.compression)
              << " names=" << data.name_count << " enums=" << data.enum_count
              << " structs=" << data.structs.size() << " extensions=";
    for (const auto& extension : data.extensions) {
        std::cout << extension << ',';
    }
    std::cout << "\nSchema indexes are property ordinals, not byte offsets.\n";
}

void PrintUsmapStruct(const UsmapData& data, const std::string_view name) {
    const auto& item = FindUsmapStruct(data, name);
    std::cout << item.name;
    if (item.super) {
        std::cout << " : " << *item.super;
    }
    if (item.package_path) {
        std::cout << " path=" << *item.package_path;
    }
    std::cout << " property_count=" << item.property_count
              << " serializable=" << item.properties.size() << '\n';
    for (const auto& property : item.properties) {
        std::cout << "  schema[" << property.schema_index << "] " << property.name << " : " << property.type;
        if (property.array_dim != 1) {
            std::cout << '[' << static_cast<unsigned>(property.array_dim) << ']';
        }
        std::cout << '\n';
    }
}

} // namespace arc
