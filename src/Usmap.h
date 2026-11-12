#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace arc {

struct UsmapProperty {
    std::uint16_t schema_index{};
    std::uint8_t array_dim{};
    std::string name;
    std::string type;
};

struct UsmapStruct {
    std::string name;
    std::optional<std::string> super;
    std::uint16_t property_count{};
    std::vector<UsmapProperty> properties;
    std::optional<std::string> package_path;
};

struct UsmapData {
    std::uint8_t version{};
    std::uint8_t compression{};
    std::uint32_t name_count{};
    std::uint32_t enum_count{};
    std::vector<UsmapStruct> structs;
    std::vector<std::string> extensions;
};

// Supports uncompressed .usmap versions 0-4. Schema indexes are ordinals, not byte offsets.
UsmapData LoadUsmap(const std::filesystem::path& path);
const UsmapStruct& FindUsmapStruct(const UsmapData& data, std::string_view name);
void PrintUsmapInfo(const UsmapData& data);
void PrintUsmapStruct(const UsmapData& data, std::string_view name);

} // namespace arc
