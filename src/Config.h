#pragma once

#include "Chain.h"
#include "Pattern.h"

#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <string>

namespace arc {

struct BuildConfig {
    std::string process_name;
    std::string module_name;
    std::optional<std::uint64_t> file_size;
    std::optional<std::uint32_t> pe_timestamp;
};

struct Config {
    BuildConfig build;
    std::map<std::string, Pattern> signatures;
    std::map<std::string, PointerChainSpec> chains;

    static Config Load(const std::filesystem::path& path);
    static Config Parse(const std::string& text);
};

} // namespace arc
