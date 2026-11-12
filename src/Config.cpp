#include "Config.h"

#include <fstream>
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

std::runtime_error LineError(const std::size_t line, const std::string& message) {
    return std::runtime_error("config line " + std::to_string(line) + ": " + message);
}

} // namespace

Config Config::Load(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input) {
        throw std::runtime_error("cannot open config: " + path.string());
    }
    const auto end = input.tellg();
    if (end < 0 || end > 1024 * 1024) {
        throw std::runtime_error("config is empty, unreadable, or larger than 1 MiB: " + path.string());
    }
    std::string text(static_cast<std::size_t>(end), '\0');
    input.seekg(0);
    input.read(text.data(), static_cast<std::streamsize>(text.size()));
    if (!input || input.gcount() != static_cast<std::streamsize>(text.size())) {
        throw std::runtime_error("cannot read complete config: " + path.string());
    }
    return Parse(text);
}

Config Config::Parse(const std::string& text) {
    Config result;
    std::string section;
    std::size_t line_number = 0;
    std::size_t start = 0;
    while (start <= text.size()) {
        const auto newline = text.find('\n', start);
        const auto line_text = text.substr(start, newline - start);
        ++line_number;
        const auto trimmed = Trim(line_text);
        if (!trimmed.empty() && trimmed.front() != '#' && trimmed.front() != ';') {
            if (trimmed.size() >= 2 && trimmed.front() == '[' && trimmed.back() == ']') {
                section = std::string(Trim(trimmed.substr(1, trimmed.size() - 2)));
                if (section != "build" && section != "signatures" && section != "chains") {
                    throw LineError(line_number, "unknown section [" + section + "]");
                }
            } else {
                const auto equals = trimmed.find('=');
                if (equals == std::string_view::npos || section.empty()) {
                    throw LineError(line_number, "expected key=value inside a section");
                }
                const auto key = std::string(Trim(trimmed.substr(0, equals)));
                const auto value = Trim(trimmed.substr(equals + 1));
                if (key.empty()) {
                    throw LineError(line_number, "empty key");
                }
                try {
                    if (section == "build") {
                        if (key == "process_name") {
                            result.build.process_name = std::string(value);
                        } else if (key == "module_name") {
                            result.build.module_name = std::string(value);
                        } else if (key == "file_size") {
                            if (!value.empty()) {
                                result.build.file_size = ParseUnsigned(value);
                            }
                        } else if (key == "pe_timestamp") {
                            if (!value.empty()) {
                                const auto timestamp = ParseUnsigned(value);
                                if (timestamp > std::numeric_limits<std::uint32_t>::max()) {
                                    throw std::invalid_argument("PE timestamp exceeds uint32");
                                }
                                result.build.pe_timestamp = static_cast<std::uint32_t>(timestamp);
                            }
                        } else {
                            throw std::invalid_argument("unknown build key: " + key);
                        }
                    } else if (section == "signatures") {
                        if (!value.empty() && !result.signatures.emplace(key, Pattern::Parse(value)).second) {
                            throw std::invalid_argument("duplicate signature: " + key);
                        }
                    } else if (!value.empty() && !result.chains.emplace(key, ParsePointerChain(value)).second) {
                        throw std::invalid_argument("duplicate chain: " + key);
                    }
                } catch (const std::exception& error) {
                    throw LineError(line_number, error.what());
                }
            }
        }
        if (newline == std::string::npos) {
            break;
        }
        start = newline + 1;
    }
    return result;
}

} // namespace arc
