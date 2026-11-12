#ifdef _WIN32

#include "Config.h"
#include "DumpFile.h"
#include "PeFile.h"
#include "Process.h"
#include "Scanner.h"
#include "Usmap.h"
#include "ArcDecrypt.h"

#include <windows.h>

#include <filesystem>
#include <iomanip>
#include <iomanip>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void PrintAddress(const std::uintptr_t address) {
    std::cout << "0x" << std::hex << std::uppercase << std::setw(16) << std::setfill('0') << address
              << std::dec << std::nouppercase << std::setfill(' ');
}

void Usage() {
    std::cout
        << "arc_tool modules <pid>                 List measured module identities\n"
        << "arc_tool inspect <pid> <config.ini>    Validate build, scan signatures, resolve chains\n"
        << "arc_tool file <game.exe>               Inspect an on-disk PE and engine marker strings\n"
        << "arc_tool dump <game.dmp>               Inspect MDMP modules, memory and engine strings\n"
        << "arc_tool dump-strings <game.dmp> <text>  Find a string in captured memory\n"
        << "arc_tool dump-xrefs <game.dmp> <VA>      Find little-endian pointers to VA\n"
        << "arc_tool dump-rip-xrefs <game.dmp> <VA>  Find RIP-relative LEA references\n"
        << "arc_tool dump-scan <game.dmp> <AOB>      Find an AOB pattern in captured memory\n"
        << "arc_tool dump-read <game.dmp> <VA> <size>  Hex-dump up to 4096 bytes\n"
        << "arc_tool dump-chain <game.dmp> <VA> [offset ...]  Read pointer, then pointer+offset steps\n"
        << "arc_tool dump-chain-scan <game.dmp> <base> <image_size> <offset ...>  Find captured chains\n"
        << "arc_tool dump-gnames <game.dmp> <base> <image_size>  Validate FNamePool candidates\n"
        << "arc_tool dump-gobjects <game.dmp> <data_VA> <data_size>  Validate GUObjectArray candidates\n"
        << "arc_tool dump-gobjects-check <game.dmp> <objects_VA>  Check UObject item layouts\n"
        << "arc_tool dump-gnames-lazy <game.dmp> <base> <image_size>  Validate lazy FNamePool refs\n"
        << "arc_tool usmap <file.usmap>             Validate and summarize an uncompressed usmap\n"
        << "arc_tool usmap-struct <file.usmap> <name>  Print schema properties (not byte offsets)\n";
}

std::uint32_t ParsePid(const char* text) {
    const auto pid = arc::ParseUnsigned(text);
    if (pid == 0 || pid > UINT32_MAX) {
        throw std::invalid_argument("PID must be in range 1..4294967295");
    }
    return static_cast<std::uint32_t>(pid);
}

void PrintModule(const arc::ModuleInfo& module) {
    std::cout << arc::WideToUtf8(module.name) << " base=";
    PrintAddress(module.base);
    std::cout << " size=0x" << std::hex << module.size << std::dec;
    std::error_code error;
    const auto file_size = std::filesystem::file_size(module.path, error);
    if (error) {
        std::cout << " file_size=unavailable";
    } else {
        std::cout << " file_size=" << file_size;
    }
    try {
        std::cout << " pe_timestamp=0x" << std::hex << arc::ReadPeFileTimestamp(module.path) << std::dec;
    } catch (const std::exception&) {
        std::cout << " pe_timestamp=unavailable";
    }
    std::cout << '\n';
}

void ValidateBuild(
    const std::vector<arc::ModuleInfo>& modules,
    const arc::Config& config,
    const arc::ModuleInfo& module) {
    if (config.build.process_name.empty() || config.build.module_name.empty() ||
        !config.build.file_size || !config.build.pe_timestamp) {
        throw std::runtime_error(
            "build identity is incomplete; set process_name, module_name, file_size and pe_timestamp from `arc_tool modules <pid>`");
    }
    if (modules.empty() || ::CompareStringOrdinal(
            modules.front().name.c_str(), -1,
            arc::Utf8ToWide(config.build.process_name).c_str(), -1, TRUE) != CSTR_EQUAL) {
        throw std::runtime_error("process_name does not match the target executable");
    }

    std::error_code error;
    const auto actual_size = std::filesystem::file_size(module.path, error);
    if (error) {
        throw std::runtime_error("cannot measure configured module file size: " + error.message());
    }
    if (actual_size != *config.build.file_size) {
        throw std::runtime_error("module file size does not match the configured build");
    }
    const auto actual_timestamp = arc::ReadPeFileTimestamp(module.path);
    if (actual_timestamp != *config.build.pe_timestamp) {
        throw std::runtime_error("module PE timestamp does not match the configured build");
    }
    std::cout << "Build identity validated: " << arc::WideToUtf8(module.name)
              << " file_size=" << actual_size
              << " pe_timestamp=0x" << std::hex << actual_timestamp << std::dec << '\n';
}

int Modules(const std::uint32_t pid) {
    const auto process = arc::Process::Open(pid);
    const auto modules = process.Modules();
    for (const auto& module : modules) {
        PrintModule(module);
    }
    return 0;
}

int Inspect(const std::uint32_t pid, const std::filesystem::path& config_path) {
    const auto config = arc::Config::Load(config_path);
    const auto process = arc::Process::Open(pid);
    const auto modules = process.Modules();
    if (config.build.module_name.empty()) {
        throw std::runtime_error("module_name is unset; run `arc_tool modules <pid>` first");
    }
    const auto& module = arc::FindModule(modules, config.build.module_name);
    ValidateBuild(modules, config, module);

    bool failed = false;
    std::map<std::string, std::uintptr_t> unique_signatures;
    for (const auto& [name, pattern] : config.signatures) {
        try {
            const auto matches = arc::ScanModule(process, module, pattern);
            std::cout << "signature " << name << " matches=" << matches.size() << '\n';
            for (const auto match : matches) {
                std::cout << "  VA=";
                PrintAddress(match);
                std::cout << " RVA=0x" << std::hex << (match - module.base) << std::dec << '\n';
            }
            if (matches.size() == 1) {
                unique_signatures.emplace(name, matches.front());
            }
        } catch (const std::exception& error) {
            failed = true;
            std::cerr << "signature " << name << " failed: " << error.what() << '\n';
        }
    }

    for (const auto& [name, chain] : config.chains) {
        try {
            const auto result = arc::ResolvePointerChain(process, module, chain, unique_signatures);
            std::cout << "chain " << name << " address=";
            PrintAddress(result);
            std::cout << '\n';
        } catch (const std::exception& error) {
            failed = true;
            std::cerr << "chain " << name << " failed: " << error.what() << '\n';
        }
    }
    if (config.signatures.empty() && config.chains.empty()) {
        std::cout << "Build validated; no signatures or chains are configured.\n";
    }
    return failed ? 1 : 0;
}

} // namespace

int main(int argc, char** argv) {
    try {
        if (argc == 3 && std::string_view(argv[1]) == "modules") {
            return Modules(ParsePid(argv[2]));
        }
        if (argc >= 5 && std::string_view(argv[1]) == "file-rtti") {
            std::vector<std::uint64_t> vtables;
            for (int i = 4; i < argc; ++i) vtables.push_back(arc::ParseUnsigned(argv[i]));
            arc::PrintPeRtti(argv[2], arc::ParseUnsigned(argv[3]), vtables);
            return 0;
        }
        if (argc == 3 && std::string_view(argv[1]) == "file") {
            arc::PrintPeFileInfo(argv[2]);
            return 0;
        }
        if (argc == 3 && std::string_view(argv[1]) == "dump") {
            arc::PrintDumpInfo(argv[2]);
            return 0;
        }
        if (argc == 3 && std::string_view(argv[1]) == "usmap") {
            arc::PrintUsmapInfo(arc::LoadUsmap(argv[2]));
            return 0;
        }
        if (argc == 4 && std::string_view(argv[1]) == "usmap-struct") {
            arc::PrintUsmapStruct(arc::LoadUsmap(argv[2]), argv[3]);
            return 0;
        }
        if (argc == 4 && std::string_view(argv[1]) == "dump-strings") {
            arc::PrintDumpStrings(argv[2], argv[3]);
            return 0;
        }
        if (argc == 4 && std::string_view(argv[1]) == "dump-xrefs") {
            arc::PrintDumpXrefs(argv[2], arc::ParseUnsigned(argv[3]));
            return 0;
        }
        if (argc == 4 && std::string_view(argv[1]) == "dump-rip-xrefs") {
            arc::PrintDumpRipXrefs(argv[2], arc::ParseUnsigned(argv[3]));
            return 0;
        }
        if (argc == 4 && std::string_view(argv[1]) == "dump-scan") {
            arc::PrintDumpScan(argv[2], arc::Pattern::Parse(argv[3]));
            return 0;
        }
        if (argc == 5 && std::string_view(argv[1]) == "dump-read") {
            const auto size = arc::ParseUnsigned(argv[4]);
            if (size > SIZE_MAX) {
                throw std::invalid_argument("dump read size exceeds size_t");
            }
            arc::PrintDumpRead(argv[2], arc::ParseUnsigned(argv[3]), static_cast<std::size_t>(size));
            return 0;
        }
        if (argc >= 5 && std::string_view(argv[1]) == "dump-rtti") {
            std::vector<std::uint64_t> vtables;
            for (int i = 4; i < argc; ++i) vtables.push_back(arc::ParseUnsigned(argv[i]));
            arc::PrintDumpRtti(argv[2], arc::ParseUnsigned(argv[3]), vtables);
            return 0;
        }
        if (argc >= 4 && std::string_view(argv[1]) == "dump-chain") {
            std::vector<std::uint64_t> offsets;
            for (int i = 4; i < argc; ++i) {
                offsets.push_back(arc::ParseUnsigned(argv[i]));
            }
            arc::PrintDumpPointerChain(argv[2], arc::ParseUnsigned(argv[3]), offsets);
            return 0;
        }
        if (argc >= 6 && std::string_view(argv[1]) == "dump-chain-scan") {
            std::vector<std::uint64_t> offsets;
            for (int i = 5; i < argc; ++i) {
                offsets.push_back(arc::ParseUnsigned(argv[i]));
            }
            arc::PrintDumpPointerChainScan(
                argv[2], arc::ParseUnsigned(argv[3]), arc::ParseUnsigned(argv[4]), offsets);
            return 0;
        }
        if (argc == 5 && std::string_view(argv[1]) == "dump-gnames") {
            arc::PrintDumpGNamesCandidates(
                argv[2], arc::ParseUnsigned(argv[3]), arc::ParseUnsigned(argv[4]));
            return 0;
        }
        if (argc == 5 && std::string_view(argv[1]) == "dump-gobjects") {
            arc::PrintDumpGObjectsCandidates(
                argv[2], arc::ParseUnsigned(argv[3]), arc::ParseUnsigned(argv[4]));
            return 0;
        }
        if (argc == 4 && std::string_view(argv[1]) == "dump-gobjects-check") {
            arc::PrintDumpGObjectsCheck(argv[2], arc::ParseUnsigned(argv[3]));
            return 0;
        }
        if (argc == 5 && std::string_view(argv[1]) == "dump-gnames-lazy") {
            arc::PrintDumpGNamesLazyCandidates(
                argv[2], arc::ParseUnsigned(argv[3]), arc::ParseUnsigned(argv[4]));
            return 0;
        }
        if (argc == 4 && std::string_view(argv[1]) == "inspect") {
            return Inspect(ParsePid(argv[2]), argv[3]);
        }
        Usage();
        return 2;
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}

#else

#include <iostream>

int main() {
    std::cerr << "arc_tool must be built for Windows\n";
    return 1;
}

#endif
