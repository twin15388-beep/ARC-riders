#ifdef _WIN32

#include "Config.h"
#include "DumpFile.h"
#include "PeFile.h"
#include "Process.h"
#include "Scanner.h"
#include "Usmap.h"
#include "ArcDecrypt.h"
#include "Version.h"

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
        << "arc_tool dump-fname-pool <game.dmp> <base> <image_size>  Superseded shape scan\n"
        << "arc_tool dump-fname-blocks <game.dmp> <base> <image_size> [block0_VA] [block_size] [min_entries] [max_blocks] [markers] [names_out.txt]  Recover the FName pool from a decodable block; the page sweep finds every block and [names_out.txt] writes ordinal\\tname for the whole pool\n"
        << "arc_tool dump-fname-layout <game.dmp> <VA> [window] [max_hits]  Measure the entry layout of a region\n"
        << "arc_tool live-fname-layout <pid> <VA> [window] [max_hits]  Measure the entry layout of live process memory\n"
        << "arc_tool probe <pid>                     Report which process rights are granted\n"
        << "arc_tool probe-write <pid>              Test remote allocation and writes (decides in-process tooling)\n"
        << "arc_tool version                          Print the embedded build stamp\n"
        << "arc_tool dump-scan <game.dmp> <AOB>      Find an AOB pattern in captured memory\n"
        << "arc_tool dump-read <game.dmp> <VA> <size>  Hex-dump up to 4096 bytes\n"
        << "arc_tool esp-actors <game.dmp> <base> <size> [min_num] [out.ini]  Sweep captured memory for\n"
        << "                                         the actor array and derive positions from it\n"
        << "arc_tool esp-chain <game.dmp> <base> <size> [global_rva] [\"chain\"] [out.ini]  Derive\n"
        << "                                         the ESP object graph from a dump by structural\n"
        << "                                         tests (defaults: 0x108FEEC0, \"0xA0,0x250,0x160\")\n"
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
    const std::string_view command = argc >= 2 ? std::string_view(argv[1]) : std::string_view{};
    try {
        if (argc == 2 && std::string_view(argv[1]) == "version") {
            std::cout << "arc_tool build=" << arc::kBuildStamp << '\n';
            return 0;
        }
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
        if (argc == 5 && std::string_view(argv[1]) == "dump-fname-pool") {
            arc::PrintDumpFNamePool(argv[2], arc::ParseUnsigned(argv[3]), arc::ParseUnsigned(argv[4]));
            return 0;
        }
        if (argc >= 4 && std::string_view(argv[1]) == "live-fname-layout") {
            const auto window = argc >= 5 ? arc::ParseUnsigned(argv[4]) : 0x4000;
            const auto max_hits = argc >= 6 ? arc::ParseUnsigned(argv[5]) : 512;
            if (window > UINT32_MAX) {
                throw std::invalid_argument("window must fit uint32");
            }
            arc::PrintProcessFNameLayout(ParsePid(argv[2]), arc::ParseUnsigned(argv[3]),
                static_cast<std::uint32_t>(window), static_cast<std::size_t>(max_hits));
            return 0;
        }
        if (argc >= 4 && std::string_view(argv[1]) == "dump-fname-layout") {
            const auto window = argc >= 5 ? arc::ParseUnsigned(argv[4]) : 0x4000;
            const auto max_hits = argc >= 6 ? arc::ParseUnsigned(argv[5]) : 512;
            if (window > UINT32_MAX || max_hits > SIZE_MAX) {
                throw std::invalid_argument("window must fit uint32 and max_hits size_t");
            }
            arc::PrintDumpFNameLayout(argv[2], arc::ParseUnsigned(argv[3]),
                static_cast<std::uint32_t>(window), static_cast<std::size_t>(max_hits));
            return 0;
        }
        if (argc >= 5 && std::string_view(argv[1]) == "dump-fname-blocks") {
            const auto anchor = argc >= 6 ? arc::ParseUnsigned(argv[5]) : 0;
            const auto block_size = argc >= 7 ? arc::ParseUnsigned(argv[6]) : 0x20000;
            const auto min_entries = argc >= 8 ? arc::ParseUnsigned(argv[7]) : 64;
            const auto max_blocks = argc >= 9 ? arc::ParseUnsigned(argv[8]) : 4096;
            if (block_size > UINT32_MAX || min_entries > UINT32_MAX || max_blocks > SIZE_MAX) {
                throw std::invalid_argument("block_size/min_entries must fit uint32 and max_blocks size_t");
            }
            // Trailing options come in either order and PowerShell drops an empty "" argument, so
            // classify by shape instead of position: anything ending in .txt is the names-file path.
            std::string_view marker_list;
            std::filesystem::path names_out;
            for (int i = 9; i < argc; ++i) {
                const std::string_view arg{argv[i]};
                if (arg.size() > 4 && arg.compare(arg.size() - 4, 4, ".txt") == 0) {
                    names_out = arg;
                } else if (!arg.empty()) {
                    marker_list = arg;
                }
            }
            arc::PrintDumpFNameBlocks(argv[2], arc::ParseUnsigned(argv[3]), arc::ParseUnsigned(argv[4]),
                anchor, static_cast<std::uint32_t>(block_size), static_cast<std::uint32_t>(min_entries),
                static_cast<std::size_t>(max_blocks), marker_list, names_out);
            return 0;
        }
        if (argc >= 4 && std::string_view(argv[1]) == "esp-actors") {
            // esp-actors <game.dmp> <base> <image_size> [min_num] [out.ini] - same shape classification,
            // so the threshold may be left out and the output path given as a bare last argument.
            std::uint64_t min_num = 64;
            bool have_min = false;
            std::filesystem::path out_path;
            for (int i = 5; i < argc; ++i) {
                const std::string_view arg{argv[i]};
                if (arg.size() > 4 && (arg.compare(arg.size() - 4, 4, ".ini") == 0 ||
                        arg.compare(arg.size() - 4, 4, ".txt") == 0)) {
                    out_path = arg;
                    continue;
                }
                if (!have_min) {
                    try {
                        min_num = arc::ParseUnsigned(arg);
                        have_min = true;
                        continue;
                    } catch (const std::exception&) {
                    }
                }
                throw std::invalid_argument("esp-actors takes [min_num] then [out.ini]");
            }
            arc::PrintDumpEspActors(argv[2], arc::ParseUnsigned(argv[3]), arc::ParseUnsigned(argv[4]),
                static_cast<std::uint32_t>(min_num), out_path);
            return 0;
        }
        if (argc >= 4 && std::string_view(argv[1]) == "esp-chain") {
            // esp-chain <game.dmp> <base> <image_size> [global_rva] [off1,off2,...] [out.ini]
            // Trailing arguments are classified by shape, not by position: PowerShell drops an empty
            // "" positional, so "skip the chain, keep the ini" has to work without a placeholder.
            std::uint64_t global_rva = 0x108FEEC0;
            bool have_rva = false;
            std::string_view chain_list;
            std::filesystem::path ini_out;
            for (int i = 5; i < argc; ++i) {
                const std::string_view arg{argv[i]};
                if (arg.size() > 4 && arg.compare(arg.size() - 4, 4, ".ini") == 0) {
                    ini_out = arg;
                    continue;
                }
                if (arg.find(',') != std::string_view::npos) {
                    chain_list = arg;  // "0xA0,0x250,0x160" - quote it, PowerShell splits on spaces
                    continue;
                }
                if (!have_rva) {
                    try {
                        global_rva = arc::ParseUnsigned(arg);
                        have_rva = true;
                        continue;
                    } catch (const std::exception&) {
                    }
                }
                chain_list = arg;  // a single offset with no comma, e.g. "0x250"
            }
            arc::PrintDumpEspChain(argv[2], arc::ParseUnsigned(argv[3]), arc::ParseUnsigned(argv[4]),
                global_rva, chain_list, ini_out);
            return 0;
        }
        if (argc == 3 && std::string_view(argv[1]) == "probe") {
            arc::PrintProcessProbe(ParsePid(argv[2]));
            return 0;
        }
        if (argc == 3 && std::string_view(argv[1]) == "probe-write") {
            arc::PrintProcessWriteProbe(ParsePid(argv[2]));
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
        // A missing argument usually means an empty PowerShell variable reached the command line
        // ("arc_tool.exe probe" with no PID), and a usage block inside a redirected report file reads
        // like a result. Name the argument and the variable instead.
        static constexpr std::pair<std::string_view, std::string_view> kNeedsPid[]{
            {{"probe"}, {"probe <pid>"}},
            {{"probe-write"}, {"probe-write <pid>"}},
            {{"live-fname-layout"}, {"live-fname-layout <pid> <VA> [window] [max_hits]"}},
            {{"modules"}, {"modules <pid>"}},
            {{"inspect"}, {"inspect <pid> <config.ini>"}},
        };
        for (const auto& [name, form] : kNeedsPid) {
            if (command == name) {
                std::cerr << "error: \"" << name << "\" needs a PID. In PowerShell:  "
                             "$p=(Get-Process PioneerGame).Id  - and check $p is not empty before the "
                             "call.  usage: arc_tool "
                          << form << '\n';
                return 2;
            }
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
