// Entry point for the Linux verification harness. It mirrors the argument handling of src/Main.cpp for the
// offline dump modes only, so `tools/offline-port/build.sh && tools/offline-port/run.sh` can gate a change
// against tools/offline-port/mkesp.py without a Windows box and without touching the live game.
#include "DumpFile.h"
#include "Esp.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {

std::uint64_t ParseUnsigned(const std::string_view text) {
    const std::string value{text};
    if (value.empty()) {
        throw std::invalid_argument("empty number");
    }
    const char* begin = value.c_str();
    char* end = nullptr;
    const auto parsed = std::strtoull(begin, &end, 0);
    if (end == begin || *end != '\0') {
        throw std::invalid_argument("invalid unsigned integer: " + value);
    }
    return parsed;
}

bool EndsWith(const std::string_view text, const std::string_view suffix) {
    return text.size() > suffix.size() && text.compare(text.size() - suffix.size(), suffix.size(), suffix) == 0;
}

}  // namespace

int main(int argc, char** argv) try {
    if (argc < 2) {
        std::cout << "offline harness: esp-chain <dmp> <base> <size> [global_rva] [chain] [out.ini]\n"
                     "                   esp-actors <dmp> <base> <size> [min_num] [out.ini]\n"
                     "                   dump-read <dmp> <va> <size>\n";
        return 2;
    }
    const std::string_view mode{argv[1]};
    if (mode == "esp-chain" && argc >= 4) {
        std::uint64_t global_rva = 0x108FEEC0;
        bool have_rva = false;
        std::string_view chain_list;
        std::filesystem::path ini_out;
        for (int i = 5; i < argc; ++i) {
            const std::string_view arg{argv[i]};
            if (EndsWith(arg, ".ini") || EndsWith(arg, ".txt")) {
                ini_out = arg;
                continue;
            }
            if (arg.find(',') != std::string_view::npos) {
                chain_list = arg;
                continue;
            }
            if (!have_rva) {
                try {
                    global_rva = ParseUnsigned(arg);
                    have_rva = true;
                    continue;
                } catch (const std::exception&) {
                }
            }
            chain_list = arg;
        }
        arc::PrintDumpEspChain(argv[2], ParseUnsigned(argv[3]), ParseUnsigned(argv[4]), global_rva,
            chain_list, ini_out);
        return 0;
    }
    if (mode == "esp-export") {
        // The same parser the Windows main() uses, so the gate exercises the shipped argument handling.
        const auto request = arc::ParseExportArgs({argv + 2, argv + argc});
        if (!request) {
            throw std::invalid_argument("esp-export <dmp> <base> <size> <config.ini> [out.js] [rows]");
        }
        arc::PrintDumpEspExport(request->dump, request->base, request->image_size, request->config,
            request->out, static_cast<std::size_t>(request->rows));
        return 0;
    }
    if (mode == "esp-overlay") {
        const auto request = arc::ParseOverlayArgs({argv + 2, argv + argc});
        if (!request) {
            throw std::invalid_argument("esp-overlay <out.html> [demo]");
        }
        std::ofstream page(request->html.string());
        if (!page) {
            throw std::invalid_argument("cannot write " + request->html.string());
        }
        page << arc::OverlayHtml();
        if (request->demo) {
            std::ofstream js(arc::SiblingPath(request->html, "esp-data.js").string());
            js << arc::DemoOverlayData();
        }
        std::cout << "overlay written to " << request->html.string()
                  << (request->demo ? " (plus demo esp-data.js)" : "") << "\n";
        return 0;
    }
    if (mode == "esp-actors" && argc >= 4) {
        std::uint64_t min_num = 64;
        bool have_min = false;
        std::filesystem::path out_path;
        for (int i = 5; i < argc; ++i) {
            const std::string_view arg{argv[i]};
            if (EndsWith(arg, ".ini") || EndsWith(arg, ".txt")) {
                out_path = arg;
                continue;
            }
            if (!have_min) {
                min_num = ParseUnsigned(arg);
                have_min = true;
                continue;
            }
            throw std::invalid_argument("esp-actors takes [min_num] then [out.ini]");
        }
        arc::PrintDumpEspActors(argv[2], ParseUnsigned(argv[3]), ParseUnsigned(argv[4]),
            static_cast<std::uint32_t>(min_num), out_path);
        return 0;
    }
    if (mode == "dump-read" && argc >= 4) {
        arc::PrintDumpRead(argv[2], ParseUnsigned(argv[3]), argc >= 5 ? static_cast<std::size_t>(ParseUnsigned(argv[4])) : 64);
        return 0;
    }
    if (mode == "dump-fname-blocks" && argc >= 4) {
        const auto anchor = argc >= 6 ? ParseUnsigned(argv[5]) : 0;
        const auto block_size = argc >= 7 ? ParseUnsigned(argv[6]) : 0x20000;
        const auto min_entries = argc >= 8 ? ParseUnsigned(argv[7]) : 64;
        const auto max_blocks = argc >= 9 ? ParseUnsigned(argv[8]) : 4096;
        arc::PrintDumpFNameBlocks(argv[2], ParseUnsigned(argv[3]), ParseUnsigned(argv[4]), anchor,
            static_cast<std::uint32_t>(block_size), static_cast<std::uint32_t>(min_entries),
            static_cast<std::size_t>(max_blocks), argc >= 10 ? std::string_view(argv[9]) : std::string_view{},
            argc >= 11 ? std::filesystem::path(argv[10]) : std::filesystem::path{});
        return 0;
    }
    throw std::runtime_error("unknown mode");
} catch (const std::exception& error) {
    std::cerr << "error: " << error.what() << "\n";
    return 1;
}
