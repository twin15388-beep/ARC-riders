#pragma once

#ifdef _WIN32

#include "Chain.h"
#include "Pattern.h"
#include "Process.h"

#include <cstdint>
#include <map>
#include <vector>

namespace arc {

[[nodiscard]] std::vector<std::uintptr_t> ScanModule(
    const Process& process,
    const ModuleInfo& module,
    const Pattern& pattern,
    std::size_t max_results = 128);

[[nodiscard]] std::uintptr_t ResolvePointerChain(
    const Process& process,
    const ModuleInfo& module,
    const PointerChainSpec& spec,
    const std::map<std::string, std::uintptr_t>& signatures);

} // namespace arc

#endif
