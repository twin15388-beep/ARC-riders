#ifdef _WIN32

#include "Scanner.h"

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace arc {

std::vector<std::uintptr_t> ScanModule(
    const Process& process,
    const ModuleInfo& module,
    const Pattern& pattern,
    const std::size_t max_results) {
    if (module.base == 0 || module.size == 0) {
        throw std::invalid_argument("module range is empty");
    }
    if (module.size - 1 > std::numeric_limits<std::uintptr_t>::max() - module.base) {
        throw std::overflow_error("module address range overflows uintptr_t");
    }

    constexpr std::size_t chunk_size = 1024 * 1024;
    std::vector<std::uintptr_t> results;
    std::size_t offset = 0;
    while (offset < module.size && results.size() < max_results) {
        const std::size_t amount = std::min(chunk_size + pattern.Size() - 1, module.size - offset);
        const auto bytes = process.Read(module.base + offset, amount);
        const auto matches = FindPattern(bytes, pattern, max_results - results.size());
        for (const std::size_t position : matches) {
            // The overlap belongs to this window only for matches starting in its new chunk.
            if (position < chunk_size || offset + chunk_size >= module.size) {
                results.push_back(module.base + offset + position);
                if (results.size() == max_results) {
                    break;
                }
            }
        }
        offset += std::min(chunk_size, module.size - offset);
    }
    return results;
}

std::uintptr_t ResolvePointerChain(
    const Process& process,
    const ModuleInfo& module,
    const PointerChainSpec& spec,
    const std::map<std::string, std::uintptr_t>& signatures) {
    std::uint64_t base = module.base;
    if (spec.base_kind == ChainBaseKind::Signature) {
        const auto signature = signatures.find(spec.signature_name);
        if (signature == signatures.end()) {
            throw std::runtime_error("chain requires one unique match for signature: " + spec.signature_name);
        }
        base = signature->second;
    }
    const auto initial = CheckedAdd(base, spec.base_offset);
    if (!initial || *initial > std::numeric_limits<std::uintptr_t>::max()) {
        throw std::overflow_error("chain base address overflow");
    }
    std::uintptr_t current = static_cast<std::uintptr_t>(*initial);
    for (const std::uint64_t offset : spec.offsets) {
        const std::uint64_t pointer = process.ReadU64(current);
        if (pointer == 0) {
            throw std::runtime_error("chain reached a null pointer");
        }
        const auto next = CheckedAdd(pointer, offset);
        if (!next || *next > std::numeric_limits<std::uintptr_t>::max()) {
            throw std::overflow_error("chain pointer address overflow");
        }
        current = static_cast<std::uintptr_t>(*next);
    }
    return current;
}

} // namespace arc

#endif
