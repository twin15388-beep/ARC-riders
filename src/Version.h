#pragma once

#include <string_view>

// Build provenance. Pass -DARC_BUILD_STAMP="..." when compiling so the stamp appears in every report;
// the default value makes an untagged build obvious instead of looking like a current one.
#ifndef ARC_BUILD_STAMP
#define ARC_BUILD_STAMP "untagged"
#endif

namespace arc {

inline constexpr std::string_view kBuildStamp = ARC_BUILD_STAMP;

} // namespace arc
