#!/usr/bin/env bash
# Builds the Linux verification harness for the offline dump modes. The stub windows.h in this directory is
# put first on the include path so the Windows-only sources compile as-is; -Werror keeps them honest.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
out="${ARC_PORT_OUT:-$here/build}"
mkdir -p "$out"
g++ -std=c++20 -g -O1 -Wall -Wextra -Wpedantic -Werror -D_WIN32 \
    -DARC_BUILD_STAMP='"offline-port"' \
    -I"$here" -I"$repo/src" \
    "$here/probe_main.cpp" "$here/shim.cpp" \
    "$repo/src/DumpFile.cpp" "$repo/src/Names.cpp" "$repo/src/Pattern.cpp" "$repo/src/Chain.cpp" \
    -o "$out/probe"
echo "built $out/probe"
