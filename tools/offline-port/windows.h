#pragma once

// Minimal stand-in for <windows.h>, enough for the headers the offline dump code includes (PeFile.h and
// Process.h only need HANDLE). This exists so the Windows-only translation units in src/ can be compiled
// and run on Linux against a synthetic .dmp; it is never part of the Windows build.

#include <cstddef>
#include <cstdint>

using HANDLE = void*;
using DWORD = std::uint32_t;
