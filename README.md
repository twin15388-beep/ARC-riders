# ARC Raiders external inspection tools

C++20, x64 Windows utilities for exact-build PE/process/dump inspection and Unreal `.usmap` schema reading. The project is read-only. It does **not** currently provide ESP, aim assistance, writes, hooks, an overlay, or anti-cheat bypasses.

## Current game status

Measured target: `PioneerGame.exe`, product `pioneer_2.03.x-CL-1450810`, file size `322041712`, PE timestamp `0x6AEB721B`, image base `0x140000000`, image size `0x139F9000`.

The supplied `1450810.usmap` is structurally valid: format v4, uncompressed, 113,898 names, 3,755 enums, 29,100 structs, and `CEXT/PPTH/ENVP` extensions. Its SHA-256 is `313d29e66a93e96e98d65353416e1df90bff31638daa4fd3ce3a8a50fb228f26`. This differs from the hash shown on the public download page, so provenance is recorded but not silently assumed identical.

A `.usmap` contains reflection schemas, not global RVAs or a ready-made SDK. Property `schema[N]` values are ordinals, **not byte offsets**. ARC-specific global encryption and core layouts still require validation against the same process dump.

## Build

Requirements: Windows 11, Visual Studio 2022 with **Desktop development with C++**, CMake 3.24+, x64.

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

Executable: `build\Release\arc_tool.exe`.

Portable isolated checks:

```sh
g++ -std=c++20 -Wall -Wextra -Wpedantic -Werror -Isrc \
  tests/CoreTests.cpp src/Pattern.cpp src/Config.cpp src/Chain.cpp src/Usmap.cpp \
  -o /tmp/arc_core_tests
/tmp/arc_core_tests
```

## `.usmap` inspection

Only uncompressed versions 0-4 are accepted. Parsing checks the complete payload, counts, string/name indices, nested property types, extension boundaries, and PPTH cardinality. Unknown extensions are skipped by their declared length.

```powershell
.\arc_tool.exe usmap "$env:USERPROFILE\Downloads\1450810.usmap"
.\arc_tool.exe usmap-struct "$env:USERPROFILE\Downloads\1450810.usmap" World
.\arc_tool.exe usmap-struct "$env:USERPROFILE\Downloads\1450810.usmap" PlayerCameraManager
.\arc_tool.exe usmap-struct "$env:USERPROFILE\Downloads\1450810.usmap" PioneerPlayerCharacter
```

Unreal core classes in this mapping use names such as `World`, `Actor`, `Object`, and `PlayerCameraManager`, without `U`/`A` prefixes.

## Dump inspection

```powershell
$a = "$env:USERPROFILE\Downloads\arc_tool.exe"
$d = "$env:USERPROFILE\AppData\Local\Temp\PioneerGame.DMP"
& $a dump $d
& $a dump-read $d 0x1509BB1C0 0x10
& $a dump-strings $d "SeamlessTravel"
& $a dump-scan $d "48 8B 05 ?? ?? ?? ??"
& $a dump-xrefs $d 0xA6A00000
& $a dump-gobjects-check $d 0x14DE04650
```

`dump-read` accepts at most 4096 bytes. Other discovery commands are listed by running `arc_tool.exe` without arguments. Structural candidates are not validated globals merely because a scanner prints them.

## Live inspection

```powershell
.\arc_tool.exe modules <pid>
.\arc_tool.exe inspect <pid> .\config\arc_raiders.ini
```

`inspect` validates process/module identity, file size, and PE timestamp before configured AOB scans or pointer chains. Empty settings are unset, never zero. Runtime VAs are ASLR-dependent; store build constants as RVAs with provenance.

## Verification boundary

- Build-verified: Windows AMD64 PE cross-compilation with LLVM/MinGW, warnings as errors.
- Isolated checks: portable core tests plus ASan/UBSan; the supplied 5.4 MB `.usmap` parses completely.
- Not established: exact global `FNamePool`, `GUObjectArray`, `GWorld`, decryption routines, byte offsets, generated SDK, ESP, or any in-game behavior.
- Public candidate `base+0x109BB1C0` is rejected for the supplied dump because its first pointer is zero. Other public candidates remain unvalidated until their pointed data and decryption are checked.

## Build-specific viewport candidate

`ArcDecrypt.*` isolates the published CL-1450810 viewport transform. It accepts the complete `0x100`-byte bank at LocalPlayer `+0x100`; it does not read process memory or claim runtime validation. The public global and chain have structural support in one supplied dump. The decryptor has a real-byte vector test and produces an object-shaped viewport candidate; its World pointer currently differs from the pointer-chain endpoint, so class/world validation remains open.
