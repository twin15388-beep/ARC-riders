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

### FName pool recovery from a block anchor

When the strict block chain cannot be validated, the same command now also reports *dense name
tables*: regions whose entries each decode under the measured header but do not follow each other back
to back. Every such table gets one merged pointer sweep over the whole dump, so an `[image]` referrer
line directly yields a `GNames` candidate RVA. `dump-fname-layout <dmp> <va> <window>` reads 0x400 bytes
*before* `<va>` and chains entries backwards to the start of the block (packed-stream measurement,
per-entry `hdr/size/pad`, entry-size histogram, and a `block start hint=0x...` line with a follow-up
command). This is what handles the normal case where a marker search lands in the middle of a pool
block, and it is the path to use when `dump-fname-blocks` reports `anchors=0` but prints a dense table.

`dump-fname-blocks` starts from data that can be read instead of from a guessed global address: it
locates the pool block whose first entry decodes as `None`, identifies the block header by checking
which candidate offset makes the following pointer land on another decodable block, walks the block
chain, and then lists every captured pointer to those blocks. An in-image referrer is a `GNames`
candidate with a stable RVA; a heap referrer is only valid inside the dump. It also prints the computed
pool indices (`(block << 16) | entry_offset / 2`) for the engine names the ESP chain needs.

```powershell
.\arc_tool.exe dump-fname-blocks $d 0x140000000 0x139F9000
.\arc_tool.exe dump-fname-blocks $d 0x140000000 0x139F9000 0xA6A00000   # explicit block anchor
.\arc_tool.exe dump-fname-blocks $d 0x140000000 0x139F9000 0 0x20000 64 4096 "None,Actor"
```

Several markers are searched, not just `None`, and the per-marker hit counts are printed
(`marker_hits=1140 (None=1140,ByteProperty=0,...)`), because `None`-anchored discovery on the real dump
landed on a `[0x03][A][NUL][B][NUL][lower(A)][NUL]` alias table instead of the pool. An explicit anchor VA
that the dump did not capture prints `anchor=0x... captured=no` and falls through to marker discovery, so
one run separates a missing region from an unknown entry header.

Discovery assumes a block begins where its first entry begins, and that a `FBlockInfo`-style header of
`0x8..0x30` bytes precedes the entry data. No 128 KB alignment of the block is assumed, and no
contiguous run of "named" blocks is required. `dump-fname-pool` keeps the older shape predicate
(aligned block base derived by masking the entry address, plus a run of eight blocks that each contain
one of ten names) and is superseded: that conjunction cannot pass on a UE5 block layout, so
`validated_pools=0` from it is not evidence about the game.

Entry-header encoding is chosen by measurement. `Names.h` carries two candidate codecs; the report
names the one that actually decoded the block, so the encoding is a result rather than an assumption.
Neither codec decoded this build: on `PioneerGame (3).DMP` the report was
`marker_hits=1140 region_probes=1004 anchors=0`, so no candidate `None`-anchored block reached
`min_entries=64`. That is a statement about the codecs, not about the pool being absent, so the run now
also prints what the bytes do say (below) instead of stopping at a failed hypothesis.

### Measuring the FName entry layout

When the strict walk is rejected, the same discovery pass ranks the examined regions by string density
and prints, for the top eight: the number of printable runs, the byte gap between consecutive strings,
the first string, and 64 raw bytes. A single dominant gap means a fixed entry stride; alternating gaps
mean extra per-entry fields; the raw bytes show the header word next to the text. `dump-fname-layout`
applies the identical measurement to any address, in a dump or in the live process
(`live-fname-layout`), and is deliberately independent of the header encoding: it lists ASCII runs, the
16-bit word immediately before each one, and the hex dump, which is enough to read the entry header off
the data rather than pick it from a table.

```powershell
.\arc_tool.exe dump-fname-layout $d 0x20000100 0x400 512
.\arc_tool.exe live-fname-layout <pid> 0x7ff677700000 0x400 512
```

### Access probe for a live process

A handle can be granted with `PROCESS_VM_READ` silently stripped, so the decisive question is whether a
read succeeds, not whether `OpenProcess` returned. `probe` prints the per-rights result, the token's
elevation and `SeDebugPrivilege` state, the module list recovered through `NtQueryInformationProcess`
and the PEB (no Toolhelp), the MZ check at the image base, and reads of up to five private committed
regions. The PEB walk is cross-checked against Toolhelp and reported as
`peb_walk validation: modules=N bases_also_in_toolhelp=K`, because a walk shifted by one list offset
still prints plausible-looking first entries; a disagreement tells you to trust Toolhelp. Module sizes
are additionally measured from the image's own headers in memory (`live_pe_headers ... SizeOfImage`),
since a size read out of an `LDR_DATA_TABLE_ENTRY` disagreed with the dump's PE header on this build.

On the observed run (`probe 14292`) every right was granted, `SeDebugPrivilege` was enabled, the MZ
check passed, and `private_region_reads=5 of 5`: external user-mode reads work against this build, and
the module list is reachable through Toolhelp (77 modules).

```powershell
.\arc_tool.exe probe <pid>
.\arc_tool.exe probe-write <pid>
```

`probe-write` measures remote allocation through `ntdll!NtAllocateVirtualMemory` and a
`VirtualProtectEx` call with the page's own protection (a semantic no-op for the target). On the observed
build, `OpenProcess` granted all eight rights and `ReadProcessMemory` succeeded 5 of 5 while
`VirtualAllocEx` returned error 5 with `SeDebugPrivilege` enabled, which is why injection is treated as
closed and `probe-write` does not write to game-owned memory: it only writes to a page it reserved
itself.

`arc_tool version` prints the embedded build stamp, and every FName report repeats it, because running
a stale executable otherwise looks like a negative result about the game.

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
- Not established: exact global `FNamePool`, `GUObjectArray`, `GWorld`, decryption routines, byte offsets, generated SDK, ESP, or any in-game behavior. `dump-fname-blocks` was verified end to end against a synthetic MDMP (three chained blocks, unaligned block data, in-image referrer) built for that purpose, and run against the real 12.95 GB game dump, where both shipped codecs failed to anchor a block (`anchors=0`) — the layout must still be measured. No ESP, aim, or in-game behavior has been run at all.
- Public candidate `base+0x109BB1C0` is rejected for the supplied dump because its first pointer is zero. Other public candidates remain unvalidated until their pointed data and decryption are checked.

## Build-specific viewport candidate

`ArcDecrypt.*` isolates the published CL-1450810 viewport transform. It accepts the complete `0x100`-byte bank at LocalPlayer `+0x100`; it does not read process memory or claim runtime validation. The public global and chain have structural support in one supplied dump. The decryptor has a real-byte vector test and produces an object-shaped viewport candidate; its World pointer targets a zero-vtable data block rather than UWorld, so it is rejected as a validated GameViewportClient.
