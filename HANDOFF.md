# Handoff

## Request and constraints

ARC Raiders external C++20 x64 inspection/reverse-engineering foundation; any useful functionality is acceptable. Never invent offsets, signatures, layouts, prototypes, vtable indices, build compatibility, or test results. Keep build values in one resolver/config with provenance and address type. Unset is distinct from zero. ESP/gameplay remains gated on exact-build evidence.

## Measured target and artifacts

- Product: `pioneer_2.03.x-CL-1450810`; engine file version `5.7.4.0`.
- Module: `PioneerGame.exe`; file size `322041712`; PE timestamp `0x6AEB721B`; image base `0x140000000`; image size `0x139F9000`.
- Dump: `C:\Users\Malin\AppData\Local\Temp\PioneerGame.DMP`, size `10,477,962,957`.
- User ZIP: Dropbox file `/1450810_[unknowncheats.me]_.zip`, 1,488,164 bytes, rev `66016a43183064b309220`.
- Extracted `1450810.usmap`: 5,435,248 bytes; SHA-256 `313d29e66a93e96e98d65353416e1df90bff31638daa4fd3ce3a8a50fb228f26`.
- The public file page listed a different SHA-256 (`ce99...`). The supplied file itself is structurally valid; do not claim byte identity with that listing.

## Newly implemented

- `src/Usmap.h`, `src/Usmap.cpp`: bounded uncompressed `.usmap` v0-v4 parser; validates header, counts, names, enums, nested properties, CEXT/extensions, PPTH paths. No decompression support.
- CLI: `arc_tool usmap <file>` and `arc_tool usmap-struct <file> <name>`.
- `tests/CoreTests.cpp`: synthetic valid/truncated usmap checks in addition to existing core tests.
- `CMakeLists.txt`: `Usmap.cpp` added to `arc_core`.
- `README.md`: current commands and verification boundary.

Important: usmap property indices are schema ordinals, not memory offsets. Core types are named `Object`, `World`, `Actor`, etc. The mapping does not reveal encrypted global RVAs or non-reflected UObject/UStruct layouts.

## Exact usmap result

Portable parser fully consumed the supplied file:

`version=4 compression=0 names=113898 enums=3755 structs=29100 extensions=CEXT,PPTH,ENVP`

Examples successfully queried: `World`, `PlayerCameraManager`, `PioneerPlayerCharacter`.

## Public candidate reads supplied by user

At `base+0xDB48E80` (`g_FNamePool` candidate): image pointers, not a standard pool; encrypted/custom layout remains possible but unproven.

At `base+0xDE04650` (`g_GObjectArray` candidate):
- `+0x00 = 0x146BFE650`
- `+0x08 = 0x405`
- `+0x20 = 0x14623C820`
- `+0x28 = 0x1400034E0`
These are candidate values only; no object array has been validated.

At `base+0x109BB1C0` (public GWorld chain): 16 zero bytes. Reject this chain for the supplied dump.

Earlier public post also lists `base+0xE011D18` as encrypted GWorld; not yet read.

## Earlier discovery results

- Standard live module enumeration fails with Win32 error 5. Injection reaches `VirtualAllocEx` but fails there with error 5; `LoadLibraryW` never runs. Do not repeat unchanged.
- Six full-dump GUObjectArray structural candidates were all rejected using sequential `UObject::InternalIndex` checks.
- Constructor FNamePool scan: 19,891 candidates, zero valid. Lazy paired-LEA scan: 17 pairs, zero valid.
- Known plaintext FName block at `0xA6A00000` (`None`, `ByteProperty`, etc.); ANSI length shift 6, header offset 0, string offset 2. No direct captured block-table xref found.
- No validated global RVA, decryption, SDK, ESP, or in-game behavior.

## Build and isolated checks

Commands:

```sh
g++ -std=c++20 -Wall -Wextra -Wpedantic -Werror -Isrc \
  tests/CoreTests.cpp src/Pattern.cpp src/Config.cpp src/Chain.cpp src/Usmap.cpp \
  -o /tmp/arc-riders-check/arc_core_tests && /tmp/arc-riders-check/arc_core_tests
```

Exit 0, `All core checks passed`.

The same with `-fsanitize=address,undefined -fno-omit-frame-pointer`: exit 0, `All core checks passed`.

Actual-usmap Linux harness compiled with strict warnings and exited 0; fully parsed the supplied file and printed `World` and `PlayerCameraManager`.

Windows build:

```sh
PYTHONPATH=/tmp/arc-riders-check/zig-package python3 -m ziglang c++ \
  -target x86_64-windows-gnu -std=c++20 -O2 -static \
  -Wall -Wextra -Wpedantic -Werror -DUNICODE -D_UNICODE -Isrc \
  src/Main.cpp src/DumpFile.cpp src/PeFile.cpp src/Process.cpp src/Scanner.cpp \
  src/Pattern.cpp src/Config.cpp src/Chain.cpp src/Usmap.cpp -o out/arc_tool.exe
```

Exit 0. MZ/PE/AMD64 validation passed. Size `1,043,456`; SHA-256 `de11211c2044e1aef26b1400aada08ae47b4a1812ac88b56ad25aab12a5f0036`. MSVC and Windows runtime were not tested here.

## Latest candidate rejection and new lead

User supplied `pioneer_decryption.txt` (UTF-16). The old April candidates are rejected:

- `0x146BFE650`, read through the alleged `g_GObjectArray`, contains ordinary C++ object/string functions with a security-cookie check and calls to `0x1405ECB50`/`0x1405ECD20`; it is not an FUObjectArray or decryptor.
- `0x140391A80` lands among FString extraction/copy routines, not a GUObjectArray accessor.
- `base+0xE011D18` begins with a zero qword and does not yield GWorld.
- Several old key/code addresses are not captured; no value was inferred for them.

UnknownCheats page 230 (posts 4583/4588, 9-10 November 2026) gives a newer candidate for the same patch era: global RVA `0x108FEEC0` (VA `0x1508FEEC0`), followed by pointer reads at `+0xA0`, `+0x250`, `+0x160`. It is described as EmbarkLocalPlayer to World and remains unvalidated until the user runs the chain.

Added `arc_tool dump-chain <dump> <pointer_VA> [offset ...]`, which prints each read VA/value and fails on uncaptured, null, or overflowing steps. Windows build exit 0; size `1,045,504`; SHA-256 `60d9c90b77dd78f3ddc03844903077038c82a59d428424a068e4bdfd2b13891f`; Dropbox rev `66016ffc0f0924b309220`.

## Latest runtime-state blocker

The user ran the November LocalPlayer/World candidate. Result: `step=0 read_VA=0x1509FEEC0 value=0x0`; the chain stops before any dereference. Together with zero at the two earlier GWorld candidates, this strongly suggests the existing dump was captured without an active LocalPlayer/UWorld (for example in a menu/loading state), though that state is not directly proven.

## Gameplay dump and structural scanner

A new active-gameplay dump `C:\Users\Malin\AppData\Local\Temp\PioneerGame (2).DMP` (10,681,401,676 bytes, written 2026-11-12 20:52:23 local) still has `0x1509FEEC0 = 0`. Reject public RVA `0x108FEEC0` for this exact build; stop trying stale public addresses.

Added `dump-chain-scan <dump> <base> <image_size> <offset ...>`: scans aligned captured qwords intersecting the protected image, resolves up to eight pointer+offset steps, requires nonzero 8-aligned values and captured final-pointee data, and emits up to 128 candidates with every step. This finds structural candidates only; names/back-references must validate them.

Strict core tests exit 0. Windows AMD64 build completed after the original bash wait timed out and the still-running process was awaited; final PE validation passed. Size `1,047,040`; SHA-256 `af496b227dcfe7383675bed75861cdd4d9915e26f438ddd32bb9d7586ae0098f`; Dropbox rev `660174b82c63d4b309220`.

## First chain-scan result and scanner correction

The first scan stopped at its cap after only 4,172,216 qwords (before most of `.data`). Its 128 entries mostly duplicated a few heap chains or ended back inside the protected image. No candidate was validated.

Improved `dump-chain-scan`: all chain values must be aligned canonical user pointers outside `[image_base, image_end)`; identical value tuples are printed once; only unique chains count toward the 128 cap. Added sorted ranges and binary-search VA lookup to avoid a linear memory-range lookup at every step. New summary fields are `unique_candidates` and `duplicates_suppressed`.

Strict core tests exit 0. Windows AMD64 build exit 0; size `1,056,256`; SHA-256 `24d6e32511d100f9a6f7324d66b10fbdcba9c277d67939f74e8dd5536f4d360e`; Dropbox rev `660175d9517114b309220`.

## Second chain-scan result and UObject filter

The second scan also stopped early: 10,802,494 qwords, 128 unique chains, 16 duplicates. Most entries were dense non-UObject tables around `0x15039...`. None is validated.

Added the missing semantic check: every chain value must point to captured data whose first qword is a vtable inside the protected game image. LocalPlayer, controller, intermediate reflected object, and UWorld should satisfy this; arbitrary heap tables should not. Summary now includes `pointer_chains` and `unique_uobject_candidates`.

Strict core tests exit 0. Windows AMD64 build exit 0; size `1,056,256`; SHA-256 `24dc0f90b7392c3b9b827873fa9c30eed96172a279db3b91d9a769231a9c0399`; Dropbox rev `660176cde98aa4b309220`.

## Validated structural chain candidate

The v3 scan found exactly one chain among 25,905 pointer-chain shapes after 17,916,928 captured image qwords:

- Global VA `0x1508FEEC0` = module base + RVA `0x108FEEC0`.
- step0 / LocalPlayer candidate `0x1DBCF5730`.
- step1 / PlayerController candidate `0x2A0498890` from `+0xA0`.
- step2 reflected-object candidate `0x2A0548A70` from `+0x250`.
- step3 / UWorld candidate `0x1F53F1D00` from `+0x160`.

Every value is an aligned captured heap pointer outside the image with a first-qword vtable inside the protected image. This is strong structural validation but not yet class-name or world back-reference validation.

Critical correction: earlier manual VA arithmetic was wrong by `0x100000`. `0x140000000 + 0x108FEEC0 = 0x1508FEEC0`, not `0x1509FEEC0`. The previous zero test used the wrong VA. Do not record public RVA `0x108FEEC0` as rejected; the scan independently recovered the correct VA.

## Shortest next verification step

Hex-dump 0x400 bytes at step0, 0x500 at step1, 0x300 at step2, 0x600 at step3, and 0x20 at `0x150421C80` (public viewport key-material candidate). Validate vtables, controller/local-player relationships, world/level/game-instance pointers and the encrypted viewport bank. No ESP or gameplay reads until these checks succeed.

## Latest structural and viewport result

The v3 chain scan (17,916,928 qwords; 25,905 pointer chains) found exactly one unique UObject chain and no duplicates: `base+0x108FEEC0` (VA `0x1508FEEC0`) -> `0x1DBCF5730` -> `+0xA0` = `0x2A0498890` -> `+0x250` = `0x2A0548A70` -> `+0x160` = `0x1F53F1D00`. Every value has heap storage and a first-qword vtable in the image. Object reads additionally show LocalPlayer `+0xA0` = controller, intermediate `+0x158` = controller and `+0x160` = world. Class names and world/level relations remain unvalidated.

The exact public viewport algorithm is implemented in `ArcDecrypt.*`: slot hashes the address `LocalPlayer+0xF0`; ciphertext is 16 bytes at `LocalPlayer+0x100+slot*0x20`; the seed is the address `base+0x10421C80`. A real-byte test now actually executes and verifies slot 2, key `0xA74474574EF90345`, and viewport `0x1DBDA3550`. The candidate has in-image vtable `0x14E20BE20`, but `Viewport+0x140 = 0x1F53F3D00`, not the chain endpoint `0x1F53F1D00`. Therefore viewport/world equivalence fails so far; read the second world candidate before naming either. Do not use the earlier invented SplitMix-based transform or claim its test passed.

Next command: `dump-read <DMP> 0x1F53F3D00 0x600`. Compare it with captured `0x1F53F1D00` and inspect vtable/object relationships.

## Viewport rejection after object read

`0x1F53F3D00` (read through decrypted candidate `0x1DBDA3550+0x140`) has a zero first qword and a data-only `0x600`-byte body; it is not a UObject/UWorld. The public viewport transform deterministically produces `0x1DBDA3550` and that address has an in-image vtable, but the required World back-reference fails. Reject it as a validated GameViewportClient. The pointer chain remains only structurally supported; class names are still required. No usable viewport, SDK, GObjects, ESP, or gameplay behavior is validated.

## Focused ESP handoff

Current user request: consolidate only information useful to another engineer/AI for implementing ESP, Aim, Trigger, Minimap and ImGui menu UI. See `ESP_HANDOFF_RU.md`. It contains exact measured chain/vtables, dump/USMAP identities, rejected RTTI/GObjects/Levels/viewport paths, the pending FNamePool predicate and command, constructor lead `0x144C364EB`, per-feature missing data and the ordered recovery plan. No ESP/Aim/Trigger/Minimap runtime functionality exists or was observed in-game. Latest FNamePool executable SHA-256 is `9cbf241d21024442e16ee37e5150327f054d19da53e829d1072a47d83fc96d2c`; user accidentally ran an older executable, so the new FNamePool scan remains pending.

## Route review, FName anchor tool, access probe (2026-11-13)

User asked whether the ESP route is right, and to change it if not. Findings, measured from this repo's
own code and from the Dropbox account:

- `dump-fname-pool` cannot pass by construction: it requires the block base to equal `entry & ~0x1FFFF`
  (128 KB-aligned block data), a contiguous run of eight `Chunks` entries that each point at a block
  containing one of ten hard-coded names, and the `Chunks` pointer itself to live outside the image.
  UE5 FNamePool blocks are separate allocations chained through `FBlockInfo::Next`, and engine-core
  names sit in the first blocks, so that conjunction fails even with a perfectly valid pool. The pending
  run was cancelled before it cost the user time; the command is kept and marked superseded.
- Replaced by `dump-fname-blocks`: anchor on the block whose first entry decodes as `None`, measure the
  block-header size by requiring `Next` to land on another decodable block, walk the chain (plus a
  contiguous-stride fallback), print `bytes_before_block` as raw hex, print `(block << 16) | offset / 2`
  pool indices for the names the ESP chain needs, then list every captured pointer to those blocks and
  split it into `[image] RVA=...` (a `GNames` candidate that survives restarts) and `[heap]`.
  New portable code in `src/Names.h`, `src/Names.cpp`; entry-header codec is chosen by measurement from
  two candidates, not assumed.
- Added `arc_tool probe <pid>` (`src/Process.cpp`): per-right `OpenProcess` results, token elevation and
  `SeDebugPrivilege`, module list recovered through `NtQueryInformationProcess` + PEB without Toolhelp,
  MZ check at `PEB.ImageBaseAddress`, and reads of up to five private committed regions. This settles
  the external-vs-internal question with a measurement, because `OpenProcess` can return a handle with
  `PROCESS_VM_READ` stripped by a protection callback.
- Added `arc_tool version` plus a build stamp (`src/Version.h`, `-DARC_BUILD_STAMP`) printed in every
  FName report, so running a stale executable cannot again be read as a negative result about the game.
## Second run results, marker-list discovery, Dumper-7 package (2026-11-13, later the same night)

`dump-fname-blocks` (build `2026-11-13-layout-probe`) on the real dump: `anchors=0`, and the new layout
section showed why. The densest regions are NOT the name pool:

```text
ascii_run block_base=0x30a9218b runs=93 string_to_string=0x5x19,0x4x13,0x6x7,0x20x6 first="None"
    head=00034e6f6e65004e6f6e65006e6f6e65000343616e0043616e6f6e6963616c0063616e0003436f6d00436f6d70617400636f6d0003456e6300436972636c6500
```

Byte-for-byte that is a repeated `[0x03][string A][NUL][string B][NUL][lowercase A][NUL]` table
(`None/None/none`, `Can/Canonical/can`, `Com/Compat/com`, `Enc/Circle/enc`) — a string/alias index with a
one-byte length tag, not `FNameEntry` records. The `partial ... len=1` entries in the `0x7ff8...` /
`0x7fff...` ranges are both codecs misreading ASCII in system DLLs. So a single `None` anchor cannot
distinguish "the pool was not captured" from "names are encoded", which is the only reason the search
changed: `PrintDumpFNameBlocks` now takes a marker list (default
`None,ByteProperty,IntProperty,FloatProperty,ObjectProperty,Class`), reports per-marker hit counts, and an
explicit `block0_VA` that is not captured prints `anchor=0x... captured=no` and falls through to discovery
instead of aborting — coverage and codec now answer in one run.

`Dumper7-ARC-Raiders.zip` was unzipped into `/Dumper7-ARC-Raiders/` and read through the connector. It is
not a dump output: it is the in-process package `arc_inject.exe` (956,416) + `Dumper-7.dll` (2,995,200) +
`Dumper-7.ini` (`SDKGenerationPath=C:/Dumper-7`, `LogFilePath=C:/Dumper-7/dumper7.log`,
`ShouldAutoUnload=1`) + `README.txt` (7 steps, run at the main menu from an administrator PowerShell).
`arc_inject.exe` is this repo's `src/Injector.cpp`: `OpenProcess(CREATE_THREAD|QUERY_INFORMATION|
VM_OPERATION|VM_WRITE|VM_READ)` → `VirtualAllocEx` → `WriteProcessMemory` → `CreateRemoteThread` on
`kernel32!LoadLibraryW` → 60 s wait → `GetExitCodeThread`. It previously failed at `VirtualAllocEx`
error 5; with the rights `probe` just measured it is worth running, and it is the shortest route to real
class names because Dumper-7 resolves the pool with the engine's own code. Its local rebuild differs
byte-wise from the zip copy (same source): `out/arc_inject.exe` 956,416, sha256
`2d9274c0ddec95dd6e87c402d1d4603559bf1b9bc4857f1cbea31b2f6eb4945c`.

Build `2026-11-13-markers-dumper`: size `1,249,792`, sha256
`cfe3538fe16c3f55538c96d1f94daefbb9bab6d43803140aa5bf4f10d5a646c8`, uploaded to `/arc_tool.exe` rev
`66026b805e8d04b309220` — the returned `content_hash` `fc9740a5...` equals `SHA256(SHA256(local file))`,
so the Dropbox bytes are verified identical to the build in `out/`. Core tests pass strict and under
ASan/UBSan; the dense synthetic dump still gives `PREDICATE PASS blocks=3 names=210`, the tail-dump case
still reports the measured stride, and an uncaptured anchor now continues into discovery. Nothing has been
run in game; ESP, Aim, Trigger, Minimap and the menu remain unimplemented.

- Dropbox holds `/Dumper7-ARC-Raiders.zip` (1,504,996 bytes, rev `66015caf1db934b309220`), never
  mentioned in earlier handoffs. If it is a Dumper-7 SDK for `CL-1450810`, it covers GNames/GObjects/
  UWorld RVAs and field layouts directly and the whole section-6 recovery becomes a validation task.
  It cannot be opened from this sandbox: egress to `*.dl.dropboxusercontent.com` failed with
  `SSL_ERROR_SYSCALL` (verified), and only text files reach the workspace through the connector
  (`/home/user/ARC-riders/dropbox/`).
- The older `/ARC-riders/README-RUN.md` (2026-11-11, not part of this repo) describes an external
  D3D11 overlay tool with a runtime session resolver: scan readable private memory for a GameInstance,
  accept it only when `LocalPlayers -> PlayerController -> Pawn -> RootComponent -> RelativeLocation`
  and an independent `ControlRotation` check agree. Its offsets come from an SDK dump of 2025-11-04
  (pre-1.0), so they are candidates for stale values, not evidence. The design idea worth keeping:
  chain-consistency validation needs no class names, so it does not depend on winning `GNames`.

## Build and checks for this step

Portable core checks (adds `TestNameEntries`, `TestNameBlockChain`):

```sh
g++ -std=c++20 -Wall -Wextra -Wpedantic -Werror -Isrc \
  tests/CoreTests.cpp src/Pattern.cpp src/Config.cpp src/Chain.cpp src/Usmap.cpp src/ArcDecrypt.cpp src/Names.cpp \
  -o /tmp/arc-check/arc_core_tests && /tmp/arc-check/arc_core_tests
```

Exit 0, `All core checks passed`; same with `-fsanitize=address,undefined -fno-omit-frame-pointer`, exit 0.

Windows AMD64 build:

```sh
PYTHONPATH=/tmp/arc-check/zig-package python3 -m ziglang c++ -target x86_64-windows-gnu -std=c++20 -O2 -static \
  -Wall -Wextra -Wpedantic -Werror -DUNICODE -D_UNICODE '-DARC_BUILD_STAMP="2026-11-13-fname-blocks-probe"' \
  -Isrc src/Main.cpp src/DumpFile.cpp src/PeFile.cpp src/Process.cpp src/Scanner.cpp src/Pattern.cpp \
  src/Config.cpp src/Chain.cpp src/Usmap.cpp src/ArcDecrypt.cpp src/Names.cpp -ladvapi32 -o out/arc_tool.exe
```

Exit 0. Size `1,190,912`, SHA-256 `3a7892ba226b7cb5d79e6eeba5e255fc0971425335519d39ab7a99421b23174e`,
MZ/PE/AMD64/PE32+ validated. Uploaded to Dropbox `/arc_tool.exe`, rev `660263c4bcaa54b309220` (that
revision has since been replaced at the same path by the `2026-11-13-layout-probe` build,
rev `660268df9e4014b309220`). `Process.cpp` and `DumpFile.cpp` compile only under `_WIN32`, so zig is the
only compiler that has seen them in this session; MSVC has not.

End-to-end check of the new dump command without the game: the real `PrintDumpFNameBlocks` was compiled
for Linux through a shim (`arc::MappedFile` over mmap, `arc::WideToUtf8`) by copying `src/*.cpp` plus two
substitute headers and adding `-D_WIN32`, then run against a synthetic MDMP with a Memory64List stream of
two ranges, three FName blocks of `0x20000` with `0x10` headers, block data deliberately NOT 128 KB
aligned, and an in-image qword pointing at block 0's header. Result: `anchors=1`, header probe accepted
`0x10` and rejected `0x8`/`0x18`/`0x20`/`0x28`/`0x30`, `chain blocks=3 entries=210
stop="end of chain: null next pointer"`, `referrer=0x140000100 -> 0x200000f0 [image] RVA=0x100`,
`PREDICATE PASS blocks=3 names=210 pool_referrers_image=2 heap=3`. Explicit-anchor mode, an over-strict
`min_entries`, an uncaptured anchor VA and a bad `block_size` all behaved as intended (the last two with
`error:` and exit 1). Recipe to reproduce: copy `src/*.h src/*.cpp` to a scratch dir, replace `PeFile.h`
with a portable `MappedFile` declaration and `Process.h` with a `WideToUtf8` declaration, compile
`probe_main.cpp shim.cpp DumpFile.cpp Names.cpp Pattern.cpp Chain.cpp` with `-D_WIN32`.

Both commands have since been run on the user's machine; results below. Nothing observed in game. ESP,
Aim, Trigger, Minimap and menu remain unimplemented.

## Run results and layout measurement (2026-11-13, same night)

`dump-fname-blocks` on the real 12 956 266 993-byte dump:

```text
build=2026-11-13-fname-blocks-probe
block_size=0x20000 min_entries=64 expected_first="None" captured_ranges=63459
discovery scanned_bytes=12943527936 marker_hits=1140 region_probes=1004 anchors=0
SUMMARY build=2026-11-13-fname-blocks-probe anchors=0 validated_pools=0
```

`PREDICATE` was never reached: neither carried codec (`measured_shift6_wide0_str2`,
`alt_len_bits_0_9_wide10`) decodes a dense entry stream from any of the 1 004 probed regions around
those 1 140 `None` markers. The entry header format is therefore still unknown, and a third guessed
codec is not the answer — the layout has to be read off the bytes. `arc::FindAsciiRuns` +
`arc::GapHistogram` (in `src/Names.cpp`) do exactly that and are format-independent: they report every
printable NUL-terminated run, the byte gap between consecutive runs, and the 16-bit word in front of
each string. `dump-fname-blocks` now ranks the probed regions by string density and prints the top eight
with 64 raw bytes when the strict walk fails; `dump-fname-layout <DMP> <VA> [window] [max_hits]` and
`live-fname-layout <pid> <VA> [window] [max_hits]` run the same measurement (`arc::PrintNameLayout`)
against any address, dump or live.

`probe 14292` on the live process: elevated `yes`, `se_debug_privilege=enabled`
(`privileges_reported=24`), all eight rights granted, `reader_handle=open`,
`vm_read_at_image_base=MZ ok`, `private_region_reads=5 of 5`, `toolhelp_snapshot=ok modules=77`,
`image_base=0x7ff7e6370000`. External user-mode reading is fully viable on this build, which settles
external reader + overlay as the architecture; the old `VirtualAllocEx` error 5 is no longer a reason to
prefer internal. Live base is ASLR'd, so every dump-derived value must be re-based on the live image
base, and the dump's `SizeOfImage=0x139F9000` is not usable as the live size without measuring it.

Two of the probe's own numbers were my bug rather than game facts and are now fixed in `src/Process.cpp`:
the PEB walk printed 2 modules with a garbage second entry, and it reported
`PioneerGame.exe size=0x1d82000` from the `LDR_DATA_TABLE_ENTRY`, contradicting the dump's PE header. The
walk advances through `InMemoryOrderLinks.Flink` at record `+0x10`, is cross-checked against Toolhelp
(`peb_walk validation: modules=N bases_also_in_toolhelp=K`, with an explicit warning when they disagree),
and `live_pe_headers` now reads `SizeOfImage`, `SizeOfHeaders`, the section table and `last_page_readable`
from the image itself in memory.

Verified locally: dense synthetic dump still `PREDICATE PASS blocks=3 names=210 pool_referrers_image=2
heap=3` (no regression); a second synthetic dump built with an 8-byte tail after each string, where the
strict chained walk stops after one entry, now reports `ascii_run block_base=0x20000100 runs=64
string_to_string=0x16x63` and `partial block_base=0x20000100 name_like_entries=64 gaps=0x10x63` — the
real stride is visible instead of a bare `anchors=0`. Core tests (including `TestNameLayoutProbe`) pass
strict and under ASan/UBSan. Windows build: Zig `x86_64-windows-gnu`, `-Werror`, exit 0, size
`1,245,184`, SHA-256 `17ed9f27a15d91762c6fdd82626e382cbcdca77af81d2e64f8b610f492fa17c1`, stamp
`2026-11-13-layout-probe`, MZ/PE/AMD64/PE32+ checked by hand. Not run in game.

## Shortest next verification step

1. `arc_tool version` (expect `build=2026-11-13-layout-probe`), then re-run
   `arc_tool dump-fname-blocks "<PioneerGame (3).DMP>" 0x140000000 0x139F9000` — the layout section is the
   part that matters — and `arc_tool probe <pid>` in a live match, then follow up with
   `arc_tool dump-fname-layout <DMP> <block_base>` on whatever region the report points at.
2. Unzip `Dumper7-ARC-Raiders.zip` into Dropbox so its `.hpp`/`.txt` files can be read through the
   connector; if it is a `CL-1450810` dump, validate its `GNames`/`GObjects`/`UWorld` RVAs against the
   dump instead of recovering them.
