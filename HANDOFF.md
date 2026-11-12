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
