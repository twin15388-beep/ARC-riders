# offline-port: running the Windows-only dump modes on Linux

`src/DumpFile.cpp` is guarded by `#ifdef _WIN32` and its only Windows dependency is `arc::MappedFile`.
This directory supplies a stub `<windows.h>` and a POSIX `MappedFile`, so the exact same sources can be
compiled and *executed* here against a synthetic minidump. That is what keeps the structural predicates
honest without a Windows box and without ever touching a live process.

```sh
tools/offline-port/build.sh   # compiles src/DumpFile.cpp et al with -Werror into build/probe
tools/offline-port/run.sh     # generates syn_esp.dmp and asserts both esp modes recover its ground truth
```

`mkesp.py` writes a 264 KB dump holding: a global in the image, a four-step object chain, a
UWorld/ULevel round trip at `+0x38`/`+0xE8`, a 64 element actor array whose components carry a wide
spread position, and a 128 element **decoy** array of objects with no positions. The decoy is the part
that matters: any "array of object pointers" heuristic accepts it, so `run.sh` fails if the ranking ever
stops rejecting it.

`esp-export` is gated here too: `run.sh` feeds the ini written by `esp-actors` (and a hand-written one)
back into the exporter and compares the exported coordinates and distances against the same ground truth,
so the feature layer cannot rot without the gate noticing.

Real dumps are never put here. `out/arc_tool.exe` is built with `python3 -m ziglang c++ -target
x86_64-windows-gnu` from the same sources; this harness only proves the predicates do what they claim.
