#!/usr/bin/env python3
"""Build syn_esp.dmp: a tiny but structurally honest minidump for the esp-chain / esp-actors modes.

The point is that every predicate those modes use has to fire here, and only on the truth:

  image  0x140000000 +0x2000    the global, three vtables, one code slot each
  heap   0x200000000 +0x40000   a four step object chain, a UWorld/ULevel round trip, a 64 element actor
                                 array whose components carry a wide spread position, and a 128 element
                                 decoy array of objects that are not positioned anywhere

The decoy is what makes the test worth having: a sweep that only looked for "array of objects" would be
happy with it, so the ranking (how many elements actually yield an agreed position) has to reject it.
"""
import struct
import sys
from pathlib import Path

IMAGE_BASE = 0x140000000
IMAGE_SIZE = 0x2000
HEAP_BASE = 0x200000000
HEAP_SIZE = 0x40000

VT_A = IMAGE_BASE + 0x1100
VT_B = IMAGE_BASE + 0x1108
VT_C = IMAGE_BASE + 0x1110
CODE = IMAGE_BASE + 0x1500

GLOBAL_OFF = 0x1000
CHAIN_OFFS = (0xA0, 0x250, 0x160)
OBJ0 = HEAP_BASE + 0x1000
OBJ1 = HEAP_BASE + 0x2000
OBJ2 = HEAP_BASE + 0x3000
WORLD = HEAP_BASE + 0x4000
LEVEL = HEAP_BASE + 0x4100
ACTORS_DATA = HEAP_BASE + 0x5000
ACTOR0 = HEAP_BASE + 0x8000
ACTOR_STRIDE = 0x100
ACTOR_COUNT = 64
COMPONENT0 = HEAP_BASE + 0xC000
COMPONENT_STRIDE = 0x100
COMPONENT_COUNT = ACTOR_COUNT

DECOY_HEADER = HEAP_BASE + 0x20000
DECOY_DATA = HEAP_BASE + 0x20100
DECOY0 = HEAP_BASE + 0x22000
DECOY_STRIDE = 0x100
DECOY_COUNT = 128

ROOT_COMPONENT_OFF = 0x130
RELATIVE_LOCATION_OFF = 0x11C
WORLD_LEVEL_OFF = 0x38
LEVEL_WORLD_OFF = 0xE8
LEVEL_ACTORS_OFF = 0xA0


def main(out):
    image = bytearray(IMAGE_SIZE)
    heap = bytearray(HEAP_SIZE)

    def put(buffer, base, va, fmt, *values):
        offset = va - base
        if offset < 0 or offset + struct.calcsize(fmt) > len(buffer):
            raise SystemExit(f"synthetic write at 0x{va:x} falls outside its range")
        struct.pack_into(fmt, buffer, offset, *values)

    # ---- image: the global, and three vtables whose first slot is in-image code
    put(image, IMAGE_BASE, IMAGE_BASE + GLOBAL_OFF, "<Q", OBJ0)
    for vt in (VT_A, VT_B, VT_C):
        put(image, IMAGE_BASE, vt, "<Q", CODE)

    # ---- the chain heads all carry a vtable, which is the only object header the tool checks
    chain = (OBJ0, OBJ1, OBJ2, WORLD)
    for obj in (OBJ0, OBJ1, OBJ2, WORLD, LEVEL):
        put(heap, HEAP_BASE, obj, "<Q", VT_A)

    # [image global] -> obj0 +0xA0 -> obj1 +0x250 -> obj2 +0x160 -> world
    for source, offset, target in zip(chain, CHAIN_OFFS, chain[1:]):
        put(heap, HEAP_BASE, source + offset, "<Q", target)

    # UWorld <-> ULevel round trip, at offsets inside the mode's candidate list
    put(heap, HEAP_BASE, WORLD + WORLD_LEVEL_OFF, "<Q", LEVEL)
    put(heap, HEAP_BASE, LEVEL + LEVEL_WORLD_OFF, "<Q", WORLD)

    # the level's actor array: {Data, Num, Max}
    put(heap, HEAP_BASE, LEVEL + LEVEL_ACTORS_OFF, "<QII", ACTORS_DATA, ACTOR_COUNT, ACTOR_COUNT)
    for i in range(ACTOR_COUNT):
        put(heap, HEAP_BASE, ACTORS_DATA + i * 8, "<Q", ACTOR0 + i * ACTOR_STRIDE)

    # actors: three classes worth of vtables, a RootComponent, and a wide spread position on the
    # component - the stride is exactly the pattern that made a first-match scan pick a wrong offset
    for i in range(ACTOR_COUNT):
        actor = ACTOR0 + i * ACTOR_STRIDE
        put(heap, HEAP_BASE, actor, "<Q", (VT_A, VT_B, VT_C)[i % 3])
        put(heap, HEAP_BASE, actor + ROOT_COMPONENT_OFF, "<Q", COMPONENT0 + i * COMPONENT_STRIDE)
    for i in range(COMPONENT_COUNT):
        component = COMPONENT0 + i * COMPONENT_STRIDE
        put(heap, HEAP_BASE, component, "<Q", VT_B)
        put(heap, HEAP_BASE, component + RELATIVE_LOCATION_OFF, "<fff",
            1000.0 + 53.0 * i, -2000.0 - 29.0 * i, 100.0 + 7.0 * i)

    # decoy: an array of perfectly good objects with nothing at component range but zeros
    put(heap, HEAP_BASE, DECOY_HEADER, "<QII", DECOY_DATA, DECOY_COUNT, DECOY_COUNT)
    for i in range(DECOY_COUNT):
        obj = DECOY0 + i * DECOY_STRIDE
        put(heap, HEAP_BASE, obj, "<Q", VT_C)
        put(heap, HEAP_BASE, DECOY_DATA + i * 8, "<Q", obj)

    # ---- minidump framing: header, one MemoryList directory entry per block, then the blocks
    blocks = [(IMAGE_BASE, image), (HEAP_BASE, heap)]
    header_size = 32
    directory_size = 12
    list_size = 4 + 16 * len(blocks)
    directory_at = header_size
    list_at = directory_at + directory_size * len(blocks)
    data_at = list_at + list_size

    offsets = []
    cursor = data_at
    for _, data in blocks:
        offsets.append(cursor)
        cursor += len(data)

    file_bytes = bytearray(cursor)
    # MINIDUMP_HEADER: signature, version, stream count, directory RVA, checksum, reserved, timestamp,
    # flags - 32 bytes, which is what ReadStreams walks.
    struct.pack_into("<IIIIIIQ", file_bytes, 0, 0x504D444D, 0xA793, 1, directory_at, 0, 0, 0)
    struct.pack_into("<I", file_bytes, list_at, len(blocks))
    for index, ((va, data), file_offset) in enumerate(zip(blocks, offsets)):
        struct.pack_into("<III", file_bytes, directory_at + index * directory_size, 5, list_size, list_at)
        struct.pack_into("<QII", file_bytes, list_at + 4 + index * 16, va, len(data), file_offset)
        file_bytes[file_offset:file_offset + len(data)] = data

    Path(out).write_bytes(bytes(file_bytes))
    print(f"wrote {out}: {len(file_bytes)} bytes, image@0x{IMAGE_BASE:x} heap@0x{HEAP_BASE:x}")
    print(f"truth: chain={'/'.join(hex(o) for o in CHAIN_OFFS)} world+{hex(WORLD_LEVEL_OFF)}->level "
          f"level+{hex(LEVEL_WORLD_OFF)}->world level+{hex(LEVEL_ACTORS_OFF)}=actors(num={ACTOR_COUNT}) "
          f"actor+{hex(ROOT_COMPONENT_OFF)}->component component+{hex(RELATIVE_LOCATION_OFF)}->FVector")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "syn_esp.dmp"))
