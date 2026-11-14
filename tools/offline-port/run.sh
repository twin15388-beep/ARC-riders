#!/usr/bin/env bash
# Acceptance gate for the esp-chain / esp-actors modes: builds a synthetic dump whose ground truth is known
# and checks the tool recovers exactly it. Run this after any change to the structural predicates.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="${ARC_PORT_OUT:-$here/build}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
python3 "$here/mkesp.py" "$work/syn_esp.dmp" > /dev/null

fail() { echo "FAIL: $1"; exit 1; }

"$out/probe" esp-chain "$work/syn_esp.dmp" 0x140000000 0x2000 0x1000 "" "$work/chain.ini" > "$work/chain.txt"
grep -q "HIT world=0x200004000 +0x38 -> level=0x200004100 +0xe8 -> world" "$work/chain.txt" \
    || fail "esp-chain did not recover the UWorld/ULevel round trip"
grep -q "HIT level=0x200004100 +0xa0 data=0x200005000 num=64 max=64" "$work/chain.txt" \
    || fail "esp-chain did not find the actor array"
grep -q "winner: \[actor+0x130\] -> component, \[component+0x11c\] -> FVector" "$work/chain.txt" \
    || fail "esp-chain voted the wrong component/location pair"
grep -q "positions at the winning offsets: 48/48" "$work/chain.txt" \
    || fail "esp-chain lost positions after the helper refactor"
for field in "persistent_level_off = 0x38" "level_owning_world_off = 0xe8" "level_actors_off = 0xa0" \
             "root_component_off = 0x130" "relative_location_off = 0x11c"; do
    grep -qF "$field" "$work/chain.ini" || fail "chain ini is missing '$field'"
done

"$out/probe" esp-actors "$work/syn_esp.dmp" 0x140000000 0x2000 64 "$work/actors.ini" > "$work/actors.txt"
grep -q "array\[1\] header=0x2000041a0 num=64" "$work/actors.txt" \
    || fail "esp-actors did not find the actor array by sweep"
grep -q "consistent with a real actor list" "$work/actors.txt" \
    || fail "esp-actors did not grade the actor array as real"
grep -q "array\[0\] header=0x200020000 num=128" "$work/actors.txt" \
    || fail "esp-actors lost the decoy from the report (it must stay visible as a rejected candidate)"
grep -A2 "positions=0" "$work/actors.txt" | grep -q . || fail "decoy has no vote line"
! grep -q "128.*consistent with a real actor list" "$work/actors.txt" \
    || fail "the decoy was ranked as a real actor list"
grep -qF "root_component_off = 0x130" "$work/actors.ini" || fail "actors ini is missing root_component_off"
grep -qF "relative_location_off = 0x11c" "$work/actors.ini" || fail "actors ini is missing relative_location_off"
grep -q "actor_0 = 0x200008000, 1000, -2000, 100" "$work/actors.ini" || fail "first position row is wrong"
grep -q "level_actors_off = 0xa0" "$work/actors.ini" || fail "actors ini is missing level_actors_off"

# the feature layer: the ini the sweep wrote must drive the exporter, and the numbers must be the truth
"$out/probe" esp-export "$work/syn_esp.dmp" 0x140000000 0x2000 "$work/actors.ini" "$work/esp-data.js" \
    > "$work/export.txt"
grep -q "64 of 64 actors carry a plausible position" "$work/export.txt" \
    || fail "esp-export did not read the swept actor array"
grep -q '"actors_with_position": 64' "$work/esp-data.js" || fail "exported data lost rows"
grep -q '"x": 1000.00, "y": -2000.00, "z": 100.00' "$work/esp-data.js" \
    || fail "exported position is not the synthetic truth"
grep -q '"dist": 22.38' "$work/esp-data.js" || fail "exported distance is wrong"
head -c 14 "$work/esp-data.js" | grep -q "window.ARC" || fail "the .js output must be a js assignment"
# a hand-written config must be enough on its own, with no sweep involved
printf '[esp]\nactor_array_data = 0x200005000\nactor_array_num = 64\nroot_component_off = 0x130\nrelative_location_off = 0x11c\nlocal_x = 1000\nlocal_y = -2000\nlocal_z = 100\nview_yaw_degrees = 0\nfov_degrees = 90\nscreen_width = 1920\nscreen_height = 1080\n' > "$work/manual.ini"
"$out/probe" esp-export "$work/syn_esp.dmp" 0x140000000 0x2000 "$work/manual.ini" "$work/manual.json" \
    > "$work/manual.txt"
grep -q "distance 0\\.\\." "$work/manual.txt" || fail "the local actor should be at distance 0"
grep -q "off view" "$work/manual.txt" || fail "the row at the eye should be reported as off view"
grep -q '"actors_with_position": 64' "$work/manual.json" || fail "manual config did not export rows"

# the argument handling itself: the shipped modes used to fall through to the usage text because an
# `argc == 3` check sat next to an `argc == 4` one, and only `demo` proved it
"$out/probe" esp-overlay "$work/overlay.html" demo > "$work/overlay.txt" || fail "esp-overlay rejected demo"
grep -q "demo esp-data.js" "$work/overlay.txt" || fail "esp-overlay did not report the demo file"
[ -s "$work/overlay.html" ] || fail "esp-overlay wrote an empty page"
grep -q "<canvas" "$work/overlay.html" || fail "the page it wrote is not the viewer"
[ -s "$work/esp-data.js" ] || fail "the demo data file is missing next to the page"
"$out/probe" esp-overlay 2>/dev/null && fail "esp-overlay accepted no arguments"
"$out/probe" esp-overlay "$work/x.html" not-a-flag 2>/dev/null && fail "esp-overlay accepted an unknown flag"

# and the modes that already shipped must keep answering on their fixtures
"$out/probe" esp-chain "$work/syn_esp.dmp" 0x140000000 0x2000 0x1000 "0xA0,0x8,0x8" "$work/bad.ini" \
    > "$work/bad.txt"
grep -q "FAIL: chain step +0x8" "$work/bad.txt" || fail "a broken chain must say which step broke"
if [ -s "$work/bad.ini" ]; then fail "a broken chain must not write an ini"; fi

echo "PASS: esp-chain and esp-actors recover the synthetic ground truth"
