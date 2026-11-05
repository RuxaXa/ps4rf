#!/bin/sh
# The owner's item-4 list, checked against the final console artefact (no test may assert about the
# build it is part of, so this runs after the build and writes raw output for the evidence pack).
#
# Usage: sh tests/w15_final_artifact_checks.sh <build-dir>
set -u
OUT=${1:?usage: w15_final_artifact_checks.sh <build-dir>}
ELF="$OUT/build-a/ps4rfd.elf"
BIN="$OUT/build-a/ps4rfd.bin"
ROOT=$(cd "$(dirname "$0")/.." && pwd)
FAIL=0

say() { printf '%s\n' "$*"; }
check() { # name expected actual
  if [ "$2" = "$3" ]; then say "PASS  $1 = $3"; else say "FAIL  $1: expected '$2', found '$3'"; FAIL=1; fi
}

say "== artefact: $OUT"
say "== sha256sum of the pinned files"
(cd "$OUT" && sha256sum build-a/ps4rfd.elf build-a/ps4rfd.bin build_manifest.json ps4rf_target_config.h)

say
say "== manifest gates"
python3 - "$OUT/build_manifest.json" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
g = m['gates']
print('verdict                ', m['verdict'])
print('problems               ', m['problems'])
print('label                  ', m['label'])
print('build_id               ', m['build_id'])
print('relocations            ', len(m['relocations']))
print('undefined_symbols      ', len(m['undefined_symbols']))
print('gate relocations_zero  ', g.get('relocations_zero'))
print('gate loader_port       ', json.dumps(g.get('loader_port'))[:160])
print('gate agent_version     ', json.dumps(g.get('agent_version')))
print('gate kread keys        ', sorted((g.get('kread') or {}).keys()))
print('gate resident          ', json.dumps(g.get('resident'))[:120])
PY

say
say "== the version constant is compiled into the artefact"
check "agent_version in ELF strings" "1" "$(strings "$ELF" | grep -c '^ps4rfd-target-w15$')"
strings "$ELF" | grep -E '^(ps4rfd-target-|ps4rfd-live-)' | sort -u | sed 's/^/  string: /' 

say
say "== no KREAD_SIM in the target artefact"
check "sim_trace symbol in ELF" "0" "$(nm -a "$ELF" 2>/dev/null | grep -c 'sim_trace')"
check "ps4rf_kread_sim.c in sources" "0" "$(python3 -c "import json,sys;m=json.load(open('$OUT/build_manifest.json'));print(sum(1 for s in m['sources'] if 'kread_sim' in str(s)))")"
check "hashes-source object files" "0" "$(ls "$OUT" | grep -c 'kread_sim')"
PS4RF_TARGET_KREAD_SIM=1 PS4RF_TARGET_KREAD=1 sh "$ROOT/native/target/build_ps4.sh" "$OUT-refused-sim" /home/hermes/fw900-sdk-audit/libPS4 /home/hermes/.hermes/cache/scratch/ps4rf-w14/baseline/psk.bin >/dev/null 2>&1
check "console build refuses KREAD_SIM (rc 2)" "2" "$?"
rm -rf "$OUT-refused-sim"

say
say "== no loader port reference in the target"
check "9090 occurrences in ELF strings" "0" "$(strings "$ELF" | grep -c '9090')"
# the loader *connection* is what must be gone: the SDK's own payload_utils helpers link in regardless,
# so this looks for a loader port or a loader client, not for the word "payload"
check "loader client symbols" "0" "$(nm -a "$ELF" 2>/dev/null | grep -ciE 'payload_loader|binloader|connect_payload')"
check "loader references in target sources" "0" "$(grep -riE '9090|binloader|payload_loader' "$ROOT"/native/target/*.c "$ROOT"/native/target/*.h | grep -vc '^\s*$')"

say
say "== region_index is data driven, and exactly one production kread call site"
check "kernel.read args in the optable" "length offset region_index" "$(grep -o '"[a-z_]*"' "$ROOT/native/target/ps4rf_optable_data.h" | grep -E '"(region_index|offset|length)"' | tr -d '\"' | sort -u | tr '\n' ' ' | sed 's/ $//')"
check "production ps4rf_kread_run call sites" "1" "$(grep -h 'ps4rf_kread_run(&' "$ROOT"/native/target/*.c | grep -vc '^\s*\*')"
check "call site file" "ps4rf_stub.c" "$(grep -l 'ps4rf_kread_run(&' "$ROOT"/native/target/*.c | xargs -n1 basename | tr '\n' ' ' | sed 's/ $//')"
grep -n 'ps4rf_kread_run(&' "$ROOT"/native/target/*.c | sed 's/^/  /'

say
if [ "$FAIL" = 0 ]; then say "ARTEFACT CHECKS: ALL PASS"; else say "ARTEFACT CHECKS: FAILURES PRESENT"; fi
exit "$FAIL"
