#!/bin/sh
# PS4RF P4/W8 -- host build of the target agent (offline validation).
# Usage: native/target/build_host.sh [outdir]
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUT=${1:-$ROOT/native/build/target-host}
SRC="$ROOT/native/src"
TGT="$ROOT/native/target"
CC=${CC:-gcc}

mkdir -p "$OUT"
CF="-std=c11 -Os -fno-builtin -fno-strict-aliasing -Wall -Wextra -Wno-unused-parameter -I$TGT -I$SRC"
ATTEST_UNITS=""
ATTEST_STUB=""
if [ "${PS4RF_TARGET_ATTEST:-0}" = "1" ]; then
  CF="$CF -DPS4RF_TARGET_ATTEST=1"
  ATTEST_UNITS=" $TGT/ps4rf_attest.c"
  # host build: the two SDK entry points are stand-ins (tests/harness may replace the object)
  ATTEST_STUB=" $TGT/ps4rf_attest_host.c"
fi
BOOT_UNITS=""
if [ "${PS4RF_TARGET_BOOTID:-0}" = "1" ]; then
  # W11: read-only userland boot binding. The console value is replaced by the honest host
  # stand-in inside ps4rf_platform_host.c (PS4RF_HOST_BOOTTIME).
  CF="$CF -DPS4RF_TARGET_BOOTID=1"
  BOOT_UNITS=" $TGT/ps4rf_boot.c"
fi
BOOTREAD_UNITS=""
BOOTREAD_STUB=""
if [ "${PS4RF_TARGET_BOOTREAD:-0}" = "1" ]; then
  # W11.2: the fixed privileged boot read. On the host, kexec() fails and there is no kernel base
  # (ps4rf_bootread_host.c), so the run reports the failure instead of inventing a measurement;
  # tests/harness links simulated leaves against the same production callback.
  CF="$CF -DPS4RF_TARGET_BOOTREAD=1"
  BOOTREAD_UNITS=" $TGT/ps4rf_bootread.c"
  BOOTREAD_STUB=" $TGT/ps4rf_bootread_host.c"
fi
KREAD_UNITS=""
KREAD_STUB=""
if [ "${PS4RF_TARGET_KREAD:-0}" = "1" ]; then
  # W12: the bounded kernel.read provider. On the host, kexec() fails and there is no kernel base
  # (ps4rf_kread_host.c), so the run reports the failure instead of inventing a measurement. The
  # region table is generated here, from the canonical registry, exactly like the console build.
  CF="$CF -DPS4RF_TARGET_KREAD=1"
  KREAD_UNITS=" $TGT/ps4rf_kread.c"
  KREAD_STUB=" $TGT/ps4rf_kread_host.c"
  # W15 rehearsal: PS4RF_TARGET_KREAD_SIM=1 swaps the failing stand-in for the simulated *success*
  # path (tests/harness/ps4rf_kread_sim.c: a synthetic kernel image, seeded from the profile's
  # pinned window, with the simulated syscall-11 dispatch). Dev-host only -- the console build
  # refuses this switch, and the manifest of a console artefact records no simulated object.
  if [ "${PS4RF_TARGET_KREAD_SIM:-0}" = "1" ]; then
    KREAD_STUB=" $ROOT/tests/harness/ps4rf_kread_sim.c"
  fi
  # the table is the generator's output (drift is enforced by the target build and the gate)
  python3 "$TGT/gen_kread_regions.py" --write --out "$OUT/ps4rf_kread_regions.h"
  CF="$CF -I$OUT"
fi
# W15R2/W15R3: the lifetime boot binding. The console measures it through the provider's single
# callback over the compiled `boottime` row; the dev-host build enables the same code path so the
# owner's offline cases can make that measurement succeed (PS4RF_KREAD_SIM_BOOTTIME), fail
# (PS4RF_KREAD_SIM_MODE=kexec_error) or never return (PS4RF_KREAD_SIM_MODE=hang). It needs the
# bounded provider, exactly like the console build -- and the console build refuses the simulated
# image, which is why the rehearsal switch lives here and not there.
if [ "${PS4RF_TARGET_BOOTBIND:-0}" = "1" ]; then
  if [ "${PS4RF_TARGET_KREAD:-0}" != "1" ]; then
    echo "refused: PS4RF_TARGET_BOOTBIND=1 needs PS4RF_TARGET_KREAD=1 (the binding is measured through the provider's single callback)" >&2
    exit 2
  fi
  CF="$CF -DPS4RF_TARGET_BOOTBIND=1"
fi
# W17F: the bounded snapshot recipe and the allowlisted ioctl invoke. The modules are the same
# ones the console build uses; the platform seams are the fail-closed host stand-ins
# (ps4rf_recipe_host.c: kexec() fails, no kernel base; ps4rf_ioctl_host.c: no device). The
# dev-host rehearsal swaps in tests/harness/ps4rf_recipe_sim.c, which defines both platform layers
# strongly and replays a recorded device trace through the same production providers.
RECIPE_UNITS=""
RECIPE_STUB=""
if [ "${PS4RF_TARGET_RECIPE:-0}" = "1" ]; then
  CF="$CF -DPS4RF_TARGET_RECIPE=1"
  RECIPE_UNITS=" $TGT/ps4rf_recipe.c $TGT/ps4rf_recipe_target.c"
  RECIPE_STUB=" $TGT/ps4rf_recipe_host.c"
  # the recipe table is the generator's output (same file the console build uses)
  python3 "$TGT/gen_recipe.py" >/dev/null
fi
IOCTL_UNITS=""
IOCTL_STUB=""
if [ "${PS4RF_TARGET_IOCTL:-0}" = "1" ]; then
  CF="$CF -DPS4RF_TARGET_IOCTL=1"
  IOCTL_UNITS=" $TGT/ps4rf_ioctl.c"
  IOCTL_STUB=" $TGT/ps4rf_ioctl_host.c"
fi
SIM_UNITS=""
if [ "${PS4RF_TARGET_RECIPE_SIM:-0}" = "1" ] || [ "${PS4RF_TARGET_IOCTL_SIM:-0}" = "1" ]; then
  if [ "${PS4RF_TARGET_RECIPE:-0}" != "1" ] || [ "${PS4RF_TARGET_IOCTL:-0}" != "1" ]; then
    echo "refused: a recipe/ioctl rehearsal needs both PS4RF_TARGET_RECIPE=1 and PS4RF_TARGET_IOCTL=1" >&2
    exit 2
  fi
  SIM_UNITS=" $ROOT/tests/harness/ps4rf_recipe_sim.c"
fi
$CC $CF -o "$OUT/ps4rfd_host" \
    "$TGT/ps4rfd_host.c" "$TGT/ps4rf_platform_host.c" "$TGT/ps4rf_shim.c" \
    "$TGT/ps4rf_resources.c" "$TGT/ps4rf_evidence.c" "$TGT/ps4rf_telemetry.c" \
    "$TGT/ps4rf_stub.c" "$TGT/ps4rf_router.c" "$TGT/ps4rf_agent.c" "$TGT/ps4rf_daemon.c"$ATTEST_UNITS$ATTEST_STUB$BOOT_UNITS$BOOTREAD_UNITS$BOOTREAD_STUB$KREAD_UNITS$KREAD_STUB$RECIPE_UNITS$RECIPE_STUB$IOCTL_UNITS$IOCTL_STUB$SIM_UNITS \
    "$SRC/ps4rf_protocol.c" "$SRC/sha256.c" "$SRC/chacha20poly1305.c" "$SRC/jcs.c"
echo "built $OUT/ps4rfd_host"
