#!/bin/sh
# PS4RF P4/W8 -- PS4 userland target build (libPS4 regime, reproducible).
#
# Usage:
#   native/target/build_ps4.sh OUTDIR SDK [PSK_FILE]
#
# Environment (defaults match the W8 plan):
#   PS4RF_AGENT_HOST       relay host the agent connects out to     (192.168.1.148)
#   PS4RF_AGENT_PORT       relay port for the reverse connection    (9028)
#   PS4RF_AGENT_SECONDS    lifetime bound                           (900)
#   PS4RF_AGENT_IDLE       idle bound                               (180)
#   PS4RF_AGENT_LABEL      HELLO label                              (ps4rfd-live-1)
#   PS4RF_AGENT_CONTEXT    HELLO context                            (fw13-52-userland-w8)
#
# The build is performed twice; the ELF and the flat BIN of both runs must be byte
# identical. build_manifest.py then runs every static gate on the artefact.
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUT=${1:?usage: build_ps4.sh OUTDIR SDK [PSK_FILE]}
SDK=${2:?usage: build_ps4.sh OUTDIR SDK [PSK_FILE]}
PSK_FILE=${3:-$ROOT/.psk-w8.bin}

HOST=${PS4RF_AGENT_HOST:-192.168.1.148}
PORT=${PS4RF_AGENT_PORT:-9028}
LIFETIME=${PS4RF_AGENT_SECONDS:-900}
IDLE=${PS4RF_AGENT_IDLE:-180}
ATTEST=${PS4RF_TARGET_ATTEST:-0}
BOOTID=${PS4RF_TARGET_BOOTID:-0}
BOOTREAD=${PS4RF_TARGET_BOOTREAD:-0}
KREAD=${PS4RF_TARGET_KREAD:-0}
# W15R2: the lifetime boot binding. Only meaningful together with the bounded provider: the one
# privileged callback is what measures the boot instant once per agent lifetime (the userland
# sysctl route is not a boot-binding source on this firmware -- W11.1 live).
BOOTBIND=${PS4RF_TARGET_BOOTBIND:-0}
if [ "$BOOTBIND" = "1" ] && [ "$KREAD" != "1" ]; then
  echo "refused: PS4RF_TARGET_BOOTBIND=1 needs PS4RF_TARGET_KREAD=1 (the boot binding is measured through the provider's single callback)" >&2
  exit 2
fi
# W15: the simulated kernel image is a *dev-host rehearsal* stand-in. It must never be linked into
# a console artefact -- on a console the read either reaches the real kernel or it fails closed.
if [ "${PS4RF_TARGET_KREAD_SIM:-0}" = "1" ]; then
  echo "refused: PS4RF_TARGET_KREAD_SIM is a dev-host rehearsal switch and must not be part of a console build" >&2
  exit 2
fi
# W17F: the recipe/ioctl rehearsal objects (recorded device trace + simulated kernel memory) are
# dev-host stand-ins for the same reason.
if [ "${PS4RF_TARGET_RECIPE_SIM:-0}" = "1" ] || [ "${PS4RF_TARGET_IOCTL_SIM:-0}" = "1" ]; then
  echo "refused: PS4RF_TARGET_RECIPE_SIM / PS4RF_TARGET_IOCTL_SIM are dev-host rehearsal switches and must not be part of a console build" >&2
  exit 2
fi
# W17F: the bounded recipe read is a privileged read: on a console it is only served by a build
# that carries the lifetime boot binding (exactly like the bounded region read).
RECIPE=${PS4RF_TARGET_RECIPE:-0}
IOCTL=${PS4RF_TARGET_IOCTL:-0}
# W17: a recipe build reads kernel memory through the privileged transition, so it is refused
# without the lifetime's boot-binding gate. The one documented exception is the *provider build*
# the read waves are accepted in (W15R3: KREAD + RESIDENT, no binding): on FW 13.52 the console's
# boot-time measurement does not establish a binding (the W15R3 evidence records the lifetime as
# UNRESOLVED), so a build that carries the gate refuses every privileged read on this console. A
# wave that wants that configuration must say so explicitly and must report the binding as an
# observation; it may never be the default.
if [ "$RECIPE" = "1" ] && [ "$BOOTBIND" != "1" ] && [ "${PS4RF_TARGET_BINDING_OBSERVED:-0}" != "1" ]; then
  echo "refused: PS4RF_TARGET_RECIPE=1 needs PS4RF_TARGET_BOOTBIND=1 (the recipe reads kernel memory through the privileged transition); set PS4RF_TARGET_BINDING_OBSERVED=1 only for the documented provider build whose wave reports the binding as an observation" >&2
  exit 2
fi
if [ "$ATTEST" = "1" ]; then
  LABEL=${PS4RF_AGENT_LABEL:-ps4rfd-live-w9}
  CONTEXT=${PS4RF_AGENT_CONTEXT:-fw13-52-attest-w9}
  PROFILE=w9
elif [ "$BOOTID" = "1" ]; then
  LABEL=${PS4RF_AGENT_LABEL:-ps4rfd-live-w11}
  CONTEXT=${PS4RF_AGENT_CONTEXT:-fw13-52-bootid-w11}
  PROFILE=w11
elif [ "$BOOTREAD" = "1" ]; then
  # W11.2: the fixed privileged boot identity read. One build, one privileged callback.
  LABEL=${PS4RF_AGENT_LABEL:-ps4rfd-live-w112}
  CONTEXT=${PS4RF_AGENT_CONTEXT:-fw13-52-bootread-w112}
  PROFILE=w11.2
elif [ "$KREAD" = "1" ]; then
  # W12: the bounded kernel.read provider. One build, one privileged callback, one region table.
  # W14: with RESIDENT=1 the same artefact serves several sessions in one lifetime instead of one.
  if [ "${PS4RF_AGENT_RESIDENT:-0}" = "1" ]; then
    LABEL=${PS4RF_AGENT_LABEL:-ps4rfd-live-w15}
    CONTEXT=${PS4RF_AGENT_CONTEXT:-fw13-52-resident-w15}
  else
    LABEL=${PS4RF_AGENT_LABEL:-ps4rfd-live-w13c2}
    CONTEXT=${PS4RF_AGENT_CONTEXT:-fw13-52-kread-w12}
  fi
  PROFILE=w12
else
  LABEL=${PS4RF_AGENT_LABEL:-ps4rfd-live-1}
  CONTEXT=${PS4RF_AGENT_CONTEXT:-fw13-52-userland-w8}
  PROFILE=w8
fi
PROVIDER=ps4rfd-native-stub
# W17: the providers this build compiles. The manifest gates each one against the *linked* dispatch
# path, so a build that asks for a provider and does not wire it fails; a build that does not ask
# for it is not judged on it (the W15R3 read artefact stays exactly as it was).
# NOTE: kread is deliberately not listed here. The W12/W14 gate is a single provider gate -- it
# requires exactly one privileged driver, one rdmsr leaf and no other wave module in the image --
# so it keeps its own profile build (the accepted W15R3 read artefact stays the artefact it gates).
# The W17 gate below covers the recipe/ioctl wiring of this build, and the read driver that is also
# compiled in here is byte-identical to the module that gate already signed off.
PROVIDERS=""
if [ "$RECIPE" = "1" ]; then PROVIDERS="recipe"; fi
if [ "$IOCTL" = "1" ]; then PROVIDERS="${PROVIDERS:+$PROVIDERS,}ioctl"; fi
# the lifetime boot-binding gate is part of the artefact's identity, so the manifest records it:
# with it the privileged providers refuse a lifetime that could not measure a binding, without it
# the wave is the documented provider build and reports the binding as an observation.
if [ "$BOOTBIND" = "1" ]; then PROVIDERS="${PROVIDERS:+$PROVIDERS,}binding"; fi

TGT="$ROOT/native/target"
SRC="$ROOT/native/src"

[ -f "$SDK/crt0.s" ] || { echo "SDK crt0.s not found in $SDK" >&2; exit 2; }
[ -f "$SDK/linker.x" ] || { echo "SDK linker.x not found in $SDK" >&2; exit 2; }
[ -f "$SDK/libPS4.a" ] || { echo "SDK libPS4.a not found in $SDK" >&2; exit 2; }
[ -f "$PSK_FILE" ] || { echo "PSK file not found: $PSK_FILE" >&2; exit 2; }

mkdir -p "$OUT"

# --- generated region table (W12): built before the build id, it is a build input ----------
# The table is GENERATED AT BUILD TIME from the canonical registry: the compiled header is the
# generator's output in $OUT (which precedes $TGT on the include path), and a checked-in header
# that no longer matches a fresh generation stops the build first (drift = FAIL).
if [ "$KREAD" = "1" ]; then
  python3 "$TGT/gen_kread_regions.py" --check || {
    echo "KREAD REGION TABLE GATE FAILED: regenerate with gen_kread_regions.py --write" >&2; exit 1; }
  python3 "$TGT/gen_kread_regions.py" --write --out "$OUT/ps4rf_kread_regions.h"
fi

# --- generated configuration + key material (never committed) ----------------------
# always regenerate: the configuration header carries the key material and the endpoint
if true; then
  {
    echo '/* GENERATED by build_ps4.sh -- build configuration + pre-shared key. */'
    echo '#ifndef PS4RF_TARGET_CONFIG_H'
    echo '#define PS4RF_TARGET_CONFIG_H'
    echo "#define PS4RF_TARGET_HOST \"$HOST\""
    echo "#define PS4RF_TARGET_PORT $PORT"
    echo '#define PS4RF_TARGET_CONNECT_ATTEMPTS 60'
    echo "#define PS4RF_TARGET_LIFETIME_S $LIFETIME"
    echo "#define PS4RF_TARGET_IDLE_S $IDLE"
    echo "#define PS4RF_TARGET_LABEL \"$LABEL\""
    if [ "${PS4RF_AGENT_RESIDENT:-0}" = "1" ]; then
      echo "#define PS4RF_TARGET_RESIDENT 1"
      echo "#define PS4RF_TARGET_MAX_SESSIONS ${PS4RF_AGENT_MAX_SESSIONS:-0}"
      echo "#define PS4RF_TARGET_IDLE_ROUNDS ${PS4RF_AGENT_IDLE_ROUNDS:-0}"
      echo "#define PS4RF_TARGET_IDLE_PAUSE_MS ${PS4RF_AGENT_IDLE_PAUSE_MS:-250}"
      echo "#define PS4RF_TARGET_BACKOFF_MAX_MS ${PS4RF_AGENT_BACKOFF_MAX_MS:-2000}"
    fi
    if [ "$BOOTBIND" = "1" ]; then
      echo "#define PS4RF_TARGET_BOOTBIND 1"
    fi
    echo "#define PS4RF_TARGET_CONTEXT \"$CONTEXT\""
    echo "#define PS4RF_TARGET_PROVIDER_ID \"$PROVIDER\""
    echo "#define PS4RF_TARGET_BUILD_ID \"__BUILD_ID__\""
    printf 'static const unsigned char PS4RF_TARGET_PSK[32] = {'
    od -An -v -tu1 -N32 "$PSK_FILE" | tr -s ' ' '\n' | grep -v '^$' | tr '\n' ',' | sed 's/,$/}/'
    echo ';'
    echo '#endif /* PS4RF_TARGET_CONFIG_H */'
  } > "$OUT/ps4rf_target_config.h.tpl"
  # The build id identifies the compiled inputs. The attestation files are part of that set
  # only in the W9 profile, so the W8 artefact keeps the build id (and therefore the hash) it
  # was reviewed and run with.
  ID_FILES=$(ls "$TGT"/*.c "$TGT"/*.h "$TGT"/compat_ps4/*.h | grep -v -e '/ps4rf_attest' -e '/ps4rf_boot')
  if [ "$ATTEST" = "1" ]; then
    ID_FILES="$ID_FILES
$(ls "$TGT"/ps4rf_attest*.c "$TGT"/ps4rf_attest*.h)"
  fi
  if [ "$BOOTID" = "1" ]; then
    ID_FILES="$ID_FILES
$(ls "$TGT"/ps4rf_boot*.c "$TGT"/ps4rf_boot*.h)"
  fi
  if [ "$BOOTREAD" = "1" ]; then
    # named precisely: the host stand-in is not part of the console artefact
    ID_FILES="$ID_FILES
$TGT/ps4rf_bootread.c
$TGT/ps4rf_bootread.h"
  fi
  if [ "$KREAD" = "1" ]; then
    # the module and the table it compiles: the table is a build input, not a source of truth
    ID_FILES="$ID_FILES
$TGT/ps4rf_kread.c
$TGT/ps4rf_kread.h
$OUT/ps4rf_kread_regions.h"
  fi
  BUILD_ID=$(cat $ID_FILES "$SRC"/ps4rf_protocol.c "$SRC"/sha256.c \
                 "$SRC"/chacha20poly1305.c "$SRC"/jcs.c "$OUT/ps4rf_target_config.h.tpl" \
             | sha256sum | cut -c1-32)
  sed "s/__BUILD_ID__/$BUILD_ID/" "$OUT/ps4rf_target_config.h.tpl" > "$OUT/ps4rf_target_config.h"
  rm -f "$OUT/ps4rf_target_config.h.tpl"
fi
BUILD_ID=$(sed -n 's/.*PS4RF_TARGET_BUILD_ID "\(.*\)"/\1/p' "$OUT/ps4rf_target_config.h")

CF="-DPS4RF_TARGET_PS4 -I$OUT -I$TGT/compat_ps4 -I$SDK/include -I$TGT -I$SRC -Os -std=c11 -fno-builtin -mcmodel=small -march=btver2 -m64 -fpie -fPIC -Wall -Wextra -Wno-unused-parameter"
ATTEST_UNITS=""
if [ "$ATTEST" = "1" ]; then
  CF="$CF -DPS4RF_TARGET_ATTEST=1"
  ATTEST_UNITS=" $TGT/ps4rf_attest.c"
fi
BOOT_UNITS=""
BOOT_OBJS_FLAG=""
if [ "$BOOTID" = "1" ]; then
  CF="$CF -DPS4RF_TARGET_BOOTID=1"
  BOOT_UNITS=" $TGT/ps4rf_boot.c"
  BOOT_OBJS_FLAG="1"
fi
BOOTREAD_UNITS=""
BOOTREAD_OBJS_FLAG=""
if [ "$BOOTREAD" = "1" ]; then
  CF="$CF -DPS4RF_TARGET_BOOTREAD=1"
  BOOTREAD_UNITS=" $TGT/ps4rf_bootread.c"
  BOOTREAD_OBJS_FLAG="1"
fi
KREAD_UNITS=""
KREAD_OBJS_FLAG=""
if [ "$KREAD" = "1" ]; then
  CF="$CF -DPS4RF_TARGET_KREAD=1"
  KREAD_UNITS=" $TGT/ps4rf_kread.c"
  KREAD_OBJS_FLAG="1"
fi
# W17F: the bounded snapshot recipe and the allowlisted ioctl invoke. The recipe module is the
# same one the console uses; the platform seam (ps4rf_recipe_target.c) links the console leaf and
# the console's kexec()/get_kernel_base() from libPS4.
RECIPE_UNITS=""
RECIPE_OBJS_FLAG=""
if [ "$RECIPE" = "1" ]; then
  CF="$CF -DPS4RF_TARGET_RECIPE=1"
  RECIPE_UNITS=" $TGT/ps4rf_recipe.c $TGT/ps4rf_recipe_target.c"
  RECIPE_OBJS_FLAG="1"
  # the recipe table is the generator's output (same file the console build uses)
  python3 "$TGT/gen_recipe.py" >/dev/null
fi
IOCTL_UNITS=""
IOCTL_OBJS_FLAG=""
if [ "$IOCTL" = "1" ]; then
  CF="$CF -DPS4RF_TARGET_IOCTL=1"
  IOCTL_UNITS=" $TGT/ps4rf_ioctl.c $TGT/ps4rf_ioctl_ps4.c"
  IOCTL_OBJS_FLAG="1"
fi
if [ "$BOOTBIND" = "1" ]; then
  CF="$CF -DPS4RF_TARGET_BOOTBIND=1"
fi
RESIDENT_FLAG=""
if [ "${PS4RF_AGENT_RESIDENT:-0}" = "1" ]; then
  CF="$CF -DPS4RF_TARGET_RESIDENT=1"
  RESIDENT_FLAG="--resident"
fi

build_once() {
  DIR=$1
  ATTEST_OBJS=""
  if [ "$ATTEST" = "1" ]; then ATTEST_OBJS=" $DIR/ps4rf_attest.o"; fi
  BOOT_OBJS=""
  if [ "$BOOT_OBJS_FLAG" = "1" ]; then BOOT_OBJS=" $DIR/ps4rf_boot.o"; fi
  BOOTREAD_OBJS=""
  if [ "$BOOTREAD_OBJS_FLAG" = "1" ]; then BOOTREAD_OBJS=" $DIR/ps4rf_bootread.o"; fi
  KREAD_OBJS=""
  if [ "$KREAD_OBJS_FLAG" = "1" ]; then KREAD_OBJS=" $DIR/ps4rf_kread.o"; fi
  RECIPE_OBJS=""
  if [ "$RECIPE_OBJS_FLAG" = "1" ]; then RECIPE_OBJS=" $DIR/ps4rf_recipe.o $DIR/ps4rf_recipe_target.o"; fi
  IOCTL_OBJS=""
  if [ "$IOCTL_OBJS_FLAG" = "1" ]; then IOCTL_OBJS=" $DIR/ps4rf_ioctl.o $DIR/ps4rf_ioctl_ps4.o"; fi
  mkdir -p "$DIR"
  gcc -c -o "$DIR/crt0.o" "$SDK/crt0.s" $CF
  for unit in "$TGT/ps4rfd_target.c" "$TGT/ps4rf_platform_ps4.c" "$TGT/ps4rf_shim.c" \
              "$TGT/ps4rf_resources.c" "$TGT/ps4rf_evidence.c" "$TGT/ps4rf_telemetry.c" \
              "$TGT/ps4rf_stub.c" "$TGT/ps4rf_router.c" "$TGT/ps4rf_agent.c" "$TGT/ps4rf_daemon.c"$ATTEST_UNITS$BOOT_UNITS$BOOTREAD_UNITS$KREAD_UNITS$RECIPE_UNITS$IOCTL_UNITS \
              "$SRC/ps4rf_protocol.c" "$SRC/sha256.c" "$SRC/chacha20poly1305.c" "$SRC/jcs.c"; do
    gcc -c -o "$DIR/$(basename "${unit%.c}").o" "$unit" $CF
  done
  gcc -T "$SDK/linker.x" -nostartfiles -nostdlib -o "$DIR/ps4rfd.elf" \
      "$DIR"/crt0.o "$DIR"/ps4rfd_target.o "$DIR"/ps4rf_platform_ps4.o "$DIR"/ps4rf_shim.o \
      "$DIR"/ps4rf_resources.o "$DIR"/ps4rf_evidence.o "$DIR"/ps4rf_telemetry.o \
      "$DIR"/ps4rf_stub.o "$DIR"/ps4rf_router.o "$DIR"/ps4rf_agent.o "$DIR"/ps4rf_daemon.o$ATTEST_OBJS$BOOT_OBJS \
      "$DIR"/ps4rf_protocol.o "$DIR"/sha256.o "$DIR"/chacha20poly1305.o "$DIR"/jcs.o$BOOTREAD_OBJS$KREAD_OBJS$RECIPE_OBJS$IOCTL_OBJS \
      "$SDK/libPS4.a" -m64 -Wl,--gc-sections -Wl,-Map="$DIR/ps4rfd.map"
  objcopy -O binary "$DIR/ps4rfd.elf" "$DIR/ps4rfd.bin"
}

build_once "$OUT/build-a"
build_once "$OUT/build-b"

cmp -s "$OUT/build-a/ps4rfd.elf" "$OUT/build-b/ps4rfd.elf" || { echo "REPRO FAIL: ELF differs" >&2; exit 1; }
cmp -s "$OUT/build-a/ps4rfd.bin" "$OUT/build-b/ps4rfd.bin" || { echo "REPRO FAIL: BIN differs" >&2; exit 1; }

python3 "$TGT/build_manifest.py" --elf "$OUT/build-a/ps4rfd.elf" --bin "$OUT/build-a/ps4rfd.bin" \
  --out "$OUT/build_manifest.json" --source-root "$ROOT" --sdk "$SDK" \
  --expect-host "$HOST" --expect-port "$PORT" --label "$LABEL" --build-id "$BUILD_ID" \
  --profile "$PROFILE" --repro-elf "$OUT/build-b/ps4rfd.elf" $RESIDENT_FLAG \
  --providers "$PROVIDERS"

sha256sum "$OUT/build-a/ps4rfd.elf" "$OUT/build-a/ps4rfd.bin" "$OUT/build_manifest.json" \
         "$OUT/ps4rf_target_config.h" | sed 's#  .*/#  #' > "$OUT/SHA256SUMS.ps4.txt"
echo "target build OK: $OUT (build id $BUILD_ID, reproducible twice)"
