#!/usr/bin/env bash
# W17 live wave -- one attempt, one upload, one session (resident payload: the lifetime serves
# more than one session, so a failed attempt inside a live lifetime can be re-run in a second one).
#
# Order (the wave's own order, see tools/experiments/live.py):
#   the sheet listens -> ONE payload delivery -> session/profile binding + the daemon's own status
#   -> recipe live -> ioctl live -> Q6 live -> Q6 evidence -> OWN1 live -> OWN1 evidence.
#
# Nothing here probes the loader port: there is exactly one POST, guarded before it is sent, and
# the port is never touched again. The KLog capture is passive (the console pushes to it).
#
# Each attempt is its own wave: its own payload (PS4RF_W17_BIN), its own guard
# (evidence/upload-guard-w17[-n].json). A spent guard is never reset and never reused.
set -u
cd "$(dirname "$0")"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
PORT=${PS4RF_W17_PORT:-9028}
CONSOLE=${PS4RF_W17_CONSOLE:-192.168.1.141}
ATTEMPT=${PS4RF_W17_ATTEMPT:-1}
SUF=""
[ "$ATTEMPT" != "1" ] && SUF="-$ATTEMPT"
BIN=${PS4RF_W17_BIN:-payload/ps4rfd.bin}
STAGES=${PS4RF_W17_STAGES:-full}
# the build the wave delivers: the sheet only proceeds with an agent that reports exactly this id
# (a payload left over from an earlier wave keeps reaching the listener otherwise)
if [ -z "${PS4RF_W17_EXPECT_BUILD:-}" ] && [ -f "$(dirname "$BIN")/build_manifest.json" ]; then
  PS4RF_W17_EXPECT_BUILD=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1])).get('build_id',''))" "$(dirname "$BIN")/build_manifest.json")
fi
EXPECT_BUILD=${PS4RF_W17_EXPECT_BUILD:-}
export PS4RF_W17_EXPECT_BUILD
BIN_SHA=$(sha256sum "$BIN" | awk '{print $1}')
GUARD="evidence/upload-guard-w17$SUF.json"
RECORD="evidence/upload-w17$SUF.json"
SHEET_OUT="evidence/live-w17$SUF"
SHEET_LOG="evidence/live-w17$SUF.stdout.log"
export W17_SUF="$SUF"

echo "wave=W17-live n=$ATTEMPT attempt=$STAMP host=$(hostname) cwd=$PWD port=$PORT console=$CONSOLE"
echo "payload=$BIN sha256=$BIN_SHA"
mkdir -p evidence

if ss -ltn 2>/dev/null | grep -q ":$PORT"; then
  echo "ABORT: something already listens on $PORT"; exit 1
fi
if [ -e "$GUARD" ]; then
  echo "ABORT: $GUARD exists -- this attempt was already made"; exit 1
fi

# --- 1. passive KLog capture (context only; never a probe of the loader) -----------------------
python3 klog_capture.py --host "$CONSOLE" --port 3232 --out "evidence/klog-w17$SUF" \
        --duration 1800 > "evidence/klog-w17$SUF.stdout.log" 2>&1 &
KLOG=$!
sleep 3
kill -0 "$KLOG" 2>/dev/null && echo "KLOG: capture running (pid $KLOG)" \
  || echo "KLOG: capture exited early (context only, the wave continues)"

# --- 2. the sheet, listening -------------------------------------------------------------------
python3 -m tools.experiments.live --listen "$PORT" --psk-file psk.bin \
        --out "$SHEET_OUT" --timeout 1800 --stages "$STAGES" --expect-build "$EXPECT_BUILD" \
        > "$SHEET_LOG" 2>&1 &
SHEET=$!
for _ in $(seq 1 60); do
  if ss -ltn 2>/dev/null | grep -q ":$PORT"; then break; fi
  if ! kill -0 "$SHEET" 2>/dev/null; then
    echo "ABORT: the sheet exited during preflight -- no upload was sent"
    tail -5 "$SHEET_LOG"; exit 3
  fi
  sleep 0.5
done
if ! ss -ltn 2>/dev/null | grep -q ":$PORT"; then
  echo "ABORT: the sheet never started listening on $PORT -- no upload was sent"; exit 3
fi
echo "SHEET: listening on $PORT (pid $SHEET)"

# --- 3. the ONE upload of this attempt ---------------------------------------------------------
python3 -m tools.experiments.upload --console "$CONSOLE" --port 9090 \
        --bin "$BIN" --expect-sha256 "$BIN_SHA" \
        --guard "$GUARD" --record "$RECORD" \
        --confirm-rearmed 'BinLoader rearmed'
echo "UPLOAD: exit $?"

# --- 4. wait for the sheet ---------------------------------------------------------------------
for _ in $(seq 1 900); do
  if ! kill -0 "$SHEET" 2>/dev/null; then break; fi
  sleep 2
done
kill -0 "$SHEET" 2>/dev/null && echo "SHEET: still running after 1800 s" || echo "SHEET: finished"

# --- 5. stop the capture, then summarise -------------------------------------------------------
sleep 5
kill -0 "$KLOG" 2>/dev/null && { kill -TERM "$KLOG" 2>/dev/null; sleep 2; }
echo "KLOG: stopped"
python3 "$(dirname "$0")/w17_summary.py"
echo "done at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
