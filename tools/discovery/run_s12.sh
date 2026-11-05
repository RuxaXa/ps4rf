#!/bin/sh
# S1.2 final artifact chain: scans -> blind -> integration checks -> evidence pack.
# Every number in EVIDENCE.md comes from these files; nothing is typed by hand.
set -e
cd /home/hermes/projects/ps4rf
S=/home/hermes/audits/ps4-exploit-discovery-s1/sprint1.2
mkdir -p "$S"

.venv/bin/python -m tools.discovery.cli scan --fw 13.52 --out "$S/s12-scan-fw1352.json"
echo "SCAN-1352-DONE"

.venv/bin/python -m tools.discovery.cli scan --fw 9.00 --out "$S/s12-scan-fw900.json"
echo "SCAN-900-DONE"

.venv/bin/python - "$S" <<'PY'
import json, sys
from tools.discovery import s12_blind
out = sys.argv[1]
r = s12_blind.run()
open(f"{out}/s12-blind.json", "w").write(json.dumps(r, indent=2, sort_keys=True) + "\n")
print("BLIND", r["verdict"], json.dumps(r["summary"]))
PY
echo "BLIND-DONE"

.venv/bin/python - "$S" <<'PY'
import json, sys
from tools.discovery import s12_check
out = sys.argv[1]
r = s12_check.run()
open(f"{out}/s12-check.json", "w").write(json.dumps(r, indent=2, sort_keys=True) + "\n")
print("CHECK", json.dumps(r["d3_freeze"]), json.dumps(r["queue"]["by_detector"]))
PY
echo "CHECK-DONE"

.venv/bin/python - "$S" <<'PY'
import json, sys
from tools.discovery import s12_evidence
out = sys.argv[1]
r = s12_evidence.build()
open(f"{out}/s12-evidence.json", "w").write(json.dumps(r, indent=2, sort_keys=True) + "\n")
open(f"{out}/EVIDENCE.md", "w").write(s12_evidence.render_markdown(r))
print("EVIDENCE", r["verdict"], json.dumps(r["checks"]))
PY
echo "EVIDENCE-DONE"
