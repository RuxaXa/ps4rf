"""ps4rf_angr_run — angr runner (P3 v0.1 PLACEHOLDER).

This file is the contract stub for the real angr integration: the adapter passes
a request document, the runner answers with a ``ps4rf.angr.export/v1`` export.

Contract (v0.1):

  ps4rf_angr_run run --request <request.json> --out <export.json>
  ps4rf_angr_run --version

Request schema ``ps4rf.angr.request/v1``::

  {"schema": "ps4rf.angr.request/v1", "mode": "analyze|dataflow|symbolic",
   "artifact": "<path>", "artifact_sha256": "<sha>",
   "entry": "0x...",        # mode=analyze
   "function": "0x...",     # mode=dataflow
   "target": "0x..."}       # mode=symbolic

Export schema ``ps4rf.angr.export/v1``: see ``tools/angr/README.md`` and the
models in ``tools/angr/adapter.py`` (analyze: info/entry/functions/cfg,
dataflow: function/edges, symbolic: target/paths).

Exit codes: 0 ok · 3 artifact unknown/missing · 4 bad request · 7 target not
found/unreachable · 8 analysis failed.

The real implementation (angr CFGFast + def-use dataflow + symbolic
exploration of the target) lands with an angr installation; until then this
placeholder never runs in tests — the mock answers instead and is hash-pinned
separately, so the placeholder hash in the export stays a real binding.
"""

from __future__ import annotations

import sys

SCHEMA_ID = "ps4rf.angr.export/v1"
REQUEST_SCHEMA_ID = "ps4rf.angr.request/v1"
RUNNER_ID = "ps4rf_angr_run"


def main(argv: list[str] | None = None) -> int:
    argv = list(argv if argv is not None else sys.argv[1:])
    if any(flag in ("-v", "--version") for flag in argv):
        print(f"angr {RUNNER_ID} placeholder")
        return 0
    print("ps4rf_angr_run: placeholder — the real angr implementation lands with "
          "angr installed; offline tests use tools/angr/mock/angr_mock.py",
          file=sys.stderr)
    return 4


if __name__ == "__main__":
    raise SystemExit(main())
