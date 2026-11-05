"""W18b -- the stepped measurement-path diagnosis (NO OWN-1 trigger in this script).

Per the owner's steps:
  1. a known-working small read as the lifetime control,
  2. the new bitmap base with a minimal length,
  3. growing lengths only while the agent stays alive,
  4. the PTSLOT area separately, minimal length first,
  5. the combined OWN-1 baseline read only when both areas proved stable separately,
  6. every step records EOF vs open-socket/timeout and the last answered request.

Each step is ONE request. The script stops at the first step that kills the agent (no blind
retries) and records everything it saw.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import socket
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from tools.experiments.device import load_policy  # noqa: E402
from tools.experiments.rpc import RpcError, RpcTarget  # noqa: E402
from tools.hostctl.endpoint import SocketEndpoint, listen  # noqa: E402
from tools.hostctl.session import HostSession  # noqa: E402

DIAG = "own1-diag-ladder"


def _stamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _write(out: pathlib.Path, name: str, doc) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / name).write_text(json.dumps(doc, indent=1, sort_keys=True))


def cell_facts(snapshot) -> dict:
    import hashlib as _h
    return {name: {"status": c.status, "why": c.why, "length": c.length,
                   "addr": hex(c.addr), "root_value": hex(c.root_value),
                   "data_sha256": _h.sha256(c.data).hexdigest(),
                   "data_len": len(c.data)}
            for name, c in snapshot.cells.items()}


def classify_transport(exc: Exception) -> str:
    """EOF (peer closed -> process likely died) vs open-socket timeout (process likely hung)."""
    text = str(exc)
    if "peer closed" in text:
        return "EOF_PROCESS_GONE"
    if "timeout" in text:
        return "OPEN_SOCKET_TIMEOUT_PROCESS_LIKELY_HUNG"
    return f"OTHER:{type(exc).__name__}"


def run(port: int, psk_file: pathlib.Path, out: pathlib.Path, *, expect_build: str,
        timeout: float = 240.0) -> dict:
    """The stepped diagnosis: one request per step, stop at the first agent death."""
    psk = pathlib.Path(psk_file).read_bytes()
    summary: dict = {"schema": "ps4rf.w18b.diag.v1", "started_at": _stamp(),
                     "port": port, "expected_build": expect_build, "steps": []}
    from tools.experiments.live import wait_for_matching_agent
    session, hello, ready, rounds = wait_for_matching_agent(
        port, out=out, psk=psk, session_id="w18b-diag", timeout=timeout,
        want_build=expect_build)
    if session is None:
        summary["verdict"] = "BUILD_MISMATCH"
        summary["connections_seen"] = rounds
        summary["finished_at"] = _stamp()
        _write(out, "w18b-diag-summary.json", summary)
        return summary
    summary["agent"] = {"build_id": hello.get("build_id"),
                        "boot_status": (ready or {}).get("boot_status")}
    _write(out, "w18b-agent.json", summary["agent"])
    target = RpcTarget(session)
    last_ok = None
    verdict = "COMPLETE"
    # the owner's order: control first, then BMP growing, then page probes, then PT growing,
    # then the PT boot control. Every step is exactly ONE request for its own recipe.
    STEPS = [
        ("S1_control", "diag1-control", None),
        ("S2_bmp16", "diag2-bmp16", {"idx_bitmap_word": 2520}),
        ("S2_bmp64", "diag2-bmp64", {"idx_bitmap_word": 2520}),
        ("S2_bmp256", "diag2-bmp256", {"idx_bitmap_word": 2520}),
        ("S2_bmp1024", "diag2-bmp1024", {"idx_bitmap_word": 2520}),
        ("S3_pg512_end", "diag3-pg512-end", {"idx_bitmap_word": 2496}),
        ("S3_pg512_cross", "diag3-pg512-cross", {"idx_bitmap_word": 2528}),
        ("S3_pg1024_cross", "diag3-pg1024-cross", {"idx_bitmap_word": 2496}),
        ("S4_pt8", "diag4-pt8", {"idx_ptslot": 315}),
        ("S4_pt64", "diag4-pt64", {"idx_ptslot": 315}),
        ("S4_pt512", "diag4-pt512", {"idx_ptslot": 315}),
        ("S4b_pt4096_boot", "diag5-pt4096boot", {"idx_ptslot": 0}),
    ]
    for step_name, recipe, indices in STEPS:
        try:
            snap = target.run_recipe(recipe, indices, indices_full=True)
            facts = cell_facts(snap)
            bad = [n for n, f in facts.items() if f["status"] != 0]
            summary["steps"].append({
                "step": step_name, "recipe": recipe, "at": _stamp(), "ok": True,
                "cell_status": {n: f["status"] for n, f in facts.items()},
                "refused_cells": bad, "cells": facts})
            if bad:
                # the provider answered with a refusal (cell status != 0): the path itself
                # answered, so the agent lives; record and continue (refusal is a result)
                summary["steps"][-1]["note"] = "provider refused these cells (agent alive)"
            last_ok = step_name
        except RpcError as exc:
            summary["steps"].append({"step": step_name, "recipe": recipe, "at": _stamp(),
                                     "ok": False, "kind": "RPC_ERROR", "error": str(exc)[:400],
                                     "note": "agent alive, answered with an error status"})
            last_ok = step_name + " (error answer, alive)"
        except Exception as exc:                                # noqa: BLE001
            kind = classify_transport(exc)
            summary["steps"].append({"step": step_name, "recipe": recipe, "at": _stamp(),
                                     "ok": False, "kind": kind, "error": str(exc)[:400],
                                     "note": "the agent did not answer this request"})
            verdict = f"AGENT_DIED_AT_{step_name}"
            break
        _write(out, "w18b-progress.json", summary)
    # step 5: the combined OWN-1 baseline read (still no trigger) only after both areas proved
    if verdict == "COMPLETE":
        try:
            from tools.experiments import own1 as OWN1_MOD
            snap = target.run_recipe(OWN1_MOD.RECIPE, OWN1_MOD.INDICES)
            summary["steps"].append({"step": "S5_own1_baseline", "recipe": OWN1_MOD.RECIPE,
                                     "at": _stamp(), "ok": True,
                                     "cell_status": {n: c.status for n, c in snap.cells.items()},
                                     "cells": cell_facts(snap)})
            last_ok = "S5_own1_baseline"
        except Exception as exc:                                # noqa: BLE001
            kind = classify_transport(exc)
            summary["steps"].append({"step": "S5_own1_baseline", "recipe": OWN1_MOD.RECIPE,
                                     "at": _stamp(), "ok": False, "kind": kind,
                                     "error": str(exc)[:400]})
            verdict = f"AGENT_DIED_AT_S5"
    summary["verdict"] = verdict
    summary["last_ok"] = last_ok
    summary["exchanges"] = target.exchanges
    summary["finished_at"] = _stamp()
    _write(out, "w18b-diag-summary.json", summary)
    session.close()
    return summary


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", type=int, default=9028)
    ap.add_argument("--psk-file", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--timeout", type=float, default=240.0)
    ap.add_argument("--expect-build", required=True)
    a = ap.parse_args()
    s = run(a.listen, pathlib.Path(a.psk_file), pathlib.Path(a.out),
            expect_build=a.expect_build, timeout=a.timeout)
    print(json.dumps({"verdict": s.get("verdict"), "last_ok": s.get("last_ok"),
                      "steps": [(x["step"], x.get("ok"), x.get("transport", ""))
                                for x in s.get("steps", [])]}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
