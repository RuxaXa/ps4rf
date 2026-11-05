"""Command-line entry points for the reproducible S1.1 evidence runs."""
from __future__ import annotations

import argparse
import json
import pathlib
import resource
import time
import tracemalloc

from . import validate
from .locks import SyncCatalog
from .s11 import analyze_lapse_pair

DATA = pathlib.Path(__file__).resolve().parent / "data"


def _write(path: str, payload: dict) -> None:
    target = pathlib.Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n",
                      encoding="utf-8")


def catalog_profile(fw: str) -> dict:
    env = validate.Environment.load(str(DATA), only=[fw])
    tracemalloc.start()
    started = time.time()
    catalog = SyncCatalog(env.images[fw], env.indexes[fw])
    elapsed = time.time() - started
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    usage = resource.getrusage(resource.RUSAGE_SELF)
    return {
        "schema": "ps4rf.discovery.s11.catalog-profile/1",
        "firmware": fw,
        "image_sha256": env.images[fw].sha256,
        "elapsed_s": round(elapsed, 3),
        "python_current_bytes": current,
        "python_peak_bytes": peak,
        "max_rss_kib": int(usage.ru_maxrss),
        "catalog": catalog.stats(),
        "bounded_policy": {
            "per_function_decode_cap": "0x1000",
            "minimum_probe_window": "0x300",
            "cache": "compact call summaries plus candidate bodies",
            "silent_abort": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(prog="tools.discovery.s11_cli")
    sub = parser.add_subparsers(dest="command", required=True)
    pair = sub.add_parser("pair")
    pair.add_argument("--syscall", type=int, required=True)
    pair.add_argument("--out", required=True)
    catalog = sub.add_parser("catalog")
    catalog.add_argument("--fw", choices=["9.00", "13.52"], required=True)
    catalog.add_argument("--out", required=True)
    args = parser.parse_args()
    if args.command == "pair":
        env = validate.Environment.load(str(DATA), only=["9.00", "13.52"])
        payload = analyze_lapse_pair(env, args.syscall)
    else:
        payload = catalog_profile(args.fw)
    _write(args.out, payload)
    firmware = payload.get("firmware")
    print(json.dumps({
        "written": args.out,
        "verdict": payload.get("verdict"),
        "firmware": (firmware if isinstance(firmware, str)
                     else sorted(firmware) if isinstance(firmware, dict) else None),
        "elapsed_s": payload.get("elapsed_s", payload.get("runtime", {}).get("elapsed_s")),
    }, indent=2))
    return 0 if payload.get("verdict", "PASS") != "FAIL" else 1


if __name__ == "__main__":
    raise SystemExit(main())
