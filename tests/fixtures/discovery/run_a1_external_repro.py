"""Run each external A1 reproduction in a clean interpreter.

The fixture stubs ``capstone`` at import time and asserts the *audited* behaviour, so it
must be executed in a process where the real capstone was never imported, and it must be
run one proof at a time: the last proof aborts on its own assertion, which would hide the
others.  An AssertionError is the expected outcome on the corrected tree.
"""
from __future__ import annotations

import importlib.util
import sys

FIXTURE = "a1_external_repro.py"
PROOFS = ("handle_store_proof", "refcount_guard_proof", "shortest_path_proof",
          "queue_merge_proof", "entry_gate_proof")


def load(path: str):
    spec = importlib.util.spec_from_file_location("a1_external_repro", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main(argv) -> int:
    module = load(argv[1] if len(argv) > 1 else FIXTURE)
    failures = 0
    for name in PROOFS:
        proof = getattr(module, name)
        try:
            proof()
        except AssertionError:
            print(f">>> {name}: audited behaviour GONE (fixed)")
        except Exception as exc:                       # harness problem, not a fix
            print(f">>> {name}: HARNESS ERROR {type(exc).__name__}: {exc}")
            failures += 1
        else:
            print(f">>> {name}: STILL REPRODUCES the audited behaviour")
            failures += 1
    print("SUMMARY:", "all five findings no longer reproduce" if failures == 0
          else f"{failures} proof(s) still reproduce or errored")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
