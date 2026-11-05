# Direct Hermes instruction

Take ownership of this PS4RF handoff candidate.

First, do not write new PS4 exploit or kernel code. Validate the host/mock core exactly as packaged:

```bash
python -m pip install -e .[dev]
python tools/preflight.py
python -m pytest -q
python tools/freeze/run_gate_suite.py
```

If a gate fails, report the failing test, exception, root cause and smallest patch. Do not redesign unrelated core architecture. Only after the runner creates `PS4RF-CORE-1.0-MOCK-READY` may you begin OrbisProbe integration.

Then inventory the real OrbisProbe source, map it to PS4RF and implement its adapter against the mock. After that implement Metasploit, Ghidra, Rizin, angr and AFL++ adapters. Plan a native PS4 agent only after the adapter layer is stable and after applying the user's live-environment approvals and transport rules.
