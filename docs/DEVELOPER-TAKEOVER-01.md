# PS4RF — Direct developer handoff, patch 01

**Baseline:** Hermes source export `93cc14854e985cf22152c3e560be10cd91e8a201` (`s19-partial-baseline`).  The original upload `ps4rf-source-handoff-93cc148.zip` has SHA-256 `bb45b381e614684aec76c9667808a1ca15a8f4c2d783240384dd3df454b80a5e`. ZIP extraction and CRC check passed locally.  No Sony firmware image was used.

## Bug addressed

`tools/discovery/patterns.py::detect_lock_coverage` used `_blocks_without_lock`, which excludes an entire basic block as soon as it contains an observed acquisition call. A store **before** the lock call in that same block was therefore silently hidden from D3, although its instructions are reachable before the acquisition.

The patch introduces `tools/discovery/lock_paths.py::stores_before_any_lock`, which traverses CFG successors but inspects instructions **in order** in each block, yielding stores only until the first lock acquisition. Existing D3 output remains rank 2 (`CONDITIONAL` at most): this is not a lock-identity, lock-release or cross-function proof.

Changes:

- D3 calls the instruction-order-aware helper and describes the exact evidence boundary.
- Added binutils-generated positive/negative assembler fixtures with a store before/after a lock in the *same* block; updated fixture JSON and source generator.
- Added 7 no-Capstone lightweight tests: pre-lock store, post-lock store, all-path locks, one-path gap, loop, unreachable store, empty view.
- Added an integration regression asserting that the earlier block-granularity helper hides the positive control.

## Locally executed checks

- `python -m pytest -q tests/test_discovery_lock_paths_unit.py`: **7 passed**.
- `python tests/fixtures/discovery/gen_lock_coverage.py --check`: **passed** (assembled bytes match source).
- `python -m compileall -q tools/discovery/lock_paths.py tools/discovery/patterns.py tests/test_discovery_lock_paths_unit.py`: **passed**.
- `git diff --check`: **passed**.

**Not run here:** `python -m pytest tests/ -q -k discovery` (and the full `test_discovery_lock_coverage.py`) because Capstone is not installed in this runtime and package-index access was unavailable. **Do not** claim Hermes' 301/301 result still holds after this patch until it is independently re-run. The firmware analysis also cannot be repeated without local image access.

## Apply and validate on a source tree

```bash
cd /path/to/unpacked/ps4rf-93cc148
git apply --check /path/to/PS4RF_93cc148_D3_Instruction_Order.patch
git apply /path/to/PS4RF_93cc148_D3_Instruction_Order.patch
python -m pytest -q tests/test_discovery_lock_paths_unit.py
python -m pytest -q tests/test_discovery_lock_coverage.py
python tests/fixtures/discovery/gen_lock_coverage.py --check
python -m pytest -q tests/ -k discovery
```

The patch assumes exact baseline source `93cc148`. Apply to a **new clean working copy**, not to a tree with ongoing Hermes edits. If comparing FW 13.52 scans, retain the original image hash and do not silently reclassify ranks or historical observations.

## Remaining limitations and next development gates

1. **D3:** Lock identities, unlock points and caller-held locks remain outside this local helper's proof. A missing CFG edge may also hide a path. Nothing in this patch authorizes promoting D3 to PROVEN.
2. **D2/D3/S1.9:** The private firmware differential, including the fixed 13.52 negative control, requires a real run and independent review after patch application.
3. **A1-08/A1-09:** Remain open/partial according to the handoff. Do not silently close them based on a green fixture test.
4. **Blind benchmark:** Remains BLOCKED, not a validated autonomous-discovery capability.
5. **Repository safety:** Do not push Hermes' original Git history. The archived `references/` were deliberately excluded; a fresh private repository requires a separate reviewed import. The source package still contains some local IP/path literals.

**Scope statement:** This is a narrowly scoped, independently authored correction, not a claim that PS4RF's discovery engine has been completed or that a new vulnerability has been found.
