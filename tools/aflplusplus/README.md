# tools/aflplusplus — adapter v0.1 (P3)

Offline-implemented AFL++ workflow integration. Scope per handoff
(`HERMES-TODO.md` P3): **corpus / crash / reproducer workflow** — the spec
framing is "corpus/crash/reproducer management via evidence", which is exactly
what this adapter does: every invocation produces one hash-bound result
document plus (for `afl-tmin`) the minimized reproducer file.

**No fuzzing happens here.** `afl-fuzz` is used only for a version probe; the
adapter drives the management surface and nothing is run against a target. No
real AFL++ is involved anywhere in this repository — every command defaults to
the tool-surface mock (`tools/aflplusplus/mock/afl_mock.py`); a real
installation swaps the per-tool argv.

## Tool surface (v0.1)

| Purpose | Tool | Mock invocation |
|---|---|---|
| Version probe | `afl-fuzz` | `afl_mock.py afl-fuzz --version` |
| Coverage of one input | `afl-showmap` | `afl_mock.py afl-showmap --target T --input I --out R` |
| Corpus minimization | `afl-cmin` | `afl_mock.py afl-cmin --corpus D --out R` |
| Reproducer minimization | `afl-tmin` | `afl_mock.py afl-tmin --input C --out-min M --out R` |
| Crash triage / dedup | `afl-collect` | `afl_mock.py afl-collect --crashes D --out R` |

Exit codes: 0 ok · 2 usage · 3 target not in catalog · 4 bad input (missing
file/dir, empty corpus, non-crash file) · 8 injected failure · 9 unknown tool.

## Files

| File | Role |
|---|---|
| `adapter.py` | `AflAdapter` (health/showmap/cmin/tmin/triage/hash_file), strict tool-discriminated result models, `AflRunRecord`, `verify_run_record` |
| `mock/afl_mock.py` | tool-surface mock: deterministic mock rules over input bytes (coverage, cmin greedy keep, tmin magic+signature rule, collect grouping); never runs or fuzzes anything |

Tests: `tests/test_aflplusplus_adapter.py` (22 tests) · fixtures:
`tests/fixtures/aflplusplus/` (target, corpus, crashes, result documents and the
minimized reproducer, all hashes pinned).

## DoD (P3 line) → tests

| Item | Test |
|---|---|
| Tool detected, version reported | `test_health_reports_afl_version` |
| Hashing | `test_hash_file_matches_pinned_target` |
| Corpus (coverage + minimization) | `test_showmap_returns_pinned_coverage`, `test_showmap_flags_crash_inputs`, `test_cmin_keeps_and_drops_as_pinned`, `test_cmin_refuses_empty_directory` |
| Reproducer | `test_tmin_shrinks_and_preserves_signature`, `test_tmin_refuses_non_crash_input` |
| Crash | `test_triage_groups_crashes_by_signature`, `test_triage_refuses_non_crash_directory` |
| Evidence binding | `test_run_records_verify_and_detect_tamper`, `test_verify_detects_count_input_and_minimized_drift`, `test_runs_keep_distinct_result_files` |
| Fail closed | `test_showmap_refuses_hash_mismatch_before_invocation`, `test_unknown_target_is_refused_single_attempt`, `test_injected_failure_single_attempt`, `test_timeout_kills_process_without_retry`, `test_config_requires_argv_lists_not_shell_strings`, `test_cmin_partition_and_showmap_consistency_are_enforced`, `test_tmin_and_collect_invariants_are_enforced` |
| Offline + inert | `test_afl_sources_stay_shell_free_and_firmware_free`, `test_mock_never_executes_or_fuzzes` |

## Model invariants (refusals)

* coverage ids: unique, sorted, `0x%04x`; `crashes` ⇔ a signature is present;
* corpus: entries sorted and unique, `total` matches, kept/dropped partition the
  corpus exactly, kept sorted, `coverage_total` within the achievable range;
* reproducer: `preserved_signature` must be true (a minimized input that no
  longer crashes is refused) and the minimized file must not grow;
* triage: groups sorted by signature and unique, members sorted and unique
  across groups, `total` equals the member count.

## Safety properties (pinned by tests)

* argv lists only — never a shell; no network imports; single attempt, no retry;
  timeout kills the process.
* Expected target/input hashes refuse **before** any invocation.
* Results, all inputs (target, seeds, crash files) and the minimized reproducer
  are hashed into the run record; `verify_run_record` re-reads, re-validates,
  re-hashes every input and the minimized file, re-checks that recorded crash
  inputs still carry the crash magic, and recounts. Result tamper, count drift,
  input drift and minimized drift are all detected.
* Distinct result files per (tool, input set) — queries never clobber each
  other's evidence.
* No firmware addresses/RVAs, no profile knowledge in this module.

## Assumptions (v0.1, for review)

1. **Mock rules replace real semantics**: coverage ids and crash signatures are
   derived deterministically from input bytes; a real run uses shared-memory
   coverage and crash-state signatures (e.g. via `afl-collect`/gdb tooling).
   The adapter surface (results, records, refusals) stays.
2. **No fuzzing**: corpus growth and `afl-fuzz` campaigns are out of scope for
   v0.1; only the version probe touches `afl-fuzz`.
3. **`afl-collect` as triage**: crash dedup is modelled on AFL++'s crash
   collector; the real tool's debugger integration is a later phase.
4. **Targets are files**: `showmap` requires the committed fixture target hash
   in mock mode; a real target binary path is a later-phase concern.

## Minimal usage

```python
from tools.aflplusplus.adapter import AflAdapter, AflConfig, verify_run_record

adapter = AflAdapter(AflConfig(work_dir="/tmp/ps4rf-afl"))     # mock by default
cov = adapter.showmap("tests/fixtures/aflplusplus/target.bin",
                      "tests/fixtures/aflplusplus/corpus/seed0.bin")
print(cov.tuples, cov.crashes)
cmin = adapter.cmin("tests/fixtures/aflplusplus/corpus")
print(cmin.kept, [(d.name, d.reason) for d in cmin.dropped])
rep = adapter.tmin("tests/fixtures/aflplusplus/crashes/crash_a.bin")
print(rep.input.size, "->", rep.minimized.size, rep.preserved_signature)
triage = adapter.triage("tests/fixtures/aflplusplus/crashes")
print([(g.signature, g.members) for g in triage.groups])
verify_run_record(rep.run)
```

## Explicitly not included

Real fuzzing campaigns, live target execution, shared-memory coverage, gdb-based
crash collection, corpus bootstrapping, RVA/profile binding. P3 (tool adapters)
is complete with this adapter — Ghidra, Rizin, angr and AFL++ each have a
fail-closed, offline, mock-tested v0.1.
