# tools/angr — adapter v0.1 (P3)

Offline-implemented angr integration. Scope per handoff (`HERMES-TODO.md` P3):
**CFG / dataflow / constraints** (plus artifact and runner hashing).

No real angr is involved anywhere in this repository: angr is a Python library,
so the adapter talks to a *runner process* with a request/export contract, and
every test uses the runner mock (`tools/angr/mock/angr_mock.py`). The committed
placeholder `scripts/ps4rf_angr_run.py` is the real, hash-pinned contract stub;
the actual angr implementation (CFGFast, def-use dataflow, symbolic exploration)
lands with an angr installation and does not change the adapter surface.

## Contract (v0.1)

Request `ps4rf.angr.request/v1` (written by the adapter):

```json
{"schema": "ps4rf.angr.request/v1", "mode": "analyze|dataflow|symbolic",
 "artifact": "<abs path>", "artifact_sha256": "<sha>",
 "entry": "0x...",     // analyze
 "function": "0x...",  // dataflow
 "target": "0x..."}    // symbolic
```

Export `ps4rf.angr.export/v1` (written by the runner), mode-discriminated:

| Mode | Payload |
|---|---|
| analyze | `info` (arch/bits/endian/os), `entry`, `functions` (name/offset/size/blocks), `cfg` (nodes offset+size, edges src/dst/type ∈ call, jump, fallthrough, ret, other) |
| dataflow | `function` (name/offset/size), `edges` (from/to/kind ∈ reg, mem, stack/value) |
| symbolic | `target`, `paths` (path_id, reached, steps, constraints: expr/satisfiable/solution) |

Every export carries `artifact.sha256` and `generator` (tool/version/runner/
runner_sha256) — both are cross-checked against the adapter's own values.

Invocation: `runner_cmd run --request <req.json> --out <export.json>`; runner
health: `runner_cmd --version`. Exit codes: 0 ok · 3 artifact unknown/missing ·
4 bad request · 7 function/target not found · 8 analysis failed; 2/9 usage.

## Files

| File | Role |
|---|---|
| `adapter.py` | `AngrAdapter` (health/analyze/dataflow/symbolic/hash_artifact/hash_runner), strict mode-discriminated models, `AngrRunRecord`, `verify_run_record` |
| `mock/angr_mock.py` | runner mock: hashes the artifact, serves a canned catalog, deterministic exports, injection hooks; never loads/executes the artifact |
| `scripts/ps4rf_angr_run.py` | committed runner placeholder (hash-pinned; real implementation lands with angr) |

Tests: `tests/test_angr_adapter.py` (25 tests) · fixtures: `tests/fixtures/angr/`
(artifact + three mode exports, all hashes pinned).

## DoD (P3 line) → tests

| Item | Test |
|---|---|
| Tool detected, version reported | `test_health_reports_runner_version` |
| Hashing (artifact + runner) | `test_hashes_match_pinned_fixtures` |
| CFG | `test_analyze_returns_pinned_functions_and_cfg`, `test_cfg_edges_must_reference_nodes`, `test_analyze_export_rejects_inconsistent_functions_and_nodes` |
| Dataflow | `test_dataflow_returns_pinned_edges`, `test_dataflow_unknown_function_is_refused_single_attempt`, `test_dataflow_and_symbolic_exports_enforce_range_and_target` |
| Constraints | `test_symbolic_returns_pinned_paths_and_constraints`, `test_constraint_requires_consistent_satisfiability`, `test_symbolic_unreachable_target_is_refused` |
| Evidence binding | `test_analyze_export_is_byte_identical_to_committed_fixture`, `test_request_document_matches_contract`, `test_run_records_verify_and_detect_tamper`, `test_verify_detects_count_and_request_drift`, `test_runs_keep_distinct_evidence_files` |
| Fail closed | `test_analyze_refuses_expected_artifact_hash_mismatch`, `test_analyze_refuses_runner_hash_drift`, `test_unknown_artifact_is_refused_single_attempt`, `test_injected_failure_single_attempt`, `test_timeout_kills_process_without_retry`, `test_analyze_accepts_expected_entry_and_refuses_mismatch`, `test_config_requires_argv_list_not_shell_string` |
| Offline + inert | `test_angr_sources_stay_shell_free_and_firmware_free`, `test_mock_never_executes_the_artifact` |

## Safety properties (pinned by tests)

* argv list only — never a shell; no network imports; single attempt, no retry;
  timeout kills the process.
* Expected artifact **and** runner hashes refuse **before** any invocation.
* Request and export are both written to disk and hash-bound in the run record;
  `verify_run_record` re-reads and re-checks artifact, runner, request and
  export hashes, re-validates the mode-discriminated export and recounts.
* Invariants refused at validation time: CFG edges leaving the node set, CFG
  nodes ≠ union of function blocks, blocks outside their function,
  dataflow sources outside the queried function, paths that did not reach the
  queried target, constraints whose `satisfiable` contradicts their `solution`,
  unknown keys, wrong schema id.
* No firmware addresses/RVAs, no profile knowledge in this module.

## Assumptions (v0.1, for review)

1. **Runner process contract**: the real runner will be an argv swap
   (`python -m ps4rf_angr_run` or a venv with angr); request/export stay.
   No `angr.Project` object is ever constructed inside PS4RF.
2. **Symbolic scope**: paths are recorded for one target address per run;
   satisfiability and one example solution per constraint (no solver session,
   no strategy configuration yet).
3. **Dataflow scope**: def-use edges for one function per run (from → to with
   register/memory/stack kind); no interprocedural propagation yet.
4. **Offline catalog**: the mock knows the committed fixture hash only;
   "not a function"/"target unreachable" (exit 7) is an explicit refusal.

## Minimal usage

```python
from tools.angr.adapter import AngrAdapter, AngrConfig, verify_run_record

adapter = AngrAdapter(AngrConfig(work_dir="/tmp/ps4rf-angr"))  # mock by default
analysis = adapter.analyze("tests/fixtures/angr/artifact.bin",
                           expected_artifact_sha256="efd36183...")
print([(f.name, f.blocks) for f in analysis.functions])
print([(e.from_addr, e.to_addr, e.kind.value) for e in
       adapter.dataflow("tests/fixtures/angr/artifact.bin", "0x401060").edges])
paths = adapter.symbolic("tests/fixtures/angr/artifact.bin", "0x40110c").paths
print([(p.path_id, [c.expr for c in p.constraints]) for p in paths])
verify_run_record(analysis.run)
```

## Explicitly not included

Real angr execution, solver sessions/strategies, interprocedural dataflow,
hook/SimProcedure support, state merging, RVA/profile binding. P3 continues with
the AFL++ adapter (corpus / crash / reproducer workflow).
