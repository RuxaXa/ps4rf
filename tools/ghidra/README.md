# tools/ghidra — adapter v0.1 (P3)

Offline-implemented Ghidra integration. Scope per handoff (`HERMES-TODO.md` P3):
**headless, function list, decompile, xrefs, hashing**.

No real Ghidra and no Java are involved anywhere in this repository: the adapter
drives a headless CLI, and the CLI used by every test is the loopback mock
(`tools/ghidra/mock/headless_mock.py`). The adapter is the part that becomes
production-relevant — a real installation only swaps `headless_cmd`.

## Files

| File | Role |
|---|---|
| `adapter.py` | `GhidraAdapter` (health/analyze/list_functions/decompile/xrefs/hash_artifact), export models, `GhidraRunRecord`, `verify_run_record` |
| `mock/headless_mock.py` | `analyzeHeadless`-style mock: hashes the artifact, serves a canned catalog, writes deterministic JSON; never executes the artifact |
| `scripts/ps4rf_ghidra_export.py` | placeholder postscript (hashed per run; real implementation lands with the first real Ghidra run) |

Tests: `tests/test_ghidra_adapter.py` (19 tests) · fixtures:
`tests/fixtures/ghidra/` (artifact, export, pinned hashes).

## DoD (P3 line) → tests

| Item | Test |
|---|---|
| Headless detected, version reported | `test_health_reports_headless_version` |
| Hashing: artifact, postscript, export | `test_hash_artifact_matches_pinned_fixture`, `test_analyze_returns_pinned_functions` |
| Function list | `test_analyze_returns_pinned_functions` |
| Decompile | `test_decompile_by_name_and_entry`, `test_decompilation_text_binding_is_enforced` |
| Xrefs (both directions, typed) | `test_xrefs_directions` |
| Evidence binding | `test_export_is_byte_identical_to_committed_fixture`, `test_run_record_verifies_and_detects_tamper`, `test_schema_id_is_checked` |
| Fail closed | `test_analyze_refuses_expected_artifact_hash_mismatch`, `test_analyze_refuses_script_hash_drift`, `test_unknown_artifact_is_refused_single_attempt`, `test_injected_failure_single_attempt`, `test_timeout_kills_process_without_retry`, `test_result_accessors_require_analysis`, `test_config_requires_argv_list_not_shell_string` |
| Offline + inert | `test_ghidra_sources_stay_shell_free_and_firmware_free`, `test_mock_never_executes_the_artifact` |

## Export contract `ps4rf.ghidra.export/v1`

```json
{
  "schema": "ps4rf.ghidra.export/v1",
  "artifact": {"sha256": "..."},
  "program": {"name": "...", "language": "...", "image_base": "0x..."},
  "functions": [{"name": "...", "entry": "0x...", "size": 64, "body_sha256": "..."}],
  "xrefs": [{"from": "0x...", "to": "0x...", "type": "CALL|JUMP|DATA|OTHER"}],
  "decompilations": [{"function": "...", "entry": "0x...", "text": "...",
                      "text_sha256": "..."}],
  "generator": {"tool": "ghidra-headless", "version": "...", "script": "...",
                "script_sha256": "..."}
}
```

Validation is strict (`extra="forbid"`), addresses are opaque lowercase hex
(`0x…`, never interpreted as firmware RVAs), decompilation text and the
postscript are hash-bound, and the export deliberately omits the artifact path
so committed fixtures stay byte-reproducible.

## Safety properties (pinned by tests)

* argv list only — never a shell; no network imports; single attempt, no retry;
  timeout kills the process.
* Expected artifact/postscript hashes refuse **before** any process starts.
* After a run: export hash, artifact hash, postscript hash and counts are
  cross-checked; tamper is detected (`verify_run_record`).
* No firmware addresses, no RVA mapping, no profile knowledge in this module —
  binding addresses to profiles stays a PS4RF profile-domain task.
* The mock hashes and catalogues; it never parses or executes the artifact.

## Assumptions (v0.1, for review)

1. **CLI surface**: `analyzeHeadless <project_location> <project_name> -import
   <file> -scriptPath <dir> -postScript <script> [out.json] -deleteProject` and
   `--version`; exit codes documented in the mock. Real Ghidra's exact flags and
   version output will be reconciled with the first real installation.
2. **Export contract** is ours (no upstream format): it is the interface between
   the future real postscript and the adapter.
3. **No project artifacts**: the mock creates nothing outside the export; the
   adapter does not manage Ghidra projects beyond passing the directory.
4. **Decompiler scope**: only functions present in `decompilations` can be
   decompiled; absence is an explicit `GhidraNotFound`, not a silent skip.

## Minimal usage

```python
from tools.ghidra.adapter import GhidraAdapter, GhidraConfig

adapter = GhidraAdapter(GhidraConfig(project_dir="/tmp/ps4rf-ghidra"))  # mock by default
analysis = adapter.analyze("tests/fixtures/ghidra/artifact.bin",
                           expected_artifact_sha256="bb249eaf...")
print([f.name for f in adapter.list_functions()])
print(adapter.decompile("mock_init").text)
print(adapter.xrefs("0x401208"))
```

## Explicitly not included

Real Ghidra/Java execution, the real postscript implementation, project
management, diffing across program versions, RVA/profile binding, automatic
re-analysis. P3 continues with Rizin → angr → AFL++ adapters.
