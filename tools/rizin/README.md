# tools/rizin — adapter v0.1 (P3)

Offline-implemented rizin integration. Scope per handoff (`HERMES-TODO.md` P3):
**xrefs, CFG, basic-block boundaries** (plus artifact hashing and function
listing via `aflj`).

No real rizin is involved anywhere in this repository: the adapter drives a
rizin-style CLI and every test uses the command-surface mock
(`tools/rizin/mock/rizin_mock.py`). The adapter is the production-relevant part;
a real installation only swaps `rizin_cmd`.

## Command surface (v0.1)

| Purpose | Commands (one invocation each) |
|---|---|
| analyze | `aaa`, `?e __PS4RF_:info__`, `ij`, `?e __PS4RF_:functions__`, `aflj` |
| xrefs | `aaa`, `?e __PS4RF_:xr__`, `axtj @ <addr>` (to) / `axfj @ <addr>` (from) |
| CFG | `aaa`, `?e __PS4RF_:cfg__`, `agfj @ <addr>` |
| boundaries | `aaa`, `?e __PS4RF_:bb__`, `afbj @ <addr>` |

Facts about these commands were verified against radare2/rizin documentation
(`?e` echo, `aflj` function list, `axtj`/`axfj` xrefs to/from, `afbj` basic
blocks with size/jump/fail/ninstr, `agfj` block graph; `-q`, `-e k=v`, repeated
`-c`). stdout is split on the `?e` echo markers; anything outside the marker
sections is a refusal.

## Files

| File | Role |
|---|---|
| `adapter.py` | `RizinAdapter`, strict normalized models, `RizinRunRecord`, `verify_run_record`, marker parsing, tolerant-but-strict normalization |
| `mock/rizin_mock.py` | command-surface mock: hashes the artifact, serves a canned catalog, emits deterministic JSON, never parses/executes the artifact |

Tests: `tests/test_rizin_adapter.py` (25 tests) · fixtures: `tests/fixtures/rizin/`
(artifact + five stdout captures, all hashes pinned).

## DoD (P3 line) → tests

| Item | Test |
|---|---|
| Tool detected, version reported | `test_health_reports_rizin_version` |
| Hashing + normalization | `test_hash_artifact_matches_pinned_fixture`, `test_analyze_normalizes_int_offsets_and_drops_extra_keys` |
| Function list | `test_analyze_returns_pinned_functions` |
| Xrefs (both directions) | `test_xrefs_to_and_from`, `test_xref_direction_contradiction_is_refused` |
| CFG (blocks + edges) | `test_cfg_blocks_and_edges`, `test_cfg_consistency_is_enforced`, `test_cfg_offset_must_match_query_target` |
| Boundaries | `test_boundaries_pinned_and_range_checked`, `test_queries_work_without_prior_analysis` |
| Evidence binding | `test_analyze_stdout_is_byte_identical_to_committed_fixture`, `test_query_stdouts_match_committed_fixtures`, `test_run_record_verifies_and_detects_tamper`, `test_run_record_detects_semantic_tamper_with_rehashed_stdout`, `test_two_queries_keep_distinct_evidence_files`, `test_marker_contract_is_enforced` |
| Fail closed | `test_analyze_refuses_expected_artifact_hash_mismatch`, `test_unknown_artifact_is_refused_single_attempt`, `test_injected_failure_single_attempt`, `test_timeout_kills_process_without_retry`, `test_not_a_function_is_refused_single_attempt`, `test_config_requires_argv_list_not_shell_string` |
| Offline + inert | `test_rizin_sources_stay_shell_free_and_firmware_free`, `test_mock_never_executes_the_artifact` |

## Normalized model (adapter contract)

```json
{"info": {"arch": "x86", "bits": 64, "endian": "little", "os": "linux"},
 "function": {"name": "sym.f", "offset": "0x401000", "size": 72, "type": "sym"},
 "xref": {"from": "0x401070", "to": "0x401158", "type": "CALL"},
 "block": {"offset": "0x4010cc", "size": 48, "jump": "0x4010fc",
           "fail": "0x401118", "ninstr": 7},
 "edge": {"src": "0x4010cc", "dst": "0x4010fc", "type": "jump"}}
```

Normalization is **tolerant where rizin metadata is opaque** (unknown keys such
as `nbbs`, `cc`, `opaddr`, `traced`, `minbound` are dropped; integer offsets are
converted to lowercase hex) and **strict where the adapter interprets**:

* missing/mistyped fields, empty sections, stray output, duplicate markers,
  duplicate/descending/overlapping blocks → refusal;
* an xref that contradicts the queried address/direction → refusal;
* a CFG whose offset differs from the query, whose edge contradicts its block's
  `jump`/`fail`, or where declared jumps/fails have no edge → refusal;
* `boundaries` cross-checks each block against the function range (when the
  function is known from a prior `analyze`).

## Safety properties (pinned by tests)

* argv list only — never a shell; no network imports; single attempt, no retry;
  timeout kills the process.
* Expected artifact hash refuses **before** any invocation.
* stdout is captured byte-exactly per query (unique file per kind+target),
  hashed into the run record; `verify_run_record` re-reads, re-parses,
  re-validates and recounts — byte drift and semantic drift (with re-hashed
  stdout) are both detected.
* No firmware addresses/RVAs, no profile knowledge in this module.

## Assumptions (v0.1, for review)

1. **Invocation style**: `rizin -q -e scr.color=0 -c <cmd> ... <artifact>`,
   markers echoed with `?e`. One invocation per query kind (no `rz-pipe` session
   yet); a real integration may batch queries in one session — the parsing and
   validation layers stay unchanged.
2. **JSON shapes**: `ij` is read as a small normalized info subset; `aflj`,
   `axtj`/`axfj`, `agfj`, `afbj` supply fields that are normalized to the model
   above. Exact upstream key names/extra keys for a given rizin release will be
   reconciled with the first real run (normalization already tolerates extras).
3. **Xref types** are normalized to `CALL|JUMP|DATA|OTHER` (rizin's native codes
   mapped); `agfj` edges are `jump|fail|other`.
4. **Offline catalog**: the mock only knows the committed fixture hash; "not a
   function" (exit 7) is an explicit refusal, not a silent empty result.

## Minimal usage

```python
from tools.rizin.adapter import RizinAdapter, RizinConfig, verify_run_record

adapter = RizinAdapter(RizinConfig(work_dir="/tmp/ps4rf-rizin"))  # mock by default
analysis = adapter.analyze("tests/fixtures/rizin/artifact.bin",
                           expected_artifact_sha256="2e2a2432...")
print([f.name for f in analysis.functions])
print([x.from_addr for x in adapter.xrefs("0x401158").xrefs])
result = adapter.cfg("0x4010cc")
print([(b.offset, b.size) for b in result.cfg.blocks])
print([(b.offset, b.size) for b in adapter.boundaries("0x401048").blocks])
verify_run_record(result.run)
```

## Explicitly not included

Real rizin execution, rz-pipe sessions, disassembly/instruction text,
string/import enumeration, diffing, RVA/profile binding, automatic batch
analysis. P3 continues with angr → AFL++ adapters.
