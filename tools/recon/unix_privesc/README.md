# tools/recon/unix_privesc — platform-independent local enumeration (adapter v0.1)

Local enumeration classification substrate, deliberately **platform-independent**:
Linux- and OrbisOS/FreeBSD-specific checks can later be derived from it, but
nothing Linux-specific is assumed here. The layer is **pure data, offline and
inert**: it parses a hash-bound collector document and classifies the captured
categories per target platform. Nothing is executed — not on the host, not on a
target and not on a console.

**Scope note (PS4/OrbisOS)**: PS4-specific checks are owned by PS4RF
surface/experiment modules and are implemented later natively. Raw PS4/OrbisOS
hints land in a separate `platform_specific` bucket with a pinned scope note
(`PS4_SCOPE_NOTE`); this layer makes **no PS4 coverage claim**.

## Files

| File | Role |
|---|---|
| `models.py` | `ps4rf.unix_privesc.collect/v1` input contract, `Category` set with platform semantics, observation-only report models, `classification_status` rule |
| `adapter.py` | `UnixPrivescAdapter.classify` (hash gate, single attempt, strict parsing), `detect_platform`, `classify_document`, `verify_report` |
| `mock/collector_mock.py` | inert deterministic generator: synthetic Linux + FreeBSD/OrbisOS collector documents (`synth-*` hosts, no credentials, no real paths beyond generic/typical ones) |

Tests: `tests/test_unix_privesc_adapter.py` · fixtures:
`tests/fixtures/unix_privesc/` (two pinned documents + README).

## DoD → tests

| Item | Test |
|---|---|
| Platform detection (3 cases) | `test_platform_detection_three_cases` |
| `linux_only` on FreeBSD → inapplicable, never dropped | `test_orbisos_document_yields_no_linux_only_interpretation` |
| No Linux-only interpretation for OrbisOS (no `/proc`, no `systemd`) | `test_orbisos_document_yields_no_linux_only_interpretation` |
| `freebsd_only` (jails) on Linux → inapplicable | `test_freebsd_only_jails_on_linux_is_inapplicable` |
| Unknown platform → refused interpretation, raw data present | `test_unknown_platform_refuses_interpretation_but_keeps_raw` |
| PS4/OrbisOS bucket separate + ownership note | `test_orbisos_platform_specific_bucket_is_separate_and_deferred` |
| Inapplicable category with entries refuses | `test_inapplicable_category_with_entries_is_refused` |
| Hash mismatch refuses before parsing | `test_hash_mismatch_refuses_before_parsing` |
| Schema strictness (extra fields, schema id, duplicates) | `test_schema_rejects_extra_fields_and_bad_schema_id`, `test_duplicate_category_blocks_are_rejected`, `test_adapter_schema_violation_fails_closed` |
| Everything OBSERVATION + `requires_verification=True` (recursive) | `test_every_report_node_is_observation_requiring_verification`, `test_observation_validator_refuses_non_observation_output` |
| Evidence binding / re-verification | `test_verify_report_rehashes_and_detects_tamper` |
| Fail closed, single attempt | `test_hash_mismatch_refuses_before_parsing`, `test_adapter_state_and_missing_document` |
| Fixture determinism / regeneration | `test_mock_regenerates_fixtures_byte_identically`, `test_fixture_readme_pins_match`, `test_mock_cli_offline_roundtrip` |
| No execution, no network (static) | `test_sources_stay_static_inert_and_offline` |

## Input contract `ps4rf.unix_privesc.collect/v1`

```json
{
  "schema": "ps4rf.unix_privesc.collect/v1",
  "collector": {"tool": "ps4rf-unix-collector", "version": "0.1-mock"},
  "target": {"hostname": "synth-host", "platform_hint": "Linux",
             "os": "Linux (synthetic)", "kernel": "6.8.0-synth"},
  "categories": [
    {"category": "os_kernel", "entries": [{"key": "os.name", "value": "..."}]},
    {"category": "jails", "entries": [{"key": "jails.count", "value": "1"}]}
  ],
  "platform_specific": [{"key": "orbisos.family_marker", "value": "synthetic"}]
}
```

* `platform_hint` is the collector's **verbatim** platform string (e.g. from
  `uname -s`); classification is a pure mapping, nothing is inferred across
  fields. `orbis`/`freebsd` → `freebsd_orbisos`, `linux` → `linux`, everything
  else → `unknown` (never guessed).
* All entries are raw key/value strings, carried through uninterpreted.
* Validation is strict (`extra="forbid"`): unknown fields, unknown categories,
  duplicate category blocks or a foreign `schema` id refuse (fail closed).
* `platform_specific` may carry PS4/OrbisOS raw hints; on a `linux` target that
  is a contradiction and refuses.

## Captured categories and platform semantics

`posix`: `os_kernel`, `identity`, `mounts`, `filesystem_permissions`, `suid`,
`sgid`, `path`, `environment`, `processes`, `services`, `sockets`, `cron`,
`writable_executables`, `writable_libraries`, `writable_configuration`,
`device_nodes`, `loaded_modules`, `sysctls`, `shells`, `installed_binaries`.
`linux_only`: `procfs`, `systemd`. `freebsd_only`: `jails`.

Classification status per platform (single source of truth:
`models.classification_status`):

| target platform | posix | linux_only | freebsd_only |
|---|---|---|---|
| `linux` | applicable | applicable | inapplicable |
| `freebsd_orbisos` | applicable | inapplicable | applicable |
| `unknown` | applicable | refused | refused |

Rules (pinned by tests):

* Every declared category appears in the report, even when the document has no
  entries for it — an inapplicable category is **recorded**, never dropped.
* An inapplicable category must carry no entries; if it does, the document
  contradicts itself and is refused (`never misapplied`).
* On `unknown`, `platform_interpretation` is `"refused"` for the document and
  `refused` for every platform-specific category, while the raw enumeration
  stays accessible in the report.
* PS4/OrbisOS hints stay in the separate `platform_specific` bucket
  (`owner="ps4rf.surface/experiment"`, `status=deferred`, pinned scope note).

## Output classification

Every node of the report tree is an explicit `OBSERVATION` with
`requires_verification=True` (model default + validator; a recursive test walks
the serialized tree). Recon output is **never** an exploit finding.

## Evidence binding

* `UnixPrivescAdapter.classify(path, expected_sha256=...)` hashes the document
  bytes first; a mismatch refuses **before** parsing. Single attempt, no
  retries, no partial output.
* The report records `document_sha256`, byte size, collector tool/version and
  hostname (`DocumentBinding`).
* `verify_report(report, path)` re-hashes, re-validates, re-classifies and
  requires the report to re-derive byte-for-byte (canonical dump); any drift
  raises `UnixPrivescEvidenceError`.

## Safety properties (pinned by tests)

* No command execution, no process spawning, no shell, no `eval`/`exec`, no
  dynamic imports; no network imports anywhere in the package (static test over
  all `.py` files).
* The mock is a generator, not a collector: deterministic bytes (sorted keys,
  no timestamps), fake hosts, no credentials, offline.
* Strict fail-closed input handling; raw strings are never interpreted beyond
  the documented platform mapping.

## Minimal usage

```python
from tools.recon.unix_privesc.adapter import UnixPrivescAdapter, verify_report

adapter = UnixPrivescAdapter()
report = adapter.classify("tests/fixtures/unix_privesc/collector-linux.json",
                          expected_sha256="fcbc305e...")
print(report.platform, {c.category.value: c.status.value for c in report.categories})
assert verify_report(report, "tests/fixtures/unix_privesc/collector-linux.json")
```

## Fixture regeneration

```bash
.venv/bin/python -m tools.recon.unix_privesc.mock.collector_mock \
    --variant linux --out tests/fixtures/unix_privesc/collector-linux.json
.venv/bin/python -m tools.recon.unix_privesc.mock.collector_mock \
    --variant freebsd_orbisos --out tests/fixtures/unix_privesc/collector-freebsd-orbisos.json
```

Pinned hashes live in `tests/fixtures/unix_privesc/README.md` and in the test
file; regeneration is required to update both.

## Assumptions (v0.1, for review)

1. The collector document contract is ours; the collector itself (target-side
   execution) is out of scope for this offline delivery.
2. `platform_hint` is taken verbatim from the collector; a future real
   collector must populate it from the target's own platform string.
3. The category set is closed for v1; new categories extend
   `Category` + `CATEGORY_SEMANTICS`.
4. `unknown` is a first-class outcome: refusing interpretation is preferred
   over guessing.

## Explicitly not included

Target-side collection, PS4-specific checks (owned by surface/experiment,
implemented later natively), exploit logic, privilege-escalation reasoning,
profile binding, kernel/console interaction.
