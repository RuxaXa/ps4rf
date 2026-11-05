# tools/recon/peass — PEASS-ng/linPEAS result adapter v0.1 (P4)

Offline-implemented PEASS-ng/linPEAS integration for **Linux host / auxiliary
target enumeration** and **container/VM/support-environment assessment**.
Follows the adapter conventions of `tools/ghidra/README.md` (CLI mock by
default, argv-list commands, hash-bound run records, `verify_run_record`,
single attempt, fail-closed errors) and `tools/aflplusplus/README.md` (one
hash-bound result document per invocation).

The adapter **parses scan results**. Real linPEAS runs happen on the scanned
target by the operator; this module ingests their output (`ingest`) or drives
the **offline mock scan profile** (`scan` — synthetic reports, used by the
tests). It never contacts a target, never executes a real scanner and never
uses a shell.

Parsing covers: filesystem, permissions, SUID/SGID binaries, capabilities,
services, cron jobs, sockets, credentials (presence only), mounts, kernel/OS
information, interesting binaries, and container/VM indicators.

## Files

| File | Role |
|---|---|
| `models.py` | Report/finding/run models, canonical JSON (`dump_canonical`), target-OS policy constants and the only classification value (`OBSERVATION`) |
| `parser.py` | Pure parser for linPEAS-style text: OS detection, section→category mapping, credential redaction |
| `adapter.py` | `PeassAdapter` (`health`/`scan`/`ingest`), hash-bound `PeassRunRecord`, `verify_run_record` |
| `mock/linpeas_mock.py` | Deterministic offline mock: emits a synthetic linPEAS-style report for `linux` and `orbisos`; never contacts or executes anything |

Tests: `tests/test_peass_adapter.py` · fixtures: `tests/fixtures/peass/`
(scan outputs + canonical analysis documents + pinned hashes, including the
mock's own hash).

## DoD (P4 recon line) → tests

| Item | Test |
|---|---|
| Offline mock detected, version reported | `test_health_reports_mock_version`, `test_mock_cli_version_and_unknown_target` |
| Hashing: scan, scanner, analysis document | `test_hash_file_matches_pinned_fixtures`, `test_scan_is_deterministic_and_matches_pinned_fixture`, `test_ingest_writes_byte_identical_canonical_documents` |
| Enumeration categories parsed | `test_linux_analysis_covers_all_required_categories` |
| Target-OS policy (LINUX / FREEBSD_ORBISOS / UNKNOWN) | `test_linux_target_is_compatible_with_canonical_reason`, `test_orbisos_target_is_not_compatible_with_native_ps4_reason`, `test_unknown_target_fails_closed`, `test_mixed_os_markers_fail_closed_to_unknown`, `test_compatibility_verdict_cannot_be_hand_rolled` |
| No vulnerability classification, ever | `test_whole_output_tree_is_observation_only`, `test_observation_walker_detects_a_violation`, `test_finding_model_rejects_any_other_classification` |
| Credentials: presence only, never copied | `test_credentials_are_reported_without_copying_values` |
| Hash-bound run record + evidence re-verification | `test_run_record_carries_cmd_hash_counts_and_timestamps`, `test_verify_run_record_and_detects_document_tamper`, `test_verify_run_record_detects_scan_tamper` |
| Fail closed | `test_ingest_refuses_expected_hash_mismatch_before_any_parse`, `test_scan_refuses_expected_scanner_hash_mismatch_before_any_run`, `test_scan_refuses_expected_scan_output_drift_single_attempt`, `test_scan_injected_failure_single_attempt`, `test_scan_timeout_kills_process_without_retry`, `test_unparseable_scan_is_refused`, `test_missing_scan_file_is_refused`, `test_scan_refuses_unknown_target`, `test_config_requires_argv_list_not_shell_string` |
| Offline + inert | `test_fixtures_stay_synthetic_deterministic_and_clean`, `test_peass_sources_stay_shell_free_and_offline`, `test_mock_never_runs_anything` |

## Target-OS policy (PS4/OrbisOS is FreeBSD-based)

linPEAS is **not** a generic PS4 scanner. The adapter detects the target OS
from scan content (provenance header plus the System Information section) and
reports one of:

| Detected OS | `compatible` | Reason (canonical, from `models.py`) |
|---|---|---|
| `LINUX` | `True` | linPEAS assumptions apply; findings remain observations requiring verification |
| `FREEBSD_ORBISOS` | `False` | linPEAS assumptions do not apply to PS4/OrbisOS; PS4-specific checks must be implemented natively later via PS4RF surface/experiment modules |
| `UNKNOWN` | `False` | fail closed until the target OS is known |

The verdict is derived from the detected OS and re-checked by the
`PeassReport` validator against the canonical reasons; a report cannot mark
itself compatible by hand. Ambiguous markers (Linux *and* FreeBSD markers in
the detection window) fail closed to `UNKNOWN`.

## Classification rule

Every finding is an `OBSERVATION` with `requires_verification=True`. The field
types (`Literal`) and a finding validator reject any other value, and a test
walks the entire output object tree (model dump and on-disk document) failing
on any other classification value. Adapter output is **never** a vulnerability
claim: linPEAS output describes the target, it does not prove anything about
it.

## Hash binding

* The scan output is the pinned input. `ingest(..., expected_scan_sha256=...)`
  refuses **before any parsing** on mismatch (the refusal path is pinned by a
  test that proves the parser was never called).
* `scan(..., expected_scanner_sha256=...)` pins the local scanner artifact and
  refuses **before any run**; the produced scan is cross-checked against
  `expected_scan_sha256` (drift refusal after the single attempt).
* Every analysis writes one canonical document
  (`{scan8}-analysis.json`); `PeassRunRecord` carries scanner cmd/argv,
  tool/version, scan path + sha256, document path + sha256, counts (total,
  per category) and timestamps. `verify_run_record` re-hashes the scan,
  re-parses it, re-counts every category and byte-checks the document against
  the canonical rendering.

## Provenance

Provenance is declared, not implied: the mock writes `# scanner: linPEAS
…`, `# synthetic: true` and refuses unknown targets (exit 3); the parser reads
these header lines into `PeassScannerInfo`. When a scan was produced elsewhere,
`ingest` records `scanner_cmd = ["<scanner-command-not-recorded>"]` unless the
caller supplies the producing command — the adapter never invents one.

## Credentials

Credential-like entries are reported as observations ("credential-like artifact
observed") with any value rewritten to `[value withheld]` by the parser before
it can reach the models. Tests pin that a value placed in a `keyword: value`
line is absent from every output surface; the committed fixtures contain no
secret-like values at all.

## Safety properties (pinned by tests)

* No target contact: nothing in `tools/recon` uses shells (`shell=True`), raw
  sockets or remote/HTTP libraries; the only process the adapter can start is
  `scanner_cmd` (the loopback mock by default).
* The mock is inert: no subprocess/socket/eval/exec/os.system in its source.
* Single attempt per invocation, no retries; a timeout kills the process.
* Fail closed: empty/unsupported scans, missing files, unknown targets, hash
  mismatches and evidence drift all refuse.

## Assumptions (v0.1, for review)

1. **Scan format**: linPEAS-style `╔══════════╣ <title>` section headers and
   `╚ <text>` entry lines; section titles map onto a fixed category set,
   unknown sections are skipped, and a scan with no recognized finding is
   refused rather than treated as clean. Reconcile against the first real
   linPEAS capture.
2. **CLI surface** of the mock: `--target linux|orbisos --output <path>` and
   `--version`; exit codes documented in the mock header. A real installation
   only swaps `scanner_cmd` (and `scanner_artifact` for the hash pre-check).
3. **Compatibility policy** is adapter-local; PS4-specific checks are
   explicitly out of scope here and land natively later via PS4RF
   surface/experiment modules.
4. **Container/VM/support-environment** signals are represented as
   `environment` findings (plus mounts/services observations) — no separate
   runtime probing is performed.

## Fixtures & regeneration

Committed fixtures live in `tests/fixtures/peass/` (scan outputs, canonical
analysis documents, pinned sha256s — see that directory's README for the full
regeneration recipe):

```
.venv/bin/python -m tools.recon.peass.mock.linpeas_mock --target linux \
    --output tests/fixtures/peass/scan-linux.txt
.venv/bin/python -m tools.recon.peass.mock.linpeas_mock --target orbisos \
    --output tests/fixtures/peass/scan-orbisos.txt
```

## Minimal usage

```python
from tools.recon.peass.adapter import PeassAdapter, verify_run_record
from tools.recon.peass.models import PeassConfig

adapter = PeassAdapter(PeassConfig(work_dir="/tmp/ps4rf-peass"))  # mock scanner by default
analysis = adapter.ingest("tests/fixtures/peass/scan-linux.txt",
                          expected_scan_sha256="5ecef87f...")
print(analysis.report.target.os, analysis.report.compatibility.compatible)
print(analysis.run.category_counts)
assert verify_run_record(analysis.run)

# offline demo scan against the mock profile (tests only -- never a real target):
# analysis = adapter.scan("linux")
```

## Explicitly not included

Real linPEAS execution against targets, live host access, auto-exploitation
from scanner output, vulnerability classification, PS4-native enumeration
(that is a later PS4RF surface/experiment task), WiFi/network scanning.
