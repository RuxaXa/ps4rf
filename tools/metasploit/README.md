# tools/metasploit — adapter v0.1 (P2)

Offline-implemented Metasploit integration per spec v0.3 §12 / v0.4 N4.
Nothing here talks to a real Metasploit: the adapter is exercised end-to-end
against a loopback msfrpcd mock over real HTTP + MessagePack. No target, no
hardware, no external network.

## Files

| File | Role |
|---|---|
| `adapter.py` | `MetasploitAdapter` (§12.2 method set) + `MetasploitRunRecord` + `verify_run_record` |
| `provider.py` | `MsfModuleManifest` validation, `metasploit:<ref>` bridge to `ExploitManifest`, authority rule, host-core operations (§12.6) |
| `mock/msfrpcd_mock.py` | `MockMsfRpc`: loopback MessagePack-RPC mock, deterministic, no secrets in logs |
| `modules/*.exploit.yaml` | Synthetic example manifests (PROVIDER status) — no real exploit content |
| `redact.py` | FINAL (N4), unchanged |

Tests: `tests/test_metasploit_adapter.py`, `tests/test_metasploit_provider.py`,
`tests/test_msf_redaction.py` (T-MSF-01/02/03 per v0.4 §10.4).

## DoD §12.7 → tests

| # | DoD item | Test |
|---|---|---|
| 1 | RPC server detected, `health()` returns version | `test_dod1_health_reports_framework_revision` |
| 2 | Modules listed/read from a fixed catalog | `test_dod2_list_modules_and_module_info` |
| 3 | Auxiliary run → job id + evidence record | `test_dod3_auxiliary_run_yields_job_and_evidence_record` |
| 4 | Exploit as provider → `metasploit:` manifest bridge validates | `test_dod4_manifests_load_and_validate`, `test_dod4_bridge_exploit_manifest` |
| 5 | Results in evidence: `metasploit_run_record` + hash binding | `test_dod5_run_record_redacts_secrets`, `test_output_hash_binding_and_verification`, `test_verify_run_record_rejects_tampered_options_hash` |
| 6 | Sessions listed/inspected, ownership enforced | `test_dod6_session_lifecycle_and_ownership`, `test_foreign_sessions_cannot_be_driven` |
| 7 | Capability only via PS4RF verify; PROVEN only after `verify.*`; violation is a test case | `test_dod7_authority_rule_precedence`, `test_dod7_msf_record_cannot_claim_proven`, `test_dod7_msf_provider_verification_still_capped_at_observed`, `test_dod7_proven_via_separate_native_verify_run`, `test_dod7_verified_by_requires_verify_namespace`, `test_dod7_operation_must_match_the_grant` |
| 8 | Whole suite offline against the mock | every test above (no network, no subprocess) |

## Safety properties pinned by tests

* Loopback or TLS only: `MsfConfig` refuses non-local endpoints without TLS (§12.1).
* Token from environment only; missing token → refusal *before* any request.
* No automatic retry (single attempt per call, §12.5/§49).
* `module_run` defaults to `dry_run=True` (check-only, no `module.execute`).
* `session_command`/`session_close` only for sessions adopted by this adapter's
  own runs; commands are logged (method/command/sha256 of the response).
* Redaction (N4): option secrets become `<redacted>`; `options_sha256` is computed
  over the redacted object, so it is identical for different secret values —
  no clear text, no digest, no fingerprint in evidence.
* Capability ceiling: any record in the `^metasploit:` namespace is clamped to
  OBSERVED by the resolution engine and by `grant_from_verification`.

## Documented assumptions (v0.1, for review)

1. **Wire format**: JSON-RPC 2.0 envelope inside MessagePack, `POST /api/`,
   `Content-Type: binary/message-pack`, token as `params[0]` on every call —
   the de-facto client behaviour of msfrpcd. The mock implements exactly this.
2. **Module listing methods** use the daemon naming `module.exploits`,
   `module.auxiliary`, `module.post`.
3. **Single-token auth** (`params[0]`) instead of user/password+session-token:
   §12.1 requires the credential to come from an environment variable; the mock
   validates it per call and never echoes it.
4. **Result mapping** (`v0.1`, to revisit with a real daemon): check codes
   `vulnerable→VULNERABLE`, `safe→PATCHED`, `detected/unknown→UNKNOWN`,
   `error→ERROR`; `module.execute.result` `success/failure/dead/timeout/error`
   → `SUCCESS/FAILED/DEAD_TARGET/TIMEOUT/ERROR`. Session creation is derived
   from the session list delta around `module.execute`.
5. **Synchronous sessions**: `session_command` assumes the mock's synchronous
   write+read pair; a real msfrpcd would need read polling/waiting.
6. **PROVEN interpretation**: §12.3 caps the MSF *provider namespace* at
   OBSERVED; PROVEN can therefore only be attributed to a separate PS4RF-native
   verification record (`verify.*`, different run, provider outside
   `^metasploit:`). This is enforced in tests, not just documented — flagged
   for review since §12.3's example flow is terse on attribution.
7. **Reliability model**: `ReliabilityStats` mirrors v0.4 §9.6 locally; it moves
   to `core/models/exploit.py` with delivery 2 (core was not touched in P2).
8. **Dependency**: `msgpack>=1.0` added to `pyproject.toml` (transport codec).

## Minimal usage

```python
from tools.metasploit.adapter import MetasploitAdapter, MsfConfig
from tools.metasploit.mock.msfrpcd_mock import MockMsfRpc

with MockMsfRpc() as mock:                      # offline; real: point to msfrpcd
    os.environ["PS4RF_MSF_TOKEN"] = "..."       # never stored anywhere else
    adapter = MetasploitAdapter(MsfConfig(port=mock.port))
    adapter.health()
    record = adapter.module_run("auxiliary", "auxiliary/ps4/example_probe",
                                {"RHOSTS": "192.0.2.10"}, dry_run=False)
```

## Explicitly not included

Real Metasploit connectivity, TLS server side, orchestrating check→run→verify,
profile or evidence-store writes beyond the run record, orchestrating retries,
payload delivery. Safety gates stay in PS4RF (§12.5); the adapter never chains.
