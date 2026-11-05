# P4-CCP — acceptance requirements for the agent (ps4rfd)

**Source.** Owner message *"CCP-Test — Anforderungen an den Agent (ps4rfd)"* (2026-10-07), normalized
into repository form. No requirement was added, dropped or reworded in substance; operation names and
error codes are kept verbatim.

**Status.** **Specification only — no live action.** This is the acceptance spec for the first
hardware-side CCP step (P4 pull-forward).

**Integration finding.** The frozen core stays frozen. The only admitted extension forms are:
registry entries, profile data, mock extension, and **one** new provider module.

**Owner constraints (verbatim).** FW-13.52 bindings (device paths, function offsets, ioctls) are *not*
delivered by the owner — they come from this project's own research and live in `profiles/fw1352/`.
Nothing beyond test slots / test keys is provided.

---

## 1. Gates before the first CCP call

* **Freeze** — G1–G8 green and the tag `PS4RF-CORE-1.0-MOCK-READY` set (or a documented exception).
  *Status: NOT met.* `FREEZE-STATUS.md`: "FREEZE PATCH APPLIED — REAL G1–G8 EXECUTION PENDING — TAG
  NOT CREATED". `CURRENT-STATE.json` carries `status: FREEZE_PATCH_APPLIED_REAL_GATES_PENDING`.
* **Phase 2 isolated PASS** — `memory.alloc`/`memory.free`, `keymgr.claim`/`keymgr.release`,
  `gpuvm.map`/`gpuvm.unmap` (if the provider is kernel-based), `kernel.snapshot`: 10 runs each,
  `cleanup_report = COMPLETE`. *Status: pending (hardware).*
* **Profile** — `profiles/fw1352` validated: CCP struct layouts, provider binding,
  `validation_chain` all PASS — else `PROFILE_MISMATCH`, no test.
  *Status: prepared offline* (`profiles/fw1352/ccp-layouts.json` + the revision candidate
  `profiles/fw1352/profile-13.52-ccp1.json`); promotion pending (see section 6/7).
* **Capability** — `ccp.*` requires `PROVEN`; `verify.ccp.submit` must exist in the registry and run
  as a separate run. *Status: `verify.ccp.submit` is not registered yet (Stage 0 work).*

## 2. Requirements for the agent (REQ-CCP)

### A. Operations (registry extension — data plus additive spec)

* `keymgr.claim` → opaque slot ref + generation, session-bound.
* `keymgr.load_test_key` → **framework test key only** (test config), **session-owned slot only**;
  a foreign or protected slot → `RESOURCE_STATE_INVALID`.
* `keymgr.release` → the slot must not be usable afterwards (`INV_SLOT_001`).
* `keymgr.snapshot` → telemetry, only where the profile allows it.
* `ccp.submit` → `buffer-ref`, `slot-ref`, `algorithm`, `data_id`.
* `verify.ccp.submit` → known-answer test, `mutating=False`, `recovery_safe=False`.

No new error codes (freeze discipline): existing codes plus the `details` field.

### B. Contracts

* No raw addresses on the wire — only `mem:`/`gpumap:`/`slot:` refs (v0.1 section 5).
* Per-submission state machine: `BUFFER_READY → SLOT_ACQUIRED → KEY_LOADED → SUBMIT_ACTIVE →
  RESULT_COLLECTED → SLOT_RELEASED → FREED`; every transition is a telemetry event.
* Serialization per slot: a second `ccp.submit` on the same slot while `SUBMIT_ACTIVE` →
  `RESOURCE_STATE_INVALID`. Cross-slot parallelism up to `max_parallel_tasks` is allowed.
* Mandatory timeout: every submit carries a soft/hard timeout; a hard timeout → `HANG_SUSPECTED` →
  poison/recovery path, and the in-flight submit is recorded as `IN_FLIGHT_AT_RECOVERY` in evidence.
* Cleanup fail-closed: slot release and buffer free must be confirmed `FREED`, otherwise
  `console_dirty`.
* `INV_CCP_002`: after a failed submit *N* the state for *N+1* is treated as new — an assertion the
  experiment can test, not a claim the agent makes.
* Determinism: same key + same data → same digest; no state carry-over between runs.

### C. Safety (hard prohibitions)

* Only framework-claimed test slots; default resources: fresh test slot, known test key, known test
  data (v0.1 section 50).
* No key material in telemetry, evidence or logs — not even as a hash.
* No auto-retry after a hang or panic.
* The agent implementation reaches CCP **only** through the profile-declared binding (e.g.
  `provider: KERNEL_EXEC_SYMBOL` or `DEVICE_IOCTL` — the choice is profile business, not agent code).

### D. Verification contract

`verify.ccp.submit` runs the known-answer test and returns `{expected, observed, match}`. The
*expected* value is computed by the host from the test config (HMAC-SHA256 over the test vector with
the test key) — the agent never hardcodes a digest. Only on `match` **and** in a separate run does
`grant_from_verification()` produce the `PROVEN` record.

## 3. Stages

* **Stage 0 — Mock:** extend `MockAgent` with `ccp.submit` (HMAC via `hashlib`), run the known-answer
  end-to-end in the existing round trip — completely offline. *Status: open.*
* **Stage 1 — Hardware phase 2:** primitives in isolation (see the gate table). *Status: armed by the
  gates of section 1; requires hardware.*
* **Stage 2 — Phase 3 acceptance:** known-answer HMAC (the experiment of section 4).
* **Stage 3 —** verification run → `ccp.submit` `PROVEN` → capability upgrade under review.
* **Stage 4 —** acceptance checklist (section 5).
* **Stage 5 —** only after that: research experiments (`ccp_double_fetch`, `ccp_multi_message_failure`,
  `historical_hmac_prefix`, `zero_key_c3`).

## 4. Acceptance experiment (Stage 2)

`experiments/ccp-known-answer-hmac.yaml` — stored verbatim from the owner message (only a header note
was added). Resolution rule: the host harness resolves `"<EXPECTED_DIGEST aus Test-Config>"` at load
time from `profiles/fw1352/test_config.json` (`expected.digest_hex`); the agent must never embed it.

## 5. Phase-3 acceptance checklist

1. Known-answer submit returns the expected digest; the assertion passes.
2. Submit on a released slot is refused (`INV_SLOT_001`).
3. Submit on a never-loaded slot is refused (key/state).
4. Cleanup: slot `FREED`, mapping `UNMAPPED`, buffer `FREED` — report `COMPLETE`.
5. Separate verification run → `ccp.submit` `PROVEN`, `verified_by.operation == "verify.ccp.submit"`,
   `verification_run != trigger_run`.
6. Negotiation before verification: `ccp.*` denied (`ASSURANCE_INSUFFICIENT`).
7. One hang test (submit without a timeout confirmation) → poison → `IN_FLIGHT_AT_RECOVERY` →
   reconnect shows `RECOVERY_REQUIRED`, only `recovery_safe` ops.
8. Evidence: digest, vector IDs, timings, resource transitions, per-run cleanup.
9. No protected slot touched (telemetry review of the run).

## 6. Handover to the agent implementer

* **Test config** — `profiles/fw1352/test_config.json` (local only, gitignored, never committed and
  never copied into telemetry/evidence/logs): test key ID + key material, vector ID + data,
  host-computed expected digest, recompute command. Written 2026-10-07.
* **Profile extension** — `profiles/fw1352/ccp-layouts.json`: CCP message layout, request envelope,
  the fully decoded npdrm claim → submit → release walkthrough, per-operation bindings with RVAs,
  slot semantics, provider binding (`KERNEL_EXEC_SYMBOL`, entry `0x625330`) with the device-ioctl
  alternative marked `UNRESOLVED`, plus `profile_delta` (locators + operation policy) ready to
  promote. Revision candidate: `profiles/fw1352/profile-13.52-ccp1.json`.
* **This REQ list** as acceptance spec — every REQ-CCP point is individually testable.
* **Evidence references** — pinned image `cf157ffd…d92eca35`; campaign artifacts listed in
  `ccp-layouts.json` (`evidence_base`).

## 7. Open points / blockers (honest state)

* Gate 1 is **red**: the freeze gates G1–G8 have not been executed in the real environment, so the tag
  does not exist yet.
* Stage 0 is **not implemented**: `keymgr.load_test_key` and `verify.ccp.submit` are not in
  `core/rpc/registry.py`, and the mock has no `ccp.submit` yet.
* The provider module (KERNEL_EXEC_SYMBOL) does not exist; the primitive that stores *new* key
  material into a slot is unmapped in the research (candidates: sm storage `0x630230` with the
  `{0x101/0x102, handle}` request, or a `0xC1000`-family submit message) — see `ccp-layouts.json`
  `unresolved`.
* The device-permission gate `0x3B2EE0` (`[obj+0x58] == 0x3800000000000010`) is byte-verified but its
  live passability is not.
* The profile revision still needs schema validation and its canonical stamp before any promotion
  (mechanical step, `tools/profiles/loader.py`), and the binding windows need a live byte-match
  (W16) before the revision can be promoted.
