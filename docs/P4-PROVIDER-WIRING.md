# P4/W7 — Provider wiring

Status: **W7 complete (pending owner review)**. W7 connects the components built in
W3–W6 into **one** dispatch path and nothing else: it builds the way, not the primitive.

* offline · no live PS4 access · no kernel code · no payloads · no privileged PS4
  implementation · no invented firmware addresses
* Core changes only where a documented integration finding demands them: exactly one
  patch (F7, [below](#f7-integration-patch)), documented in `CHANGELOG.md`, hashed
  separately and gated as revision **R2** in `FREEZE-DRIFT.md`
* the stub route is wired; all 14 deferred-privilege operations and the single
  deferred-host-chain operation stay `DEFERRED` — a perfect gate result still answers
  `OPERATION_DEFERRED` with `provider_entry = false`

## The normative dispatch chain

```
REQUEST
 → RPC validation              core wire envelopes + W3 argument validation
 → OperationRegistry           the frozen registry: unknown operation is refused
 → Capability resolution       record presence, availability, target context, session/boot binding
 → effective_grant             assurance against the frozen authority ceiling / provider policy
 → W4 capability gate          tools/primitive_iface/gate.py (frozen policy, unchanged in W7)
 → W5 profile binding          tools/profiles/w4_adapter.py: the profile part only
 → Provider router             tools/dispatch/matrix.py: exactly one provider per route
 → Primitive interface         validated context in, structured result out
 → Resource / recovery policy  central ResourceManager, cleanup result into evidence
 → Response + evidence         structured result or mapped error, never a traceback
```

Each step can refuse; a refusal records the step that stopped it (`stopped_at`). Reason →
step mapping (W4 reason to chain step): `RECOVERY_REQUIRED` → `resource_policy`,
`CAPABILITY_MISSING`/`CONTEXT_MISMATCH`/`BINDING_MISMATCH` → `capability_resolution`,
`ASSURANCE_TOO_LOW`/`PROVIDER_NOT_ALLOWED` → `effective_grant`, `EVIDENCE_MISSING`/
`APPROVAL_MISSING` → `w4_gate`, `PROFILE_UNBOUND` → `w5_profile_binding`, `NOT_WIRED` →
`provider_router`.

## Provider router matrix

`python tools/dispatch/matrix.py --matrix` prints the machine-readable matrix; the parity
check (`parity_errors()`) cross-checks it against **every** earlier matrix: the frozen
registry, the W3 interface table, the W4 requirement table and the W5 operation/profile
matrix.

| route | operations | provider | state in W7 |
|---|---|---|---|
| `stub` | 16 | `ps4rfd-stub` | `WIRED` |
| `mock_only` | 4 | `mock-provider` | `TEST_ONLY` (answers `OPERATION_DEFERRED`) |
| `deferred_privilege` | 14 | `native-provider` | `DEFERRED` |
| `deferred_host_chain` | 1 (`verify.userland.exec`) | `host-chain-provider` | `DEFERRED` |

* every registered operation has **exactly one** route (35 of 35, none twice)
* **no implicit fallback**: an operation outside the registry or without a route raises
  `UnknownOperation` and the request is refused with `OPERATION_UNSUPPORTED`
* an operation whose provider is not `WIRED` is refused at the `provider_router` step with
  `NOT_WIRED` / `OPERATION_DEFERRED`, `provider_entry = false`
* the host-chain operation keeps its own route: it is **not** reclassified as a native
  privileged operation, and its verification→grant chain uses the existing
  `VerificationEvidence` contract (no shortcut from a host-chain result to `PROVEN`)

## Provider interface

A handler receives an `InvocationContext` and returns a `ProviderResult`
(`tools/dispatch/providers.py`):

* context: `run_id`, `request_id`, `operation`, validated `arguments`, `seq`, provider
  name/type, profile binding + `profile_sha256`, `boot_id`, `session_id`, context label,
  capability + effective assurance, the per-request resource view, the evidence sink,
  route, `wired`
* result: `ok`, `result` payload, `error_code`, resource changes, cleanup, `entered`

A provider therefore never parses JSON, never trusts a session id, never decides a
capability, never picks a profile and never makes an authority decision — those decisions
are made **before** entry. It returns structured results; the dispatcher maps them into
the frozen response envelope (`ok_response`/`error_response`) and validates it. A provider
exception never reaches the wire: it becomes `INTERNAL_ERROR` with the detail kept in
evidence only.

## Provider invocation evidence

Every attempt — accepted or refused — writes exactly one record
(`tools/dispatch/evidence.py`) with: `run_id`, `request_id`, `operation`,
`selected_provider`, `provider_type`, `capability`, `effective_assurance`, `w4_decision`,
`w4_reasons`, `profile_sha256`, `boot_id`, `session_id`, `context`, `provider_entry`,
`stopped_at`, `result`, `error`, `error_detail`, `resource_changes`, `cleanup`, `metadata`.

A refused dispatch always names the stopping step, so "why was nothing executed" is
answerable from the record alone. `metadata` carries analysis references (e.g. W6
findings) and is **never** a gate input — the W4 gate rejects unknown claim keys outright.

## One provider entry path (no bypass)

`Dispatcher._enter_provider` is the only place where a provider handler is invoked on the
productive path, and `Dispatcher.dispatch` is the only productive entry. Unit tests may
call a handler directly; the productive RPC path never does. A test asserts this
structurally (one `provider.enter(` call site in the package) and behaviourally
(forged/replayed claims, direct provider access and W6 metadata all leave the decision
unchanged).

## Resource ownership

* one owner: the session's `core.resources.manager.ResourceManager`
* every request gets a `RequestResourceView`: it delegates `acquire`/`release`/`cleanup`
  to the central manager (refs keep the frozen `<kind>:<16 hex>` shape) and attributes the
  refs to **one** request, so the cleanup result can go into evidence. There is no
  provider-local shadow registry
* a provider cannot adopt a foreign ref: releasing or attaching cleanup to another
  request's ref is refused and recorded as a violation in the evidence
* the W3 stub keeps its own bookkeeping (its semantics are frozen); its adapter reports
  what it holds, and the record marks it as `reported_by: provider`
* cleanup result → evidence → recovery: a cleanup report of `PARTIAL`, or any resource with
  `CLEANUP_FAILED`/`UNCERTAIN`, puts the session into `RECOVERY_REQUIRED`. A `PENDING`
  report (resources intentionally held) does not.

## Recovery and concurrency

* the recovery check runs centrally **before** any provider entry: a session that is not
  `ACTIVE` refuses mutating operations that are not recovery-safe with
  `SESSION_RECOVERY_REQUIRED`, `stopped_at = resource_policy`, `provider_entry = false`
* a poison arriving between acceptance and entry is caught by the same check (test hook
  `before_entry`, plus a test that asserts zero provider entries)
* concurrent dispatches stay isolated: request ids, evidence records, resource ownership
  and gate inputs are per request; `max_inflight` is enforced and answers
  `TOO_MANY_INFLIGHT`

## Integration of W4 / W5 / W6

* **W4** is the policy gate for every gated route and is unchanged in W7. `ELIGIBLE` still
  authorizes nothing: it can only remove gate reasons
* **W5** supplies the profile part only, through `tools/profiles/w4_adapter.py`
  (`profile_preconditions` → `profile_binding_for_gate`). A profile mismatch, an
  unverified (fixture-only) profile or a boot binding from a previous boot collapses into
  the single W4 reason `PROFILE_UNBOUND` → entry count 0
* **W6** findings are analysis metadata (`metadata` field, `impact.w4 = NONE`). They cannot
  change provider selection, the gate result or authorization — asserted by test

## Authority integration (work order §18)

| scenario | result | stopping step |
|---|---|---|
| `NATIVE` available + `OBSERVED` for a privileged capability | `OPERATION_DEFERRED` (`ASSURANCE_TOO_LOW`) | `effective_grant` |
| `NATIVE` provider present, **no** `VerificationEvidence` | `OPERATION_DEFERRED` (`EVIDENCE_MISSING`) | `w4_gate` |
| valid `VerificationEvidence`, W5 mismatch | `OPERATION_DEFERRED` (`PROFILE_UNBOUND`) | `w5_profile_binding` |
| valid evidence + W5 match, provider not implemented | `OPERATION_DEFERRED` (`NOT_WIRED`) | `provider_router` |
| fully wired **test** provider, every prerequisite satisfied | provider entry exactly once | — |

The last row uses the documented test provider
(`tools/dispatch/providers.py::TestProvider`, never part of `default_providers()`); it does
not claim a verification result it did not produce (`verified` stays false, the observed
payload marks itself as scripted). Production keeps the route `DEFERRED`.

## F7 integration patch

F7 (recorded in W3) was: the W4 requirement table already names `NATIVE` as an allowed
provider for the deferred-privilege operations, but the frozen `ProviderType` enum could
not express it, so a native provider record was not representable at all. W7 fixes exactly
that, minimally:

| file | change | sha256 (before → after) |
|---|---|---|
| `core/models/common.py` | `ProviderType` gains the member `NATIVE` | `7163f308…` → `0ba89705…` |
| `core/models/capability.py` | one authority rule for `NATIVE`: `max_assurance = OBSERVED`, availability write allowed, `availability_rank = 25` | `2d999bc7…` → `2052a9e6…` |

Conservative by construction: the ceiling is `OBSERVED`, so the mere existence of a native
provider can never produce `PROVEN`; `PROVEN` remains reachable only through the frozen
`VerificationEvidence` path. No other rule, minimum or rank changed, and no other core
file was touched. The patch is documented in `CHANGELOG.md` with the F7 reference, hashed
separately, and gated as **R2 (F7)** in `FREEZE-DRIFT.md` (the drift log now names each
revision with its review document); `SHA256SUMS` stays byte-identical to the freeze.

## Unchanged: F8, F9, F10

* **F8** — `kernel.read`, `kernel.snapshot`, `kernel.dump.full` stay conservative
  `mutating = True` in the frozen core; W7 follows the core and does not correct it
* **F9** — the native `memory.alloc` contract still requires an explicit `size`; the
  looser mock semantics are not applied to native
* **F10** — sync operation flags come exclusively from the frozen core registry;
  historical spec drafts are not runtime policy

## What W7 does not do

No live PS4 connection, no BinLoader, no kernel primitives, no GPUVM/KeyMgr/CCP
implementation, no SAMU access, no payload. All 14 privileged operations and the host-chain
operation remain `DEFERRED` by design; their provider state is the switch that the first
controlled target integration step will flip, one operation at a time, with new evidence.
