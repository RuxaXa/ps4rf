# PS4RF capability gate process (§70) — P4/W4

Status: **normative for P4/W4** — the process by which a
``deferred-privilege`` primitive may ever leave ``OPERATION_DEFERRED``. Decided by
the Project Owner / Research Lead (W4 scope, 2026-10-05). The decision logic lives in
`tools/primitive_iface/gate.py`; `tests/test_capability_gate.py` checks this document,
the module and the frozen core against each other.

**W4 produces gate decisions only.** P4 stays userland only: W4 implements no
primitive, no provider wiring, no kernel code, no payload and no on-console action.
The freeze tag `PS4RF-CORE-1.0-MOCK-READY` (`1536e35`) and core/wire revision R1 stay
untouched, and the integration findings F7–F10 stay open as recorded.

## 1. Starting position

* 14 operations are `deferred-privilege` (`gpuvm.map/unmap/lookup`, `keymgr.claim/
  release/snapshot`, `ccp.submit`, `kernel.read/snapshot/dump.full`,
  `verify.kernel.read/exec/copyout`, `verify.samu.access`); one further operation is
  `deferred-host-chain` (`verify.userland.exec`). The remaining 20 are `stub` (16) or
  `mock-only` (4) and are outside this process.
* Every one of them answers `OPERATION_DEFERRED` today, and **keeps answering
  `OPERATION_DEFERRED` while any precondition below is missing**. A partially
  satisfied gate is a deferred gate.
* Observables that carry **no** gate authority, ever: a present symbol, a firmware
  RVA, a profile entry, a mock success, the mere existence of an interface, and any
  operator claim. The gate accepts them as `claims` input and ignores them
  (test-enforced).

## 2. Capability gate state model

The decision is a pure function of the gate context:

```
context = (capability records, verification records, evidence refs, profile binding,
           session_id, boot_id, session_state, provider, provider_type, wired,
           §70 approval record)
decision = { decision: DEFERRED | ELIGIBLE, reasons: [...], next_action, wire_code }
```

| decision | meaning | wire answer |
|---|---|---|
| `DEFERRED` | at least one precondition is missing or wrong | `OPERATION_DEFERRED` |
| `ELIGIBLE` | **every** precondition is satisfied and evidenced | `OPERATION_DEFERRED` |

`ELIGIBLE` is not an activation: the operation is only *eligible to be requested*
(from W5/W7 plus a §70 record). `executable` is hard-`False` in W4 and the wire code
stays `OPERATION_DEFERRED`; a decision can never execute anything.

Reason codes (evaluation and reporting order, all failing checks are reported):

| reason | condition | owner of the fix |
|---|---|---|
| `RECOVERY_REQUIRED` | session state is not `ACTIVE` and the operation is not one of the three `recovery_safe` operations | on-console recovery handling (P5) |
| `CAPABILITY_MISSING` | no capability record for the required capability, or its availability is not `AVAILABLE` | W7 (capability intake) |
| `ASSURANCE_TOO_LOW` | record assurance below the frozen minimum for the namespace | W7 (frozen verification path) |
| `PROVIDER_NOT_ALLOWED` | provider type not permitted for the operation | W7 (registration, F7) |
| `CONTEXT_MISMATCH` | record context not in the allowed context set | P5 (on-site context evidence) |
| `BINDING_MISMATCH` | record is not `SESSION`-scoped to the current session, or belongs to a different boot | W7 (intake binding) |
| `PROFILE_UNBOUND` | profile binding absent, incomplete or without `sha256` | W5 (profile data) |
| `EVIDENCE_MISSING` | no passing verification record from the required `verify.*` operation, or no hash-bound evidence reference | P5 + W7 |
| `APPROVAL_MISSING` | §70 Capability Missing Record not approved | Project Owner / Research Lead |
| `NOT_WIRED` | provider not wired for this operation | W7 |

## 3. Matrix for the 14 deferred-privilege operations

Minimum assurance is **read** from the frozen core
(`core.models.capability.default_authority().min_assurance_for_grant`), never
restated: every privileged namespace (`kernel`, `gpuvm`, `keymgr`, `ccp`, `samu`)
requires `PROVEN`; only `userland`-class namespaces accept `OBSERVED`.

| op | namespace | min assurance | class | verification op | profile required | cleanup required |
|---|---|---|---|---|---|---|
| `gpuvm.map` | gpuvm | PROVEN | mutating | `verify.kernel.read` | yes | yes |
| `gpuvm.unmap` | gpuvm | PROVEN | mutating | `verify.kernel.read` | yes | yes |
| `gpuvm.lookup` | gpuvm | PROVEN | observational | `verify.kernel.read` | yes | no |
| `keymgr.claim` | keymgr | PROVEN | mutating | `verify.kernel.read` | yes | yes |
| `keymgr.release` | keymgr | PROVEN | mutating | `verify.kernel.read` | yes | yes |
| `keymgr.snapshot` | keymgr | PROVEN | read | `verify.kernel.copyout` | yes | yes |
| `ccp.submit` | ccp | PROVEN | mutating | `verify.kernel.read` | yes | yes |
| `kernel.read` | kernel | PROVEN | read | `verify.kernel.read` | yes | no |
| `kernel.snapshot.recipe` | kernel | PROVEN | read | `verify.kernel.read` | yes | no |
| `ioctl.invoke` | ioctl | OBSERVED | mutating | `verify.kernel.read` | yes | no |
| `kernel.snapshot` | kernel | PROVEN | read | `verify.kernel.copyout` | yes | yes |
| `kernel.dump.full` | kernel | PROVEN | read | `verify.kernel.copyout` | yes | yes |
| `verify.kernel.read` | kernel | PROVEN | observational | `verify.kernel.read` | yes | no |
| `verify.kernel.exec` | kernel | PROVEN | observational | `verify.kernel.exec` | yes | no |
| `verify.kernel.copyout` | kernel | PROVEN | observational | `verify.kernel.copyout` | yes | no |
| `verify.samu.access` | samu | PROVEN | observational | `verify.samu.access` | yes | no |
| `verify.userland.exec` | userland | OBSERVED | observational | `verify.userland.exec` | no | no |

(`verify.userland.exec` — the host-chain operation — appears with
`min_assurance = OBSERVED`, no §70 requirement and no profile binding, but under the
same "deferred until wired" rule as everything else.)

Per-operation contexts, profile fields, allowed providers, resource kinds, cleanup
and recovery flags are the normative matrix in `tools/primitive_iface/gate.py`
(`--matrix` dumps it); `tests/test_capability_gate.py` keeps this table in sync.

**Allowed providers.** A privileged capability may be carried by `EXPLOIT`,
`OPERATOR` or (once F7 is resolved) `NATIVE`. `MOCK` is **excluded by policy** for
privileged capabilities: mock success is not evidence about the console, so mock
records can never grant a privileged capability on the native path. `RUNTIME_PROBE`
is limited to `userland`-class operations by its frozen assurance ceiling
(`OBSERVED`).

## 4. Fail-closed decision logic

Order of evaluation, all failures reported at once:

1. **Recovery** — state ≠ `ACTIVE` and not `recovery_safe` → `RECOVERY_REQUIRED`.
2. **Capability** — a record for the required capability must exist and be
   `AVAILABLE`, else `CAPABILITY_MISSING`.
3. **Assurance** — `ASSURANCE_RANK(record) ≥ ASSURANCE_RANK(frozen minimum)`, else
   `ASSURANCE_TOO_LOW`. `AVAILABLE` with too little assurance stays deferred.
4. **Provider** — provider type ∈ allowed set, and the record's provider must be the
   acting provider, else `PROVIDER_NOT_ALLOWED`.
5. **Context** — record context ∈ allowed context set, else `CONTEXT_MISMATCH`.
   Privileged operations require `JAILBROKEN_PROCESS`; `HOMEBREW` is never
   sufficient for them.
6. **Binding** — `SESSION` scope with matching `session_id`; a `BOOT`-scoped record
   never activates a gated operation (it expires on reboot by the frozen model), and
   a record from another boot is refused.
7. **Profile binding** — W5 data present, complete for every required field and
   carrying a `sha256`, else `PROFILE_UNBOUND`. A profile entry alone is **not**
   activation.
8. **Verification evidence** — a passing record from the required `verify.*`
   operation, bound to the same session/boot, capability-consistent, non-mock, plus a
   hash-bound evidence reference, else `EVIDENCE_MISSING`. The frozen path
   (`core/models/verification.py`: `VerificationRecord` → grant) is the only accepted
   evidence path for privileged capabilities.
9. **§70 approval** — an approved Capability Missing Record; an implementing agent
   must never self-approve, else `APPROVAL_MISSING`.
10. **Wiring** — even with 1–9 satisfied, a non-wired provider yields `NOT_WIRED`.

Any single failure keeps `OPERATION_DEFERRED`. There is no "probably fine" path and
no partial activation.

## 5. Verification and evidence requirements

* Evidence must be **hash-bound**: every accepted verification record needs an
  evidence reference with `run_id` and `sha256` (no unhashed screenshots, no prose).
* `profile_sha256` of the verification record must correspond to the profile binding
  in force; a profile change invalidates the evidence.
* `expected`/`observed` are mandatory fields of the verification record: a
  verification without a concrete expected value proves nothing about the console.
* Mock-derived evidence is refused for privileged capabilities (policy; see §3 and
  finding F11 in `docs/P4-PRIMITIVE-INTERFACES.md`).
* Evidence recorded before a boot boundary does not survive it: session/boot mismatch
  is `EVIDENCE_MISSING`.

## 6. Recovery and cleanup policy per class

| class | recovery behaviour | cleanup obligation |
|---|---|---|
| `read` (`kernel.read`, `kernel.snapshot`, `keymgr.snapshot`, `kernel.dump.full`) | not `recovery_safe`; deferred while state ≠ `ACTIVE`; a snapshot/dump ref must be released | `kernel.snapshot`/`keymgr.snapshot`/`kernel.dump.full` acquire a ref (`snapshot`/`keymgr`/`dump` kind) with a cleanup callback and report `PENDING`/`COMPLETE`; `kernel.read` holds no ref |
| `mutating` (`gpuvm.map/unmap`, `keymgr.claim/release`, `ccp.submit`) | deferred while state ≠ `ACTIVE`; `recoverable = True`, `out_of_band_cleanup_safe = False` — a hang therefore leaves a leak that the BYE report must declare (`PARTIAL`, `final_state: LEAKED`) | every acquisition must be releasable by its counterpart operation (`gpuvm.unmap`, `keymgr.release`); the cleanup callback destroys the handle, never reports success after destroy |
| `observational` (`gpuvm.lookup`, `verify.*`) | deferred while state ≠ `ACTIVE` unless the operation is `recovery_safe` (none of the gated ones are) | read-only paths; `verify.kernel.copyout`/`kernel.snapshot` follow the no-bytes-on-mismatch rule: mismatch is `PROFILE_MISMATCH`, buffer zeroized, `Telemetry state.snapshot outcome=HASH_MISMATCH` |

Conservative consequence of F8/F10: the frozen core flags `kernel.read`,
`kernel.snapshot`, `kernel.dump.full`, `gpuvm.lookup` and all sync operations as
`mutating=True`. The gate therefore treats them as non-recovery-safe, even where a
read-only intent is obvious. The core stays unchanged.

## 7. Transition from `OPERATION_DEFERRED` to executable

In order, each step owned and evidenced by a different party — no single artifact
flips the switch:

1. **W5** provides profile binding data (sha256, value domains, evidence-only
   placeholders; no invented RVA/signature values).
2. **W7** wires the provider (registration resolving F7, intake bound to
   session/boot, authority rule proposal `max_assurance = OBSERVED`,
   `availability_rank = 25`, evidence store references).
3. **On-site run (P5)** produces a passing verification record with a hash-bound
   evidence reference — through the frozen path, not through a mock.
4. **§70 Capability Missing Record** is approved by the Project Owner / Research
   Lead for this concrete primitive (capability, missing-capability evidence,
   proposed primitive, profile binding, risk note).
5. **Gate re-evaluation** returns `ELIGIBLE` for that operation only.
6. **Implementation** of the primitive happens under the approved §70 record, in its
   own work package, with its own gate run — and only then can the wire answer change
   from `OPERATION_DEFERRED`.

Until step 6 is complete, `OPERATION_DEFERRED` remains the answer even when 1–5 are
done. W4 stops after step 5's *mechanism*; it does not perform 1–6.

## 8. Handoff contract

**W4 → W5** (profile binding data): a profile per boot/target with `sha256`; a value
for every `profile_fields` entry of the matrix; evidence-only placeholders (a profile
entry that is not evidence-backed is refused by construction in W5).

**W4 → W7** (provider wiring): capability intake through the frozen
`CapabilityIntake` (session/boot binding); provider registration resolving F7 as an
integration finding; authority rule proposal as above; the `wired` flag per gated
operation; evidence-store references with `sha256`.

**W4 → Owner** (§70 records): one approved Capability Missing Record per primitive,
never self-approved, with capability name, missing-capability evidence, proposed
primitive, profile binding and risk note.

**Explicit non-contributions:** W4 does not replace W5 profile data, does not perform
W6 differential runs, does not wire W7 providers, and does not implement any
privileged primitive.

## 9. Verification

* `python tools/primitive_iface/gate.py --self-test` — matrix completeness (14 + 1),
  frozen-assurance cross-check per namespace, reason/owner completeness,
  "empty context is always DEFERRED", "no decision is ever executable",
  "wire code stays `OPERATION_DEFERRED`".
* `python tools/primitive_iface/gate.py --matrix` — machine-readable matrix and
  handoff contract for the evidence pack.
* `tests/test_capability_gate.py` — the required negative scenarios (missing
  capability, availability without assurance, wrong context, wrong boot/session,
  wrong profile binding, missing verification evidence, wrong provider, recovery
  required, everything satisfied but not wired → still deferred, no path from mock
  evidence to privileged release), plus table/doc parity and the rule that claims
  carry no authority.
* Full regression: the W2 native parity suite and the W3 interface suite stay green
  in the same gate run.
