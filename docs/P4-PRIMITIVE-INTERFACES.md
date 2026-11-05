# PS4RF primitive interface freeze v1 (P4/W3)

Status: **normative for P4/W3** — decided within the approved P4 plan
(`P4-NATIVE-PS4RFD-PLAN.md`, work package W3). The machine-readable table is
`tools/primitive_iface/schema.py`; this document carries the prose contract and the
inventory. A test (`tests/test_primitive_interfaces.py`) checks the table here, the
module and the frozen core registry against each other, so the freeze cannot drift
silently in either direction.

Scope guard (unchanged): P4 stays **userland only**. This package freezes *interfaces*
and implements a host-side stub for the unprivileged operations. It adds no kernel,
GPUVM, KeyMgr, CCP, SAMU, PUP, EAP, SBRAM or EMC primitive, no payload, no hardware
action, and it does not touch frozen core behaviour.

## 1. Method

Every one of the 35 operations registered in `core/rpc/registry.py` is mapped to
exactly one provider interface with a strict request/response schema, its capability
binding, its `mutating`/`recovery_safe` flags and an explicit implementation status:

| status | meaning | count |
|---|---|---|
| `stub` | implemented in the host-side W3 stub, no privilege needed | 16 |
| `deferred-privilege` | interface frozen; implementation needs the §70 gate and on-site hardware/profile binding (W4/P5) | 14 |
| `deferred-host-chain` | interface frozen; implementation needs the verification→grant chain (W7) | 1 |
| `mock-only` | fault-injection surface of the mock reference, not a native primitive | 4 |

Flags are **read from the frozen core**, not restated: `--self-test` compares
capability, `mutating` and `recovery_safe` for all 35 operations against
`default_registry()` and fails on any difference.

## 2. Message envelope

Reused unchanged from the wire freeze (D12/D19, `docs/P4-WIRE-SPEC-v1.md`); pinned by
`tests/fixtures/parity/vectors-v1.json`:

```
REQUEST  {"header": {"request_id": "REQ-<32 hex>"},
          "body": {"operation": "<op>", "arguments": {...}}}      # body.seq optional echo
RESPONSE {"header": {"in_reply_to": "REQ-<32 hex>"},
          "status": "OK",  "result": {...},  "cleanup": {...}?}
RESPONSE {"header": {"in_reply_to": "REQ-<32 hex>"},
          "status": "ERROR", "error": {"code": "<frozen code>"}}
BYE      {"msg": "BYE", "reason": "CLIENT_CLOSE|RECOVERY_REQUIRED|SERVER_CLOSE",
          "cleanup": {"state": "PENDING|COMPLETE|PARTIAL", "resources": [...]}}
```

`header.request_id` shape and its uniqueness/reuse behaviour stay owned by
`core/rpc/requests.py` (`RequestIdRegistry`); `lead_id` passthrough stays D19
(no new global id algorithm in P4). Unknown request/response fields, unknown
argument fields, wrong types, missing required fields and unknown error codes are
**refused** (`ARGUMENT_INVALID`) — the validator is fail-closed, never
pass-through.

`session.shutdown` (W14 §15, wire catalogue revision R4) is the one addition since the W3 surface:
an authenticated admin shutdown. It carries **no capability** — capability-bearing operations are the
privileged ones and are never wired on the target agent, an invariant this revision keeps — and its
contract instead requires one argument, `capability`, whose only admitted value is `session.admin`
(`CAPABILITY_REQUIRED` otherwise). It is read-only (it releases the session's resources and ends the
agent's lifetime — no kernel state, no reboot, no loader, no persistence) and recovery-safe by
policy. It is served *only* by the resident agent: outside the resident mode the handler refuses with
`OPERATION_DEFERRED`, so the single-session profiles keep exactly the served set they had. No operation may return bytes of privileged memory in error details
(snapshot contract, source in §3).

## 3. Operation inventory (machine-checked)

| op | family | status | capability | mutating | recovery_safe |
|---|---|---|---|---|---|
| `session.ping` | session | `stub` | — | no | yes |
| `session.status` | session | `stub` | — | no | yes |
| `session.shutdown` | session | `stub` | — | no | yes |
| `telemetry.read` | telemetry | `stub` | — | no | yes |
| `experiment.load` | experiment | `stub` | — | yes | no |
| `memory.alloc` | memory | `stub` | memory.alloc | yes | no |
| `memory.free` | memory | `stub` | memory.free | yes | no |
| `sync.barrier.create` | sync | `stub` | — | yes | no |
| `sync.barrier.destroy` | sync | `stub` | — | yes | no |
| `sync.barrier.release` | sync | `stub` | — | yes | no |
| `sync.barrier.wait` | sync | `stub` | — | yes | no |
| `sync.gate.arrive` | sync | `stub` | — | yes | no |
| `sync.gate.create` | sync | `stub` | — | yes | no |
| `sync.gate.destroy` | sync | `stub` | — | yes | no |
| `sync.gate.release` | sync | `stub` | — | yes | no |
| `sync.gate.status` | sync | `stub` | — | yes | no |
| `sync.gate.wait` | sync | `stub` | — | yes | no |
| `mock.block` | mock | `mock-only` | — | yes | no |
| `mock.free_fail` | mock | `mock-only` | — | yes | no |
| `mock.hang` | mock | `mock-only` | — | yes | no |
| `mock.leak` | mock | `mock-only` | — | yes | no |
| `gpuvm.lookup` | gpuvm | `deferred-privilege` | gpuvm.lookup | yes | no |
| `gpuvm.map` | gpuvm | `deferred-privilege` | gpuvm.map | yes | no |
| `gpuvm.unmap` | gpuvm | `deferred-privilege` | gpuvm.unmap | yes | no |
| `keymgr.claim` | keymgr | `deferred-privilege` | keymgr.claim | yes | no |
| `keymgr.release` | keymgr | `deferred-privilege` | keymgr.release | yes | no |
| `keymgr.snapshot` | keymgr | `deferred-privilege` | keymgr.snapshot | yes | no |
| `ccp.submit` | ccp | `deferred-privilege` | ccp.submit | yes | no |
| `kernel.dump.full` | kernel | `deferred-privilege` | kernel.dump.full | yes | no |
| `kernel.read` | kernel | `deferred-privilege` | kernel.read | yes | no |
| `kernel.snapshot` | kernel | `deferred-privilege` | kernel.read | yes | no |
| `kernel.snapshot.recipe` | kernel | `deferred-privilege` | kernel.read | yes | no |
| `ioctl.invoke` | ioctl | `deferred-privilege` | ioctl.invoke | yes | no |
| `verify.kernel.copyout` | verify | `deferred-privilege` | — | no | no |
| `verify.kernel.exec` | verify | `deferred-privilege` | — | no | no |
| `verify.kernel.read` | verify | `deferred-privilege` | — | no | no |
| `verify.samu.access` | verify | `deferred-privilege` | — | no | no |
| `verify.userland.exec` | verify | `deferred-host-chain` | — | no | no |

Per-operation **argument and result fields** (types, requiredness, notes) are the
normative table in `tools/primitive_iface/schema.py`; §5 states how each gated
operation is *not* implemented. Field-level schemas for the privileged families are
the W3 interface freeze (in-repo property, D12-style): no historical byte identity is
claimed, and no concrete address, slot or signature value appears anywhere in this
package — those live in profiles (W5) and are bound at call time.

Semantics that carry over from the existing evidence:

* `sync.gate.*` — gate = manual research window: `arrive` registers a unique
  participant, release happens **only** via `sync.gate.release`; `destroy` wakes
  waiters with `RESOURCE_DESTROYED`, never success; creation acquires the ref first
  and publishes it second (B12, no empty ref). `sync.barrier.*` uses the same
  creation/cleanup path and releases automatically when `parties` players arrived.
* `memory.alloc`/`memory.free` — refs are runtime-generated (`mem:<16 uppercase
  hex>`), never client-supplied; a double free is `RESOURCE_STATE_INVALID`.
* `kernel.snapshot` — range policy → read → SHA-256 → compare → only on match are
  data released; mismatch is `PROFILE_MISMATCH`, the buffer is zeroized and the
  bytes never leave the agent; `expected_sha256` is mandatory for `explicit` and
  optional for `region_ref`; no bytes in error details.
* Recovery gate (central): while the session is not `ACTIVE`, every mutating
  operation is refused with `SESSION_RECOVERY_REQUIRED`; only the `recovery_safe`
  set (`session.ping`, `session.status`, `telemetry.read`) keeps working.

`OPERATION_DEFERRED` is the one **new** error code introduced here: it separates
"interface exists, implementation gated" from `OPERATION_UNSUPPORTED`
("no such operation"). The distinction is required so a gated operation can never
look like a typo, and vice versa.

## 4. Native provider registration (proposal, not applied)

W7 registers the native agent as a provider. The proposal, derived from the frozen
authority table and the W7 plan text ("cap at OBSERVED until P5 proves otherwise"):

* `provider_type = NATIVE`, `max_assurance = OBSERVED`, `availability_write = True`,
  `availability_rank = 25` (above `BOOTSTRAP` 20, below `RUNTIME_PROBE`/`EXPLOIT` 30 —
  the agent observes the live console, but a provider that owns its primitive knows
  more about it).
* Consequence of the inherited minimum-assurance table: the native provider can carry
  `memory`/`userland`/`sync`-style capabilities at `OBSERVED`; **no**
  `kernel`/`gpuvm`/`keymgr`/`ccp`/`samu` capability may be granted from it alone
  (those namespaces require `PROVEN`).
* Nothing here is applied to the frozen core in W3; see finding F7.

## 5. Deferral reasons (explicit, per status)

* `deferred-privilege` — 14 operations (`gpuvm.*`, `keymgr.*`, `ccp.submit`,
  `kernel.*`, `verify.kernel.*`, `verify.samu.access`): the interface is frozen and
  documentable today, the implementation needs a §70 Capability Missing Record
  approved by the Project Owner / Research Lead **and** on-site hardware with
  profile binding. Until then the stub answers `OPERATION_DEFERRED` and never fakes a
  success. This is precisely the P4 release caveat: "Kernel code / payloads only with
  explicit new approval".
* `deferred-host-chain` — `verify.userland.exec`: the observing probe itself is
  userland-safe, but the operation only has meaning through the verification→grant
  chain (`core/models/verification.py` + authority resolution), which W7 wires.
* `mock-only` — `mock.*` fault injection is harness surface of the mock reference
  (parity target of W6), not part of the provider surface; the native agent must not
  expose it as a research primitive.

## 6. Findings (recorded, not patched)

* **F7 — `ProviderType.NATIVE` does not exist** in `core/models/common.py`
  (`FIRMWARE_PROFILE`, `BOOTSTRAP`, `EXPLOIT`, `RUNTIME_PROBE`, `MOCK`, `OPERATOR`).
  Registering the native agent needs either a new enum member or a deliberate reuse
  of an existing type. Adding an enum member is a frozen-core change → W7 with an
  integration finding; W3 records the gap and the concrete proposal (§4).
* **F8 — read-class kernel ops are `mutating=True`** in `core/rpc/registry.py`
  (`kernel.read`, `kernel.snapshot`, `kernel.dump.full`), while the specified
  snapshot flow only reads and hashes. The native interface follows the frozen core;
  the discrepancy is recorded for the next planned core revision.
* **F9 — the mock tolerates `memory.alloc` without arguments** while the canonical
  request in the parity catalog carries `{"size": 4096}`. The frozen interface
  requires `size`, so an omitting host receives `ARGUMENT_INVALID` instead of a
  silent allocation; the stricter behaviour is deliberate and pinned by a test.
* **F10 — sync flags: spec draft vs frozen core.** `Pasted_text(5).txt` l.424-426
  drafts `sync.barrier.wait/release` as `mutating=False`; the frozen registry
  registers all sync operations as `mutating=True`, `recovery_safe=False`. The native
  interface follows the frozen core; the difference is recorded, not patched.
* **F11 — mock evidence is admissible for privileged capabilities in the frozen
  authority table.** `default_authority()` gives `MOCK` `max_assurance = PROVEN`
  while the privileged namespaces require `PROVEN`, so a mock record could in
  principle meet the assurance bar. The W4 capability gate
  (`tools/primitive_iface/gate.py`) excludes `MOCK` for privileged capabilities by
  policy — mock success is not evidence about the console. Recorded, not patched.

## 7. Registry wiring plan (W7, no core change here)

1. Land the native provider registration with finding F7 resolved (§4 values).
2. Route `native_provider.call()` through the same envelope validators as the stub
   (`tools/primitive_iface/validate.py`), so host-side and on-console agents cannot
   drift in schema terms.
3. Route the ingestion path through `CapabilityIntake` for every capability the
   agent reports, with `provider_type` per §4 and assurance clamped by
   `max_assurance` — no `PROVEN` claim without store-bound verification.
4. Availability transitions from agent reports only where `availability_write` is
   true and `availability_rank` decides ties (frozen authority resolution).
5. Any frozen-core edit this requires goes through the normal path: minimal patch +
   recorded integration finding + fresh freeze check (drift log + gate).

## 8. Verification

* `python tools/primitive_iface/schema.py --self-test` — structure plus the
  cross-check against the frozen core registry and the capability catalog.
* `python tools/primitive_iface/validate.py --self-test` — 105 envelope/schema checks
  over all 35 operations (valid inputs accepted, unknown fields refused).
* `python tools/primitive_iface/stub.py --self-test` — 48 behavioural checks: refs,
  gate/barrier semantics, destroy→`RESOURCE_DESTROYED`, recovery gate, deferral
  refusal, clean and recovery BYE.
* `tests/test_primitive_interfaces.py` — table/module/registry/parity-catalog parity
  and the fail-closed rules as part of the gate suite.

## 9. Out of scope in v1

* Any implementation of a privileged family (needs §70 + hardware, W4/P5).
* Profile schema and RVAs/signature values (W5); the interface references them only
  symbolically.
* Mock-vs-native differential execution (W6) and the live acceptance mapping (W8).
* `EVENT`/`READY` semantics (still reserved, D13).
