# WIRE-CATALOG R2 — kernel.read bounded-region args (W13-C2)

**Wave:** W13-C2 · **Revision id:** `WIRE-CATALOG R2: kernel.read bounded-region args`
**Status:** offline complete, build against this revision is reproducible, live not started
**Supersedes nothing structurally:** framing, handshake, AEAD and the operation registry are unchanged.

## 1. Why this revision exists (real finding, not a refactor)

Live attempt 2 of W13-C1 uploaded the reviewed payload with the corrected trigger read
(region `amd_iommu`, compiled index `1`, offset `0`, length `16`). The target answered
`KREAD_REGION_INDEX_INVALID` with no callback; the host refused to persist evidence and the
release was consumed at the single provider entry.

Two defects were found, and both are fixed here:

* **Root cause A (payload).** The trigger read its arguments one nesting level too high — from
  `body` instead of `body.arguments` — so it never saw the host's values and handed sentinels to
  the provider, which refused with `KREAD_REGION_INDEX_INVALID`. This is the defect the live run
  actually died on.
* **Root cause B (wire contract).** The frozen argument table required `addr:int` and `size:int`
  for `kernel.read`, so a *correct* bounded triplet request was an unknown argument set and the
  router answered `ARGUMENT_INVALID` before the route decision — verified offline against the real
  router, and now asserted by the offline smoke fixture for the retired pair.

Taken together: **the old wire contract demanded exactly the raw kernel address the PS4RF security
contract forbids**, so the bounded trigger could not be expressed on it at all. Root cause A is a
payload defect, root cause B is the contract defect this revision closes.

## 2. The revision, exactly

Old contract (retired):

```text
kernel.read(addr: int required, size: int required)
```

New contract (normative):

```text
kernel.read(region_index: int required, offset: int required, length: int required)
```

* `size` is replaced entirely by `length`. The retired names are **never** valid `kernel.read`
  arguments again: `addr`, `address`, `va`, `kernel_va`, `ptr`, `source`, `size`.
* Unknown fields fail closed: any key outside the operation's slice fails the whole request in the
  generated validator the production router calls.
* Operation, capability (`kernel.read`), route (`DEFERRED_PRIVILEGE` → `PS4RF_TARGET_DEFERRED`) are
  unchanged. The target router still executes nothing itself; there is **no** second operation
  `kernel.read.bounded`, so W4/W5/W7 capability and policy models are not duplicated.
* Wire framing is untouched: handshake, AEAD, frame format, request header, protocol framing
  version. Only this one operation's argument contract moved.
* Target resolution is unchanged and stays target-side:
  `region_index` → compile-time region table → fixed RVA → checked offset → checked length →
  internal runtime VA. The host never sends an RVA or a VA.
* Bounds are unchanged (index < compiled count, row exists, not UNRESOLVED, `length` 1..4096,
  `offset < region length`, `offset + length` checked, fully contained, canonical runtime
  address, one-shot guard set before any block write).

## 3. Trigger parse (payload)

* The trigger reads **only** `body.arguments.region_index`, `body.arguments.offset`,
  `body.arguments.length`. The same keys directly under `body` are **not** a request (this is the
  live W13-C1 mistake, now a required regression test).
* A field that is missing, not an integer, negative or outside its 32-bit range makes the whole
  request invalid: the payload answers `ARGUMENT_INVALID` explicitly, **before** any bound rule and
  before any kexec. No sentinel substitution, no default region, no silent repair.
* The explicit refusal does not touch the one-shot guard: a malformed request is not a read
  attempt, so it cannot consume the single read this payload is allowed to perform.
* The provider module still never sees host input: no `jval`, no key name, no request bytes reach
  `ps4rf_kread.c` (the build gate asserts this). The parse lives in the trigger, the refusal
  verdict in the module.

## 4. Host contract

The host request for the next `amd_iommu` read is exactly:

```json
{
  "operation": "kernel.read",
  "arguments": {
    "region_index": 1,
    "offset": 0,
    "length": 16
  }
}
```

No other form is accepted. The session builder produces `{operation, arguments}` and the
regression suite asserts the body built from the release window equals this object and contains no
address-shaped key.

## 5. Affected normative sources (section 8 list)

| source | change |
| --- | --- |
| W3 interface schema (`tools/primitive_iface/schema.py`) | `kernel.read` args = the bounded triplet, all required, with the revision referenced in the source comment |
| generated args table (`native/target/ps4rf_optable_data.h`) | regenerated: `PS4RF_ARG_ROW_COUNT 49`, `kernel.read` rows `region_index`/`offset`/`length` |
| native operation table (`gen_optable.py` inputs) | unchanged operation rows (name, capability, route) |
| Python registry / schema parity | asserted by `tests/test_w13c2_wire_arguments.py` (schema ⇄ generated table) |
| W3 primitive interface mapping | re-derived from the schema; `tests/test_primitive_interfaces.py` builds its requests from the schema and now sends the triplet |
| request validation (agents + tools) | `tools/hostctl/smoke.py`, `tools/dispatch/dispatch.py`, `tools/dispatch/cli.py`, `tools/profiles/w10_gate.py` send the triplet; the retired pair now yields `ARGUMENT_INVALID` |
| native parity vectors | framing/parity vectors carry no operation arguments — verified, nothing to change (documented here rather than silently skipped) |
| host smoke fixtures (`native/target/ps4rfd_host.c`) | sends the triplet (expects `OPERATION_DEFERRED`) **and** the retired `addr`/`size` pair (expects `ARGUMENT_INVALID`) |
| documentation | this file; W13-C1 request-shape note marked superseded; CHANGELOG |
| generated artifacts | `ps4rf_optable_data.h` (table hash `a56533785899c81e45eb53494c8f78727b63c88b928b827545259c2a9f043247`) |

Scope decision: the other deferred read-class operations (`kernel.snapshot`,
`verify.kernel.read`, `verify.kernel.copyout`) keep their frozen W3 argument sets. They stay
deferred, unwired and without a provider; this revision is about the one operation the live
finding names.

## 6. Required tests (sections 9 and 10)

* `tests/harness/optable_args_check.c` reads the checked-in generated table: exactly three
  required integer arguments, names `region_index`/`offset`/`length`, no forbidden name.
* `tests/test_w13c2_wire_arguments.py` — 16 tests, all against production code:
  * the generated table, the W3 schema and the operation row agree on the triplet;
  * the agent parses `body.arguments` and never a flat body (the live error);
  * the host's wire body is exactly the approved object;
  * **nested triplet**: accepted, `OPERATION_DEFERRED`, and the bounded run is entered (on the
    host stand-in it ends in `RESULT_INVALID`: no kernel, and a zeroed block must not read as a
    successful callback);
  * **refused before any provider entry**, response code `ARGUMENT_INVALID`: the flat body, the
    retired `addr`/`size` pair, `triplet + addr`, `triplet + size`, missing `region_index`,
    missing `offset`, missing `length`, wrong type, unknown field, empty arguments;
  * for the flat body, the retired pair, missing fields, wrong types and the empty object the
    trigger's own verdict is `ARGUMENT_INVALID` with `cb_status = 255` (NOT_RUN), no callback, no
    kexec, no bytes returned.

## 7. Mutants (section 11)

`run_mutants_c2.py` builds a hard-linked scratch tree per mutant, mutates, regenerates the catalog
where needed and requires the contract tests to turn **red**:

| mutant | result |
| --- | --- |
| `m8_parser_flat_body_again` | tests red |
| `m9_legacy_pair_allowed_again` | tests red |
| `m10_both_schemas_accepted` | tests red |
| `m11_region_index_optional` | tests red |
| `m12_offset_optional` | tests red |
| `m13_length_optional` | tests red |
| `m14_refusal_replaced_by_silent_default` | tests red |

The seven W13-C1 mutants remain build-gate killers and are re-run on this tree
(`run_mutants_c1_rerun.py`).

## 8. Trust objects (section 13)

The consumed release `W13-C1-READ-1-NEW-PAYLOAD` stays `CONSUMED`; its trust objects are not
reused. The W13-C1 records are marked `SUPERSEDED` in the local trust/status store. After the final
build this revision gets a fresh §70 approval and a fresh W13 release bound to the new payload,
the current `profile_sha256`, the current `boot_id` and the window `amd_iommu / index 1 / offset 0 /
length 16` with its expected bytes and SHA256.

## 9. What this revision does not do

No upload, no rearm, no probe connect, no port 9090 contact, no second read, no new region, no
kernel writes, no arbitrary calls, no W14 start. The next live step happens only after the owner's
explicit `BinLoader rearmed`.
