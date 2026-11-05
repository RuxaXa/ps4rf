# P4/W5 — profile binding (offline contract)

W5 makes target facts machine-readable and checkable: *does this primitive belong to
exactly this target, this firmware build and this boot?* It supplies the profile part
of the W4 capability gate and nothing else.

**W5 never delivers:** an executable operation, a removed `NOT_WIRED` reason, raised
capability assurance, verification evidence, a runtime reachability claim, or a
capability derived from a symbol/RVA.

Modules: `tools/profiles/schema.py` (facts, canonical hash, validation, precondition
codes, operation matrix) · `binding.py` (boot/runtime binding, probe contract) ·
`loader.py` (the only entrance for profile documents) · `w4_adapter.py` (W4 seam).
Fixtures: `tests/fixtures/profiles/` (+ generator `gen_profiles.py`).
Schema: `schemas/profile.schema.json`.

## 1. Target identity

A profile carries one target identity: `platform`, `model_family`,
`firmware_version`, `firmware_build_id`, `architecture`, `hardware_revision`, plus
`profile_id`, `profile_version` and the derived `canonical_sha256`. Identity fields are
compared verbatim against the expected target; an unknown on-site value is the string
`UNRESOLVED` and keeps the profile fail-closed.

## 2. Facts are persistent, bindings are not

Profile facts survive a reboot. A **BOOT binding** ties one profile hash to one
`boot_id` and expires with that boot: after a reboot the old runtime binding is
invalid while the facts remain valid and a new BOOT binding must be created. A
**runtime binding** additionally resolves locators against the runtime bases of the
current boot.

    runtime address = profile locator (relative) + runtime base of the module

Absolute addresses are inexpressible: the profile schema is a strict key allowlist, so
a field such as a runtime address cannot appear at all.

## 3. Symbol / RVA binding (locator facts)

Each gated operation's locator fact records: the symbolic `operation`, the
`module`/image, a relative `locator` (`kind: rva|relative`, `value`), the expected
`section`, the expected `permissions`, optionally `expected_bytes` (offset + hex, a
signature/boundary check), the `provenance` (`kind: evidence|fixture`, `source`,
`sha256`) and the `confidence` of the fact.

A fact is admissible only if it is evidence-backed: `confidence: OBSERVED|PROVEN`
requires `provenance.kind = evidence` with a source and a sha256 — a fact that is not
evidence-backed is refused by construction. Fixture facts must say so
(`kind: fixture`) and mark the whole profile `fixture: true`.

## 4. Preconditions handed to W4

    PROFILE_MATCH · PROFILE_MISMATCH · PROFILE_UNVERIFIED
    LOCATOR_MISSING · LOCATOR_MISMATCH · BOOT_BINDING_MISMATCH
    PROFILE_BINDING_MISSING   (nothing submitted at all)

`profile_preconditions()` reports *every* failing code in a fixed order and returns
`PROFILE_MATCH` only when nothing fails. `PROFILE_UNVERIFIED` covers unresolved facts;
`PROFILE_MISMATCH` covers a declared hash that does not match the canonical content,
an identity mismatch (wrong firmware/build) and verification evidence that references
a different profile hash; `BOOT_BINDING_MISMATCH` covers a missing, foreign or
expired boot binding; `LOCATOR_MISSING`/`LOCATOR_MISMATCH` cover a missing locator and
any disagreement in module, section, permissions or expected bytes.

## 5. Binding integrity

Profiles are canonicalized with the frozen core canonicalizer
(`core.canonical.canonical_bytes`: JCS + safe-number policy) and hashed; the hash is
computed over the document without its own hash field. Any change to firmware
identity, a locator, expected bytes, the operation mapping or a section/permission
expectation changes the profile hash. `VerificationRecord.profile_sha256` must
reference exactly this hash — a record that references another hash is rejected.

## 6. Runtime probe contract (specified, not executed)

For every operation the later bind sequence is fixed:

    profile fact → boot binding → runtime base → locator → bounded read
    → expected signature/section check → runtime binding

A probe plan must be `mode: read`, must not contain writes, and must be bounded
(≤ 4096 bytes). Every deviation fails the binding: wrong module, wrong section, wrong
permissions, a signature mismatch, a failed section check or a base that is not an
address all refuse the binding instead of producing a partial one. W5 defines and
validates this contract; it executes nothing — driving it is P5/W7 work on site.

## 7. Operation mapping (no implicit defaults)

All 14 gated operations have an explicit entry, either `profile_required` with a
`locator_ref` and `profile_fields`, or an explicit `profile_not_required` with a
reason. The validator refuses a profile that omits any of them and refuses a policy
entry that contradicts the frozen W4 matrix. The machine-readable matrix is
`tests/fixtures/profiles/operation-matrix.json` (generated, pinned).

## 8. W4 integration

W5 feeds only the `profile_binding` input of the W4 gate. Every failing W5 code
collapses into the single W4 reason `PROFILE_UNBOUND`; the W5 code stays visible in
the binding and in the gate's details. The gate module itself is unchanged.

    before W5:  PROFILE_UNBOUND + NOT_WIRED     (nothing bound)
    after W5:   NOT_WIRED                       (bound and evidenced, still not executable)
    always:     executable = False, wire = OPERATION_DEFERRED

The adapter refuses a structurally matching profile that is not evidence-backed
(`require_evidence_backed = True` by default): a fixture match is not a fact about a
console. Satisfying the profile reason removes *only* that reason — `NOT_WIRED` and
the W4 provider/evidence/capability requirements are untouched.

## 9. F11 regression

A perfect profile match never legitimises a mock provider: with a mock capability
record (even `PROVEN`) and a perfect profile, the decision stays `DEFERRED` because
the W4 provider policy rejects `MOCK` for privileged capabilities. The profile acts
through the W4 gate or not at all.

## 10. Fixtures and open on-site values

`tests/fixtures/profiles/` holds three clearly marked fixtures: two placeholder
skeletons (fw1352, fw900) whose unknown on-site values stay `UNRESOLVED`, and one
concrete fixture whose locators are deliberately non-address-like placeholders (small
integers, never a real firmware RVA) with `fixture` provenance. No real FW13.52
address is invented anywhere; real locators come from the on-site evidence pass. While
on-site values are missing the gate stays fail-closed. `profiles/fw1352/` and
`profiles/fw900/` remain evidence-only placeholders.

## 11. Handoff

* **W6** compares mock and native behaviour; a profile match alone is never evidence
  of reachability.
* **W7** wires the native provider and must pass profiles, boot bindings and evidence
  through the W4 gate — never around it.
* **P5/on site** produces the real locator facts (with capture artifacts and hashes)
  that replace the fixtures; only then can `evidence_backed` become true.
