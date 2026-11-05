# P4/W6 — differential harness (offline, analysis only)

W6 compares offline firmware/profile/artifact inputs and turns the differences into
research findings and profile *candidates*. It is analysis, not authorization: no
finding and no candidate can enable an operation, and a candidate is never a fact.

Modules: `tools/differential/normalize.py` (canonical forms, hashes, determinism) ·
`schema.py` (classifications, confidence, validation) · `inventory.py` (offline
artifact inventories: zip bundle, ELF, raw blob, inventory) · `compare.py` (the five
layers + run orchestration) · `candidates.py` (OBSERVATION-only generation) ·
`cli.py` (`diff profiles|artifacts|operations`, `report`).
Fixtures: `tests/fixtures/differential/` (+ generator).

## 1. Input classes (all hash-bound)

* two PS4RF profiles (W5 schema) - compared by canonical hash and field by field;
* offline binary/image artifacts: zip bundles (members hashed individually, an inner
  `MANIFEST.sha256` parsed as manifest facts), ELF images (sections with file offsets,
  sizes, section-byte sha256, permission bits, architecture), raw blobs (one region,
  permissions/architecture `UNRESOLVED`);
* normalized inventories (`ps4rf.differential.inventory.v1`) - from fixes or future
  adapters;
* optional external analysis results (Ghidra/Rizin/angr/AFL++) via
  `ps4rf.external-analysis.v1`.

Every input is hashed (profiles by their canonical hash, artifacts by file hash) and
recorded in the report; `--expect-before/--expect-after` bind a declared hash and a
mismatch refuses the run.

## 2. Normalization

Version `ps4rf.normalize.v1`. Canonicalization uses the frozen core canonicalizer
(JCS + safe-number policy), so profiles, diff reports and wire frames follow one rule
set. u64 quantities render fixed width (`0x` + 16 hex digits). Ordering is deterministic
everywhere. Absolute runtime addresses never enter a comparison: address-style fields
(`runtime_address`, `absolute_address`, `slide`, `runtime_base`, …) are refused, locators
must be relative, and file offsets are named `file_offset` so they cannot be mistaken for
addresses.

The report separates a deterministic core from volatile metadata: `output_sha256` is
computed over the report without `timestamp`, `run_id` and itself. `--timestamp` pins the
timestamp, so two runs over semantically identical inputs produce byte-identical output.

## 3. Layers

**A. Target identity** - `platform`, `model_family`, `firmware_version`,
`firmware_build_id`, `architecture`, `hardware_revision`. A value that is `UNRESOLVED` on
either side yields `UNRESOLVED`/`WEAK`, not a change claim.

**B. Profile** - operation mapping (`profile_required`, `locator_ref`, `profile_fields`,
policy reason), locator presence, locator kind/value, module, section, permissions,
expected bytes, provenance, confidence. `unresolved -> resolved` and
`resolved -> unresolved` are reported as `UNRESOLVED`, never as a change of fact.

**C. Artifact/section** - entries by path: added/removed, resized, permission change,
region-hash (signature) change, and relocation-aware offset comparison (`file_offset`
moves only when name, size and content hash are equal → `MOVED`).

**D. Primitive contracts** - the 14 gated operations: requirement added/removed, locator
changed, verification requirement changed, profile policy changed, and
`unresolved <-> resolved`.

**External** - optional analysis results, always capped at `WEAK`: they are claims by
another tool, not facts of this harness.

## 4. Classification and confidence

Classes: `UNCHANGED` `ADDED` `REMOVED` `MOVED` `CHANGED` `PERMISSION_CHANGED`
`SIGNATURE_CHANGED` `UNRESOLVED` `INCOMPARABLE` `ARTIFACT_MISSING`.
Confidence: `EXACT` `STRONG` `WEAK` `UNKNOWN`.

Facts that come from a fixture-marked input are capped at `WEAK`, and so are external
analysis findings; a confidence cap can only lower a confidence, never raise it. A
difference is never a verdict: the vocabulary contains no "vulnerability", "fixed",
"exploitable", "BUG", "PRIMITIVE" or "PROVEN", and a finding that contains such a word in
its values is refused by the validator.

## 5. Relocation awareness

Comparisons use `module + relative locator + section` for profiles and
`name + file_offset + size + content hash` for artifacts. A pure shift with unchanged
content is `MOVED`; a shift with changed content is `SIGNATURE_CHANGED`/`CHANGED`. Nothing
is compared as an absolute address, so a slide cannot produce a finding.

## 6. Candidates

A candidate is generated per *difference* finding (`ADDED`, `REMOVED`, `MOVED`,
`CHANGED`, `PERMISSION_CHANGED`, `SIGNATURE_CHANGED`, `UNRESOLVED`) - never for
`UNCHANGED`, `INCOMPARABLE` or `ARTIFACT_MISSING`. Every candidate carries status
`OBSERVATION`, the hashes of its evidence (finding hash + input hashes), the required
path, and `impact.w4 = NONE`:

    W6 diff -> candidate -> review/verification -> W5 profile update
            -> new profile_sha256 -> new boot/runtime binding

`candidates.py` imports neither the W4 gate nor any profile writer: it cannot remove a
W4 reason, allow a provider, raise assurance, remove `NOT_WIRED` or mutate an active
profile. The candidate schema also forbids verdict-like status values.

## 7. Report format

`ps4rf.differential.run.v1`, deterministic JSON (``--md`` adds a human-readable report):

    schema, run_id, timestamp, tool{name,version}, normalization_version, config_sha256,
    config, command, inputs[{role,kind,path,sha256,architecture,fixture,missing}],
    findings[{id,layer,class,confidence,subject,operation,before,after,provenance}],
    candidates[{schema,id,status,kind,subject,evidence,requires,impact}],
    summary{findings,candidates,counts,identical,notes}, output_sha256

`run_id` is derived from the deterministic core (`W6-<hash16>`), so identical runs share
an id.

## 8. Fail-closed rules

A run is refused when: an input hash does not match the declared one; a profile fails the
W5 schema or its declared canonical hash; the normalization version is unknown; an
external analysis input is missing, malformed, or references a different artifact; a
locator is malformed; provenance is incomplete. An architecture conflict yields a single
`INCOMPARABLE` finding (profile layers are not compared) instead of noise. A missing
artifact yields `ARTIFACT_MISSING` and nothing is synthesized.

## 9. Fixtures

`tests/fixtures/differential/`: two section inventories (one phenomenon per entry:
moved, permission change, signature change, resize, add, remove, plus an untouched
control), two operation inventories (requirement added/removed, locator moved,
verification requirement changed, policy changed, unresolved↔resolved), and two external
analysis inputs (Ghidra-shaped before, Rizin-shaped after). The firmware 9.00 vs 13.52
differential runs on the existing W5 profile fixtures; **firmware images are not present
in the repository**, so the artifact layer reports `ARTIFACT_MISSING` for them instead of
inventing content. Real bundles (`references/`) and the harness ELF are handled by the
same engine and stay real inputs.

## 10. W4/W5 handoff

* W6 can produce profile candidates; those are not W5 facts. A candidate needs review and
  verification, after which the profile is updated, gets a new canonical hash and needs a
  new boot/runtime binding.
* A W6 finding never removes a W4 reason, never allows a provider, never raises assurance
  and never removes `NOT_WIRED`. Even a perfect W5 binding leaves a non-wired privileged
  operation at `OPERATION_DEFERRED`.
* Sections 70 and the frozen verification-evidence path remain the only way to a
  privileged capability.

## 11. Tool adapter preparation

The external analysis schema (`ps4rf.external-analysis.v1`) already accepts Ghidra,
Rizin, angr and AFL++ outputs: `tool`, `version`, `artifact_sha256`, `entries[{kind,name,
size,locator}]`. **No adapter is implemented** in W6 - the ingestion path exists, is
validated, and any finding derived from it is capped at `WEAK` with an explicit note.

## 12. Limits

W6 makes no statement about exploitability, reachability or severity, and cannot turn a
difference into a capability. Its output is a lead list for review, nothing else.
