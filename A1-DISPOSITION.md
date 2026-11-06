# PS4RF — disposition of the independent audit A1

Audit: *PS4RF Independent Audit A1*, target commit `1328aa5bada42f90d9773d3df851e543bb583947`.
Disposition date: 2026-11-05. Scope: engine correctness and reproducibility only — no
firmware claim, no console contact, no exploit execution.

A1-01 … A1-07 are the engine findings; each one is closed by a code change plus the
auditor's own counterexample kept as a regression test. A1-10 and A1-11 are
reproducibility findings and are closed. A1-08 and A1-09 are evaluation-discipline
findings: A1-09 is corrected in the label data, A1-08 is an open gate that no code
change can close.

## Findings

### A1-01 (HIGH) — a short *possible* summary beat a longer *proved* path — FIXED

*Counterexample:* rank-1 primitive, one synthetic `reaches` hop with status `possible`,
plus a concrete `entry → helper → primitive` route where both hops are `proved`. The
walk stopped at the first entry it met, so the summary hop won on hop count and the
chain reported `possible`.

*Fix:* `semgraph._entry_paths()` enumerates every entry-rooted reverse path (depth and
expansion budgets), `_path_key()` orders by worst hop status first and hop count second,
and the chosen path plus up to three runner-up paths are published under
`chain["path_selection"]` (`rule`, `paths_considered`, `truncated`, `alternatives`).

*Tests:* `test_a_possible_summary_hop_does_not_eclipse_a_proved_concrete_path`,
`test_chain_path_selection_is_stable_under_edge_order`.

### A1-02 (HIGH) — merging could join a top rank with another record's evidence — FIXED

*Counterexample:* two findings for the same detector and function, rank 1 and rank 3,
different slots and different claims. The old merge kept `min(rank)` from one record and
the hypothesis, window and falsification from whichever record arrived first, so the
output depended on scan order and the rank did not belong to the published proof.

*Fix:* `queue._record_key()` is a total order (falsifiable first, then strongest rank,
then a canonical evidence dump) and picks one canonical representative per group. The
candidate's hypothesis, rank and window come from that record only; every other record
is published beside it in `evidence.sites[]` with its own rank, claims, window and
counter-evidence. `evidence.rank_of_hypothesis` states which record the rank belongs to.

*Test:* `test_merged_evidence_never_mixes_ranks_and_is_permutation_invariant` (asserts
byte-identical output for both input permutations).

### A1-03 (HIGH) — `REQ_UNPRIV_ENTRY` was cleared without authorization evidence — FIXED

*Counterexample:* a proved path from `entry:sysent[…]` cleared the unprivileged-entry
requirement on the strength of the entry *kind* alone, although a syscall handler can
gate on credentials and a command id and a cdevsw node can be root-only.

*Fix:* the requirement is split. `REQ_ENTRY_REACHABLE` (control flow) is cleared by a
fully proved entry-rooted path. `REQ_UNPRIV_ENTRY` is cleared only by recorded
authorization evidence — a whitelisted `basis` **and** the evidence that was read
(`chains.AUTHORIZATION_BASES`, `chains.entry_authorization()`); a claim without
provenance clears nothing. `REQ_INPUT_CONTROLLED` needs taint or argument provenance.
`Chain.entry_privilege` reports `UNPRIVILEGED` / `PRIVILEGED` / `UNKNOWN`, and every open
blocker now carries the concrete reason next to the requirement text.

*Tests:* `test_chain_requires_an_entry_rooted_witness_path` (updated: privilege stays
open), `test_recorded_authorization_evidence_is_what_clears_privilege`,
`test_an_authorization_claim_without_evidence_clears_nothing`.

### A1-04 (MEDIUM) — a refcount guard could be invented from an unrelated compare — FIXED

*Counterexample:* `lock dec dword [rdi+0x28]; cmp eax, 0x10; call release`. The old
detector set `guarded=True` whenever the character `"1"` occurred in the operands of any
`cmp` within eight instructions.

*Fix:* `handles.guard_proof()` parses the operands. A guard is *proven* only when a
compare touches the same field (or a register reloaded from it) against an immediate of
0 or 1 **and** a conditional branch consumes the flags before the release call. Every
other shape yields `guard_state="unknown"` with the reason (`Drop.guard_reason`), never
"unprotected". `Drop.guarded` is now derived from that proof.

*Tests:* `test_unrelated_compare_never_proves_a_refcount_guard`,
`test_count_compare_with_a_consuming_branch_is_a_proven_guard` (positive control),
`test_count_compare_without_a_branch_is_not_a_guard`,
`test_release_shape_reports_unknown_guard_instead_of_protected`,
`test_release_shape_still_recognises_a_real_guard`.

### A1-05 (LOW, dormant) — plain `mov` stores never reached the handle summary — FIXED

*Counterexample:* `mov dword ptr [rdi+0x10], eax` produced an empty `stores` map, because
every `mov` was consumed by the register-provenance branch before the store branch ran.

*Fix:* `handles.summarize()` treats the two facts separately. Register provenance reads
the destination register; a memory write is recorded only when the **destination**
operand is a record field (`_dest_mem_field()`), which also stops a load from being
booked as a write at its source offset. `movzx/movsxd/movsx` stay load-only;
`movups/movdqu/movq/movd` are store-capable.

*Test:* `test_plain_mov_store_is_summarised_and_a_load_is_not`.

### A1-06 (HIGH design risk) — invented cross-function `transfers-reference` edges — PARTIAL

*Counterexample:* every acquire in the caller plus *any* drop in the callee produced a
`transfers-reference` edge, with a witness text claiming the register was handed over.

*Partial remediation:* `semgraph._argument_carries()` requires a bounded, full-width
caller argument-placement witness. Without such evidence, the transfer stays UNKNOWN.
A caller placement alone cannot prove what the callee releases; the graph now requires
a separate, concrete `callee_identity_witness` for a PROVED transfer. That producer
is **not implemented** in PR #8, and the FW 13.52 audit found 55/55 placements refused.
Thus the old false proof is addressed, but the complete positive proof path is still open.

*Tests:* `test_argument_register_hand_off_proves_a_transfer`,
`test_a_register_the_call_never_receives_proves_nothing`,
`test_an_unproven_transfer_hop_stays_unknown_in_a_chain`.

### A1-07 (HIGH design risk) — graph was finding-centred, not entry-rooted — MITIGATED

*Fix (step 1):* `semgraph.build()` expands control flow outward from the finding functions
(call and tail-jump edges for callees that carry no finding) under an explicit budget
(`MAX_EXPANDED_FUNCTIONS = 96`, `MAX_EXPANSION_DEPTH = 2`), publishing the budget, the
expanded count and the truncation reason in `graph["expansion"]`.

*Fix (step 2, the audit's actual recommendation):* `build(..., whole_program=True)` and
`cli semgraph --whole-program` seed the walk from the scan artefact's `scanned_rvas`, i.e.
from **every function the scan analysed**, so a route through a function without a finding
exists in the graph at all. Budget `MAX_WHOLE_PROGRAM_FUNCTIONS = 2000`,
`MAX_WHOLE_PROGRAM_DEPTH = 64`; `expansion` publishes `mode`, `root_source`,
`function_budget`, `depth_budget`, `truncated`, `truncated_reason` and the control-flow edge
count. A scan artefact without `scanned_rvas` is reported as **truncated** rather than
silently falling back to the finding functions, because a finding-centred graph relabelled
whole-program would hide exactly the gap this finding is about.

It stays opt-in: the frozen S1.3 artefacts were produced in finding-centred mode and must
stay comparable, so switching the default is a separate decision with its own evidence.

*Measured on FW 13.52* (same scan artefact, only the seeding differs; the graph itself is
not firmware and is not committed):

| | finding-centred | whole-program |
| --- | --- | --- |
| graph nodes | 1814 | 3088 |
| graph edges | 11359 | 21348 |
| `function -> function` control flow | 5018 | 11986 |
| functions with an inbound call edge | 1264 | 2369 |
| functions on a route of at least two hops | 656 | 1956 |
| chains whose chosen path is `proved` | 211 / 370 | **254 / 370** |
| chains with a cross-subsystem transition | 24 | **33** |
| published alternatives | 314 | 410 |

The row that matters is not the node count: every finding function was already a node in
both graphs, so "is it in the graph" never discriminated. The routes into it did. 43 chains
move from `possible` to `proved` and 9 gain a cross-subsystem hop, which is the exact
under-reporting A1-01 and A1-07 described — `cross_subsystem = 0` was partly an artefact of
where the walk started.

Both runs stay truncated and say so (2000 of 2053 scanned roots). Making 2053 the budget
would not change the honesty of the artefact, only the runtime.

### A1-08 (MEDIUM, experimental validity) — no independent blind test left — OPEN GATE

Afterglow is marked burned and its root-cause narrative lives in `families.json`, so it
cannot serve as fresh blind validation. No code change can close this: it needs a new
held-back set, locked in a separate process, with the *whole* available context audited
(agent history, evidence directories, prompts), not just detector sources. Tracked as the
P3 gate. The S1.3 statement stays as it is: no independent generalization success.

### A1-09 (MEDIUM, benchmark label error) — “all FW 13.52 is negative” — CORRECTED

`tools/discovery/data/training/references.json`, `fw1352-frozen-corpus`: the note no
longer claims the firmware as a whole, the scope is now
`label_scope: "corrected-functions-only"` and `unlabeled_functions: "unknown"`. An
unlabelled function is `UNKNOWN`, never a true negative — the same firmware carries a
positive ReLapse case.

### A1-10 (MEDIUM, reproducibility) — undeclared disassembly dependency — FIXED

`pyproject.toml` now declares `capstone>=5` as a runtime dependency, because
`tools/discovery` imports it and four discovery test modules failed at collection in a
clean environment. The change is recorded in `FREEZE-DRIFT.md` (old manifest hash kept,
new hash and reason added) so the freeze gate stays green.

### A1-11 (LOW, reproducibility) — order-sensitive test — FIXED

`tests/test_event_capture.py::test_single_socket_reader` compared `Path.glob()` output —
filesystem enumeration order — against a fixed list. The reader set is now sorted before
the comparison, so the test asserts the property it means (which modules read the socket),
not the directory layout. Ordering semantics elsewhere are untouched.

## Verification

Fixture: the A1-04/05/06 counterexamples are assembled by real binutils
(`tests/fixtures/discovery/a1-regressions.S`) and decoded through the same capstone path
as firmware, with the generated image committed (`a1-regressions.json`) and
`test_fixture_matches_generator` failing if the image drifts.

* New regression tests: 15 (13 in `tests/test_discovery_a1_regressions.py`, 2 in
  `tests/test_discovery_semgraph.py`); collected tests 1272 → 1287, no test removed.
* Targeted suites: `test_discovery_a1_regressions.py`, `test_discovery_semgraph.py`,
  `test_discovery_handles.py` — 35 passed.
* `test_freeze_drift.py` — 6 passed after the drift entry.
* Full suite on this tree: **1268 passed, 11 failed, 5 skipped, 3 xfailed**.
* Baseline, clean worktree of the untouched commit `1328aa5`: **1253 passed, 11 failed,
  5 skipped, 3 xfailed**. The failure sets are identical (`diff` of the FAILED lines is
  empty apart from the freeze-drift test that this change caused and which is fixed), and
  the 15 extra passes are exactly the 15 new regression tests. Of the 11 failures, **four**
  are missing environment prerequisites (two cached trust objects, a prebuilt host daemon);
  the other **seven** are a repository defect that predates this work — the host-side frozen
  response schema for `session.status` declares 3 result fields while the daemon emits 12
  undeclared ones. Corrected in `A1-MATRIX.md` ("The eleven suite failures, one by one")
  after the earlier, wrong summary here called all eleven environmental.

## Re-audit cross-check (second reading of the A1 report)

The audit was re-read against this tree, comparing each finding to the wording of its own
remediation rather than to a summary of it.

Work done in that pass:

* **A1-06 gained the audit's second counterexample.** The audit asked for "an unrelated
  acquired object plus a callee that decrements a different object". `pass_other_object`
  acquires into `rax` and hands the callee `rcx`, so the transfer must stay unproven;
  `pass_by_lea` is instead an **interior-pointer negative control**:
  `lea rdi, [rax+0x10]` derives another address and must not prove transfer of the
  same object. Only identity `lea rdi, [rax]` may serve as a local same-address
  placement witness. Both forms can be checked with Capstone/binutils fixtures.
* **A1-10 is pinned, not merely declared.** `capstone>=5` became `capstone>=5,<6`: an open
  lower bound lets a future major change decode behaviour under a fixed analysis.
  `FREEZE-DRIFT.md` carries the new hash and the reason. Offline install for an environment
  without an index: on a connected host `pip download capstone==5.0.7 -d wheels/`, then
  `pip install --no-index --find-links wheels capstone==5.0.7` — 5.0.7 is the version the
  fixtures were built and verified against.
* **A1-01's alternatives are asserted, not just produced**: the chosen path must be the
  proved two-hop route while the `possible` one-hop summary appears under
  `path_selection.alternatives`, identical when the edge order is reversed.
* **A1-07 now has whole-program mode** (see above), opt-in, with its budget published.
* **A1-05 is recorded as what the audit says it is.** The store summary was repaired (a
  destination-operand test separates store from load) and pinned by a fixture, but the field
  still has **no consumer** outside its producer and its tests. The defect was dormant, so
  this removes a latent false negative rather than a current scan failure. If the field is
  still unconsumed at the next milestone it should be deleted rather than kept as decoration.

Still open, with the reason:

* **A1-08 is closed inside the repository only.** `tools/discovery/seal.py` refuses reads of
  `data/corpus`, `data/blind` and `data/negative` during a blind run through a CPython audit
  hook, and `blindrun.py` records whether the seal was active. The audit asks for the *whole*
  context to be audited — agent history, evidence directories, prompts, summaries — and none
  of that is covered. A held-back set created in the session that read the answer stays
  contaminated regardless of what the seal says.
* **A1-09 stays a labelling rule, not a proof.** `label_scope: corrected-functions-only` and
  `unlabeled = UNKNOWN` are recorded in the label data and the corpus validator refuses a
  negative claim that is not function- and bug-class-scoped; whether the underlying
  correction evidence is complete is not something this repository can establish.
* **Whole-program mode is not yet the default**, so the frozen S1.3 artefacts remain
  finding-centred by construction.

On the audit's note that the suite totals are Hermes' claim: they are reproducible from the
tree. Baseline `1328aa5` in a clean worktree: 11 failed / 1253 passed / 5 skipped / 3 xfailed.
The corrected tree: 11 failed / 1332 passed / 5 skipped / 3 xfailed. The identical set is
*not* uniform: 4 are missing environment prerequisites (2 cached trust objects, the dev-host
daemon), 7 are a pre-existing schema defect — see `A1-MATRIX.md` for the per-test split. Being
identical on the baseline proves "not introduced here"; it does not prove "not our bug".

## What this disposition does not claim

No statement about any PlayStation firmware, no exploitability, no live console work, no
claim that the discovery engine now finds real bugs. The findings were logic defects in
the engine; the fixes make the engine's statements match its evidence.

## Next steps (P1 → P3)

* P1: historical PS4/PS5 exploit corpus with root causes, research approaches and firmware
  differences; training and blind cases kept strictly apart.
* P2: autonomous rediscovery — unknown firmware binaries with no PoC, no function
  addresses, no bug class, no patch site.
* P3: generalization proven on independent blind tests, then new failure mechanisms and
  cross-subsystem combinations. A1-08 is the gate that must be closed before any
  generalization claim is made.
