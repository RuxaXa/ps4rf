# PS4RF — A1 acceptance matrix

**Scope:** the 11 findings of the independent audit A1 against source snapshot
`1328aa5bada42f90d9773d3df851e543bb583947`, measured in the worktree
`/home/hermes/work/ps4rf-a1` (branch `a1-disposition`).
**Rule applied:** a finding is `FIXED` only when the auditor's own counterexample is now
refused by code and a test fails if the fix is reverted. `PARTIAL` means the demonstrated
defect is gone but the audit's stated recommendation is not met. `OPEN` means no code change
can close it. Nothing here claims kernel-level correctness — the audit's own split.

| # | Finding (audit) | Status | Regression test | Concrete evidence |
| --- | --- | --- | --- | --- |
| A1-01 | Chain search prefers a short *possible* summary over a longer *proved* path | **FIXED** | `test_a_possible_summary_hop_does_not_eclipse_a_proved_concrete_path`, `test_chain_path_selection_is_stable_under_edge_order` | Auditor's H3 now raises: chosen path is `proved`, 2 hops, `cross_subsystem` 1 instead of `possible`/1/0 (`test_every_audited_counterexample_is_gone`) |
| A1-02 | Candidate merge keeps rank from one record and evidence from another | **FIXED** | `test_merged_evidence_never_mixes_ranks_and_is_permutation_invariant` | Both input orders produce byte-identical JSON (`json.dumps(..., sort_keys=True)` compared); H4 raises on the old code |
| A1-03 | Entry authorization assumed rather than evidenced | **FIXED** | `test_recorded_authorization_evidence_is_what_clears_privilege`, `test_an_authorization_claim_without_evidence_clears_nothing`, `test_unrooted_primitive_is_unknown_not_implicitly_reachable` | H5 keeps `BLOCK_REQ_UNPRIV_ENTRY` open; a whitelisted `basis` without evidence text clears nothing |
| A1-04 | Refcount guard "proven" by a substring test (`"1" in op_str`) | **FIXED** | `test_unrelated_compare_never_proves_a_refcount_guard`, `test_count_compare_with_a_consuming_branch_is_a_proven_guard`, `test_count_compare_without_a_branch_is_not_a_guard`, `test_release_shape_reports_unknown_guard_instead_of_protected`, `test_release_shape_still_recognises_a_real_guard` | H2 raises: `cmp eax, 0x10` yields `guarded=False`, `guard_state="unknown"` with a reason; a real `cmp [rdi+0x28], 1` + `jne` still proves |
| A1-05 | Store summary books loads as stores / misses plain `mov [mem], reg` | **FIXED (defect) — dead field still OPEN** | `test_plain_mov_store_is_summarised_and_a_load_is_not` | H1 raises: `stores == {0x10: {4}}` instead of `{}`. **No consumer** of `summarize(...).stores` exists outside `handles.py` and its tests — `grep -rn "\.stores\b"` finds only those; the audit's "remove if deliberately unused" is not done |
| A1-06 | Unproven cross-function object transfer | **PARTIAL (2026-11-06 independent audit)** | `test_argument_register_hand_off_proves_a_transfer`, `test_an_interior_pointer_lea_does_not_prove_object_identity`, `test_proved_transfer_requires_both_witness_halves`, `test_mutation_partial_width_lea_guard_is_discriminating` | The former `lea rdi,[rax+0x10]` positive expectation was **wrong**: an interior address is not the same object. Caller-side and graph proof guards now refuse unsupported claims; however PR #8 creates **no** `callee_identity_witness`, and FW 13.52 `_argument_carries` returned false at all 55 checked call sites. Full production caller-to-callee identity proof remains open |
| A1-07 | Graph is finding-centred, so a route through a function without a finding cannot exist | **PARTIAL (opt-in)** | `test_whole_program_mode_seeds_from_every_scanned_function`, `test_whole_program_without_a_scanned_list_is_truncated_not_silently_reduced`, `test_the_function_budget_is_published_when_it_bites`, `test_the_roots_a_budget_left_out_are_published`, `test_finding_centred_mode_is_still_the_default_and_says_so` | `build(whole_program=True)` / `cli semgraph --whole-program` seeds from `scanned_rvas`; on FW 13.52 measured under four controlled configurations (see `A1-07-CONTROLLED-COMPARISON.md`). **Not the default**, so the frozen S1.3 artefacts stay finding-centred |
| A1-08 | No independent blind test remains; evaluation gate not closed | **OPEN** | — (none possible in-repo) | `tools/discovery/seal.py` refuses reads of `data/corpus`, `data/blind`, `data/negative` through a CPython audit hook, and `blindrun.py` records whether the seal was active. That covers the **repository only**. Agent history, delegation logs, prompts, skills and summaries are outside it, and a held-back set built in a session that read the answer is contaminated regardless. Closing this needs the separate evaluator described in `P3-BLINDTEST-ARCHITECTURE.md`, not a code change here |
| A1-09 | Unlabelled functions treated as true negatives | **PARTIAL** | `test_the_committed_label_scope_says_unlabelled_is_unknown` | `tools/discovery/data/training/references.json` entry `fw1352-frozen-corpus` carries `label_scope: "corrected-functions-only"`, `unlabeled_functions: "unknown"` and the note "never a true negative"; the corpus validator refuses an unscoped negative claim, and the new test pins all three so the rule cannot be dropped in the next revision. Residual gap: whether the *underlying correction evidence* is complete is not something this repository can establish |
| A1-10 | `capstone` used but not declared as a runtime dependency | **FIXED** | `tests/test_freeze_drift.py::test_logged_hashes_match_reality`, `test_no_undocumented_drift` | `pyproject.toml:19` → `"capstone>=5,<6"` (pinned range, not an open floor); `FREEZE-DRIFT.md` carries the new hash, the reason and the offline path (`pip download capstone==5.0.7`) |
| A1-11 | Reader list comparison assumes ordering | **FIXED** | `tests/test_event_capture.py::test_single_socket_reader` | `readers = sorted(...)` before comparison; the test asserts the multi-reader case is what fails, single reader passes |

**Current totals (2026-11-06 audit): 7 FIXED, 3 PARTIAL (A1-06, A1-07, A1-09), 1 OPEN (A1-08).** A1-05 is counted under FIXED
for the defect, with its dead field tracked as an open item below.

## What each status rests on

The distinction that matters is between *removing the demonstrated counterexample* and
*meeting the recommendation*. A1-01 … A1-05, A1-10 and A1-11 are the first kind: the
auditor's script asserts a specific wrong output, and that assertion now fails to hold while
the correct output is pinned by a named test. A1-07 was closed the same way at first — the
demonstrated under-reporting is gone — but the recommendation was a different architecture,
so the stronger form was implemented as an opt-in mode and the finding stays `PARTIAL` until
that mode is the default or the frozen artefacts are regenerated in it.

A1-08 and A1-09 are not code defects that a patch closes. A1-08 asks for an evaluation gate
whose subject is *this project's own context*, so no line of code in the audited tree can
satisfy it; A1-09 asks for label completeness, which is an evidence question about the
corrections, not about the file that records the rule.

## The eleven suite failures, one by one

Originally the suite on this tree reported **11 failed / 1332 passed / 5 skipped / 3 xfailed**.
After provisioning the four missing environment prerequisites it reports **7 failed / 1364
passed / 4 skipped / 3 xfailed**, and the seven that remain have a single repository cause. All
eleven also failed on the untouched baseline `1328aa5`, which proves only that they were not
introduced by the A1 work — not that they are environmental. One by one:

### Four are missing environment prerequisites (A/B proven)

| test | exact failure | missing artefact |
| --- | --- | --- |
| `test_w13_release_window.py::test_the_transcribed_owner_records_are_accepted_and_pinned` | `AssertionError: both records must be transcribed` | `ps4rf-w13-c1/release-w13c1-read1.json`, `…/approval-w13c1-read1.json` |
| `…::test_a_wrong_compiled_index_in_the_release_is_refused` | `ValueError: W13_RELEASE_INVALID: [Errno 2] No such file or directory: …/release-w13c1-read1.json` (`tools/research/release.py:141`) | same release JSON |
| `…::test_a_release_bound_to_another_payload_is_refused` | same `ValueError`, same path | same release JSON |
| `test_w14_live_controller.py::test_the_live_run_sheet_passes_offline_against_the_same_daemon` | `AssertionError: the dev-host daemon is missing: …/ps4rf-w14/dev-host/ps4rfd_host` | that binary |

A/B, not assertion — re-verified here, not taken on report:

* With the artefacts absent: `test_w13_release_window.py` 3 failed, `test_w14_live_controller.py`
  1 failed.
* Copying the two trust objects from
  `/home/hermes/07-evidence/20261006T144834Z_ps4rf_p4w13c1-r3-offline-ready/trust-objects/` into
  `…/scratch/ps4rf-w13-c1/` (`a2b5d2a435e34c0289f239d1e733ea4049a09840816ee2afcb6db056e053596d`,
  `a788c81d0347923c209e93c353e79136a816fa0c54d5a675a6f85de6289b4f93`) turns
  `test_w13_release_window.py` green: **27 passed, 1 skipped**.
* `sh native/target/build_host.sh …/scratch/ps4rf-w14/dev-host` (gcc 14.2.0, the repo's own
  script) produces `ps4rfd_host` and `test_w14_live_controller.py` goes **2 passed**.
* Both artefacts are now provisioned in the scratch tree, so the suite's standing count is
  7 failures, not 11.

### Seven are a repository defect, not an environment issue

`tools/primitive_iface/schema.py` declares `session.status` with three result fields
(`session_state`, `mutating_allowed`, `held_resources`). `native/target/ps4rf_stub.c` emits
those three plus **twelve undeclared ones**:

```
boot_status, boot_detail, boot_sec, boot_usec,
window_kind, window_status, window_index, window_len,
window_cursor, window_count, window_hex, window_sha256
```

The controller validates against the frozen schema and refuses the frame —
`ARGUMENT_INVALID: session.status: unknown result field(s): …` — so `step:status` fails before
any boot logic runs. The six `test_boot_binding_live` end-to-end cases then die with
`TypeError: 'NoneType' object is not subscriptable` at `test_boot_binding_live.py:235/249/264/278/289`
(`boot_binding_event` is `None` because the event was never read), and
`test_target_build.py::test_offline_controller_agent_end_to_end` fails its `step:status` and
`offline end-to-end` checks. One cause, seven tests.

Both files are byte-identical to the baseline (`schema.py` `63961018…5c621`,
`ps4rf_stub.c` `90af200a…c1db7c`), so "same on the baseline" is a statement about history, not
about cause.

**And the repository understates it.** `docs/P4-W16-CCP-BINDING-MATCH.md:129-137` records this
as "pre-existing red… the schema does not know the four W15 fields" and states it was "not
caused by W16". Four is the W15-era part (`boot_*`); the other **eight are `window_*` fields
that belong to the W16 window surface**. The breach is pre-existing, but W16 widened it from
4 to 12 undeclared fields while the document claims W16 is uninvolved.

### What this means for the A1 verdict

The A1 work neither caused nor is blocked by these. But "11 environmental failures, zero
failures outside that set" was wrong twice: the set is not uniform, and the log line
`docs/P4-W16-CCP-BINDING-MATCH.md` relies on has drifted since it was written. Correcting the
schema is a wire-contract change (the catalogue records such changes as numbered revisions,
e.g. `W14 §15 … wire catalogue revision R4`), so it is a scoped decision for the owner, not
something to slip in under an audit disposition.

## Open items carried forward (not part of the 11, but not hidden)

1. **A1-05's dead field.** `stores` is repaired and pinned but consumed nowhere. Either a
   consumer arrives with a detector that needs it, or it is deleted at the next milestone.
2. **A1-09 is pinned but not proven.** The label rule now has a test; what remains open is
   whether the correction evidence behind `corrected-functions-only` is complete, which the
   repository cannot answer about itself.
3. **A1-07 default.** Whole-program mode is opt-in. Making it the default invalidates
   comparison with the frozen S1.3 artefacts and therefore needs its own measurement.
4. **~~Whole-program truncation is ordered by RVA~~ — fixed.** The budget dropped
   `sysent[693]` and `sysent[696]` because they sit at the top of the text section. Seeding is
   now prioritised (entry handlers → finding functions → rest) and the rebuilt graph drops no
   handler; `test_a_budget_that_bites_drops_the_least_relevant_roots` pins it.
5. **`session.status` schema drift (7 of the 11 suite failures)** — a wire-contract revision
   for the owner, see "The eleven suite failures, one by one".

## Reproducing this matrix

```
cd /home/hermes/work/ps4rf-a1
/home/hermes/.hermes/cache/scratch/ps4rf-venv2/bin/python -m pytest \
  tests/test_discovery_a1_regressions.py tests/test_discovery_a1_external_repro.py \
  tests/test_discovery_semgraph.py tests/test_discovery_handles.py \
  tests/test_discovery_corpus.py tests/test_freeze_drift.py tests/test_event_capture.py -v
```
82 passed, 0 failed at the time of writing. Full suite: 7 failed / 1364 passed / 4 skipped /
3 xfailed, the seven being the `session.status` schema drift described above. The negative control for the whole set is
`tests/test_discovery_a1_external_repro.py`, which runs the auditor's unmodified 85-line
script (SHA-256 `9abe5faad94e7c3773c502a0f328f758727e321acdc2bcab6f0835046b81e017`) in a
clean interpreter and fails as soon as one of its five proofs succeeds again.
