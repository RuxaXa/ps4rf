# Patch 01 — independent countercheck

Baseline: `93cc14854e985cf22152c3e560be10cd91e8a201` (`s19-partial-baseline`).
External patch SHA-256:
`170c9de24e0d7351d21eb65a66725c8a456cb55a2df56901f4ebe190e8631914`.
Developer handoff SHA-256:
`df43a5c6da5293eba8a8c3da0da55953312bf4e5ced52f9000c7c696370f747f`.

Verdict: **PASS / MERGE-READY.** No blocking logic or security issue was found. The
review was performed in a detached worktree; the external reviewer did not modify files.

## Verification

```
git apply --check PS4RF_93cc148_D3_Instruction_Order.patch   PASS
python3 tests/fixtures/discovery/gen_lock_coverage.py --check PASS
pytest tests/test_discovery_lock_coverage.py \
       tests/test_discovery_lock_paths_unit.py \
       tests/test_discovery_cfg.py \
       tests/test_discovery_double_release.py -q             48 passed
pytest tests/ -q -k discovery                                311 passed, 1187 deselected
```

Positive control: the patched tests were run with `patterns.py` restored from `93cc148`.
Exactly the two intended tests failed:

* `test_each_shape_is_decided_as_the_fixture_data_says[fixture_d3_store_before_lock_same_block]`
* `test_pre_lock_store_same_block_is_a_regression_for_block_granularity`

This proves that the new integration tests discriminate the old block-level implementation.

## Firmware differential

The image set was unchanged: FW 13.52 image SHA-256
`cf157ffdbae872a20bbb9a46c8518b53d96c1ed75d4e73878466a295d92eca35`
(`NOT_PRISTINE`) and FW 9.00 SHA-256
`ffe0ec65ec0ffaadf9e18675121e7df80bdddbb83a8824b3414e4cc53cbd69f8`.

FW 13.52, identical 2 053 functions:

* D3 findings: 376 → 442, all new findings rank 2.
* 66 finding identities added; 0 removed; 0 rank changes.
* 142 new uncovered-store witnesses. Independent re-decode confirmed **142/142** lie
  before the first observed lock call in the same basic block; 0 missing witnesses.
* D1 observations, D2, D5, D6 and D8 are unchanged.
* Actionable labelled-pair gate remains `tp=1, tn=1, fp=0, fn=0`.

FW 9.00, identical 1 091 functions: 0 finding arrivals/disappearances/rank changes and
unchanged observations.

Runtime: FW 13.52 scan 104.8 s / 176.9 MB peak RSS; FW 9.00 scan 42.4 s / 150.0 MB.

## Evidence boundary

The helper proves only that some intraprocedural CFG path reaches the store before any
*observed* acquisition call. It does not bind a lock identity, model unlock, prove sharing,
model caller-held locks or repair a missing CFG edge. D3 therefore remains rank 2; this
countercheck does not close A1-08/A1-09 or the blocked blind benchmark.
