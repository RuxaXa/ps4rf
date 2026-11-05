#!/usr/bin/env python3
"""W15 §5/§6 -- unit-level proofs for the dataset snapshot and the W6 observation contract.

The resident rehearsal (`tests/test_w15_resident_research.py`) exercises the same pipeline end
to end against the real daemon; this module pins the invariants that must hold on their own:

* one read ingested twice yields exactly one blob and one snapshot row -- dedup is semantic
  (the snapshot id ignores the arrival timestamp), the snapshot binds the mandated fields and
  the blob is content-addressed,
* the W6 artifact builder emits relative locators only, and the differential refuses an
  artifact that carries a runtime-address field (fail closed),
* candidates can never leave `OBSERVATION` and can never claim a W4 impact, and the vocabulary
  refuses verdict-like status words -- ``W6 is analysis, not authorization``,
* a differential replay over the same inputs yields the same result hash, and the run moves
  neither the profile, nor the approval/release documents, nor the classification matrix nor
  the read plan.

No live step: every case runs offline on a temporary dataset and temporary artifacts.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.differential import schema as SC                                    # noqa: E402
from tools.hostctl import live_w15 as W15                                       # noqa: E402
from tools.profiles import regions as R                                         # noqa: E402
from tools.research import classification as C                                  # noqa: E402
from tools.research import dataset as D                                         # noqa: E402
from tools.research import read_plan as RP                                      # noqa: E402
from tools.research import w6_contract as W6                                    # noqa: E402

REGION = 'amd_iommu'
KBASE = 0xFFFFFFFF998F4000
MANDATED_SNAPSHOT_FIELDS = ('profile_sha256', 'boot_id', 'kbase', 'read_run_id', 'region',
                            'offset', 'length', 'sha256', 'timestamp')


def pinned_bytes() -> bytes:
    """The profile's pinned window bytes for the region (the normative source, no invention)."""
    locator = C.profile_locator(C.DEFAULT_PROFILE, f'kernel.attest.{REGION}')
    return bytes.fromhex(locator['expected_bytes']['hex'])


def read_run_record(*, read_run_id: str = 'RUN-w15-unit', raw: bytes | None = None,
                    outcome: str = 'READ') -> dict:
    """A read-run record with the W15 shape (the dataset's own input contract)."""
    raw = pinned_bytes() if raw is None else raw
    return {
        'schema': 'ps4rf.kread.read-run.v1',
        'read_run_id': read_run_id,
        'outcome': outcome,
        'provider_entries': 1,
        'run_separation': {'separated': True, 'run_ids_distinct': True,
                           'session_ids_distinct': True},
        'read_evidence': {
            'schema': 'ps4rf.kread.read-evidence.v1',
            'requested_region': REGION,
            'requested_offset': 0,
            'requested_length': len(raw),
            'observed_length': len(raw),
            'bytes_hex': raw.hex(),
            'output_sha256': hashlib.sha256(raw).hexdigest(),
            'resolved_rva': '0x7ce9e9',
        },
    }


def write_artifacts(tmp_path: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path, dict, dict]:
    """One differential input pair built the way §6 builds them (baseline + snapshot read)."""
    after = W6.read_inventory(read_run_record=read_run_record(), region_name=REGION)
    before = W15.pre_read_baseline(snapshot={'length': len(pinned_bytes())})
    before_path = tmp_path / f'before-{REGION}.json'
    after_path = tmp_path / f'after-{REGION}.json'
    W6.write_inventory(before_path, before)
    W6.write_inventory(after_path, after)
    return before_path, after_path, before, after


# ===============================================================================================
# §5 -- one read in, one blob + one snapshot row, deduplicated
# ===============================================================================================
def test_duplicate_ingest_yields_one_blob_and_one_snapshot_row(tmp_path):
    dataset = D.ResearchDataset(tmp_path / 'dataset')
    record = read_run_record()
    first = dataset.add_read(read_run_record=record, region_name=REGION, kbase=KBASE,
                             profile_sha256='a' * 64, boot_id='BOOT-w15-unit',
                             timestamp='2026-10-06T00:00:00Z')
    second = dataset.add_read(read_run_record=record, region_name=REGION, kbase=KBASE,
                              profile_sha256='a' * 64, boot_id='BOOT-w15-unit',
                              timestamp='2026-10-06T00:00:09Z')     # a different arrival time
    assert first['added'] is True and first['deduplicated'] is False
    assert second['added'] is False and second['deduplicated'] is True
    assert second['snapshot']['snapshot_id'] == first['snapshot']['snapshot_id']

    snapshots = dataset.index()['snapshots']
    assert len(snapshots) == 1, 'the duplicate must not add a second semantic snapshot row'
    blobs = sorted(path.name for path in dataset.blob_root.iterdir())
    assert len(blobs) == 1, 'the duplicate must not add a second blob'
    snapshot = snapshots[0]
    for field in MANDATED_SNAPSHOT_FIELDS:
        assert snapshot.get(field) not in (None, ''), f'the snapshot carries no {field}'
    digest = hashlib.sha256(pinned_bytes()).hexdigest()
    assert snapshot['sha256'] == digest == blobs[0]
    assert snapshot['read_run_id'] == 'RUN-w15-unit'
    assert (snapshot['region'], snapshot['offset'], snapshot['length']) == (REGION, 0, 16)
    assert dataset.get_bytes(digest) == pinned_bytes()
    assert dataset.problems() == []
    assert dataset.index_sha256() == dataset.index()['index_sha256']


# ===============================================================================================
# §6 -- the artifact stays relative, the differential refuses an address field
# ===============================================================================================
def test_the_artifact_stays_relative_and_an_address_field_is_refused(tmp_path):
    record = read_run_record()
    document = W6.read_inventory(read_run_record=record, region_name=REGION)
    blob = json.dumps(document)
    for forbidden in W6.FORBIDDEN_IN_ARTIFACT:
        assert f'"{forbidden}"' not in blob, forbidden
    assert not (SC.string_tokens(document) & set(SC.FORBIDDEN_STATUS_WORDS))
    assert document['entries'][0]['locator'] == {'kind': 'rva',
                                                 'value': R.regions()[REGION].rva}

    # the same document with one runtime-address field is refused before any comparison
    doctored = json.loads(blob)
    doctored['entries'][0]['runtime_address'] = KBASE + 0x7CE9E9
    doctored_path = tmp_path / 'doctored.json'
    doctored_path.write_text(json.dumps(doctored, indent=1, sort_keys=True) + '\n')
    _, after_path, _, _ = write_artifacts(tmp_path)
    with pytest.raises(W6.ContractError):
        W6.run_differential(after_path, doctored_path)


# ===============================================================================================
# §6 -- OBSERVATION only, W4 impact NONE, replay-stable
# ===============================================================================================
def test_the_differential_result_is_observation_only_and_replay_stable(tmp_path):
    before_path, after_path, before, after = write_artifacts(tmp_path)
    assert before['entries'] == []                     # the baseline states an absence
    report = W6.run_differential(before_path, after_path)
    assert SC.validate_report(report) == []
    candidates = W6.candidates_of(report)              # refuses a non-OBSERVATION candidate
    assert candidates, 'the arrival of a new observation must produce a candidate'
    for candidate in candidates:
        assert candidate['status'] == 'OBSERVATION'
        assert candidate['impact']['w4'] == 'NONE'
        assert candidate['not_a_fact'] is True
        assert candidate['requires']
    assert W6.artifact_differences(before, after)
    replay = W6.run_differential(before_path, after_path)
    assert replay['output_sha256'] == report['output_sha256']


def test_a_candidate_cannot_claim_w4_impact_or_a_verdict_status(tmp_path):
    before_path, after_path, _, _ = write_artifacts(tmp_path)
    candidate = W6.candidates_of(W6.run_differential(before_path, after_path))[0]

    impact_errors = SC.validate_candidate(dict(candidate, impact={'w4': 'REMOVES_HARDENING'}))
    assert any('W6 is analysis, not authorization' in error for error in impact_errors), \
        impact_errors
    for status in ('PROVEN', 'CONFIRMED', 'FIXED', 'EXPLOITABLE'):
        assert SC.validate_candidate(dict(candidate, status=status)), status
    for word in ('VERIFIED', 'VULNERABILITY', 'PRIMITIVE'):
        assert word in SC.FORBIDDEN_STATUS_WORDS
        assert SC.validate_candidate(dict(candidate, subject=word)), word
    # ... and the integration contract refuses a report that carries one anyway
    with pytest.raises(W6.ContractError):
        W6.candidates_of({'candidates': [dict(candidate, status='PROVEN')]})
    with pytest.raises(W6.ContractError):
        W6.candidates_of({'candidates': [dict(candidate, impact={'w4': 'CHANGED'})]})


# ===============================================================================================
# §6 -- analysis, not authorization: nothing moves
# ===============================================================================================
def test_the_observation_moves_no_profile_approval_release_or_plan(tmp_path):
    fixtures = tmp_path / 'fixtures'
    fixtures.mkdir()
    approval = {'id': 'approval-unit-test'}
    release = {'release_id': 'release-unit-test'}
    (fixtures / 'approval-w15-read1.json').write_text(
        json.dumps(approval, indent=1, sort_keys=True) + '\n')
    (fixtures / 'release-w15-read1.json').write_text(
        json.dumps(release, indent=1, sort_keys=True) + '\n')
    plan = {'out_dir': tmp_path, 'profile': C.DEFAULT_PROFILE, 'approval': approval,
            'release': release}

    plan_before = RP.read_plan()
    matrix_before = C.classification_matrix()
    guards_before = W15.guarded_documents(plan)
    before_path, after_path, _, _ = write_artifacts(tmp_path)
    W6.run_differential(before_path, after_path)
    guards = W15.unchanged_guards(guards_before, W15.guarded_documents(plan))
    assert guards['all_unchanged'] is True and guards['changed'] == []
    for name, entry in guards['entries'].items():
        assert entry['unchanged'] is True and entry['sha256_before'] == entry['sha256_after'], name
    assert guards['entries']['profile_file']['sha256_before'] == \
        hashlib.sha256(C.PROFILE_PATH.read_bytes()).hexdigest()
    assert RP.read_plan() == plan_before
    assert C.classification_matrix() == matrix_before

    # the guard is load bearing: a moved release fixture must be caught, never tolerated
    (fixtures / 'release-w15-read1.json').write_text(
        json.dumps(dict(release, moved=True), indent=1, sort_keys=True) + '\n')
    moved = W15.unchanged_guards(guards_before, W15.guarded_documents(plan))
    assert moved['all_unchanged'] is False
    assert 'release_fixture' in moved['changed']
