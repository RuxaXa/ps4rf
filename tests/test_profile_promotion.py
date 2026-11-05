"""W10 regressions: profile promotion, promotion validator and the untouched fixture.

The tests are deterministic and offline. Image-dependent tests skip when the pinned FW13.52
kernel image is not present on this machine (it lives outside the repository on purpose).
"""

from __future__ import annotations

import json
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.profiles import bootid, promotion, promotion_validator        # noqa: E402
from tools.profiles.schema import (                                     # noqa: E402
    STRICT_POLICY, STRUCTURAL_POLICY, canonical_profile_sha256, validate_profile,
)

FIXTURE = REPO_ROOT / 'tests/fixtures/profiles/fw1352-fixture.json'
#: the fixture as it was before W10: it must stay byte-identical through the promotion
FIXTURE_CANONICAL_SHA256 = \
    '47c0cbe92fc3cf2dd676883a68f1d6fe6aae9811479836a8ec791d250fe0e945'
PROMOTED = REPO_ROOT / 'profiles/fw1352/profile-13.52.json'
PROMOTED_SHA256 = '51b59db31ee47a9e2c5450ddfad002a80a407bf727f9ac5ae19558b82c3a4819'

needs_kernel = pytest.mark.skipif(not promotion.PINNED_KERNEL.exists(),
                                  reason='pinned FW13.52 kernel image not available')
needs_promoted = pytest.mark.skipif(not PROMOTED.exists(),
                                    reason='promoted profile not built in this workspace')


def test_fixture_is_untouched():
    fixture = json.loads(FIXTURE.read_text())
    assert canonical_profile_sha256(fixture) == FIXTURE_CANONICAL_SHA256
    assert fixture['fixture'] is True, 'the W5 fixture must stay a fixture'


def test_promotion_self_test():
    assert promotion.self_test() == []


def test_validator_self_test():
    assert promotion_validator.self_test() == []


@needs_kernel
def test_window_policy_matrix_is_seven_plus_one():
    rows = promotion.parse_w9_table()
    assert len(rows) == 8
    strict = [row for row in rows if row['policy'] == STRICT_POLICY]
    structural = [row for row in rows if row['policy'] == STRUCTURAL_POLICY]
    assert len(strict) == 7 and len(structural) == 1
    assert structural[0]['id'] == 'aperture_global'


@needs_kernel
def test_window_classification_from_pinned_segments():
    segments = promotion.program_segments(promotion.read_pinned_kernel())
    assert promotion.classify_window(0x7CE9E9, 16, segments) == ('text', 'r-x')
    assert promotion.classify_window(0x111FA18, 8, segments) == ('data', 'rw-')
    # the aperture window lies outside every PT_LOAD: the capture holds dump-area bytes there,
    # which is exactly why it can never be a firmware fingerprint
    assert promotion.classify_window(0x23D3DF8, 8, segments)[0] == 'outside-loaded-image'


@needs_kernel
def test_candidate_is_evidence_backed_and_policy_correct():
    evidence = promotion_validator._self_test_evidence()
    doc = promotion.build_candidate(w9_evidence_path=evidence)
    assert validate_profile(doc) == []
    assert doc['fixture'] is False
    locators = doc['locators']
    strict = {name: loc for name, loc in locators.items() if loc['policy'] == STRICT_POLICY}
    structural = {name: loc for name, loc in locators.items()
                  if loc['policy'] == STRUCTURAL_POLICY}
    assert len(strict) == 7 and len(structural) == 1
    assert set(structural) == {'kernel.attest.aperture_global'}
    for loc in locators.values():
        assert loc['locator']['kind'] == 'rva'
        assert isinstance(loc['locator']['value'], int)
        assert loc['provenance']['kind'] == 'evidence'
        assert loc['provenance']['sha256'] == promotion.PINNED_KERNEL_SHA256
        assert loc['confidence'] == 'OBSERVED'


@needs_kernel
def test_validator_passes_and_excludes_the_structural_window():
    evidence = promotion_validator._self_test_evidence()
    doc = promotion.build_candidate(w9_evidence_path=evidence)
    report = promotion_validator.validate(doc, w9_evidence_path=evidence)
    assert report['ok'] is True, [c for c in report['checks'] if not c['ok']]
    basis = report['identity_basis']
    assert basis['structural_windows_excluded'] == ['kernel.attest.aperture_global']
    assert len(basis['strict_windows']) == 7
    assert basis['measured_strict_mismatches'] == 0


@needs_kernel
def test_validator_rejects_mutations():
    evidence = promotion_validator._self_test_evidence()
    doc = promotion.build_candidate(w9_evidence_path=evidence)

    def mutated(mutator):
        clone = json.loads(json.dumps(doc))
        mutator(clone)
        clone['canonical_sha256'] = canonical_profile_sha256(clone)
        return clone

    def fails(clone, check):
        report = promotion_validator.validate(clone, w9_evidence_path=evidence)
        hit = [c for c in report['checks'] if c['check'] == check]
        assert hit and hit[0]['ok'] is False, f'{check} did not catch the mutation'

    def strict_bytes(clone):
        clone['locators']['kernel.attest.image_elf']['expected_bytes']['hex'] = '00' * 16

    def structural_as_strict(clone):
        clone['locators']['kernel.attest.aperture_global']['policy'] = STRICT_POLICY

    def absolute_locator(clone):
        clone['locators']['kernel.attest.code_anchor']['locator']['kind'] = 'absolute'

    def runtime_value(clone):
        clone['notes'] = clone['notes'] + ' lstar=0xffffffff998f41c0'

    def broken_provenance(clone):
        clone['locators']['kernel.attest.gbase_vtophys']['provenance']['sha256'] = '00' * 32

    def unbacked_claim(clone):
        clone['operation_policy']['kernel.read'].update(
            {'profile_required': True, 'locator_ref': 'kernel.read'})

    fails(mutated(strict_bytes), 'strict_fingerprints_match')
    fails(mutated(structural_as_strict), 'policy_matrix_present')
    fails(mutated(absolute_locator), 'relative_locators_resolve')
    fails(mutated(runtime_value), 'no_runtime_address_persisted')
    fails(mutated(broken_provenance), 'provenance_complete')
    fails(mutated(unbacked_claim), 'gated_ops_explicit_and_fail_closed')


@needs_promoted
def test_promoted_profile_hash_is_pinned():
    doc = json.loads(PROMOTED.read_text())
    assert canonical_profile_sha256(doc) == PROMOTED_SHA256
    assert doc['fixture'] is False
    assert doc['target']['firmware_version'] == '13.52'
    assert doc['target']['firmware_build_id'] == f'kernel-sha256:{promotion.PINNED_KERNEL_SHA256}'
    # no runtime address, no unresolved value, no fixture provenance anywhere
    text = json.dumps(doc, sort_keys=True)
    for needle in ('0xffffffff998f4000',            # kbase of the W9 run
                   '0xffffffff998f41c0',            # LSTAR of the W9 run
                   '0xffffffffc9824000',            # KASLR slide of the W9 run
                   '0xffffe7b0e4800000'):           # aperture value observed live
        assert needle not in text
    assert 'UNRESOLVED' not in text
    assert all(loc['provenance']['kind'] == 'evidence' for loc in doc['locators'].values()), \
        'no locator may carry fixture provenance'


@needs_promoted
@needs_kernel
def test_gated_operations_stay_explicit_and_fail_closed():
    doc = json.loads(PROMOTED.read_text())
    from tools.primitive_iface.gate import REQ_BY_OP, privilege_gated_ops
    policy = doc['operation_policy']
    assert set(policy) == set(privilege_gated_ops())
    for op, entry in policy.items():
        assert entry['reason'], f'{op} has no explicit reason'
        assert bool(entry['profile_required']) == bool(REQ_BY_OP[op].profile_required)
        if entry['locator_ref'] is not None:
            assert entry['locator_ref'] in doc['locators']
    assert policy['kernel.read']['profile_required'] is True
    assert policy['kernel.read']['locator_ref'] is None, 'kernel.read must not claim a locator'
