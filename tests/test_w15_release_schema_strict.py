#!/usr/bin/env python3
"""W15/D1 — the W13 research-read release is a fail-closed trust object: its schema is STRICT.

Owner rule D1: the release (schema ``ps4rf.w13.research-read-release.v1``) and its window
document may carry **only** the fields their declared schemas name (``additionalProperties =
false``). Any other field — an address-shaped name (``addr``, ``address``, ``va``, ``runtime_va``,
``kernel_va``, ``kernel_address``, ``ptr``, ``pointer``, ``rva``), an assurance-shaped name or an
unknown field — is refused by :func:`tools.research.release.release_problems` with the exact code
``W13_RELEASE_FORBIDDEN_FIELD``, before the approval binding is relied upon, before the provider
is entered and before any release consumption. The release itself must refuse the field; being
dropped later on the wire or in the target is not a refusal.

Proven here:
* a valid release passes with no problems and builds its window (control);
* a valid release plus one extra field is refused with exactly ``W13_RELEASE_FORBIDDEN_FIELD``
  and yields no window: ``addr``, ``runtime_va`` and an arbitrary unknown field at the release
  level; every address-shaped name (``rva`` included) and unknown fields at the window-document
  level; and address-shaped/unknown fields smuggled into the payload block;
* the forbidden-field refusal is emitted before — and independently of — the approval-binding
  checks of the same call;
* one refused case is driven through the REAL driver
  (``tools.hostctl.kreadlive.run_generic_read`` with its offline ``OfflineSession`` fixture) on a
  store whose *control* read really reads and really consumes: the refused case shows
  ``provider_entries == 0``, ``store.release_is_consumed(release_id) is False`` and no read-run
  record.

Kept honest:
* the top-level ``rva`` field of the release document stays **declared**: the accepted, pinned
  owner transcripts (``release-w13c1-read1.json``, ``release-w13c2-read1.json``) carry it and the
  green W13 suites require their acceptance. It is a pinned consistency *claim*, validated
  against the registry (a different value is ``W13_RELEASE_WINDOW_MISMATCH``). What is proven
  here is that ``rva`` — and every other address-shaped name — is refused wherever the declared
  schema does not name it, the window document included.
"""
from __future__ import annotations

import json
import pathlib
import re
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.hostctl import kreadlive as KL                                   # noqa: E402
from tools.hostctl import kreadstore as KS                                  # noqa: E402
from tools.hostctl import live_w15 as W15                                   # noqa: E402
from tools.profiles import regions as R                                     # noqa: E402
from tools.profiles.schema import canonical_profile_sha256                  # noqa: E402
from tools.research import classification as C                              # noqa: E402
from tools.research import release as REL                                   # noqa: E402

PROFILE = C.DEFAULT_PROFILE
PROFILE_SHA = canonical_profile_sha256(PROFILE)
REGION = 'amd_iommu'
BOOT = 'BOOT-w15-strict-schema'
VRUN = 'VRUN-w15-strict-schema'
EVIDENCE_SHA = 'e' * 64
PAYLOAD = {'bin_sha256': '99' * 32, 'elf_sha256': '2e' * 32,
           'build_manifest_sha256': '4d' * 32, 'build_id': '032ffa3eb281384edeffcbb11c84e242',
           'label': 'ps4rfd-live-w15'}
FORBIDDEN = REL.RELEASE_FORBIDDEN_FIELD
UNKNOWN_FIELD = 'note_extra'

#: ``rva`` is the one address-shaped name the release document declares (the pinned locator
#: claim); everywhere else — the window document included — the full address set is refused.
RELEASE_EXTRA_FIELDS = tuple(name for name in REL.ADDRESS_FIELDS if name != 'rva') + (UNKNOWN_FIELD,)
WINDOW_EXTRA_FIELDS = tuple(REL.ADDRESS_FIELDS) + (UNKNOWN_FIELD,)


def _token(problem: str, code: str) -> bool:
    """The exact refusal code as its own token (never a substring of a longer code)."""
    return re.search(rf'(?:^|[\s:]){re.escape(code)}(?::|$|\s)', str(problem)) is not None


@pytest.fixture()
def reference() -> dict:
    """The production trust objects (``live_w15.plan_fixtures``): a valid §70 approval + release."""
    return W15.plan_fixtures(profile=PROFILE, profile_sha256=PROFILE_SHA, boot_id=BOOT,
                             payload=PAYLOAD, evidence_sha256=EVIDENCE_SHA,
                             verification_run_id=VRUN, now='W15STRICT-REF')


def _problems(document: dict, reference: dict, *, boot_id: str = BOOT) -> list[str]:
    return REL.release_problems(document, profile=PROFILE, profile_sha256=PROFILE_SHA,
                                boot_id=boot_id, approval_sha256=reference['approval_sha256'])


def _codes(document: dict, reference: dict, *, boot_id: str = BOOT) -> list[str]:
    return [problem.split(':', 1)[0] for problem in _problems(document, reference, boot_id=boot_id)]


def _refused_with_forbidden(document: dict, reference: dict, *, boot_id: str = BOOT) -> dict:
    """The contract of every strict-schema refusal: exactly the code, and no window is built."""
    found = _problems(document, reference, boot_id=boot_id)
    assert found, 'the strict-schema refusal is missing'
    assert [problem.split(':', 1)[0] for problem in found] == [FORBIDDEN], found
    assert all(_token(problem, FORBIDDEN) for problem in found), found
    built = REL.released_window(document, profile=PROFILE, profile_sha256=PROFILE_SHA,
                                boot_id=boot_id, approval_sha256=reference['approval_sha256'])
    assert built['window'] is None
    assert built['refusals'] == [FORBIDDEN], built['refusals']
    return built


def _copy(document: dict) -> dict:
    return json.loads(json.dumps(document))


# ===============================================================================================
# 1. the control: the reference release passes the strict schema and builds its window
# ===============================================================================================
def test_the_valid_reference_release_passes_the_strict_schema(reference):
    release = reference['release']
    assert release['schema'] == REL.SCHEMA_RELEASE
    assert _problems(release, reference) == []
    built = REL.released_window(release, profile=PROFILE, profile_sha256=PROFILE_SHA,
                                boot_id=BOOT, approval_sha256=reference['approval_sha256'])
    assert built['problems'] == [] and built['window'] is not None
    assert built['window']['release_id'] == release['release_id']
    # the declared schema is the strict one, auditable in one place: additionalProperties = false
    # on both documents, and no address-shaped name is a window field.
    assert REL.RELEASE_SCHEMA['additionalProperties'] is False
    assert REL.RELEASE_SCHEMA['window']['additionalProperties'] is False
    assert set(REL.RELEASE_SCHEMA['properties']) == set(REL.RELEASE_FIELDS)
    assert set(REL.RELEASE_SCHEMA['window']['properties']) == set(REL.WINDOW_FIELDS)
    for name in REL.ADDRESS_FIELDS:
        assert name not in REL.WINDOW_FIELDS, name
    assert 'rva' in REL.RELEASE_FIELDS and 'rva' not in REL.WINDOW_FIELDS


# ===============================================================================================
# 2. the headline cases of the owner's list
# ===============================================================================================
def test_valid_plus_addr_is_refused_with_the_exact_code(reference):
    document = _copy(reference['release'])
    document['addr'] = '0xffff800000000000'
    _refused_with_forbidden(document, reference)


def test_valid_plus_runtime_va_is_refused(reference):
    document = _copy(reference['release'])
    document['runtime_va'] = '0xffffffff9a0c29e9'
    _refused_with_forbidden(document, reference)


def test_valid_plus_rva_inside_the_window_document_is_refused(reference):
    """``rva`` is declared *on the release document* (the pinned claim); the window document is
    no such position — there every address-shaped name, ``rva`` included, is refused."""
    document = _copy(reference['release'])
    assert 'rva' in document and 'rva' not in document['window']
    document['window']['rva'] = document['rva']
    _refused_with_forbidden(document, reference)


def test_valid_plus_an_arbitrary_unknown_field_is_refused(reference):
    document = _copy(reference['release'])
    document[UNKNOWN_FIELD] = 'anything'
    _refused_with_forbidden(document, reference)


def test_valid_plus_an_extra_field_in_a_window_document_is_refused(reference):
    document = _copy(reference['release'])
    document['window'][UNKNOWN_FIELD] = 'anything'
    _refused_with_forbidden(document, reference)


# ===============================================================================================
# 3. the full matrix: every name outside the declared schema, at both documents
# ===============================================================================================
@pytest.mark.parametrize('placement,field', [
    *(('release', field) for field in RELEASE_EXTRA_FIELDS),
    *(('window', field) for field in WINDOW_EXTRA_FIELDS),
    *(('payload', field) for field in ('addr', 'runtime_va', UNKNOWN_FIELD)),
])
def test_every_field_the_schema_does_not_declare_is_refused(reference, placement, field):
    document = _copy(reference['release'])
    if placement == 'release':
        document[field] = '0xffff800000000000'
    elif placement == 'window':
        document['window'][field] = '0xffff800000000000'
    else:
        document['payload'][field] = '0xffff800000000000'
    _refused_with_forbidden(document, reference)


# ===============================================================================================
# 4. the declared rva claim: validated against the registry, refused everywhere else
# ===============================================================================================
def test_the_declared_rva_claim_is_still_validated_against_the_registry(reference):
    release = reference['release']
    region_rva = R.regions()[REGION].rva
    assert region_rva is not None
    assert release['rva'] == hex(region_rva)                # the pinned fact, present and passing
    wrong = _copy(release)
    wrong['rva'] = '0x1000'
    codes = _codes(wrong, reference)
    assert codes == [REL.RELEASE_WINDOW_MISMATCH], codes
    built = REL.released_window(wrong, profile=PROFILE, profile_sha256=PROFILE_SHA,
                                boot_id=BOOT, approval_sha256=reference['approval_sha256'])
    assert built['window'] is None


# ===============================================================================================
# 5. the refusal precedes the approval binding (release_problems -> reject vor Approval)
# ===============================================================================================
def test_the_forbidden_field_refusal_precedes_the_approval_binding(reference):
    document = _copy(reference['release'])
    document.pop('approval_sha256')
    document['addr'] = '0xffff800000000000'
    codes = _codes(document, reference)
    assert codes == [FORBIDDEN, REL.RELEASE_APPROVAL_BINDING_MISSING], codes
    # and a release with a valid approval is still refused for the forbidden field alone
    tainted = _copy(reference['release'])
    tainted['addr'] = '0xffff800000000000'
    assert _codes(tainted, reference) == [FORBIDDEN]


# ===============================================================================================
# 6. driven through the REAL driver: entry 0, nothing consumed, nothing persisted
# ===============================================================================================
def test_a_refused_release_never_enters_the_provider_and_is_never_consumed(tmp_path):
    """The refusal keeps the provider entry at zero and the release unconsumed — proven on the
    real driver, not only on the pure function.

    The store really reads and really consumes in the *control* (entry 1, one-shot marker
    written); the refused release is then refused by the release itself, and the driver — handed
    exactly what the production session driver hands it for a missing window
    (``window_block.get('window') or {}``) and, in defence in depth, the bare region window —
    refuses before any provider entry and writes nothing.
    """
    binding = KL.synthetic_boot_binding(PROFILE)
    store = KS.VerificationEvidenceStore(tmp_path / 'store')
    verification = KL.run_verification(
        KL.OfflineSession(session_id=KL.SIM_SESSION_A,
                          event=KL.synthetic_bounded_event(runtime_kbase=KL.SIM_KBASE)),
        profile=PROFILE, boot_binding=binding, store=store,
        provider=KL.sim_provider(live_approved=False))
    assert verification['outcome'] == KL.OUTCOME_VERIFIED, verification.get('problems')
    evidence = verification['evidence']
    control = W15.plan_fixtures(profile=PROFILE, profile_sha256=PROFILE_SHA,
                                boot_id=binding.boot_id, payload=PAYLOAD,
                                evidence_sha256=evidence['evidence_sha256'],
                                verification_run_id=verification['verification_run_id'],
                                now='W15STRICT-control')
    fixtures = W15.plan_fixtures(profile=PROFILE, profile_sha256=PROFILE_SHA,
                                 boot_id=binding.boot_id, payload=PAYLOAD,
                                 evidence_sha256=evidence['evidence_sha256'],
                                 verification_run_id=verification['verification_run_id'],
                                 now='W15STRICT-tainted')
    control_id = control['release']['release_id']
    tainted_id = fixtures['release']['release_id']
    assert control_id != tainted_id
    for release_id in (control_id, tainted_id):
        KL._CONSUMED_RELEASES.pop(release_id, None)

    # --- control: a clean release really reads (entry 1) and really consumes its one-shot marker
    built = REL.released_window(control['release'], profile=PROFILE, profile_sha256=PROFILE_SHA,
                                boot_id=binding.boot_id,
                                approval_sha256=control['approval_sha256'])
    assert built['problems'] == [], built['problems']
    control_read = KL.run_generic_read(
        KL.OfflineSession(session_id=KL.SIM_SESSION_B,
                          event=KL.synthetic_bounded_event(
                              region=REGION, bytes_hex=control['expected_bytes'],
                              runtime_kbase=KL.SIM_KBASE,
                              region_index_override=control['region_index'])),
        profile=PROFILE, boot_binding=binding, store=store,
        verification_run_id=verification['verification_run_id'],
        evidence_sha256=evidence['evidence_sha256'],
        approval=control['approval'], provider=KL.sim_provider(live_approved=True),
        expected=built['window'], generic_read_run_id='RUN-w15-strict-control')
    assert control_read['outcome'] == KL.OUTCOME_READ and control_read['ok'] is True, \
        control_read['problems']
    assert control_read['provider_entries'] == 1 == control_read['generic_provider_entries']
    assert store.release_is_consumed(control_id) is True

    # --- the case: a valid release carrying an `addr` field is refused by the release itself
    document = _copy(fixtures['release'])
    document['addr'] = '0xffff800000000000'
    refused = _refused_with_forbidden(document, fixtures, boot_id=binding.boot_id)
    assert store.release_is_consumed(tainted_id) is False

    # --- driven through the REAL driver: there is no window to hand it; the driver refuses
    #     before any provider entry and writes nothing.
    fallback = refused.get('window') or {}
    result = KL.run_generic_read(
        KL.OfflineSession(session_id='SES-00000000000000000000000000000f1'),
        profile=PROFILE, boot_binding=binding, store=store,
        verification_run_id=verification['verification_run_id'],
        evidence_sha256=evidence['evidence_sha256'],
        approval=fixtures['approval'], provider=KL.sim_provider(live_approved=True),
        expected=fallback, generic_read_run_id='RUN-w15-strict-refused')
    assert result['outcome'] == KL.OUTCOME_REFUSED and result['ok'] is False
    assert result['provider_entries'] == 0 == result['generic_provider_entries']
    assert result['event'] is None and result['capability'] is None and result['decision'] is None
    assert any(_token(problem, KL.KREADLIVE_WINDOW_NOT_RELEASED)
               for problem in result['problems']), result['problems']
    assert store.release_is_consumed(tainted_id) is False

    # --- defence in depth: the driver's own release guard refuses the bare region window too
    unbound = KL.window_for(REGION, bytes_hex=fixtures['expected_bytes'], profile=PROFILE)
    assert unbound.get('problems') == [], unbound.get('problems')
    result = KL.run_generic_read(
        KL.OfflineSession(session_id='SES-00000000000000000000000000000f2'),
        profile=PROFILE, boot_binding=binding, store=store,
        verification_run_id=verification['verification_run_id'],
        evidence_sha256=evidence['evidence_sha256'],
        approval=fixtures['approval'], provider=KL.sim_provider(live_approved=True),
        expected=unbound, generic_read_run_id='RUN-w15-strict-unbound')
    assert result['outcome'] == KL.OUTCOME_REFUSED and result['ok'] is False
    assert result['provider_entries'] == 0 == result['generic_provider_entries']
    assert any(_token(problem, KL.KREADLIVE_WINDOW_NOT_RELEASED)
               for problem in result['problems']), result['problems']
    assert store.release_is_consumed(tainted_id) is False
    # nothing but the control read was ever persisted, and nothing consumed but the control
    assert store.read_run_ids() == ['RUN-w15-strict-control']
