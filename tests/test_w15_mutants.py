"""W15 -- the mutants: every mechanism this flow leans on is removed once and the removal has to
be caught, with the *expected* refusal instead of any failure.

A rehearsal that only passes proves less than one whose mechanisms are shown to be load-bearing.
Each test here removes or breaks exactly one mechanism and demands the failure -- being the
expected one, named by its exact refusal code (a refusal for an unrelated reason is a failure of
this suite, not a proof).

Host side (the release, the request mapping, the capability scope, the store, the boot binding,
the recovery flag) the mutants run through the production driver
:func:`tools.hostctl.kreadlive.run_generic_read` with its offline session fixtures: the phase-A
``VerificationEvidence`` of the pinned bootstrap window is real (persisted through the store and
rehashed on load), and the read window is a real W13 release for ``amd_iommu`` (index 1), built
by :func:`tools.hostctl.live_w15.plan_fixtures` / :func:`tools.research.release.released_window`.

====================  ========================================================  =================
mutant                mechanism removed / broken                              caught by
====================  ========================================================  =================
raw address field     an address field added to the request model and to      ``KREAD_SCHEMA_RAW_ADDRESS``;
                      the payload block (target side)                         target: build refusal
region_index bounds   the compiled-row part of the request mapping            ``KREADLIVE_REGION_NOT_COMPILED``;
                                                                              release: ``W13_RELEASE_INDEX_MISMATCH``
target index 0        the request's index decides which row is served         case ``O`` stops matching
containment removed   the two containment refusals (callback + run section)   cases ``E/E2/E3/L/P/Q``
consumed release      the one-shot release marker                              ``W13_RELEASE_ALREADY_CONSUMED``
carried capability    the derivation receipt's session binding                ``KREADLIVE_CAPABILITY_NOT_DERIVED``
evidence tampered     the store's rehash on load                              ``KREADLIVE_EVIDENCE_REHASH_MISMATCH``
                                                                              (store reason ``STORE_REHASH_MISMATCH``)
stale boot            the boot binding of the stored evidence                 ``KREAD_STALE_BOOT_ID``
wrong profile         the profile binding of the stored evidence             ``KREAD_WRONG_PROFILE``
old session reused    the session-scope of the capability derivation         ``KREADLIVE_SESSION_REUSED``
recovery required     the recovery gate before the provider router           ``KREAD_RECOVERY_REQUIRED``,
                                                                              zero provider entries
====================  ========================================================  =================

Known limits, kept honest (not silently smoothed over):
* the raw-address refusal now begins at the trust object itself: ``release_problems`` emits
  ``W13_RELEASE_FORBIDDEN_FIELD`` for any field the release/window schema does not declare
  (address-shaped or arbitrary), so the W15-D1 gap is closed -- proven in
  ``tests/test_w15_release_schema_strict.py``. What remains true here is narrower: a window dict
  handed straight to the driver is not re-schemed by the driver (the release is validated first,
  and a release that carries such a field never yields a window), and the request model refuses an
  address with ``KREAD_SCHEMA_RAW_ADDRESS``.
* an integer ``region_index`` outside the compiled table (999, -1, ``len(compiled_regions())``,
  the registry total) is refused **before** the provider entry with
  ``KREAD_REGION_INDEX_INVALID`` and ``provider_entries`` 0, with the release left unconsumed --
  the W15-D2 blocker. The old post-entry shape (``KREADLIVE_TABLE_MISMATCH`` with one entry) is the
  mutant's *failure* mode now, asserted as such below.
* :func:`run_generic_read` cannot accept a capability record from a caller (no such parameter):
  a carried record is proven impossible to submit to the driver, and it is refused by
  :func:`revalidate_derivation` -- the check the driver itself applies immediately before the
  provider entry.
"""
from __future__ import annotations

import json
import pathlib
import re
import shutil
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from tools.hostctl import kreadlive as KL                                       # noqa: E402
from tools.hostctl import kreadstore as KS                                      # noqa: E402
from tools.hostctl import live_w15 as W15                                       # noqa: E402
from tools.profiles import kread as KREAD                                       # noqa: E402
from tools.profiles import kread_capability as KC                               # noqa: E402
from tools.profiles.schema import canonical_profile_sha256                      # noqa: E402
from tools.research import classification as C                                  # noqa: E402
from tools.research import release as REL                                       # noqa: E402

PROFILE = C.DEFAULT_PROFILE
PROFILE_SHA = canonical_profile_sha256(PROFILE)
REGION = 'amd_iommu'
SESSION_C = 'SES-00000000000000000000000000000c3d'
PAYLOAD = {'bin_sha256': '99' * 32, 'elf_sha256': '2e' * 32, 'build_manifest_sha256': '4d' * 32,
           'build_id': '032ffa3eb281384edeffcbb11c84e242', 'label': 'ps4rfd-live-w15'}


# =============================================================================================
# the offline fixture: a real phase-A verification, a real §70 approval and a real W13 release
# =============================================================================================
def _fixture(tmp_path: pathlib.Path, *, label: str) -> dict:
    """One phase-A record in the store plus a fresh release for the amd_iommu window.

    The release id is unique per test (``label``), because a consumed release is spent for the
    whole process on purpose (``_CONSUMED_RELEASES``): sharing an id between tests would make
    one test's refusal another test's noise.
    """
    binding = KL.synthetic_boot_binding(PROFILE)
    store = KS.VerificationEvidenceStore(tmp_path / label / 'store')
    verification = KL.run_verification(
        KL.OfflineSession(session_id=KL.SIM_SESSION_A,
                          event=KL.synthetic_bounded_event(runtime_kbase=KL.SIM_KBASE)),
        profile=PROFILE, boot_binding=binding, store=store,
        provider=KL.sim_provider(live_approved=False))
    assert verification['outcome'] == KL.OUTCOME_VERIFIED, verification.get('problems')
    evidence = verification['evidence']
    fixtures = W15.plan_fixtures(profile=PROFILE, profile_sha256=PROFILE_SHA,
                                 boot_id=binding.boot_id, payload=PAYLOAD,
                                 evidence_sha256=evidence['evidence_sha256'],
                                 verification_run_id=verification['verification_run_id'],
                                 now=f'W15MUT-{label}')
    built = REL.released_window(fixtures['release'], profile=PROFILE, profile_sha256=PROFILE_SHA,
                                boot_id=binding.boot_id,
                                approval_sha256=fixtures['approval_sha256'])
    assert built['problems'] == [], built['problems']
    window = built['window']
    assert window['region'] == REGION and window['region_index'] == 1, window
    KL._CONSUMED_RELEASES.pop(window['release_id'], None)
    return {'label': label, 'binding': binding, 'store': store, 'verification': verification,
            'evidence': evidence, 'fixtures': fixtures, 'window': window}


def _read(fixture: dict, *, window: dict | None = None, profile=None, binding: object = ...,
          store=None, recovery: bool = False, session_id: str | None = None, request=None,
          evidence_sha256: str | None = None, generic_run: str | None = None,
          event: bool = True) -> dict:
    """One phase-B read through the *production* driver, with the mutant's deviation applied."""
    win = fixture['window'] if window is None else window
    session_id = session_id or KL.SIM_SESSION_B
    captured = None
    if event:
        index = win.get('region_index')
        captured = KL.synthetic_bounded_event(
            region=win.get('region', REGION),
            bytes_hex=win.get('bytes_hex') or fixture['fixtures']['expected_bytes'],
            runtime_kbase=KL.SIM_KBASE,
            region_index_override=(index if isinstance(index, int) and not isinstance(index, bool)
                                   else None))
    return KL.run_generic_read(
        KL.OfflineSession(session_id=session_id, event=captured),
        profile=PROFILE if profile is None else profile,
        boot_binding=fixture['binding'] if binding is ... else binding,
        store=store or fixture['store'],
        verification_run_id=fixture['verification']['verification_run_id'],
        evidence_sha256=(fixture['evidence']['evidence_sha256'] if evidence_sha256 is None
                         else evidence_sha256),
        approval=fixture['fixtures']['approval'],
        provider=KL.sim_provider(live_approved=True),
        expected=win, recovery=recovery, request=request,
        generic_read_run_id=generic_run)


def _code_token(problem: str, code: str) -> bool:
    """The exact refusal code as its own token (never a substring of a longer code)."""
    return re.search(rf'(?:^|[\s:]){re.escape(code)}(?::|$|\s)', problem) is not None


def _refused(result: dict, code: str, *, entries: int = 0) -> list[str]:
    """The mutant verdict: REFUSED, the exact code, and not one provider entry (no event)."""
    assert result['outcome'] == KL.OUTCOME_REFUSED, result.get('problems')
    assert result['ok'] is False
    assert result['provider_entries'] == entries == result['generic_provider_entries'], \
        result.get('problems')
    problems = [str(p) for p in (result.get('problems') or [])]
    assert any(_code_token(p, code) for p in problems), (code, problems)
    assert result.get('event') is None, 'a refusal must not have read anything'
    return problems


# =============================================================================================
# the control: the fixture really grants -- a refusal below is therefore the mutant's doing
# =============================================================================================
def test_the_fixture_control_read_grants_and_consumes_the_release(tmp_path):
    fixture = _fixture(tmp_path, label='control')
    result = _read(fixture, generic_run='RUN-w15-mut-control')
    assert result['outcome'] == KL.OUTCOME_READ and result['ok'] is True, result['problems']
    assert result['provider_entries'] == 1 == result['generic_provider_entries']
    assert result['event'] is not None and result['event_report']['verified'] is True
    assert result['capability']['session_id'] == KL.SIM_SESSION_B
    assert fixture['store'].release_is_consumed(fixture['window']['release_id']) is True
    assert fixture['store'].read_run_ids() == ['RUN-w15-mut-control']


# =============================================================================================
# 1. a raw address field introduced -> reject
# =============================================================================================
def test_mutant_raw_address_field_cannot_travel_and_is_refused_when_introduced(tmp_path):
    """The request is (region_index, offset, length) -- two independent proofs, both real.

    (a) Wire side: ``wire_request_for`` yields exactly those three keys, even for a window that
        carries an extra ``addr`` field: whatever a window holds, the address cannot travel.
    (b) Request model: an address field introduced into the request the chain parses is refused
        by the production request schema with ``KREAD_SCHEMA_RAW_ADDRESS``, zero entries -- and
        the same request refused directly by ``kread.parse_request``.
    """
    fixture = _fixture(tmp_path, label='raw-address')

    arguments, problems = KL.wire_request_for(fixture['window'])
    assert arguments == {'region_index': 1, 'offset': 0, 'length': 16}, arguments
    assert problems == []
    tagged_window = dict(fixture['window'], addr='0xffff800000000000')
    tagged_arguments, tagged_problems = KL.wire_request_for(tagged_window)
    assert tagged_problems == []
    assert tagged_arguments == arguments, 'an addr key must not reach the wire request'
    assert set(tagged_arguments) == {'region_index', 'offset', 'length'}, tagged_arguments

    result = _read(fixture, request={'addr': '0xffff800000000000'},
                   generic_run='RUN-w15-mut-raw-address')
    _refused(result, KREAD.KREAD_SCHEMA_RAW_ADDRESS)

    try:
        KREAD.parse_request({'operation': 'kernel.read', 'region': REGION, 'offset': 0,
                             'length': 16, 'addr': '0xffff800000000000'})
    except KREAD.KReadReject as exc:
        assert exc.reason == KREAD.KREAD_SCHEMA_RAW_ADDRESS, exc.reason
    else:                                                       # pragma: no cover - fail closed
        raise AssertionError('the request model accepted a raw address field')


# =============================================================================================
# 2. region_index bounds removed -> reject
# =============================================================================================
def test_mutant_region_index_bounds_removed_is_refused(tmp_path):
    """A window that cannot name its compiled row never reaches the provider entry.

    The pre-entry request mapping refuses a missing, negative or boolean ``region_index`` with
    ``KREADLIVE_REGION_NOT_COMPILED`` and zero entries. An integer inside the 32 bit range but
    outside the compiled table is refused in the same place, before the entry, with
    ``KREAD_REGION_INDEX_INVALID`` and zero entries (W15-D2) -- and a release that pins such an
    index is refused before any window exists
    (``W13_RELEASE_INDEX_MISMATCH``).
    """
    for label, bad in (('none', None), ('negative', -1), ('boolean', True)):
        fixture = _fixture(tmp_path, label=f'index-{label}')
        result = _read(fixture, window=dict(fixture['window'], region_index=bad),
                       generic_run=f'RUN-w15-mut-index-{label}')
        _refused(result, KL.KREADLIVE_REGION_NOT_COMPILED)

    release = fixture['fixtures']['release']
    pinned_out_of_bounds = dict(release, window=dict(release['window'], region_index=999))
    release_reasons = [p.split(':', 1)[0] for p in REL.release_problems(
        pinned_out_of_bounds, profile=PROFILE, profile_sha256=PROFILE_SHA,
        boot_id=fixture['binding'].boot_id,
        approval_sha256=fixture['fixtures']['approval_sha256'])]
    assert REL.RELEASE_INDEX_MISMATCH in release_reasons, release_reasons

    fixture = _fixture(tmp_path, label='index-out-of-table')
    result = _read(fixture, window=dict(fixture['window'], region_index=999),
                   generic_run='RUN-w15-mut-index-999')
    # W15-D2: this is the pre-entry refusal. The old shape -- the entry happens and the target
    # notices afterwards -- must not pass here, because a release must not be spent on a request
    # that can never name a compiled row.
    assert result['outcome'] == KL.OUTCOME_REFUSED, result.get('problems')
    assert result['provider_entries'] == result['generic_provider_entries'] == 0, \
        'an out-of-table index must be refused before the provider entry'
    assert result['event'] is None and result['read_evidence'] is None
    assert fixture['store'].release_is_consumed(fixture['window']['release_id']) is False
    assert any(_code_token(str(p), KL.KREAD_REGION_INDEX_INVALID)
               for p in result['problems']), result['problems']


# =============================================================================================
# 5. a consumed release reused in a later session -> reject with W13_RELEASE_ALREADY_CONSUMED
# =============================================================================================
def test_mutant_consumed_release_reused_in_a_later_session_is_refused(tmp_path):
    fixture = _fixture(tmp_path, label='consumed-release')
    release_id = fixture['window']['release_id']
    first = _read(fixture, session_id=KL.SIM_SESSION_B, generic_run='RUN-w15-mut-first')
    assert first['outcome'] == KL.OUTCOME_READ and first['provider_entries'] == 1
    assert fixture['store'].release_is_consumed(release_id) is True

    second = _read(fixture, session_id=SESSION_C, generic_run='RUN-w15-mut-reuse')
    _refused(second, KL.KREADLIVE_RELEASE_ALREADY_CONSUMED)
    assert fixture['store'].read_run_ids() == ['RUN-w15-mut-first'], \
        'the refused reuse must not have written a read run'


# =============================================================================================
# 6. a capability derived for session B carried into session C -> reject
# =============================================================================================
def test_mutant_carried_capability_is_refused_by_the_derivation_receipt(tmp_path):
    """The SESSION-scoped record cannot be carried over.

    ``run_generic_read`` accepts no capability record from a caller (by construction a carried
    record never enters the driver). The load-bearing check is the derivation receipt the driver
    itself revalidates immediately before the provider entry: the record derived for session B
    is refused for session C with ``KREADLIVE_CAPABILITY_NOT_DERIVED`` -- while the very same
    record revalidates clean for its own session (the control).
    """
    import inspect

    assert 'capability' not in inspect.signature(KL.run_generic_read).parameters, \
        'the productive path must not accept a capability record from a caller'

    fixture = _fixture(tmp_path, label='carried-capability')
    record = KL.derive_capability_record(
        fixture['store'], evidence_sha256=fixture['evidence']['evidence_sha256'],
        read_run_id='RUN-w15-carried-b', profile_sha256=PROFILE_SHA,
        boot_id=fixture['binding'].boot_id, provider=KL.sim_provider(), context=KL.CONTEXT,
        session_id=KL.SIM_SESSION_B, approval=fixture['fixtures']['approval'],
        expected=KL.bootstrap_expectation(PROFILE))
    assert record['session_id'] == KL.SIM_SESSION_B
    assert record['derivation']['derived_for_session_id'] == KL.SIM_SESSION_B

    carried = KL.revalidate_derivation(record, store=fixture['store'], session_id=SESSION_C,
                                       boot_id=fixture['binding'].boot_id,
                                       profile_sha256=PROFILE_SHA, read_run_id='RUN-w15-carried-c')
    assert carried, 'the carried record passed the provider-entry revalidation'
    assert all(_code_token(p, KL.KREADLIVE_CAPABILITY_NOT_DERIVED) for p in carried), carried
    assert any('derived_for_session_id' in p for p in carried), carried

    control = KL.revalidate_derivation(record, store=fixture['store'],
                                       session_id=KL.SIM_SESSION_B,
                                       boot_id=fixture['binding'].boot_id,
                                       profile_sha256=PROFILE_SHA, read_run_id='RUN-w15-carried-b')
    assert control == [], control


# =============================================================================================
# 7. VerificationEvidence tampered -> reject
# =============================================================================================
def test_mutant_tampered_verification_evidence_is_refused(tmp_path):
    fixture = _fixture(tmp_path, label='tampered-evidence')
    path = fixture['store'].verification_path(
        fixture['verification']['verification_run_id'])
    blob = json.loads(path.read_text())
    blob['observed_sha256'] = 'ab' * 32                       # hash not recomputed
    path.write_text(json.dumps(blob, indent=1, sort_keys=True) + '\n')

    try:
        fixture['store'].load_verification(fixture['verification']['verification_run_id'])
    except KS.StoreError as exc:
        assert exc.reason == KS.STORE_REHASH_MISMATCH, exc.reason
    else:                                                       # pragma: no cover - fail closed
        raise AssertionError('the store loaded a tampered record')

    result = _read(fixture, generic_run='RUN-w15-mut-tampered')
    _refused(result, KL.KREADLIVE_EVIDENCE_REHASH_MISMATCH)
    assert fixture['store'].read_run_ids() == []


# =============================================================================================
# 8. stale boot -> reject
# =============================================================================================
def test_mutant_stale_boot_is_refused(tmp_path):
    fixture = _fixture(tmp_path, label='stale-boot')
    other_boot = KL.synthetic_boot_binding(PROFILE, boot_time={
        'sec': KL.SIM_BOOT_TIME['sec'] + 3600, 'usec': 1})
    assert other_boot.boot_id != fixture['binding'].boot_id, \
        'the fixture no longer produces a different boot'
    result = _read(fixture, binding=other_boot, generic_run='RUN-w15-mut-stale-boot')
    _refused(result, KC.KREAD_STALE_BOOT_ID)
    assert result['decision'] is None and result['capability'] is None
    assert fixture['store'].read_run_ids() == []


# =============================================================================================
# 9. wrong profile -> reject
# =============================================================================================
def test_mutant_evidence_from_another_profile_is_refused(tmp_path):
    fixture = _fixture(tmp_path, label='wrong-profile')
    foreign = KL.rehearsal_evidence(
        KL.bootstrap_expectation(PROFILE),
        verification_run_id=fixture['verification']['verification_run_id'],
        read_run_id=KL.SIM_BOOT_READ_RUN,
        verification_session_id=KL.SIM_SESSION_A, profile_sha256='f' * 64,
        boot_id=fixture['binding'].boot_id, provider=KL.sim_provider(live_approved=False))
    foreign_store = KS.VerificationEvidenceStore(tmp_path / 'wrong-profile' / 'foreign')
    foreign_store.store_verification(foreign)

    result = _read(fixture, store=foreign_store,
                   evidence_sha256=foreign['evidence_sha256'],
                   generic_run='RUN-w15-mut-wrong-profile')
    _refused(result, KC.KREAD_WRONG_PROFILE)
    assert result['decision'] is None and foreign_store.read_run_ids() == []


# =============================================================================================
# 10. an old session capability reused -> reject
# =============================================================================================
def test_mutant_old_session_reused_in_phase_b_is_refused(tmp_path):
    fixture = _fixture(tmp_path, label='old-session')
    result = _read(fixture, session_id=KL.SIM_SESSION_A,      # the verification session
                   generic_run='RUN-w15-mut-old-session')
    _refused(result, KL.KREADLIVE_SESSION_REUSED)
    assert result['read_run_record'] is None
    assert fixture['store'].read_run_ids() == []


# =============================================================================================
# 11. Recovery Required before the provider entry -> provider entry count 0
# =============================================================================================
def test_mutant_recovery_holds_the_provider_entry_at_zero(tmp_path):
    fixture = _fixture(tmp_path, label='recovery')
    result = _read(fixture, recovery=True, generic_run='RUN-w15-mut-recovery')
    _refused(result, KC.KREAD_RECOVERY_REQUIRED)
    assert result['decision']['outcome'] == 'REJECTED', result['decision']
    assert result['event_report'] is None
    assert fixture['store'].read_run_ids() == []
    assert fixture['store'].release_is_consumed(fixture['window']['release_id']) is False


# =============================================================================================
# the target side: compiled from the *production* provider source with a documented patch
# =============================================================================================
CC = ('gcc', '-std=c11', '-O1', '-Wall', '-Wextra', '-Wno-unused-parameter')
HARNESS = REPO / 'tests' / 'harness' / 'kread_offline.c'
MODULE = REPO / 'native' / 'target' / 'ps4rf_kread.c'
HEADER = REPO / 'native' / 'target' / 'ps4rf_kread.h'
JCS = REPO / 'native' / 'src' / 'jcs.c'
SHA = REPO / 'native' / 'src' / 'sha256.c'
CASES = ('A', 'B', 'C', 'D', 'E', 'E2', 'F', 'G', 'H', 'I', 'J', 'B2', 'D2', 'E3', 'K', 'L', 'M',
         'N', 'N2', 'O', 'P', 'Q')


def _source_copy(tmp_path: pathlib.Path, *, with_header: bool = False) -> pathlib.Path:
    src = tmp_path / 'src'
    src.mkdir()
    shutil.copy(MODULE, src / 'ps4rf_kread.c')
    if with_header:
        shutil.copy(HEADER, src / 'ps4rf_kread.h')
    return src


def _mutate(path: pathlib.Path, old: str, new: str) -> None:
    """Apply one documented textual mutation -- and fail when it does not really apply."""
    text = path.read_text()
    assert old in text, f'the mutation site is absent from {path.name}: nothing would be removed'
    mutated = text.replace(old, new)
    assert mutated != text and new in mutated, f'the mutation of {path.name} did not apply'
    path.write_text(mutated)


def _compile(src: pathlib.Path, binary: pathlib.Path) -> subprocess.CompletedProcess:
    assert HARNESS.exists() and MODULE.exists() and HEADER.exists()
    return subprocess.run(
        [*CC, '-I', str(src), '-I', str(REPO / 'native' / 'target'),
         '-I', str(REPO / 'native' / 'src'), '-o', str(binary),
         str(HARNESS), str(src / 'ps4rf_kread.c'), str(JCS), str(SHA)],
        capture_output=True, text=True, timeout=300)


def _observe(binary: pathlib.Path) -> tuple[dict, list, subprocess.CompletedProcess]:
    run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=300)
    lines = [json.loads(line) for line in run.stdout.splitlines() if line.startswith('{')]
    cases = {line['case']: line for line in lines if 'case' in line}
    return cases, lines, run


def _failed_cases(cases: dict) -> set:
    return {case for case, line in cases.items() if not line['pass']}


def test_the_target_recipe_control_build_passes_every_case(tmp_path):
    """Control: the unmutated copies through the same recipe pass all 22 cases."""
    src = _source_copy(tmp_path)
    build = _compile(src, tmp_path / 'control')
    assert build.returncode == 0, build.stderr
    assert not build.stderr.strip(), f'the control build emitted warnings:\n{build.stderr}'
    cases, lines, run = _observe(tmp_path / 'control')
    assert set(cases) == set(CASES), sorted(cases)
    assert lines[-1]['suite'] == 'w12_kread_offline'
    assert lines[-1]['cases_failed'] == 0 and run.returncode == 0, \
        {case: cases[case]['observed'] for case in _failed_cases(cases)}


def test_mutant_target_raw_address_field_is_refused_by_the_frozen_layout(tmp_path):
    """Mutant 1 (target side): a raw host address added to the payload's request block.

    The frozen 4256-byte layout of ``ps4rf_kread_info`` is the gate: the mutation cannot be
    built, and the compiler names the mechanism (``ps4rf_kread_info_is_4256``).
    """
    src = _source_copy(tmp_path, with_header=True)
    _mutate(src / 'ps4rf_kread.h',
            "  uint32_t length;            /* in  : requested length, 1..PS4RF_KREAD_MAX_LEN            */",
            "  uint32_t length;            /* in  : requested length, 1..PS4RF_KREAD_MAX_LEN            */\n"
            "  uint64_t host_addr;         /* MUTANT: a raw host address as a request field             */")
    build = _compile(src, tmp_path / 'm1')
    assert build.returncode != 0, \
        'the raw address field built; the frozen result-block layout is not load-bearing'
    assert 'ps4rf_kread_info_is_4256' in build.stderr, build.stderr


def test_mutant_target_hardcoded_index_zero_breaks_the_released_row_case(tmp_path):
    """Mutant 3: the callback serves index 0 (image_elf) whatever the request named.

    The released row is index 1 (``amd_iommu``), so case ``O`` must stop matching -- and it is
    the *only* case that fails: the mutation is detected exactly where its mechanism was.
    """
    src = _source_copy(tmp_path)
    _mutate(src / 'ps4rf_kread.c',
            "  uint32_t index = info->region_index;",
            "  uint32_t index = 0u;   /* MUTANT: hardcoded back to index 0 (image_elf) */")
    build = _compile(src, tmp_path / 'm3')
    assert build.returncode == 0, build.stderr
    cases, lines, run = _observe(tmp_path / 'm3')
    failed = _failed_cases(cases)
    assert failed == {'O'}, {case: cases[case]['observed'] for case in failed}
    assert 'RESULT_INVALID' in cases['O']['observed'], cases['O']['observed']
    assert lines[-1]['cases_failed'] == 1 and run.returncode != 0


def test_mutant_target_containment_removed_breaks_the_containment_cases(tmp_path):
    """Mutant 4: both containment refusals removed (callback and run section).

    Every case whose *only* refusal was containment now reads across the region end and has to
    fail: ``E``/``E2``/``L`` (image_elf, run section), ``P``/``Q`` (the released row, run
    section) and ``E3`` (the callback's own check). Nothing else may fail.
    """
    src = _source_copy(tmp_path)
    _mutate(src / 'ps4rf_kread.c',
            "  if (sum > region->length) {                   /* region containment: cross-region refused  */\n"
            "    info->cb_status = PS4RF_KREAD_CB_CONTAINMENT;\n"
            "    return 0;\n"
            "  }",
            "  /* MUTANT: the callback's region containment refusal was removed */")
    _mutate(src / 'ps4rf_kread.c',
            "  uint32_t sum = offset + length;\n"
            "  if (sum < offset || sum > PS4RF_KREAD_REGIONS[region_index].length) {\n"
            "    info->cb_status = PS4RF_KREAD_CB_NOT_RUN;\n"
            "    info->run_status = PS4RF_KREAD_RUN_REQUEST_INVALID;\n"
            "    return PS4RF_KREAD_RUN_REQUEST_INVALID;\n"
            "  }",
            "  uint32_t sum = offset + length;\n"
            "  if (sum < offset) {   /* MUTANT: the region containment half was removed */\n"
            "    info->cb_status = PS4RF_KREAD_CB_NOT_RUN;\n"
            "    info->run_status = PS4RF_KREAD_RUN_REQUEST_INVALID;\n"
            "    return PS4RF_KREAD_RUN_REQUEST_INVALID;\n"
            "  }")
    build = _compile(src, tmp_path / 'm4')
    assert build.returncode == 0, build.stderr
    cases, lines, run = _observe(tmp_path / 'm4')
    failed = _failed_cases(cases)
    assert failed == {'E', 'E2', 'E3', 'L', 'P', 'Q'}, \
        {case: cases[case]['observed'] for case in failed}
    assert 'CROSS_REGION_REFUSED' not in cases['E3']['observed'], cases['E3']['observed']
    assert 'copied=1' in cases['E3']['observed'], cases['E3']['observed']
    assert lines[-1]['cases_failed'] == 6 and run.returncode != 0
