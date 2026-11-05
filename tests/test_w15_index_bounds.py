"""W15 -- D2: the region-index bounds decision runs IN FRONT of the release consumption and the
provider entry, and removing it must go red.

Owner ruling (D2). Today an out-of-range ``region_index`` (e.g. 999) reaches the provider entry
and is refused only afterwards by the target/event cross-check. That state is not accepted: before
the release is consumed, before the provider is entered and before any trigger could run, the host
driver itself must decide

    0 <= region_index < len(compiled_regions())

against the normative *compiled* target table (``tools.profiles.regions.compiled_regions``) --
never the policy registry total and never a second index table -- and the released window's region
name, resolved through that same table, must equal the index that goes into the target request.

What this module proves through the production driver
(:func:`tools.hostctl.kreadlive.run_generic_read`) with its offline session fixtures and a real W13
release for ``amd_iommu`` (compiled row 1):

* ``-1``, ``len(compiled_regions())``, ``999`` and an index that is only valid against the
  *policy* registry total are each refused PRE-entry with ``KREAD_REGION_INDEX_INVALID``: zero
  provider entries, the release is NOT consumed, no event, and the dispatch trace of the simulated
  session shows zero dispatches (``kexec_calls``/``dispatch_calls`` stay 0);
* a release whose region name resolves to a different compiled row than the requested index is
  refused with ``W13_RELEASE_WINDOW_MISMATCH`` and zero entries -- the target never sees it;
* the control (``amd_iommu``, compiled index 1, offset 0, length 16) still reads;
* the mutant proof: patching the bounds decision away at the point the driver uses it makes the
  same window behave the OLD way (entry >= 1, the release consumed, only the post-entry
  ``KREADLIVE_TABLE_MISMATCH`` cross-check refusing), while the unpatched run of the same window is
  refused pre-entry -- the old post-entry-reject behaviour does not satisfy the production
  assertions, and the patch target disappears (the test fails) if the production check is removed.

Honest scope: the "dispatch trace" here is the offline session's own recorder at the only boundary
this driver owns -- the session request (``OfflineSession.request``) -- shaped like the native
simulated image's trace (``tests/harness/ps4rf_kread_sim.c``: ``kexec_calls``/``dispatch_calls``,
written after every console dispatch). The native trace itself is exercised by
``tests/test_w15_resident_research.py``; for a run refused before any request is sent it is empty
by construction, and this module does not pretend to run a console.
"""
from __future__ import annotations

import json
import pathlib
import re
import sys
from unittest import mock

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from tools.hostctl import kreadlive as KL                                       # noqa: E402
from tools.hostctl import kreadstore as KS                                      # noqa: E402
from tools.hostctl import live_w15 as W15                                       # noqa: E402
from tools.profiles import regions as R                                         # noqa: E402
from tools.profiles.schema import canonical_profile_sha256                      # noqa: E402
from tools.research import classification as C                                  # noqa: E402
from tools.research import release as REL                                       # noqa: E402

PROFILE = C.DEFAULT_PROFILE
PROFILE_SHA = canonical_profile_sha256(PROFILE)
REGION = 'amd_iommu'
PAYLOAD = {'bin_sha256': '99' * 32, 'elf_sha256': '2e' * 32, 'build_manifest_sha256': '4d' * 32,
           'build_id': '032ffa3eb281384edeffcbb11c84e242', 'label': 'ps4rfd-live-w15'}

#: the two tables, read through the normative accessors -- computed, never transcribed
COMPILED_COUNT = len(R.compiled_regions())
POLICY_COUNT = len(R.regions())


# =============================================================================================
# the offline fixture: a real phase-A verification, a real section 70 approval, a real W13 release
# =============================================================================================
def _fixture(tmp_path: pathlib.Path, *, label: str) -> dict:
    """One phase-A record in the store plus a fresh release for the amd_iommu window.

    Same shape as the other W15 sheets. The release id is unique per test (``label``), because a
    consumed release is spent for the whole process on purpose (``_CONSUMED_RELEASES``).
    """
    binding = KL.synthetic_boot_binding(PROFILE)
    store = KS.VerificationEvidenceStore(tmp_path / label / 'store')
    verification = KL.run_verification(
        KL.OfflineSession(session_id=KL.SIM_SESSION_A,
                          event=KL.synthetic_bounded_event(runtime_kbase=KL.SIM_KBASE)),
        profile=PROFILE, boot_binding=binding, store=store,
        provider=KL.sim_provider(live_approved=False))
    assert verification['outcome'] == KL.OUTCOME_VERIFIED, verification.get('problems')
    fixtures = W15.plan_fixtures(profile=PROFILE, profile_sha256=PROFILE_SHA,
                                 boot_id=binding.boot_id, payload=PAYLOAD,
                                 evidence_sha256=verification['evidence']['evidence_sha256'],
                                 verification_run_id=verification['verification_run_id'],
                                 now=f'W15IDX-{label}')
    built = REL.released_window(fixtures['release'], profile=PROFILE, profile_sha256=PROFILE_SHA,
                                boot_id=binding.boot_id,
                                approval_sha256=fixtures['approval_sha256'])
    assert built['problems'] == [], built['problems']
    window = built['window']
    assert window['region'] == REGION and window['region_index'] == 1, window
    KL._CONSUMED_RELEASES.pop(window['release_id'], None)
    return {'label': label, 'binding': binding, 'store': store, 'verification': verification,
            'fixtures': fixtures, 'window': window}


class _DispatchTraceSession(KL.OfflineSession):
    """The offline session plus the simulated image's dispatch trace, persisted to disk.

    The native simulated image counts ``kexec_calls``/``dispatch_calls`` and writes its trace
    after every console dispatch (``tests/harness/ps4rf_kread_sim.c``). Offline, the only boundary
    this driver owns is the session request, so this stand-in records exactly that boundary with
    the same counter names and writes the trace at construction and after every dispatch -- a
    refused run leaves a trace on disk that says zero dispatches.
    """

    def __init__(self, *args, trace_path: pathlib.Path | None = None, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.trace_path = pathlib.Path(trace_path) if trace_path is not None else None
        self.trace = {'kexec_calls': 0, 'dispatch_calls': 0, 'requests': [],
                      'note': 'offline dispatch trace: one entry per kernel.read request sent to '
                              'the simulated session (the native sim writes the same counters '
                              'after every console dispatch)'}
        self._write_trace()

    def _write_trace(self) -> None:
        if self.trace_path is not None:
            self.trace_path.write_text(json.dumps(self.trace, indent=1, sort_keys=True) + '\n')

    def request(self, op, arguments=None, *, request_id=None):
        self.trace['kexec_calls'] += 1
        self.trace['dispatch_calls'] += 1
        self.trace['requests'].append({'operation': op, 'arguments': dict(arguments or {})})
        self._write_trace()
        return super().request(op, arguments, request_id=request_id)


def _window_index(window: dict) -> int | None:
    """The window's index when it is a real integer (never a boolean), else None."""
    index = window.get('region_index')
    return index if isinstance(index, int) and not isinstance(index, bool) else None


def _session(fixture: dict, window: dict, *, session_id: str = KL.SIM_SESSION_B,
             trace_path: pathlib.Path | None = None) -> _DispatchTraceSession:
    """A fresh simulated session whose event names the window's region/row (offline)."""
    return _DispatchTraceSession(
        session_id=session_id, trace_path=trace_path,
        event=KL.synthetic_bounded_event(
            region=window.get('region', REGION),
            bytes_hex=window.get('bytes_hex') or fixture['fixtures']['expected_bytes'],
            runtime_kbase=KL.SIM_KBASE, region_index_override=_window_index(window)))


def _read(fixture: dict, *, window: dict | None = None, session=None,
          generic_run: str | None = None) -> dict:
    """One phase-B read through the *production* driver, with the window under test."""
    win = fixture['window'] if window is None else window
    if session is None:
        session = _session(fixture, win)
    return KL.run_generic_read(
        session, profile=PROFILE, boot_binding=fixture['binding'], store=fixture['store'],
        verification_run_id=fixture['verification']['verification_run_id'],
        evidence_sha256=fixture['verification']['evidence']['evidence_sha256'],
        approval=fixture['fixtures']['approval'], provider=KL.sim_provider(live_approved=True),
        expected=win, generic_read_run_id=generic_run)


def _code_token(problem: str, code: str) -> bool:
    """The exact refusal code as its own token (never a substring of a longer code)."""
    return re.search(rf'(?:^|[\s:]){re.escape(code)}(?::|$|\s)', problem) is not None


# =============================================================================================
# 1. -1, len(compiled_regions()), 999 and a registry-only index: refused BEFORE any consumption
# =============================================================================================
@pytest.mark.parametrize('label, index', [
    ('negative', -1),
    ('compiled-count', COMPILED_COUNT),
    ('far-out', 999),
    ('registry-total-only', POLICY_COUNT - 1),
])
def test_out_of_range_index_is_refused_before_any_consumption(tmp_path, label, index):
    """The D2 refusal: pre-entry, zero entries, release untouched, zero dispatches.

    ``registry-total-only`` discriminates the normative source: that index is inside the *policy*
    registry total but outside the compiled table, so a check built on ``len(regions.regions())``
    would admit it.
    """
    assert POLICY_COUNT > COMPILED_COUNT, 'the registry-total case must discriminate the tables'
    fixture = _fixture(tmp_path, label=label)
    window = dict(fixture['window'], region_index=index)
    trace_path = tmp_path / label / 'sim-trace.json'
    session = _session(fixture, window, trace_path=trace_path)
    result = _read(fixture, window=window, session=session, generic_run=f'RUN-w15idx-{label}')

    assert result['outcome'] == KL.OUTCOME_REFUSED and result['ok'] is False, result['problems']
    problems = [str(problem) for problem in result['problems']]
    assert any(_code_token(problem, 'KREAD_REGION_INDEX_INVALID')
               for problem in problems), problems
    # nothing was entered, consumed, dispatched or persisted
    assert result['provider_entries'] == 0 == result['generic_provider_entries']
    assert result['decision'] is None and result['capability'] is None
    assert result['event'] is None and result['event_report'] is None
    assert result['read_run_id'] is None and result['read_run_record'] is None
    assert fixture['store'].release_is_consumed(fixture['window']['release_id']) is False
    assert fixture['store'].read_run_ids() == []
    # the simulated image's dispatch trace: zero dispatches for this run
    trace = json.loads(trace_path.read_text())
    assert trace['kexec_calls'] == 0 and trace['dispatch_calls'] == 0, trace
    assert trace['requests'] == [], trace
    assert session.triggered is False and session.request_arguments is None
    assert session.kernel_read_bounded is None


# =============================================================================================
# 2. the normative source: compiled_regions(), not the policy registry total
# =============================================================================================
def test_the_bounds_source_is_the_compiled_table_not_the_policy_total():
    """``0 <= index < len(compiled_regions())`` against the compiled table, and nothing else."""
    assert POLICY_COUNT > COMPILED_COUNT, (COMPILED_COUNT, POLICY_COUNT)
    assert KL.W13_RELEASE_WINDOW_MISMATCH == REL.RELEASE_WINDOW_MISMATCH, \
        'the driver and the W13 release must name one window-mismatch code'
    assert R.compiled_region_index('image_elf') == 0
    assert R.compiled_region_index(REGION) == 1
    # admitted: in range and the region resolves to exactly that row
    assert KL.region_index_bounds_problems({'region': 'image_elf', 'region_index': 0}) == []
    assert KL.region_index_bounds_problems({'region': REGION, 'region_index': 1}) == []
    # refused: everything outside 0 <= index < len(compiled_regions())
    for index in (-1, COMPILED_COUNT, 999, POLICY_COUNT - 1, True, None, '1'):
        problems = KL.region_index_bounds_problems({'region': REGION, 'region_index': index})
        assert len(problems) == 1, (index, problems)
        assert _code_token(problems[0], 'KREAD_REGION_INDEX_INVALID'), (index, problems)
    # in range but resolving to another compiled row: the disagreement code, not the bounds code
    problems = KL.region_index_bounds_problems({'region': REGION,
                                                'region_index': COMPILED_COUNT - 1})
    assert len(problems) == 1 and _code_token(problems[0], 'W13_RELEASE_WINDOW_MISMATCH'), problems
    assert not _code_token(problems[0], 'KREAD_REGION_INDEX_INVALID'), problems


# =============================================================================================
# 3. the release's region and the requested index must be the same compiled row -> 0 entries
# =============================================================================================
def test_a_release_whose_region_and_index_disagree_is_refused_with_zero_entries(tmp_path):
    """Two shapes of disagreement, both refused before anything is consumed or entered.

    ``index-pinned-to-another-row``: the release says ``amd_iommu`` but the request would name
    another compiled row. ``name-resolves-to-another-row``: the region name is replaced by another
    compiled row while the index stays 1. The target never sees either.
    """
    fixture = _fixture(tmp_path, label='row-disagreement')
    other_row = R.compiled_region_index('gbase_vtophys')
    assert other_row is not None and other_row != fixture['window']['region_index'], other_row
    for case, window in (('index-pinned-to-another-row',
                          dict(fixture['window'], region_index=other_row)),
                         ('name-resolves-to-another-row',
                          dict(fixture['window'], region='gbase_vtophys'))):
        trace_path = tmp_path / 'row-disagreement' / f'trace-{case}.json'
        session = _session(fixture, window, trace_path=trace_path)
        result = _read(fixture, window=window, session=session,
                       generic_run=f'RUN-w15idx-{case}')
        problems = [str(problem) for problem in result['problems']]
        assert result['outcome'] == KL.OUTCOME_REFUSED, (case, problems)
        assert any(_code_token(problem, REL.RELEASE_WINDOW_MISMATCH)
                   for problem in problems), (case, problems)
        assert not any(_code_token(problem, 'KREAD_REGION_INDEX_INVALID')
                       for problem in problems), (case, problems)
        assert result['provider_entries'] == 0 == result['generic_provider_entries'], case
        assert result['event'] is None and result['event_report'] is None, case
        assert fixture['store'].release_is_consumed(fixture['window']['release_id']) is False, case
        assert fixture['store'].read_run_ids() == [], case
        trace = json.loads(trace_path.read_text())
        assert trace['dispatch_calls'] == 0 and trace['kexec_calls'] == 0, (case, trace)


# =============================================================================================
# 4. the control: the released row still reads (the refusals above are the index's doing)
# =============================================================================================
def test_the_released_amd_iommu_row_still_reads(tmp_path):
    """Control: the same machinery with the released row (index 1) performs the read exactly once."""
    fixture = _fixture(tmp_path, label='control')
    trace_path = tmp_path / 'control' / 'sim-trace.json'
    session = _session(fixture, fixture['window'], trace_path=trace_path)
    result = _read(fixture, session=session, generic_run='RUN-w15idx-control')

    assert result['outcome'] == KL.OUTCOME_READ and result['ok'] is True, result['problems']
    assert result['provider_entries'] == 1 == result['generic_provider_entries']
    report = result['event_report']
    assert report['verified'] is True and report['requested_region_index'] == 1
    assert report['bytes_hex'] == fixture['fixtures']['expected_bytes']
    assert result['capability']['session_id'] == KL.SIM_SESSION_B
    assert fixture['store'].release_is_consumed(fixture['window']['release_id']) is True
    assert fixture['store'].read_run_ids() == ['RUN-w15idx-control']
    trace = json.loads(trace_path.read_text())
    assert trace['dispatch_calls'] == 1 and trace['kexec_calls'] == 1, trace
    assert trace['requests'] == [{'operation': 'kernel.read',
                                  'arguments': {'region_index': 1, 'offset': 0,
                                                'length': 16}}], trace


# =============================================================================================
# 5. the D2 mutant: remove the pre-entry decision -> the old post-entry reject returns
# =============================================================================================
def test_mutant_bounds_check_removed_falls_back_to_the_post_entry_reject(tmp_path):
    """The D2 mutant: with the bounds decision patched away, the OLD behaviour returns.

    Half A (production, unpatched): the same index-999 window is refused PRE-entry with
    ``KREAD_REGION_INDEX_INVALID``, zero provider entries, the release untouched, zero dispatches.
    Half B: the bounds decision is patched away at the point the driver uses it
    (``mock.patch.object`` on the module attribute -- if the production function is removed the
    patch fails and so does this test); the run then behaves the way D2 rejects: provider entry
    >= 1, the release consumed, and only the post-entry event cross-check refusing with
    ``KREADLIVE_TABLE_MISMATCH``. The two halves cannot both hold without the production check --
    the old post-entry-reject behaviour does not satisfy half A's guarantees.
    """
    fixture = _fixture(tmp_path, label='mutant')
    window = dict(fixture['window'], region_index=999)
    release_id = fixture['window']['release_id']

    # half A -- production: the decision lands in front of consumption, entry and trigger
    trace_a = tmp_path / 'mutant' / 'trace-production.json'
    result_a = _read(fixture, window=window,
                     session=_session(fixture, window, trace_path=trace_a),
                     generic_run='RUN-w15idx-mutant-production')
    problems_a = [str(problem) for problem in result_a['problems']]
    assert result_a['outcome'] == KL.OUTCOME_REFUSED, problems_a
    assert any(_code_token(problem, 'KREAD_REGION_INDEX_INVALID')
               for problem in problems_a), problems_a
    assert result_a['provider_entries'] == 0, problems_a
    assert fixture['store'].release_is_consumed(release_id) is False
    assert json.loads(trace_a.read_text())['dispatch_calls'] == 0

    # half B -- the mutant: the bounds check is injected away, the old path runs
    trace_b = tmp_path / 'mutant' / 'trace-mutant.json'
    session_b = _session(fixture, window, trace_path=trace_b)
    with mock.patch.object(KL, 'region_index_bounds_problems') as bounds_check:
        bounds_check.return_value = []
        result_b = _read(fixture, window=window, session=session_b,
                         generic_run='RUN-w15idx-mutant-removed')
        assert bounds_check.call_count >= 1, 'the driver never consulted the bounds decision'
    problems_b = [str(problem) for problem in result_b['problems']]
    assert result_b['provider_entries'] >= 1, ('the old behaviour is entry >= 1', problems_b)
    assert any(_code_token(problem, KL.KREADLIVE_TABLE_MISMATCH)
               for problem in problems_b), problems_b
    assert result_b['outcome'] == KL.OUTCOME_REFUSED, problems_b
    assert fixture['store'].release_is_consumed(release_id) is True, \
        'the old behaviour consumes the release before the target rejects the row'
    assert json.loads(trace_b.read_text())['dispatch_calls'] == 1, \
        'the old behaviour dispatches the trigger to the simulated target'
    # ... and the old state can never pass the production guarantees of half A
    assert result_a['provider_entries'] == 0 != result_b['provider_entries']
