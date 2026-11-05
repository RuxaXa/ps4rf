"""W17F phase 5: the offline end-to-end RPC rehearsal.

The rehearsal drives the frozen experiments through the real RPC path (host session -> agent
dispatch -> provider -> response -> classifier) against a host build of the agent whose platform
seams replay a tape recorded from the experiment layer's simulated console. These tests pin the
result: every scenario must land on the verdict the oracle vector declares, over the wire, with no
provider and no classifier called directly.
"""
from __future__ import annotations

import json
import pathlib
import re

import pytest

from tools.experiments import rehearsal, tape

REPO = pathlib.Path(__file__).resolve().parents[1]


@pytest.fixture(scope='module')
def rehearsal_summary(tmp_path_factory):
    out = tmp_path_factory.mktemp('w17-rehearsal')
    return rehearsal.rehearsal(out)


def test_the_rehearsal_covers_both_experiments_completely(rehearsal_summary):
    scenarios = [r['scenario'] for r in rehearsal_summary['results']]
    assert scenarios == list(tape.scenarios('q6')) + list(tape.scenarios('own1'))
    assert rehearsal_summary['total'] == 10


def test_every_scenario_reaches_its_oracle_verdict_over_the_wire(rehearsal_summary):
    failures = [(r['scenario'], r['classification'], r['simulated_classification'],
                 r['expected_classification'], r['agent_stderr']) for r in rehearsal_summary['results']
                if not r['ok']]
    assert not failures, failures
    q6 = [r for r in rehearsal_summary['results'] if r['scenario'].startswith('q6_')]
    own1 = [r for r in rehearsal_summary['results'] if r['scenario'].startswith('on1_')]
    assert len(q6) == 4 and len(own1) == 6
    # the two instrumentation controls must actually travel the wire, not only the simulation
    controls = [r['scenario'] for r in rehearsal_summary['results']
                if r['scenario'] in tape.CONTROL_EXPECTED]
    assert controls == ['on1_ctrl_outside', 'on1_delayed']


def test_the_rpc_path_reproduces_the_simulation_exactly(rehearsal_summary):
    for result in rehearsal_summary['results']:
        assert result['classification'] == result['simulated_classification'], result['scenario']


def test_only_the_two_dispatched_operations_answer_the_experiments(rehearsal_summary):
    allowed = {'kernel.snapshot.recipe', 'ioctl.invoke'}
    for result in rehearsal_summary['results']:
        operations = set(result['requests'])
        assert operations and operations <= allowed, (result['scenario'], operations)


def test_every_request_carries_no_address(rehearsal_summary):
    """The wire carries names and bounded content, never a locator the caller chose."""
    for result in rehearsal_summary['results']:
        for exchange in result['exchanges']:
            arguments = exchange['request']['arguments']
            for key, value in arguments.items():
                assert not re.search(r'(^|_)(addr|address|va|va_|rva|ptr|pointer|offset_abs)($|_)',
                                     key), (result['scenario'], key)
                if isinstance(value, str):
                    # a hex payload is content, but the content may never look like a locator the
                    # experiment picked as a target: the recipe/command fields decide what is read
                    assert len(value) <= 2 * 0x10000


def test_the_pointer_field_the_target_declares_is_the_one_the_tape_masks():
    """The tape masks the pointer field at the offset the target's generated policy declares, and
    that offset is the only place the provider writes its own buffer address."""
    header = (REPO / 'native/target/ps4rf_ioctl_policy_data.h').read_text()
    rows = re.findall(r'\{\s*(0x[0-9A-Fa-f]+)u,\s*\d+u,\s*\d+u,\s*\d+u,\s*\d+u,\s*'
                      r'(\d+u|0x[0-9A-Fa-f]+u|PS4RF_IOCTL_NO_PTR_FIELD),\s*0x[0-9A-Fa-f]+u\s*\}',
                      header)
    declared = {}
    for command, field in rows:
        declared[int(command, 16)] = None if field.startswith('PS4RF_IOCTL') else int(
            field.rstrip('u'), 16 if field.startswith('0x') else 10)
    assert declared, 'the generated policy carries no rule rows'
    for command, offset in tape.POINTER_FIELD.items():
        assert declared.get(command) == offset, (hex(command), declared.get(command), offset)


def test_the_recorded_tapes_are_reproducible():
    """A tape is a function of the fixtures: recording it twice must give the same bytes."""
    for scenario in list(tape.scenarios('q6')) + list(tape.scenarios('own1')):
        experiment = 'q6' if scenario.startswith('q6_') else 'own1'
        first = tape.render(scenario, experiment, tape.record(scenario, experiment)[1])
        second = tape.render(scenario, experiment, tape.record(scenario, experiment)[1])
        assert first == second
