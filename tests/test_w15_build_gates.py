"""W15 -- the build gates of the rehearsal stand-in and of the version string.

Two things must never be true at once: a *console* artefact that carries the simulated kernel image
(the rehearsal stand-in belongs to the dev host, and a console read reaches the real kernel or fails
closed), and an `agent_version` that is a stale literal (W14-D1: the string kept reporting `w8`
through two waves because only the build id, label and context were asserted).

These tests drive the real build scripts, not a copy of their logic.
"""
from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

BUILD_PS4 = REPO / 'native' / 'target' / 'build_ps4.sh'
BUILD_HOST = REPO / 'native' / 'target' / 'build_host.sh'
MANIFEST = REPO / 'native' / 'target' / 'build_manifest.py'
AGENT_C = REPO / 'native' / 'target' / 'ps4rf_agent.c'
AGENT_H = REPO / 'native' / 'target' / 'ps4rf_agent.h'
SDK = pathlib.Path('/home/hermes/fw900-sdk-audit/libPS4')


def test_the_console_build_refuses_the_simulated_image():
    """The rehearsal switch is a dev-host switch: a console build must refuse it outright."""
    done = subprocess.run(['sh', str(BUILD_PS4), '/tmp/w15-refused-build', str(SDK)],
                          env={'PATH': '/usr/bin:/bin', 'PS4RF_TARGET_KREAD_SIM': '1',
                               'PS4RF_TARGET_KREAD': '1'},
                          capture_output=True, text=True, timeout=120)
    assert done.returncode != 0, 'the console build accepted the simulated kernel image'
    assert 'PS4RF_TARGET_KREAD_SIM' in (done.stdout + done.stderr)
    assert not (pathlib.Path('/tmp/w15-refused-build') / 'ps4rfd.bin').exists()


def test_the_host_build_links_the_simulated_image_only_with_the_switch(tmp_path):
    """The switch has to change the linked object -- and only then."""
    script = BUILD_HOST.read_text()
    assert 'PS4RF_TARGET_KREAD_SIM' in script, 'the host build has no rehearsal switch'
    assert 'tests/harness/ps4rf_kread_sim.c' in script
    out = tmp_path / 'host'
    done = subprocess.run(['sh', str(BUILD_HOST), str(out)],
                          env={'PATH': '/usr/bin:/bin', 'PS4RF_TARGET_KREAD': '1',
                               'PS4RF_TARGET_KREAD_SIM': '1'},
                          capture_output=True, text=True, timeout=600)
    assert done.returncode == 0, (done.stdout[-1500:], done.stderr[-1500:])
    binary = out / 'ps4rfd_host'
    assert binary.exists()
    # the stand-in identifies itself: its own strings are in the binary, and so is the pattern
    blob = binary.read_bytes()
    assert b'PS4RF_KREAD_SIM_SEED' in blob and b'PS4RF_KREAD_SIM_TRACE' in blob
    # ... and the honest failing stand-in is *not* in it (the two are alternatives)
    assert b'ps4rf_kread_host' not in blob
    # the console gate is not merely absent from the script text: it is enforced above
    assert 'must not be part of a console build' in BUILD_PS4.read_text()


def test_the_agent_version_is_a_constant_and_not_a_wave_literal():
    """W14-D1: the version string is one constant, used at the HELLO site."""
    header, source = AGENT_H.read_text(), AGENT_C.read_text()
    assert '#define PS4RF_AGENT_VERSION "ps4rfd-target-w15"' in header
    assert 'jval_new_string(PS4RF_AGENT_VERSION)' in source
    for stale in ('ps4rfd-target-w8', 'ps4rfd-target-w9', 'ps4rfd-target-w12',
                  'ps4rfd-target-w13', 'ps4rfd-target-w14'):
        assert stale not in source, f'the stale version literal {stale!r} is back in the agent'


def _deviant_tree(tmp_path, *, header: str | None = None, source: str | None = None):
    """A source tree that differs from the real one only where the mutant says so."""
    root = tmp_path / 'tree'
    (root / 'native' / 'target').mkdir(parents=True)
    shutil.copy(AGENT_H, root / 'native' / 'target' / 'ps4rf_agent.h')
    shutil.copy(AGENT_C, root / 'native' / 'target' / 'ps4rf_agent.c')
    if header is not None:
        (root / 'native' / 'target' / 'ps4rf_agent.h').write_text(header)
    if source is not None:
        (root / 'native' / 'target' / 'ps4rf_agent.c').write_text(source)
    return root


def test_the_version_gate_accepts_the_real_tree_and_refuses_both_deviations(tmp_path):
    """The gate is driven on real trees: the shipped one, and two deliberately broken ones."""
    from native.target.build_manifest import agent_version_gate
    sys.path.insert(0, str(REPO))

    real = agent_version_gate(REPO)
    assert real['problems'] == [], real

    # 1. the constant is gone (the header stops defining it) -> the gate must refuse
    broken_h = AGENT_H.read_text().replace('#define PS4RF_AGENT_VERSION "ps4rfd-target-w15"',
                                           '/* the constant was removed */')
    assert broken_h != AGENT_H.read_text(), 'the mutant did not apply to the header'
    assert agent_version_gate(_deviant_tree(tmp_path / 'a', header=broken_h))['problems']

    # 2. the literal is back at the HELLO site -> the gate must refuse, and name it
    broken_c = AGENT_C.read_text().replace('jval_new_string(PS4RF_AGENT_VERSION)',
                                           'jval_new_string("ps4rfd-target-w8")')
    assert broken_c != AGENT_C.read_text(), 'the mutant did not apply to the source'
    problems = agent_version_gate(_deviant_tree(tmp_path / 'b', source=broken_c))['problems']
    assert any('ps4rfd-target-w8' in problem for problem in problems), problems
