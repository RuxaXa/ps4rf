"""W15 -- the gates that must hold on the *final* console artefact, proven from the sources.

Three gates already live in the target build itself (the build refuses `PS4RF_TARGET_KREAD_SIM`, the
manifest has no loader port reference, and the manifest records the `kernel.read` bounds it found in
the disassembly). The two below are the ones a build cannot make about itself:

* exactly one production call site of `ps4rf_kread_run()` -- the wired provider is the only way a
  kernel read can be asked for, so a second caller would be a second code path into the kernel;
* the version constant: the HELLO string and the manifest block come from `PS4RF_AGENT_VERSION`
  (W14-D1), which the manifest gate checks against a real and two deliberately broken trees.

Both read the real tree, and both are driven on mutants as well where a mutation is the point.
"""
from __future__ import annotations

import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

TARGET = REPO / 'native' / 'target'
AGENT_H = TARGET / 'ps4rf_agent.h'
AGENT_C = TARGET / 'ps4rf_agent.c'


def _deviant_tree(root: pathlib.Path, *, header: str | None = None, source: str | None = None,
                  extra: dict[str, str] | None = None) -> pathlib.Path:
    """A copy of native/target with the given files replaced (the gates read the tree, not the repo)."""
    root.mkdir(parents=True, exist_ok=True)
    for path in TARGET.iterdir():
        if path.is_file():
            (root / path.name).write_bytes(path.read_bytes())
    if header is not None:
        (root / AGENT_H.name).write_text(header)
    if source is not None:
        (root / AGENT_C.name).write_text(source)
    for name, text in (extra or {}).items():
        (root / name).write_text(text)
    return root


def _call_sites(text: str) -> list[str]:
    """Lines that *call* `ps4rf_kread_run(`, i.e. not the definition and not a comment."""
    hits = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith('/*') or stripped.startswith('*') or stripped.startswith('//'):
            continue
        body = line.split('/*')[0]
        if 'ps4rf_kread_run(' not in body:
            continue
        # the definition is `int ps4rf_kread_run(...)`; a call passes something, e.g. `&g_kread`
        definition = re.search(r'\bint\s+ps4rf_kread_run\s*\(', body)
        if definition:
            continue
        hits.append(body.strip())
    return hits


def test_the_final_build_has_exactly_the_named_production_kread_call_sites(tmp_path):
    """One caller per path, and the session loop reaches neither -- proven on the tree and a mutant.

    W15R2 sharpening (owner brief: "resident bootstrap -> determine the current boot identity once
    -> store lifetime_boot_id", no per-session kernel read): there are exactly TWO call sites
    in the target, and each is named and pinned by this test --
      * the wired provider's request path in ``ps4rf_stub.c`` (one call, the only request-driven
        read), and
      * the fixed lifetime boot-binding step inside ``ps4rf_kread_boot_binding`` in
        ``ps4rf_kread.c`` (one call, no request, a compile-time row of the generated table).

    W16 option B restatement (owner decision 2026-10-07): the module now carries a SECOND fixed step
    -- the binding-window fingerprint step, ``ps4rf_kread_identity_next`` -- so the tree has exactly
    THREE named call sites. Track A restatement (same owner decision, observation half): the
    observation-window step ``ps4rf_kread_obs_next`` is the THIRD fixed step, so the tree has exactly
    FOUR named call sites (request path + boot binding + binding windows + observation windows).
    That is a deliberate widening of *what the module may do*, not of what a session may trigger:
    each step is called by the agent's fixed step, spends its own one shot in exactly one read, and
    no handler and no request reaches it. What must NOT change is the property this gate is really
    about: the agent and the resident daemon hold no call site at all, so no session loop and no
    daemon state can trigger a privileged transition.
    """
    real = _call_sites(AGENT_C.read_text())
    provider = _call_sites((TARGET / 'ps4rf_stub.c').read_text())
    assert len(provider) == 1, provider                     # the provider calls it exactly once
    assert real == []                                       # the agent never reaches the provider

    daemon = _call_sites((TARGET / 'ps4rf_daemon.c').read_text())
    assert daemon == [], daemon                             # the daemon calls no run path

    module = _call_sites((TARGET / 'ps4rf_kread.c').read_text())
    assert len(module) == 3, module                         # the three fixed lifetime steps
    assert all('ps4rf_kread_run(info,' in line for line in module), module
    binding = (TARGET / 'ps4rf_kread.c').read_text()
    at_binding = binding.index('int ps4rf_kread_boot_binding(')
    at_identity = binding.index('int ps4rf_kread_identity_next(')
    assert binding.index('ps4rf_kread_run(info, (uint32_t)PS4RF_KREAD_BOOTTIME_ROW') > at_binding, \
        'the first call site must live inside ps4rf_kread_boot_binding (the boot step)'
    assert binding.index('ps4rf_kread_run(info, row_index, 0u, PS4RF_KREAD_IDENTITY_LEN)') > at_identity, \
        'the second call site must live inside ps4rf_kread_identity_next (the W16 window step)'
    at_obs = binding.index('int ps4rf_kread_obs_next(')
    assert binding.index('ps4rf_kread_run(info, row_index, 0u, length)') > at_obs, \
        'the third call site must live inside ps4rf_kread_obs_next (the Track A observation step)'

    allowed = (TARGET / 'ps4rf_kread.c').name, (TARGET / 'ps4rf_stub.c').name
    everything = [(path.name, line) for path in TARGET.glob('*.c')
                  for line in _call_sites(path.read_text())]
    assert len(everything) == 4, everything                 # exactly these, nowhere else
    assert {name for name, _line in everything} == set(allowed), everything
    per_file = {name: sum(1 for n, _l in everything if n == name) for name in allowed}
    assert per_file == {(TARGET / 'ps4rf_stub.c').name: 1,
                        (TARGET / 'ps4rf_kread.c').name: 3}, per_file
    assert all('ps4rf_kread_run(&' in line or 'ps4rf_kread_run(info,' in line
               for _name, line in everything)

    # a second caller is caught: the mutant is the gate's own failure mode
    deviant = (TARGET / 'ps4rf_agent.c').read_text().replace(
        'PS4RF_AGENT_VERSION', 'PS4RF_AGENT_VERSION')
    deviant = deviant.replace('int ps4rf_agent_dispatch', 'int ps4rf_agent_second_path(ps4rf_kread_info *i)', 1)
    tree = _deviant_tree(tmp_path / 'second', source=deviant + '\nvoid second_caller(void)\n{\n'
                         '    uint32_t r = ps4rf_kread_run(0, 0, 16, 0);\n    (void)r;\n}\n')
    mutant_agent = [line for path in tree.glob('*.c') if path.name == AGENT_C.name
                    for line in _call_sites(path.read_text())]
    assert mutant_agent != [], 'a call site in the agent must be caught by this gate'


def test_the_agent_version_comes_from_the_constant(tmp_path):
    """The HELLO string is the constant, not a literal, and the manifest gate is what says so."""
    from native.target.build_manifest import agent_version_gate

    source = AGENT_C.read_text()
    assert 'jval_new_string(PS4RF_AGENT_VERSION)' in source
    assert 'ps4rfd-target-w15' in AGENT_H.read_text()
    # no HELLO literal anywhere: the only mention of a version string in the agent is the constant
    assert re.search(r'jval_new_string\("ps4rfd-target', source) is None
    assert agent_version_gate(REPO)['problems'] == []
