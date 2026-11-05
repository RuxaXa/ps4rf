#!/usr/bin/env python3
"""PS4RF P4/W5 -> W4 adapter: the profile part of the gate decision, nothing else.

W5 feeds **only** the profile-related input of the W4 capability gate. The adapter
translates a W5 precondition verdict into the ``profile_binding`` shape the W4 gate
consumes and returns both decisions side by side, so the seam stays visible:

    before W5:  PROFILE_UNBOUND + NOT_WIRED      (nothing bound yet)
    after W5:   NOT_WIRED                        (bound, still not executable)
    always:     executable == False, wire == OPERATION_DEFERRED

The W4 gate module is not modified by W5: any failing W5 code (including a perfect
match that is not evidence-backed) collapses into the single W4 reason
``PROFILE_UNBOUND``; the W5 code itself stays visible in the binding and in the gate's
detail lines. A profile match never legitimises a mock provider: that decision belongs
to the W4 provider policy (finding F11).

Usage::

    python tools/profiles/w4_adapter.py --self-test

Exit codes: 0 = all checks passed, 1 = failed, 2 = usage error.
"""

from __future__ import annotations

import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:  # allow direct script execution
    sys.path.insert(0, str(REPO_ROOT))

from tools.primitive_iface.gate import GateContext, REQ_BY_OP, gate_for  # noqa: E402
from tools.profiles.schema import (  # noqa: E402
    BOOT_BINDING_MISMATCH, LOCATOR_MISMATCH, LOCATOR_MISSING, PROFILE_BINDING_MISSING,
    PROFILE_MATCH, PROFILE_MISMATCH, PROFILE_UNVERIFIED, UNRESOLVED, ProfileVerdict,
    profile_preconditions,
)

W4_PROFILE_REASON = 'PROFILE_UNBOUND'

# W5 code -> W4 reason. Every failure collapses into the single W4 profile reason;
# PROFILE_MATCH is the only code that can satisfy it.
PROFILE_CODE_TO_W4_REASON = {
    PROFILE_BINDING_MISSING: W4_PROFILE_REASON,
    PROFILE_MISMATCH: W4_PROFILE_REASON,
    PROFILE_UNVERIFIED: W4_PROFILE_REASON,
    BOOT_BINDING_MISMATCH: W4_PROFILE_REASON,
    LOCATOR_MISSING: W4_PROFILE_REASON,
    LOCATOR_MISMATCH: W4_PROFILE_REASON,
    PROFILE_MATCH: None,
}

HANDOFF = {
    'w5_provides': [
        'a validated profile document with a canonical sha256',
        'precondition codes: PROFILE_MATCH / PROFILE_MISMATCH / PROFILE_UNVERIFIED / '
        'LOCATOR_MISSING / LOCATOR_MISMATCH / BOOT_BINDING_MISMATCH / PROFILE_BINDING_MISSING',
        'a boot binding (boot_id + profile sha256) and, later, a runtime binding',
    ],
    'w5_never_provides': [
        'an executable operation, a removed NOT_WIRED reason, raised capability assurance',
        'verification evidence, a runtime reachability claim, or a capability derived '
        'from a symbol/RVA',
    ],
}


def profile_field_set(op: str) -> dict:
    """The profile fields the W4 matrix expects for one operation."""
    req = REQ_BY_OP.get(op)
    if req is None:
        raise ValueError(f'{op} is not a gated operation')
    # Values are supplied per call at bind time; the binding provides the field set.
    return {name: UNRESOLVED for name in req.profile_fields}


def profile_binding_for_gate(op: str, verdict: ProfileVerdict, *,
                             require_evidence_backed: bool = True) -> dict:
    """Translate a W5 verdict into the W4 ``profile_binding`` input (fail-closed)."""
    satisfied = verdict.matched and (verdict.evidence_backed or not require_evidence_backed)
    binding = {
        'present': bool(satisfied),
        'sha256': verdict.profile_sha256 if satisfied else None,
        'fields': profile_field_set(op) if satisfied else {},
        'verdict': list(verdict.codes),
        'evidence_backed': verdict.evidence_backed,
        'requires_evidence_backed': require_evidence_backed,
    }
    return binding


def evaluate(op: str, *, doc: dict | None = None, boot_binding=None, current_boot_id: str | None = None,
             requests: tuple = (), require_evidence_backed: bool = True, **gate_kwargs):
    """Return (W4 decision, W5 verdict) for one gated operation."""
    verdict = profile_preconditions(doc, requests=requests, boot_binding=boot_binding,
                                    current_boot_id=current_boot_id)
    binding = profile_binding_for_gate(op, verdict, require_evidence_backed=require_evidence_backed)
    decision = gate_for(op, GateContext(profile_binding=binding, **gate_kwargs))
    return decision, verdict


def _self_test() -> list[str]:
    from tools.profiles.schema import empty_profile, privilege_gated_ops  # noqa: PLC0415

    checks: list[str] = []
    doc = empty_profile('fw-adapter-selftest', fixture=True,
                        locator_values={op: 4096 for op in privilege_gated_ops()})
    for loc in doc['locators'].values():
        loc['section'] = '.text'
        loc['permissions'] = 'r-x'
    verdict = profile_preconditions(doc)
    if PROFILE_UNVERIFIED not in verdict.codes:
        checks.append(f'a skeleton profile must be PROFILE_UNVERIFIED, got {verdict.codes}')
    if BOOT_BINDING_MISMATCH not in verdict.codes:
        checks.append(f'a skeleton without a boot binding must fail the binding, got {verdict.codes}')
    binding = profile_binding_for_gate('kernel.read', verdict)
    if binding['present']:
        checks.append('a non-evidence-backed verdict must not present a binding')
    decision = gate_for('kernel.read', GateContext(profile_binding=binding))
    if W4_PROFILE_REASON not in decision.reasons or 'NOT_WIRED' not in decision.reasons:
        checks.append(f'pre-W5 state must be PROFILE_UNBOUND + NOT_WIRED, got {decision.reasons}')
    if decision.executable or decision.wire_code != 'OPERATION_DEFERRED':
        checks.append('adapter must never produce an executable decision')
    return checks


def main(argv: list[str]) -> int:
    if '--self-test' not in argv:
        print((__doc__ or '').strip().splitlines()[0])
        print('usage: w4_adapter.py --self-test')
        return 2
    failures = _self_test()
    if failures:
        print(f'w4 adapter self-test: {len(failures)} FAILED')
        for item in failures:
            print(f'  - {item}')
        return 1
    print('w4 adapter self-test: OK (profile part only, fail-closed, never executable)')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
