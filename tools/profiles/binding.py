#!/usr/bin/env python3
"""PS4RF P4/W5 boot/runtime binding and the runtime probe contract.

Profile facts are persistent; a *runtime* binding is not. A ``BootBinding`` ties one
profile hash to one ``boot_id`` (facts survive a reboot, the binding does not), and a
``RuntimeBinding`` resolves locators to runtime addresses as

    runtime address = profile locator (relative) + runtime base of the module

so no absolute address ever enters a profile. The probe contract is *specified and
validated* here but never executed: W5 defines the sequence and the fail-closed rules
(no writes, bounded reads) that W7/P5 will drive on site.

Usage::

    python tools/profiles/binding.py --self-test

Exit codes: 0 = all checks passed, 1 = failed, 2 = usage error.
"""

from __future__ import annotations

import pathlib
import sys
from dataclasses import dataclass, field

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:  # allow direct script execution
    sys.path.insert(0, str(REPO_ROOT))

from tools.profiles import regions                                          # noqa: E402
from tools.profiles.kread import KReadReject                                 # noqa: E402
from tools.profiles.schema import (  # noqa: E402
    BOOT_BINDING_MISMATCH, LOCATOR_MISMATCH, LOCATOR_MISSING, PROFILE_UNVERIFIED,
    UNRESOLVED, canonical_profile_sha256, unresolved_facts,
)

MAX_PROBE_BYTES = 4096
PROBE_STEPS = ('profile_fact', 'boot_binding', 'runtime_base', 'locator', 'bounded_read',
               'signature_section_check', 'runtime_binding')


class BindingError(Exception):
    """Fail-closed refusal with precondition codes."""

    def __init__(self, codes: tuple[str, ...], detail: str = ''):
        super().__init__(f'{"+".join(codes)}{": " + detail if detail else ""}')
        self.codes = codes
        self.detail = detail


@dataclass(frozen=True)
class BootBinding:
    boot_id: str
    profile_sha256: str
    facts_persistent: bool = True

    @classmethod
    def from_profile(cls, doc: dict, boot_id: str) -> 'BootBinding':
        if not boot_id:
            raise BindingError((BOOT_BINDING_MISMATCH,), 'boot_id is required')
        return cls(boot_id=boot_id, profile_sha256=canonical_profile_sha256(doc), facts_persistent=True)

    def valid_for(self, boot_id: str, profile_sha256: str) -> bool:
        return self.boot_id == boot_id and self.profile_sha256 == profile_sha256


@dataclass(frozen=True)
class RuntimeBinding:
    boot_id: str
    profile_sha256: str
    resolved: dict = field(default_factory=dict)   # operation -> {address, module, section, permissions}
    probe_complete: bool = False

    def address_for(self, operation: str) -> int | None:
        entry = self.resolved.get(operation)
        return None if entry is None else entry['address']


def create_runtime_binding(doc: dict, boot_binding: BootBinding, module_bases: dict,
                           current_boot_id: str, *, operations=None) -> RuntimeBinding:
    """Resolve locators to runtime addresses. Fail-closed on any deviation."""
    sha = canonical_profile_sha256(doc)
    if boot_binding is None or not boot_binding.valid_for(current_boot_id, sha):
        raise BindingError((BOOT_BINDING_MISMATCH,),
                           'boot binding is not valid for this boot/profile '
                           '(facts persist, the runtime binding must be recreated)')
    if unresolved_facts(doc):
        raise BindingError((PROFILE_UNVERIFIED,), 'profile still carries unresolved facts')

    policy = doc.get('operation_policy') or {}
    locators = doc.get('locators') or {}
    ops = tuple(operations) if operations is not None else tuple(policy)
    resolved: dict = {}
    for op in ops:
        entry = policy.get(op)
        if not entry or not entry.get('profile_required'):
            continue
        ref = entry.get('locator_ref')
        loc = locators.get(ref)
        if loc is None:
            raise BindingError((LOCATOR_MISSING,), f'{op}: locator {ref!r} missing')
        module = loc.get('module')
        base = module_bases.get(module)
        if base is None:
            raise BindingError((LOCATOR_MISSING,), f'{op}: no runtime base for module {module!r}')
        if not isinstance(base, int) or isinstance(base, bool) or base < 0:
            raise BindingError((LOCATOR_MISMATCH,), f'{op}: runtime base {base!r} is not an address')
        value = (loc.get('locator') or {}).get('value')
        if value == UNRESOLVED:
            raise BindingError((PROFILE_UNVERIFIED,), f'{op}: locator value unresolved')
        # W12-RVA0-BINDING: runtime resolution is checked arithmetic under the runtime rules.
        # The locator value may be 0 (image_elf sits at the image base); the resolved runtime
        # address may not be 0, must be canonical and must not overflow.
        try:
            address = regions.checked_kernel_address(base, value)
        except KReadReject as exc:
            raise BindingError((LOCATOR_MISMATCH,),
                               f'{op}: runtime resolution refused: {exc}') from None
        resolved[op] = {
            'address': address,
            'module': module,
            'section': loc.get('section'),
            'permissions': loc.get('permissions'),
        }
    return RuntimeBinding(boot_id=current_boot_id, profile_sha256=sha, resolved=resolved,
                          probe_complete=False)


# --- runtime probe contract ----------------------------------------------------------
def validate_probe_plan(plan: dict) -> list[str]:
    """A probe plan may only read, and only a bounded amount. Returns violations."""
    errors: list[str] = []
    if plan.get('mode') != 'read':
        errors.append('probe mode must be read (no writes, ever)')
    if plan.get('writes'):
        errors.append('a probe plan must not contain writes')
    size = plan.get('read_size')
    if not isinstance(size, int) or isinstance(size, bool) or size < 1:
        errors.append('read_size must be a positive integer')
    elif size > MAX_PROBE_BYTES:
        errors.append(f'read_size {size} exceeds the probe bound {MAX_PROBE_BYTES}')
    for key in ('operation', 'module', 'locator_kind', 'section', 'permissions'):
        if not plan.get(key):
            errors.append(f'plan is missing {key!r}')
    if plan.get('locator_kind') not in ('rva', 'relative'):
        errors.append('locator_kind must be rva or relative (an absolute address is not a fact)')
    return errors


def apply_probe_result(plan: dict, observation: dict, boot_binding: BootBinding,
                       doc: dict, current_boot_id: str) -> RuntimeBinding:
    """Turn one probe observation into a RuntimeBinding - or fail closed.

    Purely functional: the observation is supplied by the caller (a future on-site
    run); nothing here touches a console, and any deviation refuses the binding.
    """
    errors = validate_probe_plan(plan)
    if errors:
        raise BindingError((LOCATOR_MISMATCH,), '; '.join(errors))
    if observation.get('writes'):
        raise BindingError((LOCATOR_MISMATCH,), 'observation reports writes; probes are read-only')

    op = plan['operation']
    loc = (doc.get('locators') or {}).get((doc.get('operation_policy') or {})
                                          .get(op, {}).get('locator_ref'))
    if loc is None:
        raise BindingError((LOCATOR_MISSING,), f'{op}: locator missing')
    if loc.get('module') != plan['module']:
        raise BindingError((LOCATOR_MISMATCH,), f'{op}: module mismatch')
    if loc.get('section') != plan['section']:
        raise BindingError((LOCATOR_MISMATCH,), f'{op}: section mismatch')
    if loc.get('permissions') != plan['permissions']:
        raise BindingError((LOCATOR_MISMATCH,), f'{op}: permissions mismatch')
    expected = (loc.get('expected_bytes') or {}).get('hex')
    observed = observation.get('bytes_hex')
    if expected and observed is not None and expected != observed:
        raise BindingError((LOCATOR_MISMATCH,), f'{op}: signature mismatch '
                                               '(observed bytes differ from the expected fact)')
    if not observation.get('section_ok', False):
        raise BindingError((LOCATOR_MISMATCH,), f'{op}: section check failed')

    binding = create_runtime_binding(doc, boot_binding, {plan['module']: observation.get('runtime_base')},
                                     current_boot_id, operations=(op,))
    return RuntimeBinding(boot_id=binding.boot_id, profile_sha256=binding.profile_sha256,
                          resolved=binding.resolved, probe_complete=True)


def _self_test() -> list[str]:
    from tools.profiles import schema as S  # noqa: PLC0415

    checks: list[str] = []
    doc = S.empty_profile('fw-fixture', fixture=True,
                          locator_values={op: 4096 for op in S.privilege_gated_ops()})
    for loc in doc['locators'].values():
        loc['section'] = '.text'
        loc['permissions'] = 'r-x'
    doc['target'].update({'firmware_version': '13.52', 'firmware_build_id': 'FIXTURE-BUILD',
                          'model_family': 'PS4', 'hardware_revision': 'FIXTURE-REV'})
    errors = S.validate_profile(doc)
    if errors:
        checks += [f'fixture profile invalid: {e}' for e in errors]
        return checks

    binding = BootBinding.from_profile(doc, 'BOOT-AAA')
    if not binding.valid_for('BOOT-AAA', canonical_profile_sha256(doc)):
        checks.append('boot binding must be valid for its own boot/profile')
    if binding.valid_for('BOOT-BBB', canonical_profile_sha256(doc)):
        checks.append('boot binding must not be valid for another boot')
    runtime = create_runtime_binding(doc, binding, {'kernel': 4096}, 'BOOT-AAA',
                                     operations=('kernel.read',))
    if runtime.address_for('kernel.read') != 8192:
        checks.append('runtime address must be base + locator (8192)')
    if 'address' in str(doc.get('locators')):
        checks.append('profile must not carry runtime addresses')
    bad = validate_probe_plan({'mode': 'write', 'writes': ['x'], 'read_size': 8, 'operation': 'kernel.read',
                               'module': 'kernel', 'locator_kind': 'rva', 'section': '.text',
                               'permissions': 'r-x'})
    if not bad:
        checks.append('probe plan with writes must be refused')
    too_big = validate_probe_plan({'mode': 'read', 'read_size': MAX_PROBE_BYTES + 1, 'operation': 'kernel.read',
                                   'module': 'kernel', 'locator_kind': 'rva', 'section': '.text',
                                   'permissions': 'r-x'})
    if not too_big:
        checks.append('oversized probe must be refused')
    plan = {'mode': 'read', 'read_size': 16, 'operation': 'kernel.read', 'module': 'kernel',
            'locator_kind': 'rva', 'section': '.text', 'permissions': 'r-x'}
    if validate_probe_plan(plan):
        checks.append('valid probe plan must pass')
    obs = {'runtime_base': 4096, 'bytes_hex': None, 'section_ok': True}
    result = apply_probe_result(plan, obs, binding, doc, 'BOOT-AAA')
    if not result.probe_complete:
        checks.append('probe result must be a complete runtime binding')
    try:
        apply_probe_result(plan, {'runtime_base': 4096, 'section_ok': False}, binding, doc, 'BOOT-AAA')
    except BindingError as exc:
        if LOCATOR_MISMATCH not in exc.codes:
            checks.append('failed section check must be LOCATOR_MISMATCH')
    else:
        checks.append('failed section check must refuse the binding')
    return checks


def main(argv: list[str]) -> int:
    if '--self-test' not in argv:
        print((__doc__ or '').strip().splitlines()[0])
        print('usage: binding.py --self-test')
        return 2
    failures = _self_test()
    if failures:
        print(f'binding self-test: {len(failures)} FAILED')
        for item in failures:
            print(f'  - {item}')
        return 1
    print('binding self-test: boot/runtime binding and probe contract OK (read-only, bounded, fail-closed)')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
