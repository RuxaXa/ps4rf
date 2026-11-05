#!/usr/bin/env python3
"""PS4RF P4/W3 primitive interface freeze v1 - normative operation table.

Single source of truth for the native provider surface: every registry operation
(``core/rpc/registry.py``) is mapped to exactly one provider interface with strict
request/response schemas, a capability binding and an explicit implementation
status. ``docs/P4-PRIMITIVE-INTERFACES.md`` carries the prose contract and the
human-readable inventory table; a test cross-checks both against this module and
against the frozen core registry, so the freeze cannot drift silently.

Evidence sources (no field value is invented where a source exists):
* operation set, capability binding, ``mutating``, ``recovery_safe`` -
  ``core/rpc/registry.py`` (frozen core, read by ``--self-test``).
* message envelope (``header.request_id`` / ``header.in_reply_to`` /
  ``status`` / ``result`` / ``error``) -
  ``docs/spec-history/Pasted_text(5).txt`` l.953-967, pinned by
  ``tests/fixtures/parity/vectors-v1.json`` frames.
* mock op semantics (``session.ping``, ``session.status``, ``memory.alloc``,
  ``memory.free``, ``mock.hang``, ``mock.leak``, ``experiment.load``, unknown op) -
  ``docs/spec-history/Pasted_text(4).txt`` l.968-1032.
* sync creation without empty ref (B12) and cleanup on destroy -
  ``docs/spec-history/Pasted_text(10).txt`` l.272-288, gate semantics
  ``Pasted_text(20261005-115353).txt`` l.99.
* ``kernel.snapshot`` explicit-range contract (range policy, SHA-256 compare,
  ``PROFILE_MISMATCH``, zeroize, no bytes in error details) -
  ``docs/spec-history/Pasted_text(2).txt`` l.418-435.
* profile-bound values only, never hardcoded RVAs -
  ``docs/spec-history/Pasted_text(20261005-115353).txt`` l.52/l.223.

Field-level schemas for the privileged families are the **P4/W3 interface freeze**
(in-repo property, D12-style): no historical byte identity is claimed for them and
no concrete address/signature value appears here - those live in profiles (W5).

Usage::

    python tools/primitive_iface/schema.py --self-test

Exit codes: 0 = consistent, 1 = inconsistent (reasons printed), 2 = usage/IO error.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys
from dataclasses import dataclass, field

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SCHEMA_VERSION = 'ps4rf.primitive-interface.v1'

# --- implementation status ----------------------------------------------------------
STATUS_STUB = 'stub'                     # implemented in the host-side W3 stub
STATUS_DEFER_PRIVILEGE = 'deferred-privilege'   # interface frozen, needs section 70 + hardware
STATUS_DEFER_CHAIN = 'deferred-host-chain'      # needs the verification/grant chain (W7)
STATUS_MOCK = 'mock-only'                # fault-injection surface of the mock, not a primitive

DEFERRAL_REASONS = {
    STATUS_DEFER_PRIVILEGE: (
        'interface frozen in W3; implementation requires the section 70 capability gate '
        'and on-site hardware/profile binding (W4/P5)'),
    STATUS_DEFER_CHAIN: (
        'interface frozen in W3; implementation requires the host verification->grant chain '
        'and a Core integration finding (W7)'),
    STATUS_MOCK: (
        'fault-injection operation of the mock reference used by the parity harness; '
        'not part of the native provider surface'),
}

# --- error codes ---------------------------------------------------------------------
ERROR_CODES = frozenset({
    'ARGUMENT_INVALID',
    'OPERATION_UNSUPPORTED',
    'OPERATION_DEFERRED',
    'SESSION_RECOVERY_REQUIRED',
    'RESOURCE_STATE_INVALID',
    'RESOURCE_DESTROYED',
    'RESOURCE_LIMIT',
    'TOO_MANY_INFLIGHT',
    'PROFILE_MISMATCH',
    'CAPABILITY_REQUIRED',
    'INTERNAL_ERROR',
})
# explicitly marked as a W3 addition: the spec only knows OPERATION_UNSUPPORTED
NEW_ERROR_CODES = {
    'OPERATION_DEFERRED': (
        'P4/W3 addition: the operation exists with a frozen interface but its '
        'implementation is gated (section 70 / host chain / mock-only). Distinct from '
        'OPERATION_UNSUPPORTED, which stays "no such operation".'),
}

CLEANUP_STATES = ('PENDING', 'COMPLETE', 'PARTIAL')
REF_PATTERN = re.compile(r'^[a-z][a-z0-9_]*:[0-9A-F]{16}$')
HEX32 = re.compile(r'^[0-9a-f]{64}$')

# privilege class: the namespaces the frozen core requires PROVEN for
PRIVILEGED_NAMESPACES = ('kernel', 'gpuvm', 'keymgr', 'ccp', 'samu', 'pup', 'eap', 'sbram', 'emc', 'secure')


@dataclass(frozen=True)
class Field:
    name: str
    type: str                # int|str|bool|ref|hex32|array|object
    required: bool = True
    note: str = ''


@dataclass(frozen=True)
class Op:
    op: str
    family: str
    status: str
    capability: str | None
    mutating: bool
    recovery_safe: bool
    args: tuple[Field, ...] = ()
    result: tuple[Field, ...] | None = ()
    errors: tuple[str, ...] = ()
    source: str = ''
    defer_reason: str = ''
    result_frame: str = 'RESPONSE'
    flags_since: str = 'core/rpc/registry.py (frozen)'


def f(name, type_, required=True, note=''):
    return Field(name, type_, required, note)


# --- the 36 registry operations ------------------------------------------------------
OPS: tuple[Op, ...] = (
    # session / telemetry (recovery_safe, read-only web contract)
    Op('session.ping', 'session', STATUS_STUB, None, False, True,
       args=(), result=(f('pong', 'bool'), f('seq', 'int', False, 'echo of the request seq')),
       errors=('ARGUMENT_INVALID',),
       source='Pasted_text(4).txt l.979-981'),
    Op('session.status', 'session', STATUS_STUB, None, False, True,
       args=(), result=(f('session_state', 'str'), f('mutating_allowed', 'bool'),
                        f('held_resources', 'array', False)),
       errors=('ARGUMENT_INVALID',),
       source='Pasted_text(4).txt l.982-987'),
    Op('session.shutdown', 'session', STATUS_STUB, None, False, True,
       args=(f('capability', 'str', True, 'must be exactly "session.admin"'),),
       result=(f('status', 'str', True, '"ACCEPTED"'),),
       errors=('ARGUMENT_INVALID', 'CAPABILITY_REQUIRED'),
       source='W14 §15 (owner instruction, wire catalogue revision R4): an authenticated admin '
              'shutdown inside an ACTIVE session -- block new sessions, clean up, flush, BYE '
              'ADMIN_SHUTDOWN, exit; it changes no kernel state, triggers no reboot, reaches no '
              'loader and installs no persistence'),
    Op('telemetry.read', 'telemetry', STATUS_STUB, None, False, True,
       args=(), result=(f('session_state', 'str'), f('inflight', 'int', False),
                        f('held_resources', 'array', False)),
       errors=('ARGUMENT_INVALID',),
       source='Pasted_text(20261005-115353).txt l.88 (recovery_safe set)'),
    # memory
    Op('memory.alloc', 'memory', STATUS_STUB, 'memory.alloc', True, False,
       args=(f('size', 'int', True, '1..1048576 bytes'), f('alignment', 'int', False, 'power of two')),
       result=(f('ref', 'ref', True, 'mem:<16 hex>'),),
       errors=('ARGUMENT_INVALID', 'RESOURCE_LIMIT', 'SESSION_RECOVERY_REQUIRED'),   # core freezes the arg set, not the result fields
       source='Pasted_text(4).txt l.988-998 + parity catalog arguments {size:4096}',
       result_frame='RESPONSE'),
    Op('memory.free', 'memory', STATUS_STUB, 'memory.free', True, False,
       args=(f('ref', 'ref', True),),
       result=(f('freed', 'ref'),),
       errors=('ARGUMENT_INVALID', 'RESOURCE_STATE_INVALID', 'SESSION_RECOVERY_REQUIRED'),
       source='Pasted_text(4).txt l.999-1008'),
    # sync (gate = manual research window, barrier = participants; B12)
    Op('sync.gate.create', 'sync', STATUS_STUB, None, True, False,
       args=(f('parties', 'int', True, '>= 1'),),
       result=(f('gate', 'ref'),),
       errors=('ARGUMENT_INVALID', 'RESOURCE_LIMIT'),
       source='Pasted_text(10).txt l.272-280 (B12)'),
    Op('sync.gate.arrive', 'sync', STATUS_STUB, None, True, False,
       args=(f('gate', 'ref', True),),
       result=(f('registered', 'bool'), f('participants', 'int', False)),
       errors=('ARGUMENT_INVALID', 'RESOURCE_STATE_INVALID', 'RESOURCE_DESTROYED'),
       source='Pasted_text(20261005-115353).txt l.99 (unique participant)'),
    Op('sync.gate.wait', 'sync', STATUS_STUB, None, True, False,
       args=(f('gate', 'ref', True), f('timeout_ms', 'int', False)),
       result=(f('released', 'bool'),),
       errors=('ARGUMENT_INVALID', 'RESOURCE_STATE_INVALID', 'RESOURCE_DESTROYED', 'INTERNAL_ERROR'),
       source='Pasted_text(20261005-115353).txt l.99 (release only via sync.gate.release)'),
    Op('sync.gate.status', 'sync', STATUS_STUB, None, True, False,
       args=(f('gate', 'ref', True),),
       result=(f('participants', 'int'), f('released', 'bool'), f('destroyed', 'bool')),
       errors=('ARGUMENT_INVALID', 'RESOURCE_STATE_INVALID'),
       source='P4/W3 interface freeze'),
    Op('sync.gate.release', 'sync', STATUS_STUB, None, True, False,
       args=(f('gate', 'ref', True),),
       result=(f('released', 'bool'),),
       errors=('ARGUMENT_INVALID', 'RESOURCE_STATE_INVALID', 'RESOURCE_DESTROYED'),
       source='Pasted_text(20261005-115353).txt l.99'),
    Op('sync.gate.destroy', 'sync', STATUS_STUB, None, True, False,
       args=(f('gate', 'ref', True),),
       result=(f('destroyed', 'bool', True, 'waiters receive RESOURCE_DESTROYED, never success'),),
       errors=('ARGUMENT_INVALID', 'RESOURCE_STATE_INVALID'),
       source='Pasted_text(20261005-115353).txt l.99 + Pasted_text(10).txt l.282-288'),
    Op('sync.barrier.create', 'sync', STATUS_STUB, None, True, False,
       args=(f('parties', 'int', True, '>= 1'),),
       result=(f('barrier', 'ref'),),
       errors=('ARGUMENT_INVALID', 'RESOURCE_LIMIT'),
       source='Pasted_text(10).txt l.272-280 (B12 applies to gate and barrier alike)'),
    Op('sync.barrier.wait', 'sync', STATUS_STUB, None, True, False,
       args=(f('barrier', 'ref', True), f('timeout_ms', 'int', False)),
       result=(f('released', 'bool'),),
       errors=('ARGUMENT_INVALID', 'RESOURCE_STATE_INVALID', 'RESOURCE_DESTROYED', 'INTERNAL_ERROR'),
       source='P4/W3 interface freeze'),
    Op('sync.barrier.release', 'sync', STATUS_STUB, None, True, False,
       args=(f('barrier', 'ref', True),),
       result=(f('released', 'bool'),),
       errors=('ARGUMENT_INVALID', 'RESOURCE_STATE_INVALID', 'RESOURCE_DESTROYED'),
       source='P4/W3 interface freeze'),
    Op('sync.barrier.destroy', 'sync', STATUS_STUB, None, True, False,
       args=(f('barrier', 'ref', True),),
       result=(f('destroyed', 'bool', True, 'waiters receive RESOURCE_DESTROYED, never success'),),
       errors=('ARGUMENT_INVALID', 'RESOURCE_STATE_INVALID'),
       source='Pasted_text(10).txt l.282-288'),
    # experiment intake (host-side)
    Op('experiment.load', 'experiment', STATUS_STUB, None, True, False,
       args=(f('ir_sha256', 'hex32', True, 'sha256 of the canonical experiment IR'),),
       result=(f('accepted', 'hex32'),),
       errors=('ARGUMENT_INVALID', 'TOO_MANY_INFLIGHT'),
       source='Pasted_text(4).txt l.1024-1027 + parity catalog error frame'),
    # mock-only fault injection (parity harness target, not a primitive)
    Op('mock.hang', 'mock', STATUS_MOCK, None, True, False,
       args=(), result=None,
       errors=('INTERNAL_ERROR',),
       source='Pasted_text(4).txt l.1009-1018 (terminates with BYE RECOVERY_REQUIRED)',
       defer_reason=DEFERRAL_REASONS[STATUS_MOCK], result_frame='BYE'),
    Op('mock.block', 'mock', STATUS_MOCK, None, True, False,
       args=(f('release_gate', 'ref', False),), result=(f('blocked', 'bool'),),
       errors=('ARGUMENT_INVALID',),
       source='core/rpc/hang.py (MockHangReleased)', defer_reason=DEFERRAL_REASONS[STATUS_MOCK]),
    Op('mock.leak', 'mock', STATUS_MOCK, None, True, False,
       args=(), result=(f('leaked', 'bool'),),
       errors=('INTERNAL_ERROR',),
       source='Pasted_text(4).txt l.1019-1023', defer_reason=DEFERRAL_REASONS[STATUS_MOCK]),
    Op('mock.free_fail', 'mock', STATUS_MOCK, None, True, False,
       args=(f('ref', 'ref', False),), result=(f('forced', 'bool'),),
       errors=('ARGUMENT_INVALID', 'RESOURCE_STATE_INVALID'),
       source='core/resources/manager.py (force_cleanup_failure) + registry op set',
       defer_reason=DEFERRAL_REASONS[STATUS_MOCK]),
    # gpuvm (privileged namespace: PROVEN required by the frozen core)
    Op('gpuvm.map', 'gpuvm', STATUS_DEFER_PRIVILEGE, 'gpuvm.map', True, False,
       args=(f('gvm_id', 'int', True), f('va', 'int', True, 'aligned per profile'),
             f('size', 'int', True), f('prot', 'str', True, 'profile-bound enum')),
       result=(f('mapping', 'ref'),),
       errors=('ARGUMENT_INVALID', 'CAPABILITY_REQUIRED', 'PROFILE_MISMATCH', 'RESOURCE_LIMIT'),
       source='P4/W3 interface freeze (values from profiles, never hardcoded)',
       defer_reason=DEFERRAL_REASONS[STATUS_DEFER_PRIVILEGE]),
    Op('gpuvm.unmap', 'gpuvm', STATUS_DEFER_PRIVILEGE, 'gpuvm.unmap', True, False,
       args=(f('mapping', 'ref', True),), result=(f('unmapped', 'ref'),),
       errors=('ARGUMENT_INVALID', 'CAPABILITY_REQUIRED', 'RESOURCE_STATE_INVALID'),
       source='P4/W3 interface freeze', defer_reason=DEFERRAL_REASONS[STATUS_DEFER_PRIVILEGE]),
    Op('gpuvm.lookup', 'gpuvm', STATUS_DEFER_PRIVILEGE, 'gpuvm.lookup', True, False,
       args=(f('gvm_id', 'int', True), f('va', 'int', True)),
       result=(f('mapped', 'bool'), f('pa', 'int', False)),
       errors=('ARGUMENT_INVALID', 'CAPABILITY_REQUIRED'),
       source='P4/W3 interface freeze', defer_reason=DEFERRAL_REASONS[STATUS_DEFER_PRIVILEGE]),
    # keymgr
    Op('keymgr.claim', 'keymgr', STATUS_DEFER_PRIVILEGE, 'keymgr.claim', True, False,
       args=(f('slot', 'int', True, 'profile-bound slot index'),),
       result=(f('claim', 'ref'),),
       errors=('ARGUMENT_INVALID', 'CAPABILITY_REQUIRED', 'PROFILE_MISMATCH', 'RESOURCE_STATE_INVALID'),
       source='P4/W3 interface freeze', defer_reason=DEFERRAL_REASONS[STATUS_DEFER_PRIVILEGE]),
    Op('keymgr.release', 'keymgr', STATUS_DEFER_PRIVILEGE, 'keymgr.release', True, False,
       args=(f('claim', 'ref', True),), result=(f('released', 'ref'),),
       errors=('ARGUMENT_INVALID', 'CAPABILITY_REQUIRED', 'RESOURCE_STATE_INVALID'),
       source='P4/W3 interface freeze', defer_reason=DEFERRAL_REASONS[STATUS_DEFER_PRIVILEGE]),
    Op('keymgr.snapshot', 'keymgr', STATUS_DEFER_PRIVILEGE, 'keymgr.snapshot', True, False,
       args=(f('scope', 'str', False, 'profile-bound'),),
       result=(f('snapshot', 'ref'), f('sha256', 'hex32')),
       errors=('ARGUMENT_INVALID', 'CAPABILITY_REQUIRED', 'PROFILE_MISMATCH'),
       source='P4/W3 interface freeze', defer_reason=DEFERRAL_REASONS[STATUS_DEFER_PRIVILEGE]),
    # ccp
    Op('ccp.submit', 'ccp', STATUS_DEFER_PRIVILEGE, 'ccp.submit', True, False,
       args=(f('slot', 'int', True), f('command', 'str', True, 'profile-bound'),
             f('data', 'ref', False)),
       result=(f('submission', 'ref'),),
       errors=('ARGUMENT_INVALID', 'CAPABILITY_REQUIRED', 'PROFILE_MISMATCH', 'RESOURCE_LIMIT'),
       source='P4/W3 interface freeze', defer_reason=DEFERRAL_REASONS[STATUS_DEFER_PRIVILEGE]),
    # kernel (read-class ops stay mutating in the frozen core - see finding F8)
    # WIRE-CATALOG R2 (W13-C2): kernel.read takes the bounded region triplet, never an address.
    # The previous contract (addr:int, size:int, both required) demanded a raw kernel address
    # from host input, which the PS4RF security contract forbids -- the live W13-C1 attempt 2
    # proved it: the router refused the bounded triplet with ARGUMENT_INVALID and the operation
    # could not be driven at all. addr/address/va/kernel_va/ptr/source/size are therefore never
    # valid kernel.read arguments again; unknown fields keep failing closed in the generated
    # validator. Resolution stays target-side: region_index -> compile-time region table -> fixed
    # RVA -> checked offset -> checked length -> internal runtime VA. The operation, its
    # capability (kernel.read), its route (deferred privilege) and the wire framing are unchanged.
    Op('kernel.read', 'kernel', STATUS_DEFER_PRIVILEGE, 'kernel.read', True, False,
       args=(f('region_index', 'int', True), f('offset', 'int', True), f('length', 'int', True)),
       result=(f('data', 'str'), f('sha256', 'hex32')),
       errors=('ARGUMENT_INVALID', 'CAPABILITY_REQUIRED', 'PROFILE_MISMATCH'),
       source='P4/W3 interface freeze + WIRE-CATALOG R2: kernel.read bounded-region args',
       defer_reason=DEFERRAL_REASONS[STATUS_DEFER_PRIVILEGE]),
    Op('kernel.snapshot', 'kernel', STATUS_DEFER_PRIVILEGE, 'kernel.read', True, False,
       args=(f('range', 'str', True, 'explicit | region_ref'),
             f('addr', 'int', False, 'mandatory for explicit'),
             f('size', 'int', False, 'mandatory for explicit'),
             f('region_ref', 'str', False, 'mandatory for region_ref'),
             f('expected_sha256', 'hex32', False, 'mandatory for explicit, optional for region_ref')),
       result=(f('snapshot', 'ref'), f('sha256', 'hex32')),
       errors=('ARGUMENT_INVALID', 'CAPABILITY_REQUIRED', 'PROFILE_MISMATCH'),
       source='Pasted_text(2).txt l.418-435 (range policy, hash compare, zeroize on mismatch, '
              'no bytes in error details)',
       defer_reason=DEFERRAL_REASONS[STATUS_DEFER_PRIVILEGE]),
    # W17F: NEW operation; the frozen kernel.snapshot keeps its args contract byte for byte.
    Op('kernel.snapshot.recipe', 'kernel', STATUS_DEFER_PRIVILEGE, 'kernel.read', True, False,
       args=(f('recipe_ref', 'str', True, 'name of a generated profile recipe'),
             f('indices', 'array', False, 'one bounded index per declared indexed entry')),
       result=(f('cells', 'array'), f('sha256', 'hex32')),
       errors=('ARGUMENT_INVALID', 'CAPABILITY_REQUIRED', 'PROFILE_MISMATCH'),
       source='W17F: bounded recipe snapshot (16 entries, RVA_READ + FOLLOW_ONCE, one transition)',
       defer_reason=DEFERRAL_REASONS[STATUS_DEFER_PRIVILEGE]),
    Op('ioctl.invoke', 'ioctl', STATUS_DEFER_PRIVILEGE, 'ioctl.invoke', True, False,
       args=(f('command', 'int', True, 'allowlisted pup_update command'),
             f('blob', 'str', True, 'argument block, exact size fixed by policy'),
             f('mode', 'int', False, 'only for commands the policy declares as moded'),
             f('data', 'str', False,
               'bounded write payload the provider places in its OWN transfer buffer, whose '
               'address it writes into the policy-declared pointer field of the block: the '
               'caller never names an address')),
       result=(f('rc', 'int'), f('errno', 'int'), f('output', 'str')),
       errors=('ARGUMENT_INVALID', 'CAPABILITY_REQUIRED', 'PROFILE_MISMATCH'),
       source='W17F: generic bounded ioctl invoke (open / ioctl / close), policy target-side',
       defer_reason=DEFERRAL_REASONS[STATUS_DEFER_PRIVILEGE]),
    Op('kernel.dump.full', 'kernel', STATUS_DEFER_PRIVILEGE, 'kernel.dump.full', True, False,
       args=(), result=(f('dump', 'ref'), f('sha256', 'hex32')),
       errors=('CAPABILITY_REQUIRED', 'PROFILE_MISMATCH', 'RESOURCE_LIMIT'),
       source='P4/W3 interface freeze (full dump is a P5 privilege level)',
       defer_reason=DEFERRAL_REASONS[STATUS_DEFER_PRIVILEGE]),
    # verify.*
    Op('verify.userland.exec', 'verify', STATUS_DEFER_CHAIN, None, False, False,
       args=(f('probe', 'str', True), f('arguments', 'object', False)),
       result=(f('observed', 'object'), f('verified', 'bool')),
       errors=('ARGUMENT_INVALID', 'INTERNAL_ERROR'),
       source='core/models/verification.py (VerificationRecord -> grant)',
       defer_reason=DEFERRAL_REASONS[STATUS_DEFER_CHAIN]),
    Op('verify.kernel.read', 'verify', STATUS_DEFER_PRIVILEGE, None, False, False,
       args=(f('addr', 'int', True), f('expected', 'str', True)),
       result=(f('observed', 'str'), f('verified', 'bool')),
       errors=('ARGUMENT_INVALID', 'CAPABILITY_REQUIRED', 'PROFILE_MISMATCH'),
       source='P4/W3 interface freeze', defer_reason=DEFERRAL_REASONS[STATUS_DEFER_PRIVILEGE]),
    Op('verify.kernel.exec', 'verify', STATUS_DEFER_PRIVILEGE, None, False, False,
       args=(f('probe', 'str', True), f('arguments', 'object', False)),
       result=(f('observed', 'object'), f('verified', 'bool')),
       errors=('ARGUMENT_INVALID', 'CAPABILITY_REQUIRED', 'PROFILE_MISMATCH'),
       source='P4/W3 interface freeze', defer_reason=DEFERRAL_REASONS[STATUS_DEFER_PRIVILEGE]),
    Op('verify.kernel.copyout', 'verify', STATUS_DEFER_PRIVILEGE, None, False, False,
       args=(f('addr', 'int', True), f('size', 'int', True), f('expected', 'str', True)),
       result=(f('observed', 'str'), f('verified', 'bool')),
       errors=('ARGUMENT_INVALID', 'CAPABILITY_REQUIRED', 'PROFILE_MISMATCH'),
       source='P4/W3 interface freeze', defer_reason=DEFERRAL_REASONS[STATUS_DEFER_PRIVILEGE]),
    Op('verify.samu.access', 'verify', STATUS_DEFER_PRIVILEGE, None, False, False,
       args=(f('probe', 'str', True),),
       result=(f('observed', 'object'), f('verified', 'bool')),
       errors=('ARGUMENT_INVALID', 'CAPABILITY_REQUIRED', 'PROFILE_MISMATCH'),
       source='P4/W3 interface freeze (SAMU is a privileged namespace)',
       defer_reason=DEFERRAL_REASONS[STATUS_DEFER_PRIVILEGE]),
)

OPS_BY_NAME = {o.op: o for o in OPS}

# --- native provider registration proposal ------------------------------------------
# W7 wires the native agent as a provider. The frozen core has no NATIVE member in
# ProviderType (finding F7), so this is a *proposal* - nothing in the frozen core is
# touched by W3.
PROVIDER_RULE = {
    'provider_type': 'NATIVE',
    'provider_type_status': 'MISSING in core.models.common.ProviderType - finding F7',
    'max_assurance': 'OBSERVED',
    'availability_write': True,
    'availability_rank': 25,
    'rationale': (
        'cap at OBSERVED until P5 proves store-bound verification (W7 plan); '
        'availability_rank 25 sits above BOOTSTRAP (20) and below RUNTIME_PROBE/EXPLOIT (30): '
        'the agent observes the live console but a provider that owns its own primitive '
        'knows more about it'),
    'min_assurance_for_grant': {
        'inherited_from': 'core/models/capability.py default_authority()',
        'privileged': 'PROVEN', 'userland_and_memory': 'OBSERVED',
        'consequence': ('the native provider can carry memory/userland/sync capabilities at '
                        'OBSERVED, but no kernel/gpuvm/keymgr/ccp/samu capability is grantable '
                        'from it alone'),
    },
}

FINDINGS = (
    ('F7', 'ProviderType.NATIVE does not exist in the frozen core',
     'core/models/common.py ProviderType has FIRMWARE_PROFILE, BOOTSTRAP, EXPLOIT, '
     'RUNTIME_PROBE, MOCK, OPERATOR. Registering the native agent as a provider (W7) '
     'needs either a new enum member or a deliberate reuse of an existing type. '
     'W3 records the gap and the proposal (ProviderRule above); it does not change the core.'),
    ('F8', 'read-class kernel ops are mutating=True in the frozen registry',
     'core/rpc/registry.py registers kernel.read/snapshot/dump.full with the default '
     'mutating=True; the specified snapshot flow (Pasted_text(2).txt l.418-435) only reads '
     'and hashes. The native interface follows the frozen core (mutating=True) and records '
     'the discrepancy for the next planned core revision.'),
    ('F9', 'mock tolerates memory.alloc without arguments',
     'the mock handler ignores arguments (Pasted_text(4).txt l.988-998) while the canonical '
     'request in the parity catalog carries {size: 4096}. The native interface requires '
     'size, so a host that omits it gets ARGUMENT_INVALID instead of a silent allocation.'),
    ('F10', 'sync ops: spec draft vs frozen core flags',
     'Pasted_text(5).txt l.424-426 drafts sync.barrier.wait/release as mutating=False; '
     'core/rpc/registry.py registers all sync ops as mutating=True, recovery_safe=False. '
     'The native interface follows the frozen core; the difference is recorded, not patched.'),
    ('F11', 'mock evidence is admissible for privileged capabilities in the frozen authority table',
     'default_authority() gives MOCK max_assurance=PROVEN while the privileged namespaces '
     'require PROVEN, so a MOCK record could in principle meet the assurance bar. The W4 '
     'capability gate (tools/primitive_iface/gate.py) excludes MOCK for privileged '
     'capabilities by policy - mock success is not evidence about the console. Recorded, '
     'not patched: the frozen core stays unchanged.'),
)


def validate_structure() -> list[str]:
    """Structural self-check of this table (no core import needed)."""
    errors: list[str] = []
    names = [o.op for o in OPS]
    if len(names) != len(set(names)):
        errors.append('duplicate operation names in OPS')
    # W17F: parity against the authoritative registry source instead of a magic count. The import is
    # deliberately lazy so the module stays importable without core (see the docstring above).
    from core.rpc.registry import default_registry  # noqa: PLC0415
    registry_names = set(vars(default_registry())['_specs'])
    table_names = set(names)
    if table_names != registry_names:
        errors.append('schema/registry operation surfaces differ: '
                      f'only in registry={sorted(registry_names - table_names)} '
                      f'only in table={sorted(table_names - registry_names)}')
    for o in OPS:
        if o.status not in {STATUS_STUB, STATUS_DEFER_PRIVILEGE, STATUS_DEFER_CHAIN, STATUS_MOCK}:
            errors.append(f'{o.op}: unknown status {o.status}')
        if o.status != STATUS_STUB and not o.defer_reason:
            errors.append(f'{o.op}: missing deferral reason')
        if o.status != STATUS_STUB and o.status != STATUS_MOCK and o.result is None:
            errors.append(f'{o.op}: frozen interface must declare a result shape')
        for code in o.errors:
            if code not in ERROR_CODES:
                errors.append(f'{o.op}: unknown error code {code}')
        if o.capability is not None and o.status not in (STATUS_STUB, STATUS_DEFER_PRIVILEGE):
            errors.append(f'{o.op}: capability binding on a non-provider operation')
        for fl in o.args + (o.result or ()):
            if not fl.name or not fl.type:
                errors.append(f'{o.op}: malformed field {fl}')
        seen = set()
        for fl in o.args:
            if fl.name in seen:
                errors.append(f'{o.op}: duplicate argument {fl.name}')
            seen.add(fl.name)
    return errors


def check_against_core(registry=None) -> list[str]:
    """Cross-check the frozen core registry against this table."""
    errors: list[str] = []
    if registry is None:
        try:
            sys.path.insert(0, str(REPO_ROOT))
            from core.rpc.registry import default_registry  # noqa: PLC0415
        except Exception as exc:  # pragma: no cover - import environment
            return [f'cannot import the frozen core registry: {exc!r}']
        registry = default_registry()
    specs = getattr(registry, '_specs', {})
    core_names = set(specs)
    table_names = set(OPS_BY_NAME)
    for missing in sorted(core_names - table_names):
        errors.append(f'registry operation not mapped by W3: {missing}')
    for extra in sorted(table_names - core_names):
        errors.append(f'W3 maps an operation the registry does not know: {extra}')
    for name in sorted(core_names & table_names):
        core = specs[name]
        mine = OPS_BY_NAME[name]
        if core.requires_capability != mine.capability:
            errors.append(
                f'{name}: capability {mine.capability!r} != core {core.requires_capability!r}')
        if bool(core.mutating) != bool(mine.mutating):
            errors.append(f'{name}: mutating {mine.mutating} != core {core.mutating}')
        if bool(core.recovery_safe) != bool(mine.recovery_safe):
            errors.append(f'{name}: recovery_safe {mine.recovery_safe} != core {core.recovery_safe}')
    return errors


def check_capabilities_exist() -> list[str]:
    """Every referenced capability must exist in the frozen capability catalog."""
    errors: list[str] = []
    catalog = json.loads((REPO_ROOT / 'core' / 'capabilities' / 'catalog.json').read_text())
    known = set(catalog['capabilities'])
    for o in OPS:
        if o.capability is not None and o.capability not in known:
            errors.append(f'{o.op}: capability {o.capability} is not in the catalog')
    return errors


def inventory() -> list[dict]:
    """Machine-readable inventory (doc table parity + reporting)."""
    return [{
        'op': o.op, 'family': o.family, 'status': o.status, 'capability': o.capability,
        'mutating': o.mutating, 'recovery_safe': o.recovery_safe,
        'args': [fl.name for fl in o.args], 'result': [fl.name for fl in (o.result or ())],
        'errors': list(o.errors), 'defer_reason': o.defer_reason,
    } for o in OPS]


def main(argv: list[str]) -> int:
    if '--self-test' not in argv and '--inventory' not in argv:
        print((__doc__ or '').strip().splitlines()[0])
        print('usage: schema.py --self-test | --inventory')
        return 2
    if '--inventory' in argv:
        print(json.dumps(inventory(), indent=1, sort_keys=True))
        return 0
    errors = validate_structure() + check_against_core() + check_capabilities_exist()
    by_status = {}
    for o in OPS:
        by_status[o.status] = by_status.get(o.status, 0) + 1
    print(f'interface schema {SCHEMA_VERSION}: {len(OPS)} operations')
    for status in (STATUS_STUB, STATUS_DEFER_PRIVILEGE, STATUS_DEFER_CHAIN, STATUS_MOCK):
        print(f'  {status:<20} {by_status.get(status, 0)}')
    print(f'  error codes: {len(ERROR_CODES)} ({len(NEW_ERROR_CODES)} declared as W3 additions)')
    if errors:
        print(f'SCHEMA INCONSISTENT ({len(errors)})')
        for err in errors:
            print(f'  - {err}')
        return 1
    print('SCHEMA OK: table matches the frozen core registry and the capability catalog')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
