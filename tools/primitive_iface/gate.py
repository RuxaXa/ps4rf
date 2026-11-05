#!/usr/bin/env python3
"""PS4RF P4/W4 capability gate: decision logic for gated (deferred) operations.

W4 defines the *process* by which a gated primitive could ever leave
``OPERATION_DEFERRED`` - and nothing else. This module is a pure, deterministic
decision function: it reads a gate context (capability records, verification
evidence, profile binding, session/boot binding, provider, wiring, approval) and
returns a decision with the complete list of failing preconditions.

Hard rules (owner scope, W4):

* ``OPERATION_DEFERRED`` stays the default while **any** gate precondition is
  missing; a decision can never make an operation executable.
* Nothing activates an operation on its own: a present symbol, a firmware RVA, a
  profile entry, a mock success, the mere existence of an interface, or an operator
  claim is **ignored** by the gate (see ``GateContext.claims``).
* Privileged capabilities keep requiring the frozen verification-evidence path
  (``core/models/verification.py`` semantics); mock-derived evidence never grants a
  privileged capability.
* W4 implements no primitive and no provider wiring: the gate only decides.

Frozen-core values are **read**, not restated: the minimum assurance per capability
namespace and the provider authority rules come from
``core.models.capability.default_authority()`` and are cross-checked by
``--self-test``.

Evidence sources for the policy: ``docs/P4-W0-DECISIONS.md`` (D8/D9/D14/D17),
``docs/spec-history/70-capability-gated-native-primitive-additions.md`` (§70),
``docs/P4-PRIMITIVE-INTERFACES.md`` (W3 surface), ``Pasted_text(2).txt`` l.418-435
(kernel.snapshot contract), ``Pasted_text(20261005-115353).txt`` l.88/l.237
(central recovery gate, recovery-safe set).

Usage::

    python tools/primitive_iface/gate.py --self-test
    python tools/primitive_iface/gate.py --matrix

Exit codes: 0 = consistent, 1 = inconsistent, 2 = usage error.
"""

from __future__ import annotations

import json
import pathlib
import sys
from dataclasses import dataclass, field

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:  # allow direct script execution
    sys.path.insert(0, str(REPO_ROOT))

from tools.primitive_iface.schema import (  # noqa: E402
    OPS, OPS_BY_NAME, PRIVILEGED_NAMESPACES, STATUS_DEFER_CHAIN, STATUS_DEFER_PRIVILEGE,
    STATUS_MOCK, STATUS_STUB,
)

# --- reason codes --------------------------------------------------------------------
# Deterministic order = evaluation and reporting order.
CAPABILITY_MISSING = 'CAPABILITY_MISSING'
ASSURANCE_TOO_LOW = 'ASSURANCE_TOO_LOW'
PROVIDER_NOT_ALLOWED = 'PROVIDER_NOT_ALLOWED'
CONTEXT_MISMATCH = 'CONTEXT_MISMATCH'
BINDING_MISMATCH = 'BINDING_MISMATCH'
PROFILE_UNBOUND = 'PROFILE_UNBOUND'
EVIDENCE_MISSING = 'EVIDENCE_MISSING'
RECOVERY_REQUIRED = 'RECOVERY_REQUIRED'
APPROVAL_MISSING = 'APPROVAL_MISSING'
NOT_WIRED = 'NOT_WIRED'

REASONS = (CAPABILITY_MISSING, ASSURANCE_TOO_LOW, PROVIDER_NOT_ALLOWED, CONTEXT_MISMATCH,
           BINDING_MISMATCH, PROFILE_UNBOUND, EVIDENCE_MISSING, RECOVERY_REQUIRED,
           APPROVAL_MISSING, NOT_WIRED)

# what a caller has to provide for each reason (drives the handoff contract)
REASON_OWNER = {
    CAPABILITY_MISSING: 'W7 (capability intake from the agent)',
    ASSURANCE_TOO_LOW: 'W7 (frozen verification path must raise assurance)',
    PROVIDER_NOT_ALLOWED: 'W7 (provider registration, finding F7)',
    CONTEXT_MISMATCH: 'P5 (on-site context evidence)',
    BINDING_MISMATCH: 'W7 (session/boot binding at intake)',
    PROFILE_UNBOUND: 'W5 (profile binding data)',
    EVIDENCE_MISSING: 'P5 (real verification run) + W7 (evidence store)',
    RECOVERY_REQUIRED: 'on-console recovery handling (P5)',
    APPROVAL_MISSING: 'Project Owner / Research Lead (section 70 record)',
    NOT_WIRED: 'W7 (provider wiring)',
}

# claims that must NEVER activate anything on their own
IGNORED_CLAIMS = ('symbol', 'firmware_rva', 'profile_entry', 'mock_success',
                  'interface_exists', 'operator_claim')

# provider types that may carry a privileged capability (deliberately stricter than
# the frozen authority table for the native path: MOCK is excluded - see F11)
ALLOWED_PRIVILEGED_PROVIDERS = ('EXPLOIT', 'OPERATOR', 'NATIVE')
EXCLUDED_PROVIDERS_PRIVILEGED = ('MOCK',)
ALLOWED_USERLAND_PROVIDERS = ('EXPLOIT', 'OPERATOR', 'NATIVE', 'RUNTIME_PROBE')

WRAPPER_OP = 'provider.call'          # marker for the not-yet-existing wiring
MUTATING_CLASSES = ('read', 'mutating', 'observational')


@dataclass(frozen=True)
class Requirement:
    """Everything the gate needs to know about one gated operation."""
    op: str
    family: str
    capability: str | None          # required capability record (registry binding)
    namespace: str                  # namespace whose minimum assurance applies
    min_assurance: str              # from the frozen authority table
    class_: str                    # mutating | read | observational
    verification_op: str           # which verify.* operation must have produced evidence
    profile_required: bool
    profile_fields: tuple[str, ...]
    allowed_contexts: tuple[str, ...]
    allowed_providers: tuple[str, ...]
    resource_kind: str | None      # ref kind held by the operation, if any
    cleanup_required: bool
    recoverable: bool
    out_of_band_cleanup_safe: bool
    defer_reason: str
    sources: tuple[str, ...] = ()


@dataclass
class GateContext:
    """Caller-provided state for one operation. Nothing here executes anything."""
    capability_records: tuple[dict, ...] = ()
    verification_records: tuple[dict, ...] = ()
    evidence_refs: tuple[dict, ...] = ()
    profile_binding: dict | None = None
    session_id: str | None = None
    boot_id: str | None = None
    session_state: str = 'ACTIVE'
    provider: str | None = None
    provider_type: str | None = None
    wired: bool = False
    approval: dict | None = None
    claims: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        unknown = sorted(set(self.claims) - set(IGNORED_CLAIMS))
        if unknown:
            raise ValueError(f'unknown claim keys (claims carry no authority): {unknown}')


@dataclass
class GateDecision:
    op: str
    decision: str                    # DEFERRED | ELIGIBLE
    reasons: tuple[str, ...]         # every failing precondition, in REASONS order
    details: tuple[str, ...]
    next_action: str
    wire_code: str = 'OPERATION_DEFERRED'
    executable: bool = False         # W4 never returns True

    @property
    def deferred(self) -> bool:
        return self.decision == 'DEFERRED'


def _frozen_authority():
    from core.models.capability import default_authority  # noqa: PLC0415
    return default_authority()


def _frozen_assurance_rank() -> dict:
    from core.models.common import ASSURANCE_RANK  # noqa: PLC0415
    return {k.value if hasattr(k, 'value') else str(k): v for k, v in ASSURANCE_RANK.items()}


def _min_assurance(namespace: str) -> str:
    table = _frozen_authority().min_assurance_for_grant
    value = table.get(namespace)
    if value is None:
        value = table.get('userland')
    if value is None:
        raise KeyError(f'no minimum assurance for namespace {namespace!r}')
    return value.value if hasattr(value, 'value') else str(value)


# --- the requirement matrix ----------------------------------------------------------
# class_/resource/cleanup reflect the *frozen core* flags (F8/F10: core wins).
_KERNEL_SOURCES = ('Pasted_text(2).txt l.418-435 (snapshot contract)',
                   'Pasted_text(20261005-115353).txt l.52/l.223 (profile-bound values only)')
_VERIFY_SOURCES = ('core/models/verification.py (frozen verification->grant path)',)

REQUIREMENTS: tuple[Requirement, ...] = (
    Requirement('gpuvm.map', 'gpuvm', 'gpuvm.map', 'gpuvm', _min_assurance('gpuvm'), 'mutating',
                'verify.kernel.read', True, ('gvm_id', 'va', 'prot'),
                ('JAILBROKEN_PROCESS',), ALLOWED_PRIVILEGED_PROVIDERS, 'gpuvm', True, True, False,
                'needs section 70 approval; mapping values come from the profile', _KERNEL_SOURCES),
    Requirement('gpuvm.unmap', 'gpuvm', 'gpuvm.unmap', 'gpuvm', _min_assurance('gpuvm'), 'mutating',
                'verify.kernel.read', True, ('mapping_ref',),
                ('JAILBROKEN_PROCESS',), ALLOWED_PRIVILEGED_PROVIDERS, 'gpuvm', True, True, False,
                'needs section 70 approval; must release the mapping acquired by gpuvm.map', _KERNEL_SOURCES),
    Requirement('gpuvm.lookup', 'gpuvm', 'gpuvm.lookup', 'gpuvm', _min_assurance('gpuvm'), 'observational',
                'verify.kernel.read', True, ('gvm_id', 'va'),
                ('JAILBROKEN_PROCESS',), ALLOWED_PRIVILEGED_PROVIDERS, None, False, True, True,
                'needs section 70 approval; the frozen core still marks it mutating (F8/F10)', _KERNEL_SOURCES),
    Requirement('keymgr.claim', 'keymgr', 'keymgr.claim', 'keymgr', _min_assurance('keymgr'), 'mutating',
                'verify.kernel.read', True, ('slot',),
                ('JAILBROKEN_PROCESS',), ALLOWED_PRIVILEGED_PROVIDERS, 'keymgr', True, True, False,
                'needs section 70 approval; slot indices come from the profile', _KERNEL_SOURCES),
    Requirement('keymgr.release', 'keymgr', 'keymgr.release', 'keymgr', _min_assurance('keymgr'), 'mutating',
                'verify.kernel.read', True, ('claim_ref',),
                ('JAILBROKEN_PROCESS',), ALLOWED_PRIVILEGED_PROVIDERS, 'keymgr', True, True, False,
                'needs section 70 approval; must release the claim', _KERNEL_SOURCES),
    Requirement('keymgr.snapshot', 'keymgr', 'keymgr.snapshot', 'keymgr', _min_assurance('keymgr'), 'read',
                'verify.kernel.copyout', True, ('scope',),
                ('JAILBROKEN_PROCESS',), ALLOWED_PRIVILEGED_PROVIDERS, 'keymgr', True, True, True,
                'needs section 70 approval; bulk data leaves the agent only via copyout', _KERNEL_SOURCES),
    Requirement('ccp.submit', 'ccp', 'ccp.submit', 'ccp', _min_assurance('ccp'), 'mutating',
                'verify.kernel.read', True, ('slot', 'command'),
                ('JAILBROKEN_PROCESS',), ALLOWED_PRIVILEGED_PROVIDERS, 'ccp', True, True, False,
                'needs section 70 approval; completion is observed via kernel read', _KERNEL_SOURCES),
    Requirement('kernel.snapshot.recipe', 'kernel', 'kernel.read', 'kernel', _min_assurance('kernel'), 'read',
                'verify.kernel.read', True, ('recipe_ref',),
                ('JAILBROKEN_PROCESS',), ALLOWED_PRIVILEGED_PROVIDERS, None, False, True, True,
                'recipe and roots come from the generated profile table; no host address', _KERNEL_SOURCES),
    Requirement('ioctl.invoke', 'ioctl', 'ioctl.invoke', 'ioctl', _min_assurance('ioctl'), 'mutating',
                'verify.kernel.read', True, ('command',),
                ('JAILBROKEN_PROCESS',), ALLOWED_PRIVILEGED_PROVIDERS, None, False, True, False,
                'device, command allowlist and sizes are target-side policy; no host pointer', _KERNEL_SOURCES),
    Requirement('kernel.read', 'kernel', 'kernel.read', 'kernel', _min_assurance('kernel'), 'read',
                'verify.kernel.read', True, ('addr', 'size'),
                ('JAILBROKEN_PROCESS',), ALLOWED_PRIVILEGED_PROVIDERS, None, False, True, True,
                'needs section 70 approval; range/alignment come from the profile', _KERNEL_SOURCES),
    Requirement('kernel.snapshot', 'kernel', 'kernel.read', 'kernel', _min_assurance('kernel'), 'read',
                'verify.kernel.copyout', True, ('range', 'region_ref', 'expected_sha256'),
                ('JAILBROKEN_PROCESS',), ALLOWED_PRIVILEGED_PROVIDERS, 'snapshot', True, True, True,
                'needs section 70 approval; hash mismatch zeroizes and never releases bytes', _KERNEL_SOURCES),
    Requirement('kernel.dump.full', 'kernel', 'kernel.dump.full', 'kernel', _min_assurance('kernel'), 'read',
                'verify.kernel.copyout', True, ('region_map',),
                ('JAILBROKEN_PROCESS',), ALLOWED_PRIVILEGED_PROVIDERS, 'dump', True, True, False,
                'needs section 70 approval; full dump is a P5 privilege level', _KERNEL_SOURCES),
    Requirement('verify.kernel.read', 'verify', None, 'kernel', _min_assurance('kernel'), 'observational',
                'verify.kernel.read', True, ('addr', 'expected'),
                ('JAILBROKEN_PROCESS',), ALLOWED_PRIVILEGED_PROVIDERS, None, False, True, True,
                'needs section 70 approval; observes an expected/observed pair', _VERIFY_SOURCES),
    Requirement('verify.kernel.exec', 'verify', None, 'kernel', _min_assurance('kernel'), 'observational',
                'verify.kernel.exec', True, ('probe',),
                ('JAILBROKEN_PROCESS',), ALLOWED_PRIVILEGED_PROVIDERS, None, False, True, False,
                'needs section 70 approval; execution evidence comes from a real run', _VERIFY_SOURCES),
    Requirement('verify.kernel.copyout', 'verify', None, 'kernel', _min_assurance('kernel'), 'observational',
                'verify.kernel.copyout', True, ('addr', 'size', 'expected'),
                ('JAILBROKEN_PROCESS',), ALLOWED_PRIVILEGED_PROVIDERS, None, False, True, True,
                'needs section 70 approval; expected values must be evidence-backed', _VERIFY_SOURCES),
    Requirement('verify.samu.access', 'verify', None, 'samu', _min_assurance('samu'), 'observational',
                'verify.samu.access', True, ('probe',),
                ('JAILBROKEN_PROCESS',), ALLOWED_PRIVILEGED_PROVIDERS, None, False, True, False,
                'needs section 70 approval; SAMU is a privileged namespace', _VERIFY_SOURCES),
)

# the one gated non-privileged operation (host chain, not part of the 14)
HOST_CHAIN_REQUIREMENTS: tuple[Requirement, ...] = (
    Requirement('verify.userland.exec', 'verify', None, 'userland', _min_assurance('userland'),
                'observational', 'verify.userland.exec', False, (),
                ('HOMEBREW', 'JAILBROKEN_PROCESS'), ALLOWED_USERLAND_PROVIDERS, None, False, True, False,
                'needs the verification->grant chain (W7); no section 70 needed',
                ('core/models/verification.py (frozen verification->grant path)',)),
)

REQ_BY_OP = {r.op: r for r in REQUIREMENTS + HOST_CHAIN_REQUIREMENTS}


def privilege_gated_ops() -> tuple[str, ...]:
    """The deferred-privilege operations (owner scope) in deterministic order."""
    return tuple(o.op for o in OPS if o.status == STATUS_DEFER_PRIVILEGE)


def gate_candidates() -> tuple[str, ...]:
    return privilege_gated_ops() + tuple(o.op for o in OPS if o.status == STATUS_DEFER_CHAIN)


# --- decision logic ------------------------------------------------------------------
def gate_for(op: str, ctx: GateContext) -> GateDecision:
    """Evaluate all gate preconditions. Returns a decision, never an execution."""
    req = REQ_BY_OP.get(op)
    if req is None:
        spec = OPS_BY_NAME.get(op)
        if spec is not None and spec.status == STATUS_MOCK:
            raise ValueError(f'{op} is mock-only and not part of the gate')
        if spec is not None and spec.status == STATUS_STUB:
            raise ValueError(f'{op} is not gated (status {spec.status})')
        raise ValueError(f'unknown operation {op!r}')

    reasons: list[str] = []
    details: list[str] = []

    def fail(code: str, detail: str) -> None:
        if code not in reasons:
            reasons.append(code)
        details.append(f'{code}: {detail}')

    # 1. central recovery gate (refusal of anything not recovery_safe)
    from tools.primitive_iface.schema import OPS_BY_NAME as _OPS  # noqa: PLC0415
    spec = _OPS[op]
    if ctx.session_state != 'ACTIVE' and not spec.recovery_safe:
        fail(RECOVERY_REQUIRED, f'session state is {ctx.session_state}')

    # 2. capability record: present, AVAILABLE, right namespace, assurance high enough
    record = next((r for r in ctx.capability_records
                   if req.capability is not None and r.get('name') == req.capability), None)
    if req.capability is None:
        record = next((r for r in ctx.capability_records if r.get('namespace') == req.namespace
                       and r.get('verified_by_operation') == req.verification_op), None)
        if record is None:
            fail(CAPABILITY_MISSING, f'no verified capability record for {req.namespace}')
    elif record is None:
        fail(CAPABILITY_MISSING, f'no capability record for {req.capability}')
    if record is not None:
        availability = record.get('availability')
        if availability != 'AVAILABLE':
            if record.get('name') == req.capability or req.capability is None:
                fail(CAPABILITY_MISSING, f'capability availability is {availability}')
        ranks = _frozen_assurance_rank()
        have = ranks.get(str(record.get('assurance')), -1)
        need = ranks.get(req.min_assurance, 99)
        if have < need:
            fail(ASSURANCE_TOO_LOW,
                 f'assurance {record.get("assurance")} < required {req.min_assurance}')
        # 3. provider authority
        ptype = record.get('provider_type')
        if ptype is None:
            fail(PROVIDER_NOT_ALLOWED, 'capability record carries no provider_type')
        elif ptype not in req.allowed_providers:
            fail(PROVIDER_NOT_ALLOWED, f'provider type {ptype} not allowed for {req.op}')
        if ctx.provider is not None and record.get('provider') not in (ctx.provider, None):
            fail(PROVIDER_NOT_ALLOWED,
                 f'record provider {record.get("provider")} != acting provider {ctx.provider}')
        # 4. target context
        if record.get('context') not in req.allowed_contexts:
            fail(CONTEXT_MISMATCH, f'context {record.get("context")} not in {req.allowed_contexts}')
        # 5. boot/session binding (BOOT alone never activates)
        scope = record.get('scope', 'SESSION')
        if scope != 'SESSION':
            fail(BINDING_MISMATCH, f'scope {scope} cannot activate a gated operation')
        if ctx.session_id is None or record.get('session_id') != ctx.session_id:
            fail(BINDING_MISMATCH, 'capability record is not bound to the current session')
        if ctx.boot_id is not None and record.get('boot_id') not in (ctx.boot_id, None):
            fail(BINDING_MISMATCH, 'capability record belongs to a different boot')

    # 6. profile binding (values only, never hardcoded; W5 owns the data)
    if req.profile_required:
        binding = ctx.profile_binding or {}
        if not binding.get('present'):
            fail(PROFILE_UNBOUND, 'no profile binding submitted (W5)')
        else:
            missing = [name for name in req.profile_fields if name not in binding.get('fields', {})]
            if missing:
                fail(PROFILE_UNBOUND, f'profile binding lacks {", ".join(missing)}')
            if not binding.get('sha256'):
                fail(PROFILE_UNBOUND, 'profile binding carries no sha256')

    # 7. verification evidence via the frozen path
    verification = next((v for v in ctx.verification_records
                         if v.get('operation') == req.verification_op), None)
    if verification is None:
        fail(EVIDENCE_MISSING, f'no verification record from {req.verification_op}')
    else:
        if str(verification.get('outcome')).upper() != 'PASS':
            fail(EVIDENCE_MISSING, f'verification outcome is {verification.get("outcome")}')
        if verification.get('provider_type') == 'MOCK':
            fail(EVIDENCE_MISSING, 'mock-derived evidence cannot grant a privileged capability')
        if req.capability is not None and verification.get('capability') != req.capability:
            fail(EVIDENCE_MISSING,
                 f'verification capability {verification.get("capability")} != {req.capability}')
        if ctx.session_id is not None and verification.get('session_id') not in (ctx.session_id, None):
            fail(EVIDENCE_MISSING, 'verification belongs to a different session')
        if ctx.boot_id is not None and verification.get('boot_id') not in (ctx.boot_id, None):
            fail(EVIDENCE_MISSING, 'verification belongs to a different boot')
    refs = [e for e in ctx.evidence_refs if e.get('run_id') == (verification or {}).get('run_id')]
    if not refs or not any(r.get('sha256') for r in refs):
        fail(EVIDENCE_MISSING, 'no hash-bound evidence reference for the verification run')

    # 8. section 70 approval (owner decision; an agent must never self-approve)
    approval = ctx.approval or {}
    if not approval.get('approved'):
        fail(APPROVAL_MISSING, f'section 70 record not approved (state: {approval.get("state", "absent")})')

    # 9. wiring: even with every precondition satisfied the primitive stays deferred
    if not ctx.wired:
        fail(NOT_WIRED, 'provider not wired (W7)')

    ordered = tuple(code for code in REASONS if code in reasons)
    ordered_details = tuple(sorted(details, key=lambda d: REASONS.index(d.split(':', 1)[0])))
    decision = 'DEFERRED' if ordered else 'ELIGIBLE'
    next_action = REASON_OWNER[ordered[0]] if ordered else 'review + owner approval before any implementation'
    return GateDecision(op, decision, ordered, ordered_details, next_action)


def matrix() -> list[dict]:
    """The W4 matrix (machine-readable) for the gated operations."""
    out = []
    for req in REQUIREMENTS + HOST_CHAIN_REQUIREMENTS:
        spec = OPS_BY_NAME[req.op]
        out.append({
            'op': req.op,
            'family': req.family,
            'status': spec.status,
            'capability': req.capability,
            'namespace': req.namespace,
            'min_assurance': req.min_assurance,
            'class': req.class_,
            'verification_op': req.verification_op,
            'profile_required': req.profile_required,
            'profile_fields': list(req.profile_fields),
            'allowed_contexts': list(req.allowed_contexts),
            'allowed_providers': list(req.allowed_providers),
            'resource_kind': req.resource_kind,
            'cleanup_required': req.cleanup_required,
            'recoverable': req.recoverable,
            'out_of_band_cleanup_safe': req.out_of_band_cleanup_safe,
            'defer_reason': req.defer_reason,
            'sources': list(req.sources),
        })
    return out


HANDOFF = {
    'W5_must_provide': [
        'profile entries with a sha256 per profile and per bound operation',
        'value domains for every profile_fields entry of the matrix',
        'evidence-only placeholders (no invented RVA/signature values)',
    ],
    'W7_must_provide': [
        'capability intake bound to session_id + boot_id (frozen CapabilityIntake)',
        'provider registration resolving finding F7 (ProviderType.NATIVE) as an integration finding',
        'authority rule proposal: max_assurance OBSERVED, availability_write true, availability_rank 25',
        'wiring flag for each gated operation (gate stays DEFERRED until then)',
        'evidence-store references with sha256 for every verification run',
    ],
    'owner_must_provide': [
        'section 70 Capability Missing Record per operation (approved, never self-approved)',
        'explicit approval for the privilege level/phase of the concrete primitive',
    ],
    'invariants': [
        'a gate decision never makes an operation executable (executable is always False)',
        'missing any single precondition keeps OPERATION_DEFERRED as the wire answer',
        'mock evidence never grants a privileged capability',
        'symbols, RVAs, profile entries, mock successes, interface existence and operator',
        'claims carry no gate authority',
    ],
}


def _self_test() -> list[str]:
    errors: list[str] = []
    gated = gate_candidates()
    # W17F: no count literal. The invariant is *coverage*, not a number: every gated operation has
    # a requirement row and every row names a gated operation (checked below), and no operation of
    # a privileged namespace may sit outside the gate at all -- a new privileged primitive cannot
    # slip in with a stub status and thereby skip the section 70 path.
    ungated_privileged = sorted(o.op for o in OPS
                                if o.op.split('.')[0] in PRIVILEGED_NAMESPACES
                                and o.status not in (STATUS_DEFER_PRIVILEGE, STATUS_DEFER_CHAIN))
    if ungated_privileged:
        errors.append(f'privileged namespaces outside the gate: {ungated_privileged}')
    if len(set(gated)) != len(gated):
        errors.append('duplicate operation in the gate candidates')
    for op in gated:
        if op not in REQ_BY_OP:
            errors.append(f'{op}: gated operation without a requirement entry')
    for op in REQ_BY_OP:
        if op not in gated:
            errors.append(f'{op}: requirement entry for a non-gated operation')
    for req in REQUIREMENTS + HOST_CHAIN_REQUIREMENTS:
        spec = OPS_BY_NAME[req.op]
        if req.namespace in PRIVILEGED_NAMESPACES:
            if req.min_assurance != 'PROVEN':
                errors.append(f'{req.op}: privileged namespace must require PROVEN')
            if 'MOCK' in req.allowed_providers:
                errors.append(f'{req.op}: MOCK must not be an allowed provider for a privileged capability')
        if req.verification_op not in OPS_BY_NAME or not req.verification_op.startswith('verify.'):
            errors.append(f'{req.op}: verification_op must be a verify.* operation')
        if req.class_ not in MUTATING_CLASSES:
            errors.append(f'{req.op}: unknown class {req.class_}')
        if spec.mutating and req.class_ == 'read' and req.recoverable is False and req.cleanup_required is False:
            # conservative F8/F10 handling: core mutating wins for the recovery path
            pass
        if not req.defer_reason:
            errors.append(f'{req.op}: missing defer reason')
    # frozen-core cross-check of the minimum assurance per namespace
    for req in REQUIREMENTS + HOST_CHAIN_REQUIREMENTS:
        expected = _min_assurance(req.namespace)
        if expected != req.min_assurance:
            errors.append(f'{req.op}: min_assurance {req.min_assurance} != frozen {expected}')
    # a decision never becomes executable, and every reason is owned
    ctx = GateContext()
    for op in gated:
        decision = gate_for(op, ctx)
        if decision.executable:
            errors.append(f'{op}: decision must never be executable in W4')
        if decision.wire_code != 'OPERATION_DEFERRED':
            errors.append(f'{op}: wire code must stay OPERATION_DEFERRED')
        if decision.decision != 'DEFERRED':
            errors.append(f'{op}: empty context must be DEFERRED')
        if not decision.reasons:
            errors.append(f'{op}: empty context must report missing preconditions')
        for reason in decision.reasons:
            if reason not in REASON_OWNER:
                errors.append(f'{op}: reason {reason} has no owner (handoff gap)')
    return errors


def main(argv: list[str]) -> int:
    if '--matrix' in argv:
        print(json.dumps({'matrix': matrix(), 'handoff': HANDOFF, 'reasons': list(REASONS),
                          'ignored_claims': list(IGNORED_CLAIMS)}, indent=1, sort_keys=True))
        return 0
    if '--self-test' not in argv:
        print((__doc__ or '').strip().splitlines()[0])
        print('usage: gate.py --self-test | --matrix')
        return 2
    errors = _self_test()
    print(f'capability gate: {len(privilege_gated_ops())} deferred-privilege operations, '
          f'{len(HOST_CHAIN_REQUIREMENTS)} host-chain operation, {len(REASONS)} reasons')
    print(f'  ignored claims (no authority): {", ".join(IGNORED_CLAIMS)}')
    if errors:
        print(f'GATE INCONSISTENT ({len(errors)})')
        for err in errors:
            print(f'  - {err}')
        return 1
    print('GATE OK: matrix complete, frozen assurance cross-check passed, decisions stay DEFERRED')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
