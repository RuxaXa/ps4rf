#!/usr/bin/env python3
"""PS4RF P4/W12 kernel.read capability path: the one mandatory chain, no bypass.

The only way a bounded ``kernel.read`` can ever be authorized, in exactly this order:

.. code-block:: text

    REQUEST -> Registry -> Capability Resolution -> effective_grant -> W4 Gate
            -> W5 Profile Binding -> Boot Binding -> W7 Provider Router
            -> kernel.read native provider

Nothing here executes a read and nothing here talks to a console: the module is a pure,
deterministic *decision* function plus the evidence assembler for the read that the decision
authorizes. The single provider entry of the W12 path is represented by exactly one flag:
``GateDecision.provider_entry`` is set by exactly one return statement in this module (the
``GRANTED`` return); every refusal returns ``provider_entry=False`` and names the chain stage
it stopped at (``stopped_at``).

No circular dependency (wave-owner review item 1): the generic region-based path below needs a
present ``VerificationEvidence`` record, and a verification needs a read - the narrow way out of
that circle is the *bootstrap verification* defined in ``tools/hostctl/kreadverify.py``:
a fixed verification region (``xfast_entry``), a compile/profile-bound locator
(``ps4rf_bootread``'s ``SOURCE_RVA``, restated in ``tools/hostctl/bootpriv.py``, never a
literal here - a profile-side file carries no kernel address of its own) and a fixed bounded
expected length (16 bytes) produce the first ``VerificationEvidence`` without any
generic ``kernel.read`` having been granted. Only after a passing bootstrap verification may
the generic bounded, region-based read be used - and even then it is *eligible*, not executed
(see below).

Live provider entry is never automatic (wave-owner review item 2): the router stage requires
the explicit live-approval flag on the provider identity (``live_approved``); without it the
decision stays ``DEFERRED`` with ``KREAD_LIVE_APPROVAL_REQUIRED`` and records no provider
entry. The W4 gate's own ``ELIGIBLE`` never enters a provider by itself.

Rules (frozen for this wave):

* a request is ``{operation, region, offset, length}`` and nothing else - any address-ish key
  (``addr``, ``address``, ``va``, ``kva``, ``pointer``, ``ptr``, ``raw``, ``resolve``, in any
  casing) is a schema reject raised by the request model (``tools/profiles/kread.py``),
  never a fallback;
* the region comes from the W12 registry (``tools/profiles/regions.py``) - the registry is the
  allowlist; its ``resolve_read`` produces the only address that ever exists (inside the
  decision and the evidence, never in a request);
* preconditions: the current real ``profile_sha256`` (non-fixture, evidence-backed, canonical
  hash matches), the current ``boot_id`` (the presented ``BootBinding`` must be valid for the
  boot the capability was resolved under), the correct context (``JAILBROKEN_PROCESS``), the
  correct provider identity, a present ``VerificationEvidence`` record where required, recovery
  false, provider ``WIRED`` and explicitly live-approved;
* F7 policy, unchanged: ``ProviderType.NATIVE`` alone yields at most ``OBSERVED`` - ``PROVEN``
  only via ``VerificationEvidence``, and the separate verification flow
  (``tools/hostctl/kreadverify.py``) is what can actually move the requirement;
* ``MOCK`` never grants a privileged capability (W4 provider policy, finding F11);
* the W4 gate (``tools.primitive_iface.gate``), the W5 profile machinery
  (``tools/profiles/schema.py``, ``binding.py``, ``w4_adapter.py``) and the W7 route matrix
  (``tools/dispatch/matrix.py``) are *called*, never re-implemented - a parity test pins the
  module identities so a later duplication becomes visible.

Reason vocabulary (exact strings):

* ``KREAD_STALE_BOOT_ID``          - the boot binding belongs to a different boot (reject)
* ``KREAD_WRONG_PROFILE``          - not the current real profile / the binding references a
                                     different profile hash (reject)
* ``KREAD_VERIFICATION_NOT_SEPARATE`` - the verification record does not declare itself separate
  from the read run (pre-live item 7); the run-id inequality is re-checked by the verification module
* ``KREAD_VERIFICATION_MISSING``   - no *passing* ``VerificationEvidence`` where one is
                                     required: absent for a non-NATIVE provider, present but not
                                     ``PASS``, or the W4 gate's own ``EVIDENCE_MISSING`` (defer)
* ``KREAD_NATIVE_OBSERVED_ONLY``   - a NATIVE provider alone never yields PROVEN (defer)
* ``KREAD_MOCK_PROVEN``            - MOCK cannot grant a privileged capability (reject; the W4
                                     provider policy keeps MOCK out of the allowlist)
* ``KREAD_RECOVERY_REQUIRED``      - session in recovery: no provider entry (reject)
* ``KREAD_LIVE_APPROVAL_REQUIRED`` - provider WIRED but not live-approved: no provider entry
                                     (defer; wave-owner review item 2)
* plus the W4 table reasons that stay reachable through this path (``PROVIDER_NOT_ALLOWED``,
  ``ASSURANCE_TOO_LOW``) and the request-model / registry reasons propagated verbatim:
  ``KREAD_UNKNOWN_REGION``,
  ``KREAD_UNRESOLVED_REGION``, ``KREAD_STRICT_IDENTITY_REQUIRED``, ``KREAD_NEGATIVE_OFFSET``,
  ``KREAD_OFFSET_OVERFLOW``, ``KREAD_LENGTH_ZERO``, ``KREAD_LENGTH_EXCEEDS_MAX``,
  ``KREAD_CROSS_REGION``, ``KREAD_NON_CANONICAL_ADDRESS``, ``KREAD_SCHEMA_RAW_ADDRESS``
  (and the other ``KREAD_SCHEMA_*`` codes of the request model).

Evidence (wave-owner review item 3): the evidence assembled by :func:`read_evidence` carries
``requested_region`` / ``requested_offset`` / ``requested_length`` and, separately, the
``resolved_rva`` (unslid internal address, from the registry) and the
``resolved_runtime_va`` (kbase + rva + offset, evidence-only - never from a request).

Call convention (the injected state is the W7 session state of this boot):

* ``profile``       - the active real profile document (dict); validated with the W10
  ``promotion.check_candidate`` rules plus an explicit fixture check
* ``boot_binding``  - a ``tools.profiles.binding.BootBinding`` for the current boot
* ``capability``    - the resolved capability intake record for ``kernel.read`` (dict) with the
  fields the W4 gate consumes: ``name``, ``availability``, ``assurance``, ``context``,
  ``provider``, ``provider_type``, ``scope``, ``session_id``, ``boot_id``, ``verification``
  (the present ``VerificationEvidence`` record or ``None``), ``evidence_ref`` / ``evidence_refs``
  (hash-bound evidence reference(s) for the verification run) and ``approval`` (section 70
  record; the W4 gate is the authority that enforces it)
* ``provider``      - the W12 kernel.read provider identity: dict or object with ``name``,
  ``provider_type``, ``state`` (``WIRED`` required) and ``live_approved`` (bool; required for
  the single provider entry)
* ``recovery``      - bool; True routes the session state into the W4 central recovery gate
* ``registry``      - the region registry; defaults to ``tools.profiles.regions``

Usage::

    python tools/profiles/kread_capability.py --self-test
"""

from __future__ import annotations

import hashlib
import pathlib
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:                       # pragma: no cover - import bootstrap
    sys.path.insert(0, str(REPO_ROOT))

from core.models.common import ASSURANCE_RANK                              # noqa: E402
from tools.dispatch import matrix as router_matrix                         # noqa: E402
from tools.dispatch.evidence import REASON_TO_STEP as W7_REASON_TO_STEP    # noqa: E402
from tools.primitive_iface.gate import (                                   # noqa: E402
    APPROVAL_MISSING, ASSURANCE_TOO_LOW, BINDING_MISMATCH, CAPABILITY_MISSING,
    CONTEXT_MISMATCH, EVIDENCE_MISSING, NOT_WIRED, PROFILE_UNBOUND, PROVIDER_NOT_ALLOWED,
    RECOVERY_REQUIRED, GateContext, REQ_BY_OP, gate_for,
)
from tools.profiles import kread, promotion, regions, w4_adapter           # noqa: E402
from tools.profiles.binding import BootBinding                             # noqa: E402
from tools.profiles.kread import KReadReject                               # noqa: E402
from tools.profiles.schema import (                                        # noqa: E402
    canonical_profile_sha256, module_locator_kind, profile_preconditions,
    validate_field_value, validate_locator_value,
)

OPERATION = 'kernel.read'
EVIDENCE_SCHEMA = 'ps4rf.kread.read-evidence.v1'

#: the wire-visible request shape: exactly these keys, nothing else
REQUEST_KEYS = ('operation', 'region', 'offset', 'length')
#: any of these in a request is a schema reject (never a fallback to a raw address); the
#: authoritative scanner is ``kread.is_raw_address_key`` - this tuple is documentation only
ADDRESSISH_KEYS = ('addr', 'address', 'va', 'kva', 'pointer', 'ptr', 'raw', 'resolve')

# --- outcomes -------------------------------------------------------------------------
GRANTED = 'GRANTED'
REJECTED = 'REJECTED'
DEFERRED = 'DEFERRED'
OUTCOMES = (GRANTED, REJECTED, DEFERRED)

# --- W12 reason vocabulary (exact strings) --------------------------------------------
KREAD_STALE_BOOT_ID = 'KREAD_STALE_BOOT_ID'
KREAD_WRONG_PROFILE = 'KREAD_WRONG_PROFILE'
KREAD_VERIFICATION_MISSING = 'KREAD_VERIFICATION_MISSING'
#: the verification record does not declare itself separate from the read run (pre-live item 7)
KREAD_VERIFICATION_NOT_SEPARATE = 'KREAD_VERIFICATION_NOT_SEPARATE'
KREAD_NATIVE_OBSERVED_ONLY = 'KREAD_NATIVE_OBSERVED_ONLY'
KREAD_MOCK_PROVEN = 'KREAD_MOCK_PROVEN'
KREAD_RECOVERY_REQUIRED = 'KREAD_RECOVERY_REQUIRED'
#: wave-owner review item 2: even an eligible, WIRED provider is not entered automatically
KREAD_LIVE_APPROVAL_REQUIRED = 'KREAD_LIVE_APPROVAL_REQUIRED'

KREAD_REASONS = (KREAD_STALE_BOOT_ID, KREAD_WRONG_PROFILE, KREAD_VERIFICATION_MISSING,
                 KREAD_VERIFICATION_NOT_SEPARATE,
                 KREAD_NATIVE_OBSERVED_ONLY, KREAD_MOCK_PROVEN, KREAD_RECOVERY_REQUIRED,
                 KREAD_LIVE_APPROVAL_REQUIRED)

# --- chain stages (the name a refusal stops at) ----------------------------------------
STAGE_REQUEST = 'request'
STAGE_REGISTRY = 'registry'
STAGE_CAPABILITY = 'capability_resolution'
STAGE_GRANT = 'effective_grant'
STAGE_W4 = 'w4_gate'
STAGE_W5 = 'w5_profile_binding'
STAGE_BOOT = 'boot_binding'
STAGE_ROUTER = 'provider_router'
STAGE_RESOURCE = 'resource_policy'
STAGES = (STAGE_REQUEST, STAGE_REGISTRY, STAGE_CAPABILITY, STAGE_GRANT, STAGE_W4, STAGE_W5,
          STAGE_BOOT, STAGE_ROUTER, STAGE_RESOURCE)

#: W4 gate reasons that stay pending (deferred) rather than hard-rejected
W4_DEFERRED_REASONS = frozenset((CAPABILITY_MISSING, ASSURANCE_TOO_LOW, EVIDENCE_MISSING,
                                 APPROVAL_MISSING, NOT_WIRED, PROFILE_UNBOUND))


@dataclass
class GateDecision:
    """One W12 decision. ``provider_entry`` is true exactly once, only on GRANTED."""

    outcome: str
    stopped_at: str | None
    reasons: list[str] = field(default_factory=list)
    effective_grant: dict = field(default_factory=dict)
    resolved: object | None = None
    provider_entry: bool = False

    @property
    def granted(self) -> bool:
        return self.outcome == GRANTED

    @property
    def refused(self) -> bool:
        return self.outcome in (REJECTED, DEFERRED)


# --- small helpers ---------------------------------------------------------------------
def _assurance_rank() -> dict:
    return {key.value if hasattr(key, 'value') else str(key): rank
            for key, rank in ASSURANCE_RANK.items()}


def _attr(value, name, default=None):
    if isinstance(value, dict):
        return value.get(name, default)
    return getattr(value, name, default)


def _provider_identity(provider) -> tuple[str | None, str | None, str | None, bool]:
    if provider is None:
        return None, None, None, False
    return (str(_attr(provider, 'name') or '') or None,
            str(_attr(provider, 'provider_type') or '') or None,
            str(_attr(provider, 'state') or '') or None,
            bool(_attr(provider, 'live_approved', False)))


def _empty_grant() -> dict:
    return {'granted': False, 'assurance': None, 'required': REQ_BY_OP[OPERATION].min_assurance,
            'capability': OPERATION, 'provider': None, 'provider_type': None,
            'profile_sha256': None, 'boot_id': None, 'context': None,
            'live_approved': False}


def _refuse(outcome: str, stage: str, reasons: list[str], *, grant: dict,
            resolved: object | None = None) -> GateDecision:
    if outcome not in (REJECTED, DEFERRED):
        raise ValueError(f'not a refusal outcome: {outcome!r}')
    return GateDecision(outcome=outcome, stopped_at=stage, reasons=list(reasons),
                        effective_grant=dict(grant), resolved=resolved, provider_entry=False)


def default_registry():
    """The production registry: the W12 region registry module itself."""
    return regions


# --- the decision ----------------------------------------------------------------------
def decide(request, *, registry=None, profile=None, boot_binding=None, context=None,
           capability=None, recovery=False, provider=None) -> GateDecision:
    """Run one kernel.read request through the mandatory W12 chain and return the decision.

    Pure and deterministic: no read is performed, no provider is invoked. The decision either
    grants (``provider_entry=True``, exactly once) or names the stage and reason of the refusal.
    """
    registry = default_registry() if registry is None else registry
    grant = _empty_grant()
    requirement = REQ_BY_OP[OPERATION]
    required_context = requirement.allowed_contexts[0]

    # 1. REQUEST: the frozen request model validates the mapping (an address-ish field is a
    #    schema reject there; this path never falls back to a raw address).
    try:
        parsed = kread.parse_request(request)
    except KReadReject as exc:
        return _refuse(REJECTED, STAGE_REQUEST, [exc.reason], grant=grant)

    # 2. REGISTRY: resolve the bounded read against the allowlist. The registry owns every
    #    bounds rule (max length, no negative offset, checked addition, cross-region,
    #    canonical address); its reasons propagate verbatim.
    try:
        resolved = registry.resolve_read(parsed.region, parsed.offset, parsed.length)
    except KReadReject as exc:
        return _refuse(REJECTED, STAGE_REGISTRY, [exc.reason], grant=grant)

    # 3. CAPABILITY RESOLUTION: the record the W7 intake resolved for this operation must be
    #    present, available, for this operation, in the right context, and the acting provider
    #    must be exactly the provider the record was resolved for. Policy checks (assurance,
    #    authority, bindings) stay with the W4 gate below.
    if isinstance(capability, (list, tuple)):
        capability = next((entry for entry in capability
                           if isinstance(entry, dict) and entry.get('name') == OPERATION), None)
    if not isinstance(capability, dict) or capability.get('name') != OPERATION:
        return _refuse(REJECTED, STAGE_CAPABILITY, [CAPABILITY_MISSING], grant=grant,
                       resolved=resolved)
    grant.update(provider=capability.get('provider'), provider_type=capability.get('provider_type'),
                 context=capability.get('context'))
    if capability.get('availability') != 'AVAILABLE':
        return _refuse(REJECTED, STAGE_CAPABILITY, [CAPABILITY_MISSING], grant=grant,
                       resolved=resolved)
    if context != required_context or capability.get('context') != required_context:
        return _refuse(REJECTED, STAGE_CAPABILITY, [CONTEXT_MISMATCH], grant=grant,
                       resolved=resolved)
    current_boot_id = capability.get('boot_id')
    if not isinstance(current_boot_id, str) or not current_boot_id:
        return _refuse(REJECTED, STAGE_CAPABILITY, [BINDING_MISMATCH], grant=grant,
                       resolved=resolved)
    grant['boot_id'] = current_boot_id
    provider_name, provider_type, provider_state, live_approved = _provider_identity(provider)
    grant['live_approved'] = live_approved
    if provider_name is None or provider_type is None:
        return _refuse(REJECTED, STAGE_CAPABILITY, [PROVIDER_NOT_ALLOWED], grant=grant,
                       resolved=resolved)
    if capability.get('provider') != provider_name or \
            capability.get('provider_type') != provider_type:
        return _refuse(REJECTED, STAGE_CAPABILITY, [PROVIDER_NOT_ALLOWED], grant=grant,
                       resolved=resolved)

    # 4. EFFECTIVE GRANT: the frozen provider policy, then the evidence rule. F7: a NATIVE
    #    provider alone yields at most OBSERVED (a read cannot prove itself). F11: MOCK never
    #    carries a privileged capability. The policy table itself (REQ_BY_OP, the W4 table) is
    #    the source of the allowlist - never a copy of it.
    ranks = _assurance_rank()
    needed = ranks.get(requirement.min_assurance, 99)
    claimed = str(capability.get('assurance') or 'UNVERIFIED')
    verification = capability.get('verification') if isinstance(capability.get('verification'),
                                                               dict) else None
    verification_present = verification is not None
    verification_ok = verification_present and str(verification.get('outcome')).upper() == 'PASS'
    # Wave-owner pre-live item 7: a verification that does not declare itself separate from the read
    # run must never open the provider. The run-id inequality itself is enforced again by
    # tools/hostctl/kreadverify.py when the read evidence is verified (RUN_NOT_SEPARATE); here the
    # explicit declaration is the pre-*provider-entry* assertion.
    separation_ok = verification_present and verification.get('separate_from_read') is True
    if provider_type not in requirement.allowed_providers:
        reason = KREAD_MOCK_PROVEN if provider_type == 'MOCK' else PROVIDER_NOT_ALLOWED
        return _refuse(REJECTED, STAGE_GRANT, [reason], grant=grant, resolved=resolved)
    if not verification_ok or not separation_ok:
        reason = (KREAD_VERIFICATION_NOT_SEPARATE if verification_ok else KREAD_VERIFICATION_MISSING
                  if verification_present or provider_type != 'NATIVE'
                  else KREAD_NATIVE_OBSERVED_ONLY)
        grant['assurance'] = 'OBSERVED'
        return _refuse(DEFERRED, STAGE_GRANT, [reason], grant=grant, resolved=resolved)
    if ranks.get(claimed, -1) < needed:
        grant['assurance'] = claimed if claimed in ranks else 'UNVERIFIED'
        return _refuse(DEFERRED, STAGE_GRANT, [ASSURANCE_TOO_LOW], grant=grant,
                       resolved=resolved)
    grant['assurance'] = str(requirement.min_assurance)

    # 5. W5 PROFILE BINDING: the current real profile and the binding that references exactly
    #    its canonical hash. The verdict is the W5 module's, not a local re-implementation.
    if not isinstance(profile, dict) or profile.get('fixture') is not False \
            or promotion.check_candidate(profile):
        return _refuse(REJECTED, STAGE_W5, [KREAD_WRONG_PROFILE], grant=grant, resolved=resolved)
    profile_sha = canonical_profile_sha256(profile)
    grant['profile_sha256'] = profile_sha
    if capability.get('profile_sha256') not in (None, profile_sha):
        return _refuse(REJECTED, STAGE_W5, [KREAD_WRONG_PROFILE], grant=grant, resolved=resolved)
    if boot_binding is None:
        return _refuse(REJECTED, STAGE_BOOT, [KREAD_STALE_BOOT_ID], grant=grant,
                       resolved=resolved)
    if getattr(boot_binding, 'profile_sha256', None) != profile_sha:
        return _refuse(REJECTED, STAGE_W5, [KREAD_WRONG_PROFILE], grant=grant, resolved=resolved)

    # 6. BOOT BINDING: facts persist, the runtime binding does not - a binding from another
    #    boot must never carry this one, and this refusal happens before any provider entry.
    if getattr(boot_binding, 'boot_id', None) != current_boot_id:
        return _refuse(REJECTED, STAGE_BOOT, [KREAD_STALE_BOOT_ID], grant=grant,
                       resolved=resolved)
    verdict = profile_preconditions(profile, boot_binding=boot_binding,
                                    current_boot_id=current_boot_id)
    if not verdict.matched:
        return _refuse(REJECTED, STAGE_W5, [KREAD_WRONG_PROFILE], grant=grant, resolved=resolved)
    binding = w4_adapter.profile_binding_for_gate(OPERATION, verdict)
    if not binding.get('present'):                                  # pragma: no cover - fail-closed
        return _refuse(REJECTED, STAGE_W5, [KREAD_WRONG_PROFILE], grant=grant, resolved=resolved)
    #    W12-RVA0-BINDING: the profile's kernel locators are *relative* (kind 'rva' /
    #    'relative', zero is a valid image position - image_elf sits at the image base).
    #    The binding therefore binds the LOCATOR value, never a runtime address; the
    #    runtime `addr` domain (> 0) is not applied to a relative value any more. The
    #    runtime address only exists once the current boot's kernel base is known and is
    #    resolved and validated there, checked and fail-closed: kbase + rva must be
    #    non-zero, canonical and inside the pinned image window
    #    (regions.resolve_runtime).
    locator_kind = module_locator_kind(profile, requirement.family)
    if locator_kind is None:
        return _refuse(REJECTED, STAGE_W5, [PROFILE_UNBOUND], grant=grant, resolved=resolved)
    fields = dict(binding.get('fields') or {})
    if 'addr' in fields:
        problems = validate_locator_value(locator_kind, resolved.address)
        if problems:
            return _refuse(REJECTED, STAGE_W5, [PROFILE_UNBOUND], grant=grant,
                           resolved=resolved)
        fields['addr'] = resolved.address
    if 'size' in fields:
        problems = validate_field_value('size', resolved.length)
        if problems:
            return _refuse(REJECTED, STAGE_W5, [PROFILE_UNBOUND], grant=grant,
                           resolved=resolved)
        fields['size'] = resolved.length
    binding['fields'] = fields
    region = getattr(resolved, 'region', None)
    binding['locator'] = {'kind': locator_kind, 'field': 'addr', 'value': resolved.address,
                          'region': getattr(region, 'name', region),
                          'note': 'relative image position (rva); the runtime address is '
                                  'resolved from the current boot binding, never bound here'}

    # 7. W4 GATE: the frozen gate decides. Nothing is pre-authorized; a single failing
    #    precondition keeps the operation refused (and the provider unentered). A session in
    #    recovery announces itself here (the W4 gate is the central recovery gate), even when
    #    the capability was already accepted - the refusal stays before the provider router.
    evidence_refs = tuple(capability.get('evidence_refs') or ())
    if not evidence_refs and isinstance(capability.get('evidence_ref'), dict):
        evidence_refs = (capability['evidence_ref'],)
    gate_ctx = GateContext(
        capability_records=(capability,),
        verification_records=(verification,) if verification else (),
        evidence_refs=evidence_refs,
        profile_binding=binding,
        session_id=capability.get('session_id'),
        boot_id=current_boot_id,
        session_state='RECOVERY_REQUIRED' if recovery else 'ACTIVE',
        provider=provider_name,
        provider_type=provider_type,
        wired=provider_state == 'WIRED',
        approval=capability.get('approval') if isinstance(capability.get('approval'), dict)
        else None,
    )
    gate_decision = gate_for(OPERATION, gate_ctx)
    if gate_decision.reasons:
        first = gate_decision.reasons[0]
        if first == RECOVERY_REQUIRED:
            return _refuse(REJECTED, W7_REASON_TO_STEP.get(first, STAGE_RESOURCE),
                           [KREAD_RECOVERY_REQUIRED], grant=grant, resolved=resolved)
        if first == EVIDENCE_MISSING:
            return _refuse(DEFERRED, STAGE_W4, [KREAD_VERIFICATION_MISSING], grant=grant,
                           resolved=resolved)
        if first == PROVIDER_NOT_ALLOWED and provider_type == 'MOCK':
            return _refuse(REJECTED, W7_REASON_TO_STEP.get(first, STAGE_GRANT),
                           [KREAD_MOCK_PROVEN], grant=grant, resolved=resolved)
        outcome = DEFERRED if first in W4_DEFERRED_REASONS else REJECTED
        return _refuse(outcome, W7_REASON_TO_STEP.get(first, STAGE_W4), [first], grant=grant,
                       resolved=resolved)

    # 8. W7 PROVIDER ROUTER: one route for kernel.read (the W7 matrix is the source), the
    #    provider must be WIRED *and* explicitly live-approved - an ELIGIBLE gate result alone
    #    never enters a provider. Only here - and exactly once - does the decision record the
    #    provider entry.
    route = router_matrix.route_for(OPERATION)
    if not route.get('gated'):                                      # pragma: no cover - fail-closed
        return _refuse(DEFERRED, STAGE_ROUTER, [NOT_WIRED], grant=grant, resolved=resolved)
    if provider_state != 'WIRED':
        return _refuse(DEFERRED, STAGE_ROUTER, [NOT_WIRED], grant=grant, resolved=resolved)
    if not live_approved:
        return _refuse(DEFERRED, STAGE_ROUTER, [KREAD_LIVE_APPROVAL_REQUIRED], grant=grant,
                       resolved=resolved)
    grant.update(granted=True, assurance=str(requirement.min_assurance), provider=provider_name,
                 provider_type=provider_type, boot_id=current_boot_id, context=context,
                 live_approved=True)
    return GateDecision(outcome=GRANTED, stopped_at=None, reasons=[], effective_grant=grant,
                        resolved=resolved, provider_entry=True)


# --- evidence for the read the decision authorizes -------------------------------------
def _assemble_evidence(request, resolved, *, run_id: str, bytes_hex: str, runtime_kbase: int,
                       profile_sha256: str | None, boot_id: str | None, provider: dict,
                       output_sha256: str | None, verification: dict | None) -> dict:
    if not isinstance(request, Mapping) or any(kread.is_raw_address_key(key) for key in request):
        raise ValueError('the request must not carry an address field')
    returned = bytes.fromhex(bytes_hex)
    digest = hashlib.sha256(returned).hexdigest()
    if output_sha256 is not None and output_sha256 != digest:
        raise ValueError('the claimed output sha256 disagrees with the returned bytes '
                         '(the host recomputes it; a claim is never recorded)')
    for label, value in (('resolved', resolved), ('runtime_kbase', runtime_kbase)):
        if value is None:
            raise ValueError(f'{label} is required for the evidence')
    if isinstance(runtime_kbase, bool) or not isinstance(runtime_kbase, int):
        raise ValueError('runtime_kbase must be an integer')
    resolved_rva = getattr(resolved, 'rva', None)
    offset = getattr(resolved, 'offset', None)
    resolved_rva = resolved_rva if offset is None else _checked_address(resolved_rva, offset)
    region = getattr(resolved, 'region', None)
    region_name = region if isinstance(region, str) else getattr(region, 'name', None)
    # W12-RVA0-BINDING: the runtime address is resolved against the *current* boot's kernel
    # base with checked arithmetic (kbase + rva, then + offset), non-zero, canonical and
    # inside the pinned image window. The relative value itself is never an address.
    try:
        runtime = regions.resolve_runtime(resolved, runtime_kbase)
    except KReadReject as exc:
        raise ValueError(f'the runtime resolution refused the read: {exc}') from None
    except AttributeError as exc:                                   # pragma: no cover
        raise ValueError(f'the resolved read is incomplete: {exc}') from None
    runtime_va = runtime.runtime_address
    return {
        'schema': EVIDENCE_SCHEMA,
        'operation': OPERATION,
        'run_id': run_id,
        'requested_region': region_name,
        'requested_offset': getattr(resolved, 'offset', None),
        'requested_length': getattr(resolved, 'length', None),
        'resolved_rva': resolved_rva,
        'resolved_runtime_va': runtime_va,
        'bytes_hex': returned.hex(),
        'observed_length': len(returned),
        'output_sha256': digest,
        'profile_sha256': profile_sha256,
        'boot_id': boot_id,
        'provider': {'name': provider.get('name'), 'provider_type': provider.get('provider_type')},
        'verification': verification,
        'read': {'single_callback': True, 'writes_to_kernel': False,
                 'host_supplied_address': False},
    }


def _checked_address(a: int | None, b: int | None) -> int:
    """u64 checked addition via the frozen bounds primitive; refuse a wrap, fail closed."""
    if not isinstance(a, int) or isinstance(a, bool) or not isinstance(b, int) \
            or isinstance(b, bool) or a < 0 or b < 0:
        raise ValueError(f'address composition needs two non-negative integers ({a!r}, {b!r})')
    total = kread.checked_add(a, b)
    if total is None or not kread.is_canonical_x86_64(total):
        raise ValueError(f'address {a:#x} + {b:#x} is not a canonical x86-64 address')
    return total


def read_evidence(request, decision, *, run_id: str, bytes_hex: str, runtime_kbase: int,
                  output_sha256: str | None = None, verification: dict | None = None) -> dict:
    """Assemble the W12 read evidence for one GRANTED decision.

    The resolved addresses live here (and in the decision) - never in the request. The output
    hash is recomputed host side from the returned bytes; a claimed ``output_sha256`` that
    disagrees with the bytes is refused, never recorded.
    """
    if not isinstance(decision, GateDecision) or decision.outcome != GRANTED \
            or not decision.provider_entry:
        raise ValueError('read evidence requires a GRANTED decision with a provider entry')
    if decision.resolved is None:                                   # pragma: no cover - misuse
        raise ValueError('the decision carries no resolved read')
    grant = decision.effective_grant or {}
    return _assemble_evidence(
        request, decision.resolved, run_id=run_id, bytes_hex=bytes_hex,
        runtime_kbase=runtime_kbase, profile_sha256=grant.get('profile_sha256'),
        boot_id=grant.get('boot_id'),
        provider={'name': grant.get('provider'), 'provider_type': grant.get('provider_type')},
        output_sha256=output_sha256, verification=verification)


def fixed_read_evidence(request, resolved, *, run_id: str, bytes_hex: str, runtime_kbase: int,
                        profile_sha256: str, boot_id: str, provider: dict,
                        output_sha256: str | None = None,
                        verification: dict | None = None) -> dict:
    """Evidence for the narrow bootstrap read (fixed region, compile-bound locator).

    The bootstrap path (wave-owner review item 1) has no generic GRANTED decision to draw
    bindings from - it is what makes the first ``VerificationEvidence`` possible - so the
    callers pass the resolved fixed read and the current bindings explicitly. Everything else
    is the same evidence schema as :func:`read_evidence`.
    """
    return _assemble_evidence(request, resolved, run_id=run_id, bytes_hex=bytes_hex,
                              runtime_kbase=runtime_kbase, profile_sha256=profile_sha256,
                              boot_id=boot_id, provider=provider, output_sha256=output_sha256,
                              verification=verification)


# --- self test -------------------------------------------------------------------------
def _self_test() -> list[str]:
    """Deterministic offline self-test: vocabulary, one refusal, one grant. No console."""
    import json
    from tools.profiles import bootid

    problems: list[str] = []
    if KREAD_REASONS != (KREAD_STALE_BOOT_ID, KREAD_WRONG_PROFILE, KREAD_VERIFICATION_MISSING,
                         KREAD_VERIFICATION_NOT_SEPARATE, KREAD_NATIVE_OBSERVED_ONLY,
                         KREAD_MOCK_PROVEN, KREAD_RECOVERY_REQUIRED,
                         KREAD_LIVE_APPROVAL_REQUIRED):
        problems.append('the W12 reason vocabulary drifted')
    profile = json.loads((REPO_ROOT / 'profiles' / 'fw1352' / 'profile-13.52.json').read_text())
    sha = canonical_profile_sha256(profile)
    boot = bootid.derive_boot_id(sha, bootid.BootTime(1789910256, 860896),
                                 profile=profile)['boot_id']
    binding = BootBinding.from_profile(profile, boot)
    strict = sorted(name for name, region in regions.regions().items()
                    if region.identity_status == regions.IDENTITY_STRICT and region.length >= 16)
    if not strict:
        problems.append('the registry carries no STRICT region of at least 16 bytes')
        return problems
    request = {'operation': 'kernel.read', 'region': strict[0], 'offset': 0, 'length': 16}
    provider = {'name': 'ps4rfd-kread-privileged', 'provider_type': 'NATIVE',
                'state': 'WIRED', 'live_approved': True}
    verification = {'run_id': 'RUN-' + '2' * 32, 'operation': 'verify.kernel.read',
                    'outcome': 'PASS', 'capability': 'kernel.read', 'provider': provider['name'],
                    'provider_type': 'NATIVE', 'session_id': 'SES-' + '0' * 16, 'boot_id': boot,
                    'separate_from_read': True}
    capability = {'name': 'kernel.read', 'availability': 'AVAILABLE', 'assurance': 'PROVEN',
                  'context': 'JAILBROKEN_PROCESS', 'provider': provider['name'],
                  'provider_type': 'NATIVE', 'scope': 'SESSION', 'session_id': 'SES-' + '0' * 16,
                  'boot_id': boot, 'verification': verification,
                  'evidence_ref': {'run_id': verification['run_id'], 'sha256': 'b' * 64},
                  'approval': {'approved': True, 'state': 'APPROVED', 'id': 'CMR-self-test'}}
    granted = decide(request, registry=regions, profile=profile, boot_binding=binding,
                     context='JAILBROKEN_PROCESS', capability=capability, recovery=False,
                     provider=provider)
    if not granted.granted or not granted.provider_entry or granted.stopped_at is not None:
        problems.append(f'the complete path did not grant: {granted}')
    no_live = decide(request, registry=regions, profile=profile, boot_binding=binding,
                     context='JAILBROKEN_PROCESS', capability=capability, recovery=False,
                     provider={'name': provider['name'], 'provider_type': 'NATIVE',
                               'state': 'WIRED'})
    if no_live.reasons != [KREAD_LIVE_APPROVAL_REQUIRED] or no_live.provider_entry:
        problems.append(f'an eligible-but-not-approved provider was entered: {no_live}')
    stale = decide(request, registry=regions, profile=profile,
                   boot_binding=BootBinding(boot_id='BOOT-' + '0' * 16, profile_sha256=sha),
                   context='JAILBROKEN_PROCESS', capability=capability, recovery=False,
                   provider=provider)
    if stale.reasons != [KREAD_STALE_BOOT_ID] or stale.provider_entry:
        problems.append(f'a stale boot binding was not refused: {stale}')
    return problems


def main(argv: list[str]) -> int:
    if '--self-test' not in argv:
        print((__doc__ or '').strip().splitlines()[0])
        print('usage: kread_capability.py --self-test')
        return 2
    problems = _self_test()
    for problem in problems:
        print(f'kread capability: {problem}')
    print(f'kread capability self-test: {"ok" if not problems else "FAILED"} '
          '(chain order fixed, provider entry only on GRANTED + live approval, reasons exact)')
    return 0 if not problems else 1


if __name__ == '__main__':                                          # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
