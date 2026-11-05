#!/usr/bin/env python3
"""PS4RF P4/W5 profile schema: facts, canonical hash, preconditions, op matrix.

A profile carries **persistent facts** about one target (platform, firmware build,
module locators). It never carries runtime addresses: a runtime address is always
computed as ``locator + runtime base`` at bind time, and the key allowlist in this
module makes an absolute-address field impossible to express.

W12-RVA0-BINDING (integration finding): a **locator value is relative** and is validated
with the relative domain (``FIELD_DOMAINS['rva']``: ``0 <= rva < 2**64``, zero valid --
``image_elf`` sits at the image base). It is never validated as a runtime address. The
resolved runtime address (``kernel base + rva``) keeps its own domain
(``FIELD_DOMAINS['runtime_va']``: non-zero and canonical) and is validated where it is
actually resolved, with the current boot's base
(``tools.profiles.regions.resolve_runtime``).

W5 supplies the profile-related part of the W4 capability-gate decision and nothing
else: a matching profile does not make an operation executable, does not remove
``NOT_WIRED``, does not raise capability assurance, does not replace verification
evidence and never claims runtime reachability.

Precondition codes handed to W4 (this module's vocabulary):

``PROFILE_MATCH`` · ``PROFILE_MISMATCH`` · ``PROFILE_UNVERIFIED`` ·
``LOCATOR_MISSING`` · ``LOCATOR_MISMATCH`` · ``BOOT_BINDING_MISMATCH`` ·
``PROFILE_BINDING_MISSING`` (nothing submitted at all)

Canonicalization and hashing use the frozen core canonicalizer
(``core.canonical.canonical_bytes``: JCS + safe-number policy), so profile hashes and
wire hashes rest on the same rules. Any change to firmware identity, a locator,
expected bytes, the operation mapping or the section/permission expectation changes
the profile hash - ``VerificationRecord.profile_sha256`` must reference exactly that
hash.

Reference profiles: ``profiles/fw1352/README.md`` and ``profiles/fw900/README.md``
stay evidence-only placeholders; unknown on-site values are ``UNRESOLVED`` (or
clearly marked fixture values), and the gate stays fail-closed for them.

Usage::

    python tools/profiles/schema.py --self-test
    python tools/profiles/schema.py --matrix

Exit codes: 0 = consistent, 1 = inconsistent, 2 = usage error.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys
from dataclasses import dataclass, field

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:  # allow direct script execution
    sys.path.insert(0, str(REPO_ROOT))

from core.canonical import canonical_bytes, canonical_sha256  # noqa: E402
from tools.primitive_iface.gate import REQUIREMENTS, REQ_BY_OP, privilege_gated_ops  # noqa: E402

SCHEMA_ID = 'ps4rf.profile.v1'
UNRESOLVED = 'UNRESOLVED'
HEX64 = re.compile(r'^[0-9a-f]{64}$')
PERMISSIONS = ('r--', 'r-x', 'rw-', 'rwx')
LOCATOR_KINDS = ('rva', 'relative')
CONFIDENCE = ('UNVERIFIED', 'OBSERVED', 'PROVEN')
PROVENANCE_KINDS = ('evidence', 'fixture')

# --- key allowlists (strict: an absolute/runtime address simply cannot be expressed) --
TOP_KEYS = ('schema', 'fixture', 'profile_id', 'profile_version', 'target',
            'operation_policy', 'locators', 'modules', 'canonical_sha256', 'notes')
TARGET_KEYS = ('platform', 'model_family', 'firmware_version', 'firmware_build_id',
               'architecture', 'hardware_revision')
MODULE_KEYS = ('image', 'locator_kind')
LOCATOR_KEYS = ('module', 'locator', 'section', 'permissions', 'expected_bytes',
                'provenance', 'confidence')
# W10: what a locator result may do. Optional for older fixtures; a promoted (non-fixture)
# profile marks every locator, and the two values carry the W9 window policy semantics.
LOCATOR_POLICIES = ('STRICT_FINGERPRINT', 'STRUCTURAL_ONLY')
#: keys a locator may carry on top of LOCATOR_KEYS. Optional by design: the W5 fixtures predate
#: them and must stay untouched, so the promoted profile is the first artefact to use them.
LOCATOR_OPTIONAL_KEYS = ('policy',)
STRUCTURAL_POLICY = 'STRUCTURAL_ONLY'
STRICT_POLICY = 'STRICT_FINGERPRINT'
LOCATOR_INNER_KEYS = ('kind', 'value')
EXPECTED_BYTES_KEYS = ('offset', 'hex')
PROVENANCE_KEYS = ('kind', 'source', 'sha256')
POLICY_KEYS = ('profile_required', 'locator_ref', 'profile_fields', 'reason')

# precondition codes (W5 -> W4)
PROFILE_BINDING_MISSING = 'PROFILE_BINDING_MISSING'
PROFILE_MATCH = 'PROFILE_MATCH'
PROFILE_MISMATCH = 'PROFILE_MISMATCH'
PROFILE_UNVERIFIED = 'PROFILE_UNVERIFIED'
BOOT_BINDING_MISMATCH = 'BOOT_BINDING_MISMATCH'
LOCATOR_MISSING = 'LOCATOR_MISSING'
LOCATOR_MISMATCH = 'LOCATOR_MISMATCH'

PRECONDITION_CODES = (PROFILE_BINDING_MISSING, PROFILE_MISMATCH, PROFILE_UNVERIFIED,
                      BOOT_BINDING_MISMATCH, LOCATOR_MISSING, LOCATOR_MISMATCH)

# identity fields compared against the expected target
IDENTITY_FIELDS = ('platform', 'firmware_version', 'firmware_build_id', 'architecture')


class ProfileError(Exception):
    """Schema/validation refusal (fail-closed; never a partial acceptance)."""


@dataclass
class ProfileVerdict:
    codes: tuple[str, ...]
    details: tuple[str, ...] = ()
    profile_sha256: str | None = None
    evidence_backed: bool = False

    @property
    def matched(self) -> bool:
        return self.codes == (PROFILE_MATCH,)


@dataclass(frozen=True)
class LocatorRequest:
    """What the caller intends to access at bind time (used for mismatch checks)."""
    operation: str
    module: str | None = None
    section: str | None = None
    permissions: str | None = None
    expected_bytes_hex: str | None = None


# --- canonical hashing ---------------------------------------------------------------
def canonical_profile_bytes(doc: dict) -> bytes:
    """Canonical bytes of a profile *without* its own hash field."""
    body = {k: v for k, v in doc.items() if k != 'canonical_sha256'}
    return canonical_bytes(body)


def canonical_profile_sha256(doc: dict) -> str:
    return canonical_sha256({k: v for k, v in doc.items() if k != 'canonical_sha256'})


# --- empty/placeholder profile -------------------------------------------------------
def empty_profile(profile_id: str, *, firmware_version: str = UNRESOLVED,
                  firmware_build_id: str = UNRESOLVED, platform: str = 'ORBIS',
                  model_family: str = UNRESOLVED, architecture: str = 'x86-64',
                  fixture: bool = True, version: int = 1,
                  locator_values: dict | None = None) -> dict:
    """A profile skeleton for the 14 gated operations.

    Everything that would need an on-site value is ``UNRESOLVED`` unless the caller
    passes an explicit value (tests pass clearly marked fixture values).
    """
    locator_values = locator_values or {}
    policy: dict = {}
    locators: dict = {}
    modules: dict = {}
    for op in privilege_gated_ops():
        req = REQ_BY_OP[op]
        policy[op] = {
            'profile_required': bool(req.profile_required),
            'locator_ref': op if req.profile_required else None,
            'profile_fields': list(req.profile_fields),
            'reason': ('profile-bound values required (W4 matrix)' if req.profile_required
                       else 'profile_not_required (W4 matrix)'),
        }
        if not req.profile_required:
            continue
        module = _module_for(req.family)
        modules.setdefault(module, {'image': module, 'locator_kind': 'rva'})
        value = locator_values.get(op, UNRESOLVED)
        locators[op] = {
            'module': module,
            'locator': {'kind': 'rva', 'value': value},
            'section': 'UNRESOLVED',
            'permissions': 'UNRESOLVED',
            'expected_bytes': None,
            'provenance': {'kind': 'fixture', 'source': 'W5 placeholder (no on-site data yet)',
                           'sha256': None},
            'confidence': 'UNVERIFIED',
        }
    return {
        'schema': SCHEMA_ID,
        'fixture': fixture,
        'profile_id': profile_id,
        'profile_version': version,
        'target': {
            'platform': platform,
            'model_family': model_family,
            'firmware_version': firmware_version,
            'firmware_build_id': firmware_build_id,
            'architecture': architecture,
            'hardware_revision': UNRESOLVED,
        },
        'modules': modules,
        'locators': locators,
        'operation_policy': policy,
        'notes': 'W5 profile skeleton: values marked UNRESOLVED need on-site evidence.',
    }


def _module_for(family: str) -> str:
    return {'kernel': 'kernel', 'gpuvm': 'gpuvm', 'keymgr': 'keymgr', 'ccp': 'ccp',
            'verify': 'kernel', 'memory': 'userland', 'sync': 'userland',
            'session': 'userland', 'telemetry': 'userland', 'experiment': 'userland',
            'mock': 'userland'}.get(family, 'userland')


# --- validation ----------------------------------------------------------------------
def validate_profile(doc: dict) -> list[str]:
    """Full schema validation; returns a list of violations (empty = valid)."""
    errors: list[str] = []

    def unknown_keys(where: str, obj, allowed) -> None:
        if not isinstance(obj, dict):
            errors.append(f'{where}: must be an object')
            return
        for key in sorted(set(obj) - set(allowed)):
            errors.append(f'{where}: unknown field {key!r} (not expressible by the schema)')

    if not isinstance(doc, dict):
        return ['profile: must be an object']
    for key in sorted(set(doc) - set(TOP_KEYS)):
        errors.append(f'profile: unknown field {key!r}')
    if doc.get('schema') != SCHEMA_ID:
        errors.append(f'schema must be {SCHEMA_ID!r}')
    if not isinstance(doc.get('fixture'), bool):
        errors.append('fixture must be a boolean (fixture marking is mandatory)')
    if not isinstance(doc.get('profile_id'), str) or not doc.get('profile_id'):
        errors.append('profile_id must be a non-empty string')
    if not isinstance(doc.get('profile_version'), int) or doc.get('profile_version', 0) < 1:
        errors.append('profile_version must be an integer >= 1')

    target = doc.get('target')
    unknown_keys('target', target, TARGET_KEYS)
    if isinstance(target, dict):
        for key in TARGET_KEYS:
            if key not in target:
                errors.append(f'target: missing field {key!r}')

    modules = doc.get('modules', {})
    if not isinstance(modules, dict):
        errors.append('modules must be an object')
    else:
        for name, mod in modules.items():
            unknown_keys(f'modules.{name}', mod, MODULE_KEYS)
            if isinstance(mod, dict) and mod.get('locator_kind') not in LOCATOR_KINDS:
                errors.append(f'modules.{name}: locator_kind must be one of {LOCATOR_KINDS}')

    locators = doc.get('locators', {})
    if not isinstance(locators, dict):
        errors.append('locators must be an object')
    else:
        for name, loc in locators.items():
            where = f'locators.{name}'
            unknown_keys(where, loc, LOCATOR_KEYS + LOCATOR_OPTIONAL_KEYS)
            if not isinstance(loc, dict):
                continue
            if 'policy' in loc and loc.get('policy') not in LOCATOR_POLICIES:
                errors.append(f'{where}: policy must be one of {LOCATOR_POLICIES}')
            for key in ('module', 'locator', 'section', 'permissions', 'provenance', 'confidence'):
                if key not in loc:
                    errors.append(f'{where}: missing field {key!r}')
                    continue
            inner = loc.get('locator')
            unknown_keys(f'{where}.locator', inner, LOCATOR_INNER_KEYS)
            if not isinstance(loc.get('module'), str) or not loc.get('module'):
                errors.append(f'{where}.module must be a non-empty string')
            if not isinstance(loc.get('section'), str) or not loc.get('section'):
                errors.append(f'{where}.section must be a non-empty string')
            permissions = loc.get('permissions')
            if permissions not in PERMISSIONS + (UNRESOLVED,):
                errors.append(f'{where}.permissions must be one of {PERMISSIONS + (UNRESOLVED,)}')
            if isinstance(inner, dict):
                if inner.get('kind') not in LOCATOR_KINDS:
                    errors.append(f'{where}.locator.kind must be one of {LOCATOR_KINDS}')
                value = inner.get('value')
                if not (value == UNRESOLVED or (isinstance(value, int) and not isinstance(value, bool) and value >= 0)):
                    errors.append(f'{where}.locator.value must be a non-negative integer or {UNRESOLVED!r}')
            eb = loc.get('expected_bytes')
            if eb is not None:
                unknown_keys(f'{where}.expected_bytes', eb, EXPECTED_BYTES_KEYS)
                if isinstance(eb, dict) and not isinstance(eb.get('hex'), str):
                    errors.append(f'{where}.expected_bytes.hex must be a string')
            prov = loc.get('provenance')
            unknown_keys(f'{where}.provenance', prov, PROVENANCE_KEYS)
            if isinstance(prov, dict):
                kind = prov.get('kind')
                if kind not in PROVENANCE_KINDS:
                    errors.append(f'{where}.provenance.kind must be one of {PROVENANCE_KINDS}')
                if kind == 'evidence':
                    if not prov.get('source'):
                        errors.append(f'{where}: evidence provenance needs a source')
                    if not isinstance(prov.get('sha256'), str) or not HEX64.fullmatch(prov.get('sha256') or ''):
                        errors.append(f'{where}: evidence provenance needs a sha256 (64 hex)')
                if kind == 'fixture' and prov.get('sha256') is not None:
                    errors.append(f'{where}: fixture provenance must not claim an evidence sha256')
            confidence = loc.get('confidence')
            if confidence not in CONFIDENCE:
                errors.append(f'{where}.confidence must be one of {CONFIDENCE}')
            if confidence in ('OBSERVED', 'PROVEN') and (prov or {}).get('kind') != 'evidence':
                errors.append(f'{where}: confidence {confidence} requires evidence provenance '
                              '(a fact that is not evidence-backed is refused)')
            if isinstance(eb, dict) and eb.get('hex') not in (None, UNRESOLVED) and not HEX64_OR_HEX.fullmatch(str(eb.get('hex'))):
                errors.append(f'{where}.expected_bytes.hex must be hex or {UNRESOLVED!r}')

    policy = doc.get('operation_policy', {})
    if not isinstance(policy, dict):
        errors.append('operation_policy must be an object')
        policy = {}
    gated = set(privilege_gated_ops())
    for op in sorted(gated - set(policy)):
        errors.append(f'operation_policy: {op} has no explicit entry (no implicit defaults)')
    for op in sorted(set(policy) - gated):
        errors.append(f'operation_policy: {op} is not a gated operation')
    for op, entry in policy.items():
        unknown_keys(f'operation_policy.{op}', entry, POLICY_KEYS)
        if not isinstance(entry, dict):
            continue
        if not isinstance(entry.get('profile_required'), bool):
            errors.append(f'operation_policy.{op}: profile_required must be a boolean')
            continue
        if not entry.get('reason'):
            errors.append(f'operation_policy.{op}: an explicit reason is mandatory')
        req = REQ_BY_OP.get(op)
        if req is not None and bool(req.profile_required) != entry.get('profile_required'):
            errors.append(f'operation_policy.{op}: profile_required disagrees with the W4 matrix')
        if entry.get('profile_required'):
            ref = entry.get('locator_ref')
            if ref is None:
                # W10 revision: profile_required=True with locator_ref=None is the explicit
                # "required, but this profile carries no evidence-backed locator yet" state of a
                # promoted profile that covers a subset of the platform. It fails closed
                # downstream (profile_preconditions reports LOCATOR_MISSING) and it needs a
                # reason, so it can never be read as "no profile needed".
                pass
            elif ref not in locators:
                errors.append(f'operation_policy.{op}: locator_ref {ref!r} has no locator entry')
            if not entry.get('profile_fields'):
                errors.append(f'operation_policy.{op}: profile_fields must not be empty '
                              'when a profile is required')
        elif entry.get('locator_ref'):
            errors.append(f'operation_policy.{op}: profile_not_required must not name a locator_ref')

    declared = doc.get('canonical_sha256')
    if declared is not None:
        computed = canonical_profile_sha256(doc)
        if declared != computed:
            errors.append(f'canonical_sha256 mismatch: declared {declared[:12]}… computed {computed[:12]}…')
    # fixture marking must be honest: fixture facts or unresolved values require fixture=true
    if doc.get('fixture') is False and (unresolved_facts(doc) or fixture_facts(doc)):
        errors.append('fixture=false but the profile contains UNRESOLVED or fixture facts')
    return errors


HEX64_OR_HEX = re.compile(r'^(?:[0-9a-f]{2})+$')


def unresolved_facts(doc: dict) -> list[str]:
    """Every value that still needs an on-site fact (UNRESOLVED)."""
    out: list[str] = []
    target = doc.get('target', {})
    if isinstance(target, dict):
        for key, value in target.items():
            if value == UNRESOLVED:
                out.append(f'target.{key}')
    for name, loc in (doc.get('locators') or {}).items():
        if not isinstance(loc, dict):
            continue
        if (loc.get('locator') or {}).get('value') == UNRESOLVED:
            out.append(f'locators.{name}.locator.value')
        if loc.get('section') == UNRESOLVED:
            out.append(f'locators.{name}.section')
        if loc.get('permissions') == UNRESOLVED:
            out.append(f'locators.{name}.permissions')
    return out


def fixture_facts(doc: dict) -> list[str]:
    """Locator facts that are marked as fixtures rather than evidence."""
    out: list[str] = []
    for name, loc in (doc.get('locators') or {}).items():
        if isinstance(loc, dict) and (loc.get('provenance') or {}).get('kind') == 'fixture':
            out.append(f'locators.{name}')
    return out


def evidence_backed(doc: dict) -> bool:
    """True only when nothing is unresolved and no fact is a fixture marker."""
    return not unresolved_facts(doc) and not fixture_facts(doc)


# --- preconditions (the part W5 owns) ------------------------------------------------
def profile_preconditions(doc: dict | None, *, requests: tuple[LocatorRequest, ...] = (),
                          boot_binding=None, current_boot_id: str | None = None,
                          expected_target: dict | None = None,
                          evidence_profile_sha256: str | None = None) -> ProfileVerdict:
    """Evaluate the profile part of the gate decision. Fail-closed, all codes reported."""
    if doc is None:
        return ProfileVerdict((PROFILE_BINDING_MISSING,), ('no profile submitted',), None, False)

    codes: list[str] = []
    details: list[str] = []

    def fail(code: str, detail: str) -> None:
        if code not in codes:
            codes.append(code)
        details.append(f'{code}: {detail}')

    sha = canonical_profile_sha256(doc)
    declared = doc.get('canonical_sha256')
    if declared is not None and declared != sha:
        fail(PROFILE_MISMATCH, 'declared canonical_sha256 does not match the canonical content')

    unresolved = unresolved_facts(doc)
    if unresolved:
        fail(PROFILE_UNVERIFIED, f'{len(unresolved)} unresolved fact(s): '
                                 f'{", ".join(unresolved[:4])}{" …" if len(unresolved) > 4 else ""}')
    fixtures = fixture_facts(doc)
    if fixtures:
        details.append(f'NOTE: {len(fixtures)} fixture fact(s) - structurally matchable, '
                       'not evidence-backed')

    if expected_target:
        target = doc.get('target') or {}
        for key in IDENTITY_FIELDS:
            wished = expected_target.get(key)
            if wished is None:
                continue
            have = target.get(key)
            if have != wished:
                fail(PROFILE_MISMATCH, f'target.{key} {have!r} != expected {wished!r}')

    if boot_binding is None:
        fail(BOOT_BINDING_MISMATCH, 'no boot binding submitted')
    else:
        if getattr(boot_binding, 'profile_sha256', None) != sha:
            fail(BOOT_BINDING_MISMATCH, 'boot binding references a different profile hash')
        if current_boot_id is not None and getattr(boot_binding, 'boot_id', None) != current_boot_id:
            fail(BOOT_BINDING_MISMATCH, 'boot binding belongs to a different boot (facts persist, '
                                        'the runtime binding does not)')

    if evidence_profile_sha256 is not None and evidence_profile_sha256 != sha:
        fail(PROFILE_MISMATCH, 'verification evidence references a different profile hash')

    locators = doc.get('locators') or {}
    for request in requests:
        policy = (doc.get('operation_policy') or {}).get(request.operation)
        if not policy or not policy.get('profile_required'):
            continue  # explicit profile_not_required: no locator expected
        ref = policy.get('locator_ref')
        if ref is None:
            # explicitly pending: this profile carries no evidence-backed locator for the
            # operation (fail closed, the profile does not claim anything it cannot back)
            fail(LOCATOR_MISSING, f'{request.operation}: the profile has no evidence-backed '
                                  f'locator for this operation yet')
            continue
        loc = locators.get(ref)
        if loc is None:
            fail(LOCATOR_MISSING, f'{request.operation}: no locator entry for {ref!r}')
            continue
        if (loc.get('locator') or {}).get('value') == UNRESOLVED:
            fail(PROFILE_UNVERIFIED, f'{request.operation}: locator value is UNRESOLVED')
            continue
        if request.module is not None and loc.get('module') != request.module:
            fail(LOCATOR_MISMATCH, f'{request.operation}: module {loc.get("module")!r} != '
                                   f'requested {request.module!r}')
        if request.section is not None and loc.get('section') != request.section:
            fail(LOCATOR_MISMATCH, f'{request.operation}: section {loc.get("section")!r} != '
                                   f'requested {request.section!r}')
        if request.permissions is not None and loc.get('permissions') != request.permissions:
            fail(LOCATOR_MISMATCH, f'{request.operation}: permissions {loc.get("permissions")!r} != '
                                   f'requested {request.permissions!r}')
        if request.expected_bytes_hex is not None:
            have = (loc.get('expected_bytes') or {}).get('hex')
            if have != request.expected_bytes_hex:
                fail(LOCATOR_MISMATCH, f'{request.operation}: expected bytes differ from the '
                                       'requested signature')

    if not codes:
        codes.append(PROFILE_MATCH)
    ordered = tuple(code for code in PRECONDITION_CODES + (PROFILE_MATCH,) if code in codes)
    return ProfileVerdict(ordered, tuple(details), sha, evidence_backed(doc))


def check_evidence_profile_hash(verification_record: dict, profile_sha256: str) -> bool:
    """Verification evidence must reference exactly this profile hash."""
    return verification_record.get('profile_sha256') == profile_sha256


# --- value domains for every profile field (W4 handoff: no field without a domain) ---
@dataclass(frozen=True)
class DomainSpec:
    field: str
    kind: str            # 'u64' | 'u32' | 'hex64' | 'hex' | 'rva' | 'addr_canonical'
                         # | 'unresolved'
    description: str
    resolved: bool


def _domain(field: str, kind: str, description: str, resolved: bool) -> DomainSpec:
    return DomainSpec(field, kind, description, resolved)


FIELD_DOMAINS = {
    'addr': _domain('addr', 'u64', 'unsigned 64-bit target address, > 0', True),
    'va': _domain('va', 'u64', 'unsigned 64-bit client virtual address, > 0', True),
    'size': _domain('size', 'u64', 'byte count, >= 1 (probe plans are bounded to 4096)', True),
    # W12-RVA0-BINDING: the *relative* locator domain (the profile's locator kinds are
    # 'rva'/'relative'). A locator value is an image position, not a runtime address, and
    # zero is valid: ``image_elf`` lives at the image base (rva 0x0).
    'rva': _domain('rva', 'rva', 'relative image position (rva) inside the pinned image '
                             'window: 0 <= rva < 2**64; zero is valid', True),
    # The *runtime* domain: only ever applied to a value resolved against the current boot's
    # kernel base. Zero is not an address, and a non-canonical value is not expressible.
    'runtime_va': _domain('runtime_va', 'addr_canonical',
                          'resolved runtime address (kernel base + rva): > 0 and canonical '
                          '(48-bit sign-extended)', True),
    'expected_sha256': _domain('expected_sha256', 'hex64', '64 hex characters', True),
    'expected': _domain('expected', 'hex', 'hex-encoded comparison value', True),
    'gvm_id': _domain('gvm_id', 'unresolved', 'GPU VM identifier: no verified domain in the '
                                              'frozen core yet - on-site/owner input required', False),
    'prot': _domain('prot', 'unresolved', 'GPU mapping protection: no verified domain in the '
                                          'frozen core yet', False),
    'mapping_ref': _domain('mapping_ref', 'unresolved', 'mapping reference handed out by a prior '
                                                        'mapping: no verified domain yet', False),
    'claim_ref': _domain('claim_ref', 'unresolved', 'claim reference handed out by keymgr.claim: '
                                                    'no verified domain yet', False),
    'slot': _domain('slot', 'unresolved', 'key/CCP slot: no verified domain yet', False),
    'scope': _domain('scope', 'unresolved', 'snapshot scope selector: no verified domain yet', False),
    'command': _domain('command', 'unresolved', 'CCP command blob: no verified domain yet', False),
    'range': _domain('range', 'unresolved', 'kernel range selector: no verified domain yet', False),
    'region_ref': _domain('region_ref', 'unresolved', 'region reference: no verified domain yet', False),
    # W17F: bounded recipe selector. The admissible values are the recipe names of the generated
    # profile recipe table (tools/profiles/experiment_recipes.py); the table itself is the authority.
    'recipe_ref': _domain('recipe_ref', 'unresolved', 'recipe reference into the generated recipe table', False),
    'region_map': _domain('region_map', 'unresolved', 'region map descriptor: no verified domain '
                                                      'yet', False),
    'probe': _domain('probe', 'unresolved', 'probe descriptor for a read-only verification: no '
                                            'verified domain yet', False),
}


def validate_field_value(field: str, value) -> list[str]:
    """Check one value against its domain. An unresolved domain accepts nothing."""
    spec = FIELD_DOMAINS.get(field)
    if spec is None:
        return [f'{field}: no domain declared (every profile field needs one)']
    if not spec.resolved:
        return [f'{field}: value domain is unresolved ({spec.description}); '
                'values cannot be accepted yet - fail closed']
    if spec.kind in ('u64', 'u32'):
        limit = 2 ** 64 - 1 if spec.kind == 'u64' else 2 ** 32 - 1
        if not isinstance(value, int) or isinstance(value, bool) or not 0 < value <= limit:
            return [f'{field}: expected {spec.kind} value > 0, got {value!r}']
        return []
    if spec.kind == 'rva':
        if not isinstance(value, int) or isinstance(value, bool) \
                or not 0 <= value <= 2 ** 64 - 1:
            return [f'{field}: expected a relative image position 0 <= rva < 2**64 '
                    f'(zero is a valid locator), got {value!r}']
        return []
    if spec.kind == 'addr_canonical':
        if not isinstance(value, int) or isinstance(value, bool) or not 0 < value <= 2 ** 64 - 1:
            return [f'{field}: expected a non-zero unsigned 64-bit address, got {value!r}']
        from tools.profiles.kread import is_canonical_x86_64  # noqa: PLC0415 - no import cycle
        if not is_canonical_x86_64(value):
            return [f'{field}: address {value:#x} is not canonical (bits 63..47 must be all '
                    'zero or all one)']
        return []
    text = value if isinstance(value, str) else ''
    if spec.kind == 'hex64':
        if not HEX64.fullmatch(text):
            return [f'{field}: expected 64 hex characters, got {value!r}']
        return []
    if spec.kind == 'hex':
        if not text or not HEX64_OR_HEX.fullmatch(text):
            return [f'{field}: expected a hex string, got {value!r}']
        return []
    return [f'{field}: unknown domain kind {spec.kind!r}']


#: W12-RVA0-BINDING: every locator kind this domain model declares maps to the domain that
#: validates its *value*. Both declared kinds are relative: a locator value is an image
#: position and zero is valid; it is never a runtime address.
LOCATOR_VALUE_DOMAINS = {'rva': 'rva', 'relative': 'rva'}


def validate_locator_value(kind: str, value) -> list[str]:
    """Check one locator value against the domain of its declared kind (fail closed).

    Used by the W5 profile binding: the binding binds the *locator*, never a runtime
    address. Runtime resolution happens later, with the current boot's kernel base
    (``tools.profiles.regions.resolve_runtime``), and its result is validated against
    ``FIELD_DOMAINS['runtime_va']`` (non-zero, canonical).
    """
    field = LOCATOR_VALUE_DOMAINS.get(kind)
    if field is None:
        return [f'locator kind {kind!r} has no value domain (known kinds: '
                f'{sorted(LOCATOR_VALUE_DOMAINS)}) - fail closed']
    return [f'locator value ({kind}): {problem}'
            for problem in validate_field_value(field, value)]


def module_locator_kind(doc: dict, module: str) -> str | None:
    """The locator kind a module declares (``LOCATOR_KINDS``), or ``None`` (fail closed)."""
    entry = ((doc or {}).get('modules') or {}).get(module)
    kind = entry.get('locator_kind') if isinstance(entry, dict) else None
    return kind if kind in LOCATOR_KINDS else None


def domain_coverage() -> dict:
    """Coverage report: every profile field of the W4 matrix needs a domain."""
    needed = sorted({name for row in operation_matrix() for name in row['profile_fields']})
    missing = [name for name in needed if name not in FIELD_DOMAINS]
    return {
        'fields': needed,
        'missing': missing,
        'resolved': sorted(name for name in needed
                           if FIELD_DOMAINS.get(name) is not None and FIELD_DOMAINS[name].resolved),
        'unresolved': sorted(name for name in needed
                             if FIELD_DOMAINS.get(name) is not None and not FIELD_DOMAINS[name].resolved),
    }


# --- machine-readable operation/profile matrix ---------------------------------------
def operation_matrix() -> list[dict]:
    rows = []
    for op in privilege_gated_ops():
        req = REQ_BY_OP[op]
        rows.append({
            'op': op,
            'profile_required': bool(req.profile_required),
            'module': _module_for(req.family) if req.profile_required else None,
            'locator_kind': 'rva' if req.profile_required else None,
            'profile_fields': list(req.profile_fields),
            'w4_reason': req.defer_reason,
        })
    return rows


def _self_test() -> list[str]:
    errors: list[str] = []
    doc = empty_profile('fw-fixture', fixture=True)
    errors += [f'skeleton: {e}' for e in validate_profile(doc)]
    if unresolved_facts(doc) == []:
        errors.append('skeleton must report unresolved facts (no on-site data yet)')
    verdict = profile_preconditions(doc)
    if PROFILE_UNVERIFIED not in verdict.codes:
        errors.append('skeleton must be PROFILE_UNVERIFIED')
    if verdict.matched:
        errors.append('skeleton must not match')
    names = [row['op'] for row in operation_matrix()]
    if len(set(names)) != len(names):
        raise AssertionError('duplicate operation rows in the W4 matrix')
    if set(names) != set(privilege_gated_ops()):
        errors.append('operation matrix must cover exactly the gated operations: '
                      f'missing={sorted(set(privilege_gated_ops()) - set(names))} '
                      f'unexpected={sorted(set(names) - set(privilege_gated_ops()))}')
    for row in operation_matrix():
        if not row['profile_required'] and not row['w4_reason']:
            errors.append(f'{row["op"]}: profile_not_required needs a reason')
    # W12-RVA0-BINDING: the relative domain accepts zero, the runtime domain never does.
    if validate_locator_value('rva', 0) != []:
        errors.append('rva 0 must be a valid locator value')
    if not validate_locator_value('rva', 2 ** 64):
        errors.append('an rva beyond the unsigned 64-bit domain must be refused')
    if validate_locator_value('rva', 4096) != []:
        errors.append('a non-zero rva must stay valid')
    if not validate_field_value('runtime_va', 0):
        errors.append('a zero runtime address must be refused')
    if not validate_field_value('addr', 0):
        errors.append('the runtime address domain must keep refusing 0')
    if validate_field_value('runtime_va', 1 << 46) != []:   # bits 63..47 all zero: canonical
        errors.append('a canonical non-zero runtime address must be accepted')
    if not validate_field_value('runtime_va', 1 << 48):             # bit 48 set: not canonical
        errors.append('a non-canonical runtime address must be refused')
    coverage = domain_coverage()
    if coverage['missing']:
        errors.append(f'profile fields without a value domain: {coverage["missing"]}')
    if not coverage['unresolved']:
        errors.append('expected unresolved domains for fields without a verified type '
                      '(fail-closed until on-site facts exist)')
    return errors


def main(argv: list[str]) -> int:
    if '--matrix' in argv:
        coverage = domain_coverage()
        print(json.dumps({'schema': SCHEMA_ID, 'operations': operation_matrix(),
                          'precondition_codes': list(PRECONDITION_CODES + (PROFILE_MATCH,)),
                          'field_domains': {name: {'kind': spec.kind, 'resolved': spec.resolved,
                                                   'description': spec.description}
                                            for name, spec in sorted(FIELD_DOMAINS.items())},
                          'domain_coverage': coverage},
                         indent=1, sort_keys=True))
        return 0
    if '--self-test' not in argv:
        print((__doc__ or '').strip().splitlines()[0])
        print('usage: schema.py --self-test | --matrix')
        return 2
    errors = _self_test()
    coverage = domain_coverage()
    print(f'profile schema {SCHEMA_ID}: {len(privilege_gated_ops())} gated operations, '
          f'{len(PRECONDITION_CODES) + 1} precondition codes, '
          f'{len(coverage["fields"])} profile fields '
          f'({len(coverage["resolved"])} typed / {len(coverage["unresolved"])} unresolved)')
    if errors:
        print(f'PROFILE SCHEMA INCONSISTENT ({len(errors)})')
        for err in errors:
            print(f'  - {err}')
        return 1
    print('PROFILE SCHEMA OK: skeleton validates, preconditions fail closed, matrix complete')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
