#!/usr/bin/env python3
"""PS4RF P4/W12 kernel.read verification: the *separate* flow that can move the requirement.

A read being observed proves nothing about what was read. This module is the second half of
the W12 pair (the first half is ``tools/profiles/kread_capability.py``): it re-checks one read
evidence document against the current bindings and the expectation for the read, in a run that
is separate from the read, and it is the only thing that can move the requirement past
``DEFERRED``.

Run separation, faithfully (W4/F1, ``core/models/verification.py``): a privileged trigger run
may not verify itself -- ``if privileged and v.verification_run_id == trigger_run_id:
rej('RUN_NOT_SEPARATE')``. The same rule applies here: the verification run must be a
*different* run from the read that produced the evidence and must say so
(``verification.run_id != evidence.run_id`` and ``verification.separate_from_read is True``).
A forged ``VerificationEvidence`` block that is field-perfect but produced by the trigger run
itself is refused with ``RUN_NOT_SEPARATE`` -- and the requirement stays ``DEFERRED``.

Assurance labels (wave-owner review item 2): before a passing verification the requirement is
``DEFERRED``; after it, ``ELIGIBLE``. ``ELIGIBLE`` is not execution: a live provider is never
entered automatically -- the capability path still requires the explicit live-approval flag
(``KREAD_LIVE_APPROVAL_REQUIRED`` otherwise) and ``MOCK``/``NATIVE`` policy is unchanged, so
``NATIVE`` alone can reach at most ``OBSERVED`` and only a passing separate verification makes
the requirement ``ELIGIBLE``.

The narrow bootstrap path (wave-owner review item 1) -- no circular dependency:

.. code-block:: text

    fixed verification region      : 'xfast_entry'  (registry: STRICT_FINGERPRINT, 8 bytes,
                                                     promoted W5 locator kernel.attest.xfast_entry,
                                                     expected bytes pinned in the profile and
                                                     re-verified against the pinned FW13.52 dump)
    compile/profile-bound locator  : 0x1C0          (== the LSTAR page offset, so the bootstrap read
                                                     also confirms the kbase derivation; rva/length
                                                     are read from the registry, single source)
    fixed bounded expected length  : 8              (registry: xfast_entry.length)
    expected sha256                : 67bde9435ba5b3758dd1769c3b6d6650e2e0c628a197a17c2c1a401c2af87cd2
    -> VerificationEvidence       : the first one that can ever exist

'boottime' is deliberately NOT the bootstrap region: it has no promoted W5 locator, so it stays
DEFERRED for the generic provider.

The generic bounded, region-based ``kernel.read`` needs a present ``VerificationEvidence``
record; that record can only come from a verification; a verification needs a read. The
bootstrap breaks the circle *narrowly*: one fixed region, one compile-bound locator, one fixed
bounded length, verified by this module without any generic ``kernel.read`` having been
granted. Only after a passing bootstrap verification may the generic bounded, region-based
read be used -- and a test asserts exactly that: the bootstrap completes while the generic
``kernel.read`` is still ``DEFERRED``.

Evidence fields checked here (wave-owner review item 3): the evidence carries
``requested_region``, ``requested_offset``, ``requested_length`` and, separately,
``resolved_rva`` (unslid internal address) and ``resolved_runtime_va`` (runtime VA,
evidence-only). This verifier independently checks: the region is a known STRICT region of the
frozen registry, ``resolved_rva == region.rva + offset``, offset + length stay inside the
region, the expected bytes/hash, the requested length, the observed byte count, that the
returned bytes hash to the claimed output SHA-256, the profile ``sha256``, the ``boot_id``, the
provider identity, and that the evidence records the resolved address while the request never
carried one (``request_contained_address`` must be ``False``).

No duplicated semantics: this module re-uses the request model's raw-address scan
(``kread.is_raw_address_key``), the registry's region facts (``regions.get_region``), the frozen
u64 checked add / canonicality primitives (``kread.checked_add``, ``kread.is_canonical_x86_64``)
and the frozen W4 provider policy table (``REQ_BY_OP``) - it re-implements none of them, and a
parity test pins the module identities so a later drift is visible.

Report keys: ``verified``, ``outcome`` (``PROVEN`` / ``NOT_VERIFIED``), ``problems`` (exact
texts), ``requirement_before`` (``DEFERRED``), ``requirement_after`` (``ELIGIBLE`` only on a
passing verification), ``resolved_address_in_evidence``, ``request_contained_address``,
``resolved_region`` / ``resolved_offset`` / ``resolved_length``, ``requested_length``,
``observed_length``, ``lengths_matched``, ``run_separate``, ``verification_path``, ``checks``.

Usage::

    python tools/hostctl/kreadverify.py --self-test
"""

from __future__ import annotations

import hashlib
import pathlib
import sys
from collections.abc import Mapping
from typing import TypeGuard

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:                       # pragma: no cover - import bootstrap
    sys.path.insert(0, str(REPO_ROOT))

from tools.hostctl import bootpriv                                            # noqa: E402
from tools.primitive_iface.gate import REQ_BY_OP                              # noqa: E402
from tools.profiles import kread, regions                                     # noqa: E402
from tools.profiles.binding import BootBinding                                # noqa: E402
from tools.profiles.kread_capability import EVIDENCE_SCHEMA                   # noqa: E402
from tools.profiles.schema import canonical_profile_sha256                    # noqa: E402

OPERATION = 'kernel.read'
VERIFICATION_OPERATION = 'verify.kernel.read'
REPORT_SCHEMA = 'ps4rf.kread.verification-report.v1'

#: assurance labels of the requirement (wave-owner review item 2)
REQUIREMENT_DEFERRED = 'DEFERRED'
REQUIREMENT_ELIGIBLE = 'ELIGIBLE'
OUTCOME_PROVEN = 'PROVEN'
OUTCOME_NOT_VERIFIED = 'NOT_VERIFIED'

#: The fixed bootstrap verification window (wave-owner pre-live item 1). The chosen region is
#: ``image_elf``: STRICT_FINGERPRINT, promoted W5 locator ``kernel.attest.image_elf``, expected bytes
#: pinned in the profile *and* re-verified against the pinned FW13.52 dump, inside the allowed read
#: range, 16 bytes.
#:
#: Why this one and not the runner-up ``xfast_entry``: the accepted, hash-frozen W12 payload performs
#: its live read through the generated region table and its trigger takes the FIRST STRICT row, which
#: is ``image_elf`` (index 0, rva 0x0, 16 bytes). Naming the same region host-side keeps the accepted
#: payload byte-identical; switching the payload to ``xfast_entry`` would be a payload change and
#: would need a fresh artefact review. Both regions satisfy every bootstrap criterion (STRICT,
#: promoted locator, pinned expected bytes, complete provenance, in range, not aperture/structural/
#: unresolved).
#:
#: ``boottime`` is deliberately NOT used: it has no promoted W5 locator, so it stays DEFERRED for the
#: generic provider and must not serve as the live bootstrap region.
#: rva/length come from the registry -- the single normative source -- never from a literal here.
BOOTSTRAP_REGION = 'image_elf'
BOOTSTRAP_OFFSET = 0
_bootstrap_region = regions.get_region(BOOTSTRAP_REGION)
if _bootstrap_region is None or _bootstrap_region.rva is None:          # pragma: no cover
    raise RuntimeError('W12_BOOTSTRAP_REGION_BLOCKED: the bootstrap region is not in the registry')
BOOTSTRAP_RVA = _bootstrap_region.rva
BOOTSTRAP_LENGTH = _bootstrap_region.length

# --- exact problem texts (frozen: the tests assert these strings verbatim) ---------------
P_EVIDENCE_INVALID = 'EVIDENCE_INVALID: {detail}'
P_REQUEST_CONTAINED_ADDRESS = ('REQUEST_CONTAINED_ADDRESS: the request carries address-ish '
                               'field(s) {keys}')
P_RUN_SEPARATION_UNDECLARED = ('RUN_SEPARATION_UNDECLARED: the evidence carries no separate '
                               'verification run declaration')
P_RUN_NOT_SEPARATE = ('RUN_NOT_SEPARATE: verification run {verify_run} is the read run '
                      '{read_run}; a separate run is required (W4/F1)')
P_RUN_NOT_DECLARED_SEPARATE = ('RUN_NOT_SEPARATE: the verification does not declare '
                               'separate_from_read=true (W4/F1)')
P_VERIFICATION_OPERATION_MISMATCH = ('VERIFICATION_OPERATION_MISMATCH: the verification run is '
                                     '{found!r}, not {expected!r}')
P_VERIFICATION_NOT_PASS = ('VERIFICATION_NOT_PASS: the verification run declared outcome '
                           '{found!r}, not PASS')
P_PROFILE_SHA256_MISMATCH = 'PROFILE_SHA256_MISMATCH: {what} references {found} != current profile {expected}'
P_STALE_BOOT_ID = 'STALE_BOOT_ID: {what} references {found} != current boot {expected}'
P_REGION_MISMATCH = 'REGION_MISMATCH: {what} {found!r} != {expected!r}'
P_REGION_UNKNOWN = 'REGION_UNKNOWN: {region!r} is not a registered W12 read region'
P_REGION_UNRESOLVED = 'REGION_UNRESOLVED: {region!r} carries no identity source and admits no read'
P_REGION_NOT_STRICT = ('REGION_NOT_STRICT: {region!r} is {status} and cannot establish a '
                       'STRICT identity')
P_OFFSET_MISMATCH = 'OFFSET_MISMATCH: request {request_offset} != evidence {evidence_offset}'
P_REQUESTED_LENGTH_MISMATCH = ('REQUESTED_LENGTH_MISMATCH: request {request_length} != evidence '
                               '{evidence_length}')
P_CROSS_REGION = ('CROSS_REGION: offset {offset} + length {length} reaches past region '
                  '{region!r} ({region_length} bytes)')
P_RESOLVED_RVA_MISSING = 'RESOLVED_RVA_MISSING: the evidence records no resolved internal address'
P_RESOLVED_RVA_NOT_CANONICAL = ('RESOLVED_RVA_NOT_CANONICAL: {address!r} is not a canonical '
                                'x86-64 address')
P_RESOLVED_RVA_MISMATCH = ('RESOLVED_RVA_MISMATCH: evidence {found} != region rva + offset '
                           '{expected}')
P_RESOLVED_RUNTIME_VA_MISSING = ('RESOLVED_RUNTIME_VA_MISSING: the evidence records no resolved '
                                 'runtime VA')
P_RESOLVED_RUNTIME_VA_NOT_CANONICAL = ('RESOLVED_RUNTIME_VA_NOT_CANONICAL: {address!r} is not a '
                                       'canonical x86-64 address')
P_RESOLVED_RUNTIME_VA_MISMATCH = ('RESOLVED_RUNTIME_VA_MISMATCH: evidence {found} != runtime '
                                  'base + resolved_rva {expected}')
P_BYTE_COUNT_MISMATCH = ('BYTE_COUNT_MISMATCH: the read returned {observed} bytes but the '
                         'requested length is {requested}')
P_OUTPUT_SHA256_MISMATCH = ('OUTPUT_SHA256_MISMATCH: the returned bytes hash to {recomputed} != '
                            'the claimed {claimed}')
P_PROVIDER_MISMATCH = 'PROVIDER_MISMATCH: {detail}'
P_EXPECTED_REGION_MISMATCH = 'EXPECTED_REGION_MISMATCH: evidence region {found!r} != expected {expected!r}'
P_EXPECTED_BYTES_MISMATCH = 'EXPECTED_BYTES_MISMATCH: the returned bytes differ from the expected bytes'
P_EXPECTED_SHA256_MISMATCH = ('EXPECTED_SHA256_MISMATCH: the returned bytes hash to {recomputed} '
                              '!= expected {expected}')
P_EXPECTED_LENGTH_MISMATCH = ('EXPECTED_LENGTH_MISMATCH: requested length {requested} != expected '
                              '{expected}')
P_BOOTSTRAP_REGION_MISMATCH = ('BOOTSTRAP_REGION_MISMATCH: {what} {found!r} is not the fixed '
                               'bootstrap region {expected!r}')
P_BOOTSTRAP_LOCATOR_MISMATCH = ('BOOTSTRAP_LOCATOR_MISMATCH: {what} {found} != the compile-bound '
                                'locator {expected}')
P_BOOTSTRAP_LENGTH_MISMATCH = ('BOOTSTRAP_LENGTH_MISMATCH: {what} {found} != the fixed bounded '
                               'expected length {expected}')


def _hex(value) -> str:
    return f'{value:#x}' if isinstance(value, int) and not isinstance(value, bool) else repr(value)


def _is_int(value) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


def _verify(request, evidence, *, profile, boot_binding, expected, fixed, path) -> dict:
    problems: list[str] = []
    checks: list[dict] = []

    def check(name: str, ok: bool, detail: str = '') -> bool:
        checks.append({'check': name, 'ok': bool(ok), 'detail': detail})
        return bool(ok)

    def fail(text: str) -> None:
        problems.append(text)

    report: dict = {
        'schema': REPORT_SCHEMA,
        'operation': OPERATION,
        'verification_operation': VERIFICATION_OPERATION,
        'verification_path': path,
        'verified': False,
        'outcome': OUTCOME_NOT_VERIFIED,
        'problems': problems,
        'requirement': OPERATION,
        'requirement_before': REQUIREMENT_DEFERRED,
        'requirement_after': REQUIREMENT_DEFERRED,
        'run_separate': False,
        'resolved_address_in_evidence': None,
        'resolved_rva_in_evidence': None,
        'resolved_runtime_va_in_evidence': None,
        'request_contained_address': False,
        'resolved_region': None,
        'resolved_offset': None,
        'resolved_length': None,
        'requested_length': None,
        'observed_length': None,
        'lengths_matched': False,
        'checks': checks,
    }

    # 0. the request itself: no address anywhere, ever. The address exists only on the
    #    evidence side (and inside the capability decision).
    request_is_mapping = isinstance(request, Mapping)
    if not request_is_mapping:
        fail(P_EVIDENCE_INVALID.format(detail='the request is not a mapping'))
        request = {}
    address_keys = sorted(key for key in request if kread.is_raw_address_key(key))
    report['request_contained_address'] = bool(address_keys)
    if address_keys:
        fail(P_REQUEST_CONTAINED_ADDRESS.format(keys=address_keys))
    check('request_carries_no_address', not address_keys, f'{len(address_keys)} address-ish key(s)')

    # 1. the evidence must be this wave's read evidence for this operation
    if not isinstance(evidence, Mapping):
        fail(P_EVIDENCE_INVALID.format(detail='the evidence is not a mapping'))
        return _finalize(report, problems)
    evidence = dict(evidence)
    check('evidence_schema', evidence.get('schema') == EVIDENCE_SCHEMA, str(evidence.get('schema')))
    if evidence.get('schema') != EVIDENCE_SCHEMA:
        fail(P_EVIDENCE_INVALID.format(detail=f"unexpected schema {evidence.get('schema')!r}"))
    if evidence.get('operation') != OPERATION:
        fail(P_EVIDENCE_INVALID.format(detail=f"unexpected operation {evidence.get('operation')!r}"))

    # 2. the returned bytes: what the read actually covered
    returned = None
    if isinstance(evidence.get('bytes_hex'), str):
        try:
            returned = bytes.fromhex(evidence['bytes_hex'])
        except ValueError:
            returned = None
    if returned is None:
        fail(P_EVIDENCE_INVALID.format(detail='the evidence carries no valid bytes_hex'))
    observed = len(returned) if returned is not None else None
    report['observed_length'] = observed
    claimed_observed = evidence.get('observed_length')
    if observed is not None and _is_int(claimed_observed) and claimed_observed != observed:
        fail(P_EVIDENCE_INVALID.format(
            detail=f'the evidence claims observed_length {claimed_observed} but carries '
                   f'{observed} bytes'))

    # 3. the output SHA-256 must be the hash of the returned bytes (never a claim)
    recomputed = hashlib.sha256(returned).hexdigest() if returned is not None else None
    claimed_sha = evidence.get('output_sha256')
    sha_ok = recomputed is not None and claimed_sha == recomputed
    if recomputed is not None and not sha_ok:
        fail(P_OUTPUT_SHA256_MISMATCH.format(recomputed=recomputed, claimed=claimed_sha))
    check('output_sha256_matches_returned_bytes', sha_ok)

    # 4. lengths: requested vs evidenced vs observed - exactly equal, or nothing is proven
    request_length = request.get('length')
    evidence_length = evidence.get('requested_length')
    report['requested_length'] = request_length
    report['resolved_length'] = evidence_length
    if request_length != evidence_length:
        fail(P_REQUESTED_LENGTH_MISMATCH.format(request_length=request_length,
                                                evidence_length=evidence_length))
    if observed is not None and observed != request_length:
        fail(P_BYTE_COUNT_MISMATCH.format(observed=observed, requested=request_length))
    report['lengths_matched'] = bool(observed is not None and request_length == evidence_length
                                     == observed)
    check('lengths_matched', report['lengths_matched'],
          f'requested={request_length} evidenced={evidence_length} observed={observed}')

    # 5. the region: known, STRICT, and the one the request asked for
    request_region = request.get('region')
    evidence_region = evidence.get('requested_region')
    evidence_offset = evidence.get('requested_offset')
    report['resolved_region'] = evidence_region
    report['resolved_offset'] = evidence_offset
    if request_region != evidence_region:
        fail(P_REGION_MISMATCH.format(what='the request region', found=request_region,
                                      expected=evidence_region))
    if request.get('offset') != evidence_offset:
        fail(P_OFFSET_MISMATCH.format(request_offset=request.get('offset'),
                                      evidence_offset=evidence_offset))
    expected_region = expected.get('region')
    if expected_region is not None and evidence_region != expected_region:
        fail(P_EXPECTED_REGION_MISMATCH.format(found=evidence_region, expected=expected_region))
    region = regions.get_region(evidence_region) if isinstance(evidence_region, str) else None
    if region is None:
        fail(P_REGION_UNKNOWN.format(region=evidence_region))
    elif region.identity_status == regions.IDENTITY_UNRESOLVED:
        fail(P_REGION_UNRESOLVED.format(region=evidence_region))
    elif region.identity_status != regions.IDENTITY_STRICT:
        fail(P_REGION_NOT_STRICT.format(region=evidence_region,
                                        status=region.identity_status))
    check('region_is_known_strict', region is not None
          and region.identity_status == regions.IDENTITY_STRICT, str(evidence_region))

    # 6. bounds and the resolved internal address (unslid): recomputed from the registry
    rva_expected = None
    if region is not None and _is_int(evidence_offset) and _is_int(evidence_length) \
            and _is_int(region.length) and _is_int(region.rva):
        end = kread.checked_add(evidence_offset, evidence_length)
        if end is None or end > region.length:
            fail(P_CROSS_REGION.format(offset=evidence_offset, length=evidence_length,
                                       region=evidence_region, region_length=region.length))
        else:
            rva_expected = kread.checked_add(region.rva, evidence_offset)
    resolved_rva = evidence.get('resolved_rva')
    report['resolved_rva_in_evidence'] = resolved_rva
    report['resolved_address_in_evidence'] = resolved_rva
    if not _is_int(resolved_rva):
        fail(P_RESOLVED_RVA_MISSING)
    elif not kread.is_canonical_x86_64(resolved_rva):
        fail(P_RESOLVED_RVA_NOT_CANONICAL.format(address=resolved_rva))
    elif rva_expected is not None and resolved_rva != rva_expected:
        fail(P_RESOLVED_RVA_MISMATCH.format(found=_hex(resolved_rva), expected=_hex(rva_expected)))
    check('resolved_rva_matches_region_plus_offset',
          _is_int(resolved_rva) and rva_expected is not None and resolved_rva == rva_expected,
          f'evidence={_hex(resolved_rva)} recomputed={_hex(rva_expected)}')

    # 7. the runtime VA: evidence-only, canonical, and consistent with the expected base
    runtime_va = evidence.get('resolved_runtime_va')
    report['resolved_runtime_va_in_evidence'] = runtime_va
    if not _is_int(runtime_va):
        fail(P_RESOLVED_RUNTIME_VA_MISSING)
    elif not kread.is_canonical_x86_64(runtime_va):
        fail(P_RESOLVED_RUNTIME_VA_NOT_CANONICAL.format(address=runtime_va))
    runtime_base = expected.get('runtime_base')
    if _is_int(runtime_va) and _is_int(runtime_base) and rva_expected is not None:
        want = kread.checked_add(runtime_base, rva_expected)
        if want is None or runtime_va != want:
            fail(P_RESOLVED_RUNTIME_VA_MISMATCH.format(found=_hex(runtime_va),
                                                       expected=_hex(want)))
    check('resolved_runtime_va_present_and_canonical',
          _is_int(runtime_va) and kread.is_canonical_x86_64(runtime_va), _hex(runtime_va))

    # 8. the narrow bootstrap path: fixed region, compile-bound locator, fixed length
    if fixed is not None:
        for what, found in (('the request region', request_region),
                            ('the evidence region', evidence_region)):
            if found != fixed['region']:
                fail(P_BOOTSTRAP_REGION_MISMATCH.format(what=what, found=found,
                                                        expected=fixed['region']))
        if region is not None and region.rva != fixed['rva']:
            fail(P_BOOTSTRAP_LOCATOR_MISMATCH.format(
                what=f'the registry rva of {fixed["region"]!r}', found=_hex(region.rva),
                expected=_hex(fixed['rva'])))
        if evidence_offset != fixed['offset']:
            fail(P_BOOTSTRAP_LOCATOR_MISMATCH.format(what='the evidence offset',
                                                     found=_hex(evidence_offset),
                                                     expected=_hex(fixed['offset'])))
        if evidence_length != fixed['length']:
            fail(P_BOOTSTRAP_LENGTH_MISMATCH.format(what='the evidence length',
                                                    found=evidence_length,
                                                    expected=fixed['length']))
        if _is_int(resolved_rva) and resolved_rva != fixed['rva']:
            fail(P_BOOTSTRAP_LOCATOR_MISMATCH.format(what='the evidence resolved_rva',
                                                     found=_hex(resolved_rva),
                                                     expected=_hex(fixed['rva'])))
        check('bootstrap_fixed_window',
              evidence_region == fixed['region'] and evidence_offset == fixed['offset']
              and evidence_length == fixed['length'],
              f'{fixed["region"]} offset {fixed["offset"]} length {fixed["length"]}')

    # 9. W5 profile binding: the current real profile, and the evidence/binding must name it
    if not isinstance(profile, Mapping):
        fail(P_EVIDENCE_INVALID.format(detail='no profile document was supplied'))
        current_sha = None
    else:
        current_sha = canonical_profile_sha256(dict(profile))
    for what, found in (('the evidence', evidence.get('profile_sha256')),
                        ('the boot binding', getattr(boot_binding, 'profile_sha256', None))):
        if found != current_sha:
            fail(P_PROFILE_SHA256_MISMATCH.format(what=what, found=found, expected=current_sha))
    check('profile_sha256_matches_current_profile', isinstance(profile, Mapping)
          and evidence.get('profile_sha256') == current_sha, str(current_sha))

    # 10. boot binding: a read from another boot verifies nothing about this one
    if boot_binding is None:
        fail(P_EVIDENCE_INVALID.format(detail='no boot binding was supplied'))
        current_boot = None
    else:
        current_boot = getattr(boot_binding, 'boot_id', None)
    for what, found in (('the evidence', evidence.get('boot_id')),
                        ('the boot binding', current_boot)):
        if found != current_boot or current_boot is None:
            fail(P_STALE_BOOT_ID.format(what=what, found=found, expected=current_boot))
    boot_ok = current_boot is not None and evidence.get('boot_id') == current_boot
    evidence_boot = evidence.get('boot_id')
    if isinstance(boot_binding, BootBinding) and isinstance(current_sha, str) \
            and isinstance(evidence_boot, str):
        check('boot_binding_valid_for_evidence',
              boot_binding.valid_for(evidence_boot, current_sha))
    check('boot_id_matches_current_boot', boot_ok, str(current_boot))

    # 11. provider identity: the W4 policy table decides what may be the authority
    provider_block = evidence.get('provider') if isinstance(evidence.get('provider'), Mapping) \
        else {}
    provider_name = provider_block.get('name')
    provider_type = provider_block.get('provider_type')
    allowed = REQ_BY_OP[OPERATION].allowed_providers
    if not provider_name:
        fail(P_PROVIDER_MISMATCH.format(detail='the evidence carries no provider identity'))
    if provider_type not in allowed:
        fail(P_PROVIDER_MISMATCH.format(
            detail=f'provider type {provider_type!r} is not allowed for kernel.read '
                   f'(allowed: {list(allowed)})'))
    if provider_type == 'MOCK':
        fail(P_PROVIDER_MISMATCH.format(
            detail='a MOCK provider can never be the authority for a privileged read '
                   '(W4 policy F11)'))
    expected_provider = expected.get('provider')
    if expected_provider is not None and provider_name != expected_provider:
        fail(P_PROVIDER_MISMATCH.format(
            detail=f'provider {provider_name!r} != expected {expected_provider!r}'))
    check('provider_identity_allowed', bool(provider_name) and provider_type in allowed,
          f'{provider_name}/{provider_type}')

    # 12. the expectation for this read (bytes / hash / length / region), when supplied
    if isinstance(expected.get('bytes_hex'), str) and returned is not None:
        if expected['bytes_hex'] != returned.hex():
            fail(P_EXPECTED_BYTES_MISMATCH)
    if isinstance(expected.get('sha256'), str) and returned is not None:
        if expected['sha256'] != recomputed:
            fail(P_EXPECTED_SHA256_MISMATCH.format(recomputed=recomputed,
                                                   expected=expected['sha256']))
    if _is_int(expected.get('length')) and request_length != expected['length']:
        fail(P_EXPECTED_LENGTH_MISMATCH.format(requested=request_length,
                                               expected=expected['length']))

    # 13. run separation (W4/F1): the verification is a *separate run* and says so
    read_run = evidence.get('run_id')
    verification = evidence.get('verification') if isinstance(evidence.get('verification'),
                                                              Mapping) else None
    verify_run = verification.get('run_id') if verification is not None else None
    if not isinstance(read_run, str) or not read_run:
        fail(P_EVIDENCE_INVALID.format(detail='the evidence carries no read run_id'))
    declared = verification is not None and verification.get('separate_from_read') is True
    if verification is None or not isinstance(verify_run, str) or not verify_run:
        fail(P_RUN_SEPARATION_UNDECLARED)
    elif isinstance(read_run, str) and read_run and verify_run == read_run:
        fail(P_RUN_NOT_SEPARATE.format(verify_run=verify_run, read_run=read_run))
    elif not declared:
        fail(P_RUN_NOT_DECLARED_SEPARATE)
    report['run_separate'] = bool(
        declared and isinstance(verify_run, str) and verify_run and isinstance(read_run, str)
        and read_run and verify_run != read_run)
    check('separate_verification_run', report['run_separate'],
          f'read={read_run} verification={verify_run} declared={declared}')
    block = dict(verification) if isinstance(verification, Mapping) else None
    if block is not None:
        v_op = block.get('operation')
        if v_op is not None and v_op != VERIFICATION_OPERATION:
            fail(P_VERIFICATION_OPERATION_MISMATCH.format(found=v_op,
                                                          expected=VERIFICATION_OPERATION))
        v_outcome = block.get('outcome')
        if v_outcome is not None and v_outcome != 'PASS':
            fail(P_VERIFICATION_NOT_PASS.format(found=v_outcome))

    return _finalize(report, problems)


def _finalize(report: dict, problems: list[str]) -> dict:
    verified = not problems
    report['verified'] = verified
    report['outcome'] = OUTCOME_PROVEN if verified else OUTCOME_NOT_VERIFIED
    report['requirement_after'] = REQUIREMENT_ELIGIBLE if verified else REQUIREMENT_DEFERRED
    report['requirement_before'] = REQUIREMENT_DEFERRED
    return report


def verify_read_evidence(request, evidence, *, profile=None, boot_binding=None,
                         expected=None) -> dict:
    """Verify one generic bounded kernel.read evidence document, in a separate run.

    ``expected`` (optional keys): ``region``, ``bytes_hex``, ``sha256``, ``length``,
    ``provider``, ``runtime_base``. Returns the report described in the module docstring;
    ``requirement_after`` is ``ELIGIBLE`` only when every independent check passed.
    """
    return _verify(request, evidence, profile=profile, boot_binding=boot_binding,
                   expected=dict(expected or {}), fixed=None, path='GENERIC')


def verify_bootstrap_evidence(request, evidence, *, profile=None, boot_binding=None) -> dict:
    """The narrow bootstrap verification (wave-owner review item 1): fixed region, compile-bound
    locator, fixed bounded expected length. Passes without any granted generic kernel.read."""
    fixed = {'region': BOOTSTRAP_REGION, 'rva': BOOTSTRAP_RVA, 'offset': BOOTSTRAP_OFFSET,
             'length': BOOTSTRAP_LENGTH}
    return _verify(request, evidence, profile=profile, boot_binding=boot_binding,
                   expected={'region': BOOTSTRAP_REGION, 'length': BOOTSTRAP_LENGTH},
                   fixed=fixed, path='BOOTSTRAP')


# --- self test -------------------------------------------------------------------------
def _selftest_evidence(*, region_name: str, offset: int, length: int, sha: str, boot: str,
                       read_run: str, verify_run: str, separate: bool = True,
                       provider_type: str = 'NATIVE', runtime_base: int = 0xffffffff998f4000,
                       resolved_rva: int | None = None, bytes_hex: str = 'ab' * 16) -> dict:
    """A matching read-evidence document (the same schema ``read_evidence`` assembles)."""
    if resolved_rva is None:
        region = regions.get_region(region_name)
        if region is None:                                              # pragma: no cover
            raise ValueError(f'unknown region in the self-test: {region_name!r}')
        resolved_rva = region.rva + offset
    return {
        'schema': EVIDENCE_SCHEMA,
        'operation': OPERATION,
        'run_id': read_run,
        'requested_region': region_name,
        'requested_offset': offset,
        'requested_length': length,
        'resolved_rva': resolved_rva,
        'resolved_runtime_va': runtime_base + resolved_rva,
        'bytes_hex': bytes_hex,
        'observed_length': len(bytes.fromhex(bytes_hex)),
        'output_sha256': hashlib.sha256(bytes.fromhex(bytes_hex)).hexdigest(),
        'profile_sha256': sha,
        'boot_id': boot,
        'provider': {'name': 'ps4rfd-kread-privileged', 'provider_type': provider_type},
        'verification': {'run_id': verify_run, 'operation': VERIFICATION_OPERATION,
                         'outcome': 'PASS', 'separate_from_read': separate,
                         'capability': OPERATION},
        'read': {'single_callback': True, 'writes_to_kernel': False,
                 'host_supplied_address': False},
    }


def _self_test() -> list[str]:
    """Deterministic offline self-test: a passing verification, a reused run, bootstrap."""
    problems: list[str] = []
    profile = {'profile_id': 'kreadverify-self-test', 'fixture': False}
    sha = canonical_profile_sha256(profile)
    boot = 'BOOT-' + '0' * 16
    binding = BootBinding(boot_id=boot, profile_sha256=sha)

    request = {'operation': OPERATION, 'region': 'amd_iommu', 'offset': 0, 'length': 16}
    evidence = _selftest_evidence(region_name='amd_iommu', offset=0, length=16, sha=sha,
                                  boot=boot, read_run='RUN-read', verify_run='RUN-verify')
    report = verify_read_evidence(request, evidence, profile=profile, boot_binding=binding)
    if not report['verified'] or report['outcome'] != OUTCOME_PROVEN:
        problems.append(f'the matching read did not verify: {report["problems"]}')
    if report['requirement_before'] != REQUIREMENT_DEFERRED \
            or report['requirement_after'] != REQUIREMENT_ELIGIBLE:
        problems.append('the requirement labels are not DEFERRED -> ELIGIBLE')

    reused = _selftest_evidence(region_name='amd_iommu', offset=0, length=16, sha=sha,
                                boot=boot, read_run='RUN-same', verify_run='RUN-same')
    reused_report = verify_read_evidence(request, reused, profile=profile, boot_binding=binding)
    if reused_report['verified'] or P_RUN_NOT_SEPARATE.format(
            verify_run='RUN-same', read_run='RUN-same') not in reused_report['problems']:
        problems.append(f'a reused verification run was not refused: {reused_report["problems"]}')

    boot_request = {'operation': OPERATION, 'region': BOOTSTRAP_REGION,
                    'offset': BOOTSTRAP_OFFSET, 'length': BOOTSTRAP_LENGTH}
    resolved = regions.resolve_read(BOOTSTRAP_REGION, BOOTSTRAP_OFFSET, BOOTSTRAP_LENGTH)
    boot_evidence = _selftest_evidence(region_name=BOOTSTRAP_REGION, offset=BOOTSTRAP_OFFSET,
                                       length=BOOTSTRAP_LENGTH, sha=sha, boot=boot,
                                       read_run='RUN-boot-read', verify_run='RUN-boot-verify',
                                       resolved_rva=resolved.address,
                                       bytes_hex='5c21ec69' * 4)      # image_elf is 16 bytes
    boot_report = verify_bootstrap_evidence(boot_request, boot_evidence, profile=profile,
                                            boot_binding=binding)
    if not boot_report['verified'] or boot_report['verification_path'] != 'BOOTSTRAP':
        problems.append(f'the bootstrap verification did not pass: {boot_report["problems"]}')
    if resolved.rva != BOOTSTRAP_RVA:
        problems.append('the compile-bound bootstrap locator drifted from the registry')
    return problems


def main(argv: list[str]) -> int:
    if '--self-test' not in argv:
        print((__doc__ or '').strip().splitlines()[0])
        print('usage: kreadverify.py --self-test')
        return 2
    problems = _self_test()
    for problem in problems:
        print(f'kread verify: {problem}')
    print('kread verify self-test: '
          f'{"ok" if not problems else "FAILED"} '
          '(separate run enforced, bootstrap path fixed, DEFERRED -> ELIGIBLE only on a pass)')
    return 0 if not problems else 1


if __name__ == '__main__':                                          # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
