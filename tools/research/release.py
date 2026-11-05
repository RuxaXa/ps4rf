#!/usr/bin/env python3
"""W13 — the research read release record: the window a live read may touch, and nothing else.

Owner decision (W13 read 1, option A) plus the separation rule from the review:

* the section 70 approval (:mod:`tools.research.approval`) answers *"may the already verified
  ``kernel.read`` provider run at all in this run?"*;
* this record answers *"which concrete research window may be read exactly once?"*.

It therefore carries **only** window and context facts — region, offset, length, expected bytes +
sha256, module, section, permissions, classification, ``profile_sha256``, boot, state, a unique
``release_id`` and the ``approval_sha256`` it is bound to. It can never set or replace an approval:
the document has its own schema (``ps4rf.w13.research-read-release.v1``), the schema is **strict**
(``additionalProperties = false``: the release and its window document carry exactly the fields
declared in :data:`RELEASE_FIELDS` / :data:`WINDOW_FIELDS` and nothing else), any field outside it
is refused outright — an address-shaped name (``addr``, ``address``, ``va``, ``runtime_va``,
``kernel_va``, ``kernel_address``, ``ptr``, ``pointer``, ``rva``), an assurance-shaped name or an
unknown field (``W13_RELEASE_FORBIDDEN_FIELD``) — and an approval document handed in as a release
fails the schema check (``W13_RELEASE_INVALID``). The release itself refuses the field; dropping
it later on the wire or in the target is not a refusal. The window is built with
:func:`tools.hostctl.kreadlive.window_for` only after every cross-check passed, and it can *select*
one already-pinned window — never invent bytes, move an offset or change a length.

Fail-closed refusals (each one stops the run before an upload exists):

* ``W13_RELEASE_INVALID``                  -- malformed document / wrong schema (e.g. an approval)
* ``W13_RELEASE_NOT_APPROVED``             -- state is not APPROVED
* ``W13_RELEASE_REGION_NOT_APPROVED_READ`` -- the region is not W13 APPROVED_READ
* ``W13_RELEASE_REGION_NOT_IN_PLAN``       -- the region is not part of the research read plan
* ``W13_RELEASE_REGION_IS_BOOTSTRAP``      -- a release never hands out the pinned bootstrap window
* ``W13_RELEASE_BYTES_NOT_PINNED``         -- expected bytes differ from the profile's pinned bytes
* ``W13_RELEASE_LENGTH_MISMATCH``          -- length is not the promoted region length
* ``W13_RELEASE_WINDOW_MISMATCH``          -- offset/sha/rva outside the pinned window
* ``W13_RELEASE_PROFILE_MISMATCH``         -- another profile
* ``W13_RELEASE_BOOT_MISMATCH``            -- another boot
* ``W13_RELEASE_SECTION_MISMATCH``         -- module/section/permissions/classification disagree
* ``W13_RELEASE_APPROVAL_BINDING_MISSING`` -- no ``approval_sha256``: not bound to any approval
* ``W13_RELEASE_APPROVAL_MISMATCH``        -- bound to a *different* approval than the one in the run
* ``W13_RELEASE_FORBIDDEN_FIELD``          -- a field outside the strict release/window schema:
                                              an address-shaped, assurance-, approval- or
                                              capability-shaped name, or any other unknown field
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:  # allow direct script execution
    sys.path.insert(0, str(REPO_ROOT))

from tools.hostctl import kreadlive as KL                                   # noqa: E402
from tools.hostctl.kreadstore import canonical_bytes                        # noqa: E402
from tools.profiles import regions as R                                     # noqa: E402
from tools.research import classification as C                              # noqa: E402
from tools.research import read_plan as RP                                  # noqa: E402

SCHEMA_RELEASE = 'ps4rf.w13.research-read-release.v1'
STATE_APPROVED = 'APPROVED'

RELEASE_INVALID = 'W13_RELEASE_INVALID'
RELEASE_NOT_APPROVED = 'W13_RELEASE_NOT_APPROVED'
RELEASE_REGION_NOT_APPROVED_READ = 'W13_RELEASE_REGION_NOT_APPROVED_READ'
RELEASE_REGION_NOT_IN_PLAN = 'W13_RELEASE_REGION_NOT_IN_PLAN'
RELEASE_REGION_IS_BOOTSTRAP = 'W13_RELEASE_REGION_IS_BOOTSTRAP'
RELEASE_BYTES_NOT_PINNED = 'W13_RELEASE_BYTES_NOT_PINNED'
RELEASE_LENGTH_MISMATCH = 'W13_RELEASE_LENGTH_MISMATCH'
RELEASE_WINDOW_MISMATCH = 'W13_RELEASE_WINDOW_MISMATCH'
RELEASE_PROFILE_MISMATCH = 'W13_RELEASE_PROFILE_MISMATCH'
RELEASE_BOOT_MISMATCH = 'W13_RELEASE_BOOT_MISMATCH'
RELEASE_SECTION_MISMATCH = 'W13_RELEASE_SECTION_MISMATCH'
RELEASE_APPROVAL_BINDING_MISSING = 'W13_RELEASE_APPROVAL_BINDING_MISSING'
RELEASE_APPROVAL_MISMATCH = 'W13_RELEASE_APPROVAL_MISMATCH'
RELEASE_INDEX_MISMATCH = 'W13_RELEASE_INDEX_MISMATCH'
RELEASE_PAYLOAD_MISMATCH = 'W13_RELEASE_PAYLOAD_MISMATCH'
RELEASE_FORBIDDEN_FIELD = 'W13_RELEASE_FORBIDDEN_FIELD'

REFUSALS = (RELEASE_INVALID, RELEASE_NOT_APPROVED, RELEASE_REGION_NOT_APPROVED_READ,
            RELEASE_REGION_NOT_IN_PLAN, RELEASE_REGION_IS_BOOTSTRAP, RELEASE_BYTES_NOT_PINNED,
            RELEASE_LENGTH_MISMATCH, RELEASE_WINDOW_MISMATCH, RELEASE_PROFILE_MISMATCH,
            RELEASE_BOOT_MISMATCH, RELEASE_SECTION_MISMATCH, RELEASE_APPROVAL_BINDING_MISSING,
            RELEASE_APPROVAL_MISMATCH, RELEASE_INDEX_MISMATCH, RELEASE_PAYLOAD_MISMATCH,
            RELEASE_FORBIDDEN_FIELD)

#: The declared, strict schema of the release document (owner D1: ``additionalProperties = false``).
#: Exactly these top-level fields exist; every other field is refused by :func:`release_problems`
#: with :data:`RELEASE_FORBIDDEN_FIELD`. ``rva`` stays declared **here**: it is the pinned locator
#: fact the accepted owner transcripts carry and the registry cross-check validates — an
#: address-shaped *claim*, never a host-supplied address.
RELEASE_FIELDS = ('schema', 'release_id', 'state', 'source', 'approval_sha256', 'window',
                  'profile_sha256', 'expected_boot_id', 'module', 'section', 'permissions',
                  'classification', 'rva', 'payload', 'notes')

#: The declared, strict schema of the release's window document (``additionalProperties = false``):
#: exactly these fields — all of them required — exist; no address-shaped name is ever one.
WINDOW_FIELDS = ('region', 'offset', 'length', 'expected_bytes', 'expected_sha256',
                 'region_index')

#: The declared schema as one ``additionalProperties = false`` description: the auditable form of
#: what :func:`release_problems` enforces field by field.
RELEASE_SCHEMA = {'schema': SCHEMA_RELEASE,
                  'additionalProperties': False, 'properties': RELEASE_FIELDS,
                  'window': {'additionalProperties': False, 'properties': WINDOW_FIELDS}}

#: Fields of the release that must equal the pinned profile facts when they are present.
CONSISTENCY_FIELDS = {'module': 'module', 'section': 'section', 'permissions': 'permissions'}

#: Address-shaped field names (owner D1). A release may carry such a name only where its declared
#: schema explicitly does (only ``rva`` on the release document itself); everywhere else — the
#: window document included — every one of these names is refused as an attempted raw-address
#: field.
ADDRESS_FIELDS = ('addr', 'address', 'va', 'runtime_va', 'kernel_va', 'kernel_address',
                  'ptr', 'pointer', 'rva')

#: A release is a *window* record. Everything that could be read as authorisation belongs to the
#: approval, the gate or the capability model, and its presence in a release is a refusal
#: (owner rule 4: a release never sets assurance, PROVEN, provider authorisation or W4 approval).
ASSURANCE_FIELDS = ('assurance', 'proven', 'provider_authorization', 'provider_authorisation',
                    'capability', 'capability_record', 'w4', 'w4_approval', 'approval', 'approvals',
                    'approved', 'authorized', 'authorised', 'authorization', 'authorisation',
                    'session_capability', 'receipt')

#: The forbidden set: address-shaped and assurance-shaped names together. Each of them is refused
#: wherever the declared schema does not explicitly carry it — and so is **any** other unknown
#: field, because the schema above is strict.
FORBIDDEN_FIELDS = ADDRESS_FIELDS + ASSURANCE_FIELDS


def release_sha256(document: dict) -> str:
    """The immutable identifier of a release document (JCS bytes, nothing excluded)."""
    return hashlib.sha256(canonical_bytes(document)).hexdigest()


def load_release(path: str | pathlib.Path) -> dict:
    """Read the release document (fail closed: a malformed record is a refusal, not a traceback)."""
    try:
        document = json.loads(pathlib.Path(path).read_text())
    except (OSError, ValueError) as exc:
        raise ValueError(f'{RELEASE_INVALID}: {exc}') from exc
    if not isinstance(document, dict):
        raise ValueError(f'{RELEASE_INVALID}: the release is not a JSON object')
    return document


def _strict_problems(container: dict, *, allowed: tuple[str, ...], where: str) -> list[str]:
    """The strict-schema refusal (``additionalProperties = false``): every field outside ``allowed``
    is refused — address-shaped names, assurance-shaped names and unknown fields alike, all with
    :data:`RELEASE_FORBIDDEN_FIELD`. The release itself rejects the field; being dropped later (on
    the wire or in the target) is never the refusal the owner's rule asks for.
    """
    problems: list[str] = []
    for field in container:
        if field in allowed:
            continue
        if field in ADDRESS_FIELDS:
            problems.append(f'{RELEASE_FORBIDDEN_FIELD}: {where} carries the address-shaped field '
                            f'{field!r}; a release never carries an address — it only selects a '
                            'window')
        elif field in ASSURANCE_FIELDS:
            problems.append(f'{RELEASE_FORBIDDEN_FIELD}: {where} carries {field!r}; a release only '
                            'selects a window — it never sets an approval, an assurance, a '
                            'capability or a provider authorisation')
        else:
            problems.append(f'{RELEASE_FORBIDDEN_FIELD}: {where} carries {field!r}, which is not '
                            f'part of the declared {SCHEMA_RELEASE} schema '
                            '(additionalProperties = false)')
    return problems


def release_problems(release: dict, *, profile: dict | None = None, profile_sha256: str | None = None,
                     boot_id: str | None = None, plan: dict | None = None,
                     approval_sha256: str | None = None) -> list[str]:
    """Every cross-check of the release record. An empty list means the window may be built."""
    problems: list[str] = []
    if not isinstance(release, dict):
        return [f'{RELEASE_INVALID}: the release is not a document']
    profile = C.DEFAULT_PROFILE if profile is None else profile
    plan = RP.read_plan(profile) if plan is None else plan

    if release.get('schema') != SCHEMA_RELEASE:
        problems.append(f'{RELEASE_INVALID}: schema {release.get("schema")!r} is not '
                        f'{SCHEMA_RELEASE!r} (an approval is not a release)')
    release_id = release.get('release_id')
    if not isinstance(release_id, str) or not release_id.strip():
        problems.append(f'{RELEASE_INVALID}: the release carries no release_id')
    if release.get('consumed') is not None:
        problems.append(f'{RELEASE_FORBIDDEN_FIELD}: the release document must not carry a '
                        'consumption marker; consumption lives in the run/evidence store')
    problems.extend(_strict_problems(release, allowed=RELEASE_FIELDS, where='the release'))
    payload = release.get('payload')
    if isinstance(payload, dict):
        problems.extend(_strict_problems(payload, allowed=PAYLOAD_FIELDS + PAYLOAD_LABEL_FIELDS,
                                         where='the payload block'))

    state = str(release.get('state') or '').upper()
    if state != STATE_APPROVED:
        problems.append(f'{RELEASE_NOT_APPROVED}: state is {release.get("state")!r}')

    own_sha = release_sha256(release)
    bound_approval = release.get('approval_sha256')
    if not isinstance(bound_approval, str) or not bound_approval.strip():
        problems.append(f'{RELEASE_APPROVAL_BINDING_MISSING}: the release is not bound to a section '
                        '70 approval (no approval_sha256)')
    elif not (len(bound_approval) == 64
              and all(c in '0123456789abcdefABCDEF' for c in bound_approval)):
        problems.append(f'{RELEASE_INVALID}: approval_sha256 is not a sha256 hex digest')
    elif bound_approval.lower() == own_sha.lower():
        problems.append(f'{RELEASE_APPROVAL_MISMATCH}: the release names its own hash as the '
                        'approval: an approval is a different trust object, never the release '
                        'itself')
    elif approval_sha256 is not None and bound_approval.lower() != approval_sha256.lower():
        problems.append(f'{RELEASE_APPROVAL_MISMATCH}: the release is bound to approval '
                        f'{bound_approval[:16]}…, this run carries {approval_sha256[:16]}…')

    window = release.get('window')
    if not isinstance(window, dict):
        problems.append(f'{RELEASE_INVALID}: the release carries no window block')
        return problems
    problems.extend(_strict_problems(window, allowed=WINDOW_FIELDS, where='the window document'))
    missing = [field for field in WINDOW_FIELDS if field not in window]
    if missing:
        problems.append(f'{RELEASE_INVALID}: the window block is missing {missing}')
        return problems

    name = window.get('region')
    region = R.regions().get(name) if isinstance(name, str) else None
    if region is None:
        problems.append(f'{RELEASE_INVALID}: unknown region {name!r}')
        return problems

    if name == KL.PINNED_REGION:
        problems.append(f'{RELEASE_REGION_IS_BOOTSTRAP}: {name} is the pinned bootstrap region; the '
                        'bootstrap window is readable without a release and a release never hands '
                        'it out')

    # W13-C1: the wire request names a row of the compiled table, so the release pins that index
    # and it must be the normative one -- derived from the compiled table, never from the release.
    pinned_index = window.get('region_index')
    derived_index = R.compiled_region_index(name)
    if isinstance(pinned_index, bool) or not isinstance(pinned_index, int):
        problems.append(f'{RELEASE_INDEX_MISMATCH}: the window block names no compiled region '
                        f'index (got {pinned_index!r})')
    elif derived_index is None:
        problems.append(f'{RELEASE_INDEX_MISMATCH}: {name} is not in the compiled target table')
    elif pinned_index != derived_index:
        problems.append(f'{RELEASE_INDEX_MISMATCH}: the release pins index {pinned_index} for '
                        f'{name}, the compiled table says {derived_index}')

    classes = {row['region']: row['class'] for row in C.classification_matrix(profile)['rows']}
    if classes.get(name) != C.CLASS_APPROVED_READ:
        problems.append(f'{RELEASE_REGION_NOT_APPROVED_READ}: {name} is {classes.get(name)}, not '
                        f'{C.CLASS_APPROVED_READ}')
    if name not in {entry['region'] for entry in plan.get('entries', ())}:
        problems.append(f'{RELEASE_REGION_NOT_IN_PLAN}: {name} is not part of the research read plan')

    locator = C.profile_locator(profile, region.locator) or {}
    pinned_bytes = (locator.get('expected_bytes') or {}).get('hex')
    if pinned_bytes is None:
        problems.append(f'{RELEASE_BYTES_NOT_PINNED}: the profile pins no bytes for '
                        f'{region.locator!r}')
    expected_hex = str(window.get('expected_bytes') or '')
    if pinned_bytes is not None and expected_hex.lower() != str(pinned_bytes).lower():
        problems.append(f'{RELEASE_BYTES_NOT_PINNED}: the release names bytes '
                        f'{expected_hex[:32]}… but the profile pins {str(pinned_bytes)[:32]}…')

    try:
        raw = bytes.fromhex(expected_hex)
    except ValueError:
        problems.append(f'{RELEASE_INVALID}: expected_bytes is not hex')
        raw = b''
    length = window.get('length')
    if not isinstance(length, int):
        problems.append(f'{RELEASE_INVALID}: length is not an integer')
    elif raw and len(raw) != length:
        problems.append(f'{RELEASE_WINDOW_MISMATCH}: {len(raw)} bytes do not match length {length}')
    if isinstance(length, int) and region.length is not None and length != region.length:
        problems.append(f'{RELEASE_LENGTH_MISMATCH}: length {length} is not the promoted region '
                        f'length {region.length}')
    if isinstance(length, int) and not 0 < length <= R.MAX_READ_LEN:
        problems.append(f'{RELEASE_WINDOW_MISMATCH}: length {length} outside (0, {R.MAX_READ_LEN}]')

    offset = window.get('offset')
    if not isinstance(offset, int) or offset < 0:
        problems.append(f'{RELEASE_WINDOW_MISMATCH}: offset must be a non-negative integer')
    elif region.length is not None and isinstance(length, int) and offset + length > region.length:
        problems.append(f'{RELEASE_WINDOW_MISMATCH}: offset {offset} + length {length} leaves the '
                        f'region window {region.length}')

    expected_sha = str(window.get('expected_sha256') or '')
    if raw and hashlib.sha256(raw).hexdigest() != expected_sha.lower():
        problems.append(f'{RELEASE_WINDOW_MISMATCH}: expected_sha256 is not the hash of '
                        f'expected_bytes')

    if profile_sha256 is not None and release.get('profile_sha256') not in (None, profile_sha256):
        problems.append(f'{RELEASE_PROFILE_MISMATCH}: the release names profile '
                        f'{str(release.get("profile_sha256"))[:16]}…, the current profile is '
                        f'{profile_sha256[:16]}…')
    if boot_id is not None and release.get('expected_boot_id') not in (None, boot_id):
        problems.append(f'{RELEASE_BOOT_MISMATCH}: the release names boot '
                        f'{release.get("expected_boot_id")!r}, the current binding is {boot_id!r}')

    for field, pinned_key in CONSISTENCY_FIELDS.items():
        claimed = release.get(field, window.get(field))
        if claimed is not None and locator.get(pinned_key) is not None \
                and str(claimed) != str(locator[pinned_key]):
            problems.append(f'{RELEASE_SECTION_MISMATCH}: {field} {claimed!r} disagrees with the '
                            f'pinned profile {pinned_key} {locator[pinned_key]!r}')
    claimed_rva = release.get('rva')
    if claimed_rva is not None and region.rva is not None:
        claimed_value = int(claimed_rva, 16) if isinstance(claimed_rva, str) else int(claimed_rva)
        if claimed_value != region.rva:
            problems.append(f'{RELEASE_WINDOW_MISMATCH}: rva {hex(claimed_value)} is not the pinned '
                            f'rva {hex(region.rva)}')
    claimed_class = release.get('classification')
    if claimed_class is not None and str(claimed_class) != C.CLASS_APPROVED_READ:
        problems.append(f'{RELEASE_REGION_NOT_APPROVED_READ}: the release claims classification '
                        f'{claimed_class!r}')
    return problems


#: Optional payload binding: when a release carries it, the delivered artefact must be exactly
#: this build -- a release for one payload can never authorise a run of another one. The payload
#: block's declared schema (``additionalProperties = false``) also carries the build's human label.
PAYLOAD_FIELDS = ('bin_sha256', 'elf_sha256', 'build_manifest_sha256', 'build_id')
PAYLOAD_LABEL_FIELDS = ('label',)


def payload_problems(release: dict | None, *, bin_sha256: str | None, elf_sha256: str | None,
                     build_manifest_sha256: str | None) -> list[str]:
    """Compare a release's optional payload block against the delivered artefact ([] when fine)."""
    payload = (release or {}).get('payload')
    if payload is None:
        return []
    if not isinstance(payload, dict):
        return [f'{RELEASE_PAYLOAD_MISMATCH}: the payload block is not a document']
    problems: list[str] = []
    delivered = {'bin_sha256': bin_sha256, 'elf_sha256': elf_sha256,
                 'build_manifest_sha256': build_manifest_sha256}
    for field in PAYLOAD_FIELDS:
        pinned = payload.get(field)
        if pinned is None:
            problems.append(f'{RELEASE_PAYLOAD_MISMATCH}: the payload block names no {field}')
            continue
        if field == 'build_id':
            continue                       # build id is evidence, not a hash of the delivery
        if not isinstance(pinned, str) or not pinned:
            problems.append(f'{RELEASE_PAYLOAD_MISMATCH}: {field} is not a hash')
        elif delivered.get(field) is not None and str(pinned).lower() != str(
                delivered[field]).lower():
            problems.append(f'{RELEASE_PAYLOAD_MISMATCH}: released {field} {pinned} != delivered '
                            f'{delivered[field]}')
    return problems


def released_window(release: dict, *, profile: dict | None = None, profile_sha256: str | None = None,
                    boot_id: str | None = None, plan: dict | None = None,
                    approval_sha256: str | None = None) -> dict:
    """Build the read window for a release, or refuse (never a partial window)."""
    profile = C.DEFAULT_PROFILE if profile is None else profile
    problems = release_problems(release, profile=profile, profile_sha256=profile_sha256,
                                boot_id=boot_id, plan=plan, approval_sha256=approval_sha256)
    window_block = (release or {}).get('window') or {}
    if problems:
        return {'window': None, 'problems': problems,
                'refusals': [p.split(':', 1)[0] for p in problems]}
    window = KL.window_for(str(window_block['region']), bytes_hex=str(window_block['expected_bytes']),
                           offset=int(window_block['offset']), length=int(window_block['length']),
                           profile=profile, release_id=str(release['release_id']))
    window['approval_sha256'] = approval_sha256 or release.get('approval_sha256')
    window['release_sha256'] = release_sha256(release)
    window['region_index'] = int(window_block['region_index'])
    if window.get('problems'):
        return {'window': None,
                'problems': [f'{RELEASE_INVALID}: {problem}' for problem in window['problems']],
                'refusals': [RELEASE_INVALID]}
    return {'window': window, 'problems': [],
            'release': {'release_id': str(release['release_id']),
                        'sha256': release_sha256(release),
                        'state': release.get('state'),
                        'region': window['region'], 'offset': window['offset'],
                        'length': window['length'], 'rva': hex(window['rva']),
                        'region_index': window['region_index'],
                        'expected_bytes': window['bytes_hex'],
                        'expected_sha256': window['sha256'],
                        'approval_sha256': window.get('approval_sha256'),
                        'profile_sha256': profile_sha256, 'boot_id': boot_id,
                        'payload': (release.get('payload') if isinstance(release.get('payload'),
                                                                        dict) else None)}}


def release_document(*, release_id: str, region: str, offset: int, length: int, expected_bytes: str,
                     region_index: int, expected_sha256: str, profile_sha256: str, boot_id: str,
                     approval_sha256: str,
                     state: str = STATE_APPROVED, module: str | None = None,
                     section: str | None = None, permissions: str | None = None,
                     classification: str | None = None, rva: str | None = None,
                     source: str = 'owner live approval (transcribed verbatim)',
                     payload: dict | None = None, notes: list[str] | None = None) -> dict:
    """Helper for the transcription (used by tests and by the offline tooling, never by a live run)."""
    document = {'schema': SCHEMA_RELEASE, 'release_id': release_id, 'state': state,
                'source': source, 'approval_sha256': approval_sha256,
                'window': {'region': region, 'offset': offset, 'length': length,
                           'region_index': region_index, 'expected_bytes': expected_bytes,
                           'expected_sha256': expected_sha256},
                'profile_sha256': profile_sha256, 'expected_boot_id': boot_id}
    for key, value in (('module', module), ('section', section), ('permissions', permissions),
                       ('classification', classification), ('rva', rva), ('payload', payload)):
        if value is not None:
            document[key] = value
    if notes:
        document['notes'] = list(notes)
    return document


def _self_test() -> list[str]:
    checks: list[str] = []
    from tools.profiles.schema import canonical_profile_sha256
    from tools.research import approval as AP
    profile = C.DEFAULT_PROFILE
    profile_sha = canonical_profile_sha256(profile)
    approval = {'schema': AP.SCHEMA_APPROVAL, 'id': '70-selftest', 'state': 'APPROVED',
                'approved': True, 'approver': 'owner', 'recorded_by': 'selftest',
                'profile_sha256': profile_sha, 'boot_id': 'BOOT-selftest',
                'verification_run_id': 'VRUN-selftest', 'evidence_sha256': 'e' * 64}
    bound = AP.approval_sha256(approval)
    locator = C.profile_locator(profile, 'kernel.attest.amd_iommu') or {}
    bytes_hex = locator['expected_bytes']['hex']
    sha = hashlib.sha256(bytes.fromhex(bytes_hex)).hexdigest()
    compiled_index = R.compiled_region_index('amd_iommu')
    release = release_document(release_id='W13-RR1', region='amd_iommu', offset=0, length=16,
                               region_index=compiled_index, expected_bytes=bytes_hex,
                               expected_sha256=sha, profile_sha256=profile_sha,
                               boot_id='BOOT-selftest', approval_sha256=bound, module='kernel',
                               section='text', permissions='r-x',
                               classification='APPROVED_READ', rva='0x7ce9e9')
    built = released_window(release, profile=profile, profile_sha256=profile_sha,
                            boot_id='BOOT-selftest', approval_sha256=bound)
    if built['problems']:
        checks.append(f'the reference release was refused: {built["problems"]}')
    elif built['window']['bytes_hex'] != bytes_hex or built['window']['rva'] != 0x7CE9E9:
        checks.append('the built window does not carry the pinned bytes/rva')
    elif built['release']['release_id'] != 'W13-RR1':
        checks.append('the built window lost its release id')
    mutations = {
        RELEASE_NOT_APPROVED: dict(release, state='PENDING'),
        RELEASE_BYTES_NOT_PINNED: dict(release, window=dict(release['window'],
                                                           expected_bytes='00' * 16,
                                                           expected_sha256=hashlib.sha256(
                                                               bytes(16)).hexdigest())),
        RELEASE_LENGTH_MISMATCH: dict(release, window=dict(release['window'], length=8)),
        RELEASE_WINDOW_MISMATCH: dict(release, window=dict(release['window'], offset=4)),
        RELEASE_PROFILE_MISMATCH: dict(release, profile_sha256='b' * 64),
        RELEASE_BOOT_MISMATCH: dict(release, expected_boot_id='BOOT-other'),
        RELEASE_SECTION_MISMATCH: dict(release, section='rodata'),
        RELEASE_REGION_NOT_APPROVED_READ: dict(
            release, window=dict(release['window'], region='xfast_entry', offset=0, length=16)),
        RELEASE_APPROVAL_BINDING_MISSING: {k: v for k, v in release.items()
                                           if k != 'approval_sha256'},
        RELEASE_APPROVAL_MISMATCH: dict(release, approval_sha256='f' * 64),
        RELEASE_FORBIDDEN_FIELD: dict(release, assurance='PROVEN'),
        RELEASE_REGION_IS_BOOTSTRAP: dict(release, window=dict(release['window'],
                                                               region=KL.PINNED_REGION)),
        # W13-C1: the release pins the compiled table's row, and only that row
        RELEASE_INDEX_MISMATCH: dict(release, window=dict(release['window'],
                                                          region_index=(compiled_index or 0) + 1)),
    }
    for expected_reason, mutated in mutations.items():
        reasons = {problem.split(':', 1)[0] for problem in release_problems(
            mutated, profile=profile, profile_sha256=profile_sha, boot_id='BOOT-selftest',
            approval_sha256=bound)}
        if expected_reason not in reasons:
            checks.append(f'the mutation for {expected_reason} reported {sorted(reasons)}')
    # the strict schema (owner D1): a field the schema does not declare is refused -- in the
    # release itself and inside its window document, address-shaped or arbitrary -- and nothing
    # else changes; the top-level `rva` stays the one declared address-shaped field.
    for field in ('addr', 'address', 'va', 'runtime_va', 'kernel_va', 'kernel_address', 'ptr',
                  'pointer', 'note_extra'):
        reasons = {problem.split(':', 1)[0] for problem in release_problems(
            dict(release, **{field: '0x0'}), profile=profile, profile_sha256=profile_sha,
            boot_id='BOOT-selftest', approval_sha256=bound)}
        if reasons != {RELEASE_FORBIDDEN_FIELD}:
            checks.append(f'the strict schema did not refuse the release field {field!r} alone: '
                          f'{sorted(reasons)}')
    for field in ('addr', 'rva', 'runtime_va', 'note_extra'):
        reasons = {problem.split(':', 1)[0] for problem in release_problems(
            dict(release, window=dict(release['window'], **{field: '0x0'})), profile=profile,
            profile_sha256=profile_sha, boot_id='BOOT-selftest', approval_sha256=bound)}
        if reasons != {RELEASE_FORBIDDEN_FIELD}:
            checks.append(f'the strict window schema did not refuse the window field {field!r} '
                          f'alone: {sorted(reasons)}')
    # W13-C1: a window that names no compiled index at all is refused with the same code
    without_index = {k: (dict(v, region_index=None) if k == 'window' else v)
                     for k, v in release.items()}
    reasons = {problem.split(':', 1)[0] for problem in release_problems(
        without_index, profile=profile, profile_sha256=profile_sha, boot_id='BOOT-selftest',
        approval_sha256=bound)}
    if RELEASE_INDEX_MISMATCH not in reasons:
        checks.append(f'a window without a region index reported {sorted(reasons)}')
    reasons = {problem.split(':', 1)[0] for problem in release_problems(
        dict(approval), profile=profile, profile_sha256=profile_sha, boot_id='BOOT-selftest',
        approval_sha256=bound)}
    if RELEASE_INVALID not in reasons:
        checks.append(f'an approval document passed as a release was not refused: {sorted(reasons)}')
    return checks


def main(argv: list[str]) -> int:                                          # pragma: no cover
    if '--self-test' in argv:
        problems = _self_test()
        if problems:
            print('release self-test: FAILED')
            for problem in problems:
                print(f'  - {problem}')
            return 1
        print('release self-test: OK (window built from the record, every mutation refused, '
              'approval separation and binding enforced)')
        return 0
    if '--check' in argv:
        from tools.profiles.schema import canonical_profile_sha256
        from tools.research import approval as AP
        path = argv[argv.index('--check') + 1]
        document = load_release(path)
        approval_path = argv[argv.index('--approval') + 1] if '--approval' in argv else None
        approval_sha = None
        if approval_path:
            approval_sha = AP.approval_sha256(AP.load_approval(approval_path))
        boot_id = argv[argv.index('--boot-id') + 1] if '--boot-id' in argv else None
        built = released_window(document, profile_sha256=canonical_profile_sha256(C.DEFAULT_PROFILE),
                                boot_id=boot_id, approval_sha256=approval_sha)
        print(json.dumps({k: v for k, v in built.items() if k != 'window'}, indent=1, sort_keys=True))
        if built['window']:
            print(json.dumps(built['window'], indent=1, sort_keys=True))
        return 0 if not built['problems'] else 1
    print(__doc__)
    return 0


if __name__ == '__main__':                                                 # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
