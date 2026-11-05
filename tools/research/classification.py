#!/usr/bin/env python3
"""W13 — read-only research baseline: the region classification and promotion policy.

W13 does not invent a second region model. It *classifies* the frozen W9/W11/W12 registry into the
four W13 classes and states, machine-checkably, which of them a research read may ever touch:

``IDENTITY_ONLY``
    a ``STRICT_FINGERPRINT`` region that exists to *identify* the boot (image identity, LSTAR/kbase
    anchor, boot-time binding). Readable by the frozen rules, but never part of the research plan: a
    research read there would duplicate an identity read.

``APPROVED_READ``
    a region a research read may read *and* that passed every W13 promotion criterion with a
    documented review decision.

``STRUCTURAL_ONLY``
    an observation-only region (``aperture_global``): boot dependent, never a byte fingerprint,
    never a research target -- by explicit agreement.

``UNRESOLVED``
    not pinnable (conflicting or missing evidence): never readable, in no plan.

The promotion criteria are the owner's six, each checked against data this repository actually
carries (registry entry, profile locator, W9 attest table, repository files):

1. ``w5_locator``                      -- the profile carries ``locators.<locator>`` with
   ``kind: rva`` and the registry's rva, and the W9 attest table names the same rva
2. ``provenance_complete``             -- every file the entry names as provenance exists
3. ``profile_binding``                 -- locator ``module: kernel`` and the locator policy agrees
   with the registry identity status
4. ``section_permissions_plausible``   -- declared permissions agree with the attested kind
   (``static``+strict -> ``r--``/``r-x``, ``relocated`` -> ``rw-``)
5. ``no_known_instability``            -- not the known boot-dependent region, not ``STRUCTURAL_ONLY``
6. ``bounds_unambiguous``              -- rva and length pinned, ``0 < length <= MAX_READ_LEN``, no
   overlap with another registered window

A seventh, non-data criterion is required on top: ``review_decision`` -- an explicit, documented
decision in :data:`REVIEW_DECISIONS`. Not passing all seven means the region keeps its identity
role and stays out of the research plan; nothing is promoted implicitly, and no entry is promoted
because an interesting rva is known for it (the owner's rule).
"""
from __future__ import annotations

import json
import pathlib
import sys
from dataclasses import dataclass

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:  # allow direct script execution
    sys.path.insert(0, str(REPO_ROOT))

from tools.profiles import regions as R                                    # noqa: E402

CLASS_IDENTITY_ONLY = 'IDENTITY_ONLY'
CLASS_APPROVED_READ = 'APPROVED_READ'
CLASS_STRUCTURAL_ONLY = 'STRUCTURAL_ONLY'
CLASS_UNRESOLVED = 'UNRESOLVED'
CLASSES = (CLASS_IDENTITY_ONLY, CLASS_APPROVED_READ, CLASS_STRUCTURAL_ONLY, CLASS_UNRESOLVED)

CRITERIA = ('w5_locator', 'provenance_complete', 'profile_binding',
            'section_permissions_plausible', 'no_known_instability', 'bounds_unambiguous',
            'review_decision')
DATA_CRITERIA = CRITERIA[:-1]

SCHEMA_CLASSIFICATION = 'ps4rf.research.region-classification.v1'

# W17F: the *promoted representation* profile (decimal rva values, see tools/profiles/regions.py).
# It stays semantically distinct from the revision-2 candidate; its operation_policy is derived
# from the authoritative gated-operation source, never hand-maintained.
PROFILE_PATH = REPO_ROOT / 'profiles/fw1352/profile-13.52.json'
DEFAULT_PROFILE = json.loads(PROFILE_PATH.read_text())

#: Regions whose value is known to differ between the pinned image and a live boot. They may be
#: observed, never trusted and never promoted (``aperture_global``: pinned 0xffff82dae4800000 vs
#: phase-9 live 0xffffe26de4800000; ``keymgr_pool`` (W16): 64 live slot records whose occupancy,
#: tags and generations move while the console runs).
#: Regions whose bytes are runtime state (boot dependent or changing within a boot): readable
#: under the approved bounded-research policy, but never a plan target and never an identity
#: source. W9/W10 named the aperture; W16 the keymgr slot pool; Track A adds the five
#: observation windows of docs/P4-A-OBSERVATION-WINDOWS.md.
KNOWN_UNSTABLE = ('aperture_global', 'keymgr_pool',
                  'keymgr_ctx_lock', 'keymgr_sm_gate', 'ccp_stage_msg', 'ccp_stage_ptr',
                  'ccp_client_a_buf')

#: The permissions a locator must declare for the criterion to hold, per attested kind.
PERMISSIONS_BY_KIND = {
    'static': ('r--', 'r-x'),
    'relocated': ('rw-',),
    'structural': ('r--',),
}


class ClassificationError(Exception):
    """Raised when the classification itself is malformed (a policy bug, not a data fact)."""


@dataclass(frozen=True)
class ReviewDecision:
    """The documented W13 promotion decision for one region."""

    region: str
    classification: str
    rationale: str = ''
    priority: int | None = None          # the owner's §11 research priority (A=1 .. E=5)
    purpose: str = ''                    # what a research read there is for
    expected_datatype: str = ''          # what the bytes are expected to be


#: The W13 review decisions. One entry per region -- including the ones that stay out of the
#: research plan, because "no promotion" is a decision that must be documented too.
REVIEW_DECISIONS: dict[str, ReviewDecision] = {
    'image_elf': ReviewDecision(
        region='image_elf', classification=CLASS_IDENTITY_ONLY,
        rationale='the bootstrap identity window: its bytes *are* the image identity (ELF header at '
                  'the image base) and the phase-A bootstrap verification reads exactly this '
                  'window. A research read would duplicate an identity read and add no fact, so it '
                  'stays the identity window it was approved as (BOOTSTRAP_VERIFY_REGION).'),
    'amd_iommu': ReviewDecision(
        region='amd_iommu', classification=CLASS_APPROVED_READ, priority=1,
        purpose='re-read the AMD IOMMU anchor window and archive it as a content-addressed '
                'research artifact (A1 anchor identity at the live boot)',
        expected_datatype='16-byte window inside the read-only executable image segment '
                          '(section text / permissions r-x): an ASCII string constant, '
                          '"AMD IOMMU\\0iommu "'),
    'gbase_vtophys': ReviewDecision(
        region='gbase_vtophys', classification=CLASS_APPROVED_READ, priority=2,
        purpose='re-read the Sony gbase_vtophys anchor (ASCII string constant in the read-only '
                'executable image segment) as a structural archive fact of the live image',
        expected_datatype='16-byte window inside the read-only executable image segment '
                          '(section text / permissions r-x): an ASCII string constant, '
                          '"gbase_vtophys\\0gb"'),
    'code_anchor': ReviewDecision(
        region='code_anchor', classification=CLASS_APPROVED_READ, priority=3,
        purpose='archive the 24-byte code window of the A3 anchor (function prologue) for '
                'disassembly-side comparison against the pinned image bytes',
        expected_datatype='machine code window (function prologue)'),
    'copyout_prologue': ReviewDecision(
        region='copyout_prologue', classification=CLASS_APPROVED_READ, priority=4,
        purpose='archive the copyout prologue (SDK fw_defines K1352_COPYOUT) as the disassembly '
                'entry fact for later offline analysis',
        expected_datatype='machine code window (function prologue)'),
    'prison0_static': ReviewDecision(
        region='prison0_static', classification=CLASS_APPROVED_READ, priority=5,
        purpose='archive the relocated pointer window (SDK fw_defines K1352_PRISON_0): the live '
                'value minus the verified slide is the one structural fact the pinned image holds',
        expected_datatype='relocated 64-bit pointer (image value + verified slide)'),
    'xfast_entry': ReviewDecision(
        region='xfast_entry', classification=CLASS_IDENTITY_ONLY,
        rationale='the LSTAR/kbase identity anchor: the kbase of every read is derived from it '
                  '(kbase = LSTAR - rva). It identifies the boot; it is not a research target, and '
                  'reading it as research could only re-derive what the session already proved.'),
    'boottime': ReviewDecision(
        region='boottime', classification=CLASS_IDENTITY_ONLY,
        rationale='the FW13.52 boot-binding source (W11.2). Its own profile requirement states that '
                  'no W5 locator is promoted for it yet, so kernel.read stays deferred: it is an '
                  'identity/binding window, not an approved research read.'),
    'aperture_global': ReviewDecision(
        region='aperture_global', classification=CLASS_STRUCTURAL_ONLY,
        rationale='boot dependent by agreement (pinned image value and phase-9 live value differ), '
                  'so never a byte fingerprint and never a trusted identity source. W13 keeps it '
                  'STRUCTURAL_ONLY: not a research read target, not in the plan.'),
    'boottime_node': ReviewDecision(
        region='boottime_node', classification=CLASS_UNRESOLVED,
        rationale='not pinnable: the evidence names two different rvas for the node and the entry '
                  'itself says the variable, not the node, is what gets read. Never readable.'),
    'boottime_bintime': ReviewDecision(
        region='boottime_bintime', classification=CLASS_UNRESOLVED,
        rationale='MEDIUM confidence only and adjusted by the timekeeping routine on every tick, so '
                  'its low bits move within a boot. Not sufficiently proven; the candidate rva '
                  'stays in the evidence and never becomes readable.'),
    # --- W16: the CCP/keymgr binding windows of the revision candidate -------------------------
    # Fingerprints of the pinned image whose live byte-match (W16) is the promotion precondition
    # of profiles/fw1352/profile-13.52-ccp1.json. While that revision is a candidate its locators
    # live there and not in the promoted profile, so the W5-locator criterion fails by
    # construction: these are identity windows, never research read targets, and nothing here
    # promotes them implicitly.
    'ccp_submit_entry': ReviewDecision(
        region='ccp_submit_entry', classification=CLASS_IDENTITY_ONLY,
        rationale='CCP message submit wrapper (sbl key service): a prologue fingerprint of the '
                  'pinned image. Binding window of the unpromoted revision candidate 13.52-ccp1; '
                  'the W16 live byte-match is the fact the promotion depends on, so it stays an '
                  'identity window and is not a research read target.'),
    'ccp_device_gate': ReviewDecision(
        region='ccp_device_gate', classification=CLASS_IDENTITY_ONLY,
        rationale='device-ioctl alternative binding: the access gate that compares the calling '
                  'object attribute against the 64 bit constant recorded in ccp-layouts.json. A '
                  'prologue fingerprint of the pinned image, bound by the revision candidate; its '
                  'live passability is a separate question and no read of it is a research target '
                  'here.'),
    'keymgr_claim_entry': ReviewDecision(
        region='keymgr_claim_entry', classification=CLASS_IDENTITY_ONLY,
        rationale='keymgr slot pool claim (u16 out slot): prologue fingerprint of the pinned '
                  'image, bound by the revision candidate. Identity window until W16 matches it '
                  'live; not a research read target.'),
    'keymgr_bind_entry': ReviewDecision(
        region='keymgr_bind_entry', classification=CLASS_IDENTITY_ONLY,
        rationale='keymgr slot bind (tag = key handle): prologue fingerprint of the pinned image, '
                  'bound by the revision candidate. Identity window until W16 matches it live; not '
                  'a research read target.'),
    'keymgr_release_entry': ReviewDecision(
        region='keymgr_release_entry', classification=CLASS_IDENTITY_ONLY,
        rationale='keymgr release by slot id: prologue fingerprint of the pinned image, bound by '
                  'the revision candidate. Identity window until W16 matches it live; not a '
                  'research read target.'),
    'keymgr_ctx_lock': ReviewDecision(
        region='keymgr_ctx_lock', classification=CLASS_STRUCTURAL_ONLY,
        rationale='Track A observation window (docs/P4-A-OBSERVATION-WINDOWS.md): the keyMgrCtx '
                  'lock object and its neighbouring counters. Runtime state, so never a byte '
                  'fingerprint and never an identity source; read once per lifetime by the '
                  "payload's own fixed step under the approved bounded-research policy. Not a "
                  'research read target and out of the plan.'),
    'keymgr_sm_gate': ReviewDecision(
        region='keymgr_sm_gate', classification=CLASS_STRUCTURAL_ONLY,
        rationale='Track A observation window: the "sm loaded" gate and the following service '
                  'fields. Runtime state, so never an identity source; observation only, out of '
                  'the plan.'),
    'ccp_stage_msg': ReviewDecision(
        region='ccp_stage_msg', classification=CLASS_STRUCTURAL_ONLY,
        rationale='Track A observation window: the eipkas ioctl staging page (one CCP message). '
                  'Runtime state, so never an identity source; observation only, out of the plan.'),
    'ccp_stage_ptr': ReviewDecision(
        region='ccp_stage_ptr', classification=CLASS_STRUCTURAL_ONLY,
        rationale='Track A observation window: the submit-side global handed to the second-stage '
                  'builder. Runtime state, so never an identity source; observation only, out of '
                  'the plan.'),
    'ccp_client_a_buf': ReviewDecision(
        region='ccp_client_a_buf', classification=CLASS_STRUCTURAL_ONLY,
        rationale='Track A observation window: the CCP client-A staging buffer (one command). '
                  'Runtime state, so never an identity source; observation only, out of the plan.'),
    'keymgr_pool': ReviewDecision(
        region='keymgr_pool', classification=CLASS_STRUCTURAL_ONLY,
        rationale='the keymgr slot pool (64 records, 32 byte stride): runtime slot state, so never '
                  'a byte fingerprint and never a trusted identity source. W16 observes it once '
                  'under the approved bounded-research policy; it is not a research read target '
                  'and stays out of the plan.'),
}


def _attest_entries() -> dict[str, dict]:
    """The W9 attest table, re-read from its generator (the source of the pinned rvas/kinds)."""
    source = (REPO_ROOT / 'native/target/gen_attest_table.py').read_text()
    start = source.index('ENTRIES = [')
    end = source.index(']', start)
    table: dict[str, dict] = {}
    for line in source[start:end].splitlines():
        line = line.strip()
        if not line.startswith("('"):
            continue
        name = line.split("'")[1]
        rva = int(line.split(',')[1].strip(), 0)
        length = int(line.split(',')[2].strip())
        kind = line.split(',')[3].strip().strip("'")
        policy = line.split(',')[4].strip().strip("'")
        table[name] = {'rva': rva, 'length': length, 'kind': kind, 'policy': policy}
    return table


ATTEST = _attest_entries()


def _profile_locator(profile: dict | None, locator: str | None) -> dict | None:
    if profile is None:
        return None
    if not locator:
        return None
    node = profile.get('locators', {})
    if not isinstance(node, dict):
        return None
    flat = node.get(locator)                     # the profile stores dotted locator keys flat
    if isinstance(flat, dict):
        return flat
    for part in locator.split('.'):              # ... and nested dictionaries must work too
        node = node.get(part) if isinstance(node, dict) else None
        if node is None:
            return None
    return node if isinstance(node, dict) else None


#: Section words a decision/plan text may use, mapped to the pinned profile section they require.
SECTION_WORDS = {'rodata': ('rodata',), 'bss': ('bss',), 'text': ('text',), 'data': ('data',)}


def datatype_section_conflict(region: R.Region, text: str, profile: dict | None = None) -> str | None:
    """A section word in *text* that contradicts the pinned profile section, or ``None``.

    The pinned profile is the authority for a region's section and permissions (W9/W10 promotion over
    the pinned image): a decision or plan text must never call a window 'rodata' when the pinned
    section says 'text', and vice versa.
    """
    profile = DEFAULT_PROFILE if profile is None else profile
    pinned_section = str(((profile_locator(profile, region.locator) or {}).get('section') or '')).lower()
    lowered = text.lower()
    for word, required in SECTION_WORDS.items():
        if word in lowered and not any(token in pinned_section for token in required):
            return (f'text names section {word!r} but the pinned profile section is '
                    f'{pinned_section or "unstated"!r}')
    return None


def profile_locator(profile: dict | None, locator: str | None) -> dict | None:
    """The active profile's locator entry for *locator* (public alias of the internal lookup)."""
    return _profile_locator(profile, locator)


def _windows_overlap() -> list[tuple[str, str]]:
    """Pairs of registered regions whose windows overlap (must be empty)."""
    pinned = []
    for region in R.regions().values():
        rva, length = region.rva, region.length
        if rva is None or length is None:
            continue
        pinned.append((region.name, rva, rva + length))
    overlaps = []
    for i, (first_name, a0, a1) in enumerate(pinned):
        for second_name, b0, b1 in pinned[i + 1:]:
            if a0 < b1 and b0 < a1:
                overlaps.append((first_name, second_name))
    return overlaps


def evaluate_criteria(region: R.Region, profile: dict | None = None) -> dict[str, tuple[bool, str]]:
    """Every promotion criterion for one region, with the evidence behind the verdict."""
    profile = DEFAULT_PROFILE if profile is None else profile
    attest = ATTEST.get(region.name)
    locator = _profile_locator(profile, region.locator)
    results: dict[str, tuple[bool, str]] = {}

    # 1. a real W5 locator: profile entry, kind rva, same value, and the attest table agrees
    if region.locator is None:
        results['w5_locator'] = (False, 'no locator in the registry entry')
    elif locator is None:
        results['w5_locator'] = (False, f'profile carries no locators.{region.locator}')
    elif locator.get('locator', {}).get('kind') != 'rva':
        results['w5_locator'] = (False, f"locator kind is {locator.get('locator', {}).get('kind')!r}")
    elif region.rva is None or locator.get('locator', {}).get('value') != region.rva:
        results['w5_locator'] = (False, 'profile locator value does not equal the registry rva')
    elif attest is None:
        results['w5_locator'] = (False, 'the W9 attest table names no rva for this region')
    elif attest['rva'] != region.rva or attest['length'] != region.length:
        results['w5_locator'] = (False, 'attest table rva/length disagree with the registry entry')
    else:
        results['w5_locator'] = (
            True, f"locators.{region.locator} kind=rva value={region.rva} (attest table agrees)")

    # 2. complete provenance: every named source file exists
    missing = [source for source in region.provenance if not (REPO_ROOT / source).exists()]
    results['provenance_complete'] = (
        not missing,
        f'{len(region.provenance)} source(s) named, all present' if not missing
        else f'missing provenance file(s): {missing}')

    # 3. unambiguous profile binding: module kernel and policy agreeing with the identity status
    if locator is None:
        results['profile_binding'] = (False, 'no profile locator to bind')
    else:
        expected_policy = {'STRICT_FINGERPRINT': 'STRICT_FINGERPRINT',
                           'STRUCTURAL_ONLY': 'STRUCTURAL_ONLY'}.get(region.identity_status)
        got_policy = locator.get('policy')
        module = locator.get('module')
        if module != 'kernel':
            results['profile_binding'] = (False, f'locator module is {module!r}, not kernel')
        elif region.identity_status != R.IDENTITY_STRICT and got_policy != 'STRUCTURAL_ONLY':
            results['profile_binding'] = (
                False, f'identity {region.identity_status} but locator policy {got_policy!r}')
        elif region.identity_status == R.IDENTITY_STRICT and got_policy != expected_policy:
            results['profile_binding'] = (
                False, f'identity STRICT but locator policy {got_policy!r}')
        else:
            results['profile_binding'] = (
                True, f'locator module={module} policy={got_policy} (one binding, one profile)')

    # 4. section/permissions plausibility: declared permissions agree with the attested kind
    permissions = (locator or {}).get('permissions')
    kind = attest['kind'] if attest else None
    allowed = PERMISSIONS_BY_KIND.get(kind or '', ())
    if permissions is None:
        results['section_permissions_plausible'] = (False, 'the locator declares no permissions')
    elif kind is None:
        results['section_permissions_plausible'] = (False, 'no attested kind for this region')
    elif permissions not in allowed:
        results['section_permissions_plausible'] = (
            False, f'permissions {permissions!r} are not plausible for attested kind {kind!r} '
                   f'(expected one of {allowed})')
    else:
        # extra plausibility the data allows: a relocated window must be writable data, a
        # structural observation must not be a code window
        results['section_permissions_plausible'] = (
            True, f'permissions {permissions} match attested kind {kind}')

    # 5. no known instability
    if region.name in KNOWN_UNSTABLE:
        results['no_known_instability'] = (
            False, f'{region.name} is a known boot-dependent region (never a fingerprint)')
    elif region.identity_status == R.IDENTITY_STRUCTURAL_ONLY:
        results['no_known_instability'] = (
            False, 'STRUCTURAL_ONLY by identity: observed, never trusted, never promoted')
    else:
        results['no_known_instability'] = (True, 'static or relocated fingerprint, no drift known')

    # 6. unambiguous bounds
    rva, length = region.rva, region.length
    if rva is None or length is None:
        results['bounds_unambiguous'] = (False, 'rva/length are not pinned')
    elif not 0 < length <= R.MAX_READ_LEN:
        results['bounds_unambiguous'] = (False, f'length {length} outside (0, {R.MAX_READ_LEN}]')
    elif any(region.name in pair for pair in _windows_overlap()):
        results['bounds_unambiguous'] = (False, 'the window overlaps another registered region')
    else:
        results['bounds_unambiguous'] = (
            True, f'window [{rva}, {rva + length}) pinned, no overlap')

    # 7. the documented review decision
    decision = REVIEW_DECISIONS.get(region.name)
    if decision is None:
        results['review_decision'] = (False, 'no W13 review decision documented')
    elif decision.classification not in CLASSES:
        raise ClassificationError(f'{region.name}: unknown class {decision.classification!r}')
    elif decision.classification == CLASS_APPROVED_READ and not decision.purpose:
        results['review_decision'] = (False, 'APPROVED_READ without a documented purpose')
    else:
        conflict = datatype_section_conflict(
            region, ' '.join((decision.expected_datatype, decision.purpose, decision.rationale)),
            profile)
        if conflict:
            results['review_decision'] = (False, f'section/permission wording: {conflict}')
        else:
            results['review_decision'] = (
                True, f'review decision documented: {decision.classification}; section wording '
                      f'consistent with the pinned profile section')
    return results


def classify(region: R.Region, profile: dict | None = None) -> str:
    """The W13 class of one region, derived (never assumed)."""
    criteria = evaluate_criteria(region, profile)
    decision = REVIEW_DECISIONS.get(region.name)
    if region.identity_status == R.IDENTITY_UNRESOLVED:
        return CLASS_UNRESOLVED
    if region.identity_status == R.IDENTITY_STRUCTURAL_ONLY:
        return CLASS_STRUCTURAL_ONLY
    if decision is not None and decision.classification == CLASS_APPROVED_READ \
            and all(criteria[name][0] for name in CRITERIA):
        return CLASS_APPROVED_READ
    return CLASS_IDENTITY_ONLY


def approved_read_regions(profile: dict | None = None) -> tuple[R.Region, ...]:
    """Registry order, only the regions whose W13 class is ``APPROVED_READ``."""
    registry = R.regions()
    return tuple(region for name, region in registry.items()
                 if classify(region, profile) == CLASS_APPROVED_READ)


def classification_matrix(profile: dict | None = None) -> dict:
    """The machine-readable matrix: one row per registered region, with every criterion."""
    profile = DEFAULT_PROFILE if profile is None else profile
    registry = R.regions()
    rows = []
    for name, region in registry.items():
        criteria = evaluate_criteria(region, profile)
        decision = REVIEW_DECISIONS.get(name)
        rows.append({
            'region': name,
            'class': classify(region, profile),
            'identity_status': region.identity_status,
            'policy': region.policy,
            'rva': region.rva,
            'rva_hex': None if region.rva is None else hex(region.rva),
            'length': region.length,
            'max_read_len': min(region.length, R.MAX_READ_LEN) if region.length else None,
            'locator': region.locator,
            'provenance': list(region.provenance),
            'section': (_profile_locator(profile, region.locator) or {}).get('section'),
            'permissions': (_profile_locator(profile, region.locator) or {}).get('permissions'),
            'readable_by_frozen_rules': R.may_read(region),
            'criteria': {name_: {'pass': ok, 'evidence': detail}
                         for name_, (ok, detail) in criteria.items()},
            'criteria_passed': sum(1 for ok, _ in criteria.values() if ok),
            'review': None if decision is None else {
                'classification': decision.classification,
                'rationale': decision.rationale,
                'priority': decision.priority,
                'purpose': decision.purpose,
                'expected_datatype': decision.expected_datatype,
            },
        })
    return {
        'schema': SCHEMA_CLASSIFICATION,
        'classes': list(CLASSES),
        'criteria': list(CRITERIA),
        'profile': {'path': str(PROFILE_PATH.relative_to(REPO_ROOT))},
        'known_unstable': list(KNOWN_UNSTABLE),
        'rows': rows,
        'counts': {class_: sum(1 for row in rows if row['class'] == class_) for class_ in CLASSES},
    }


def classification_problems(profile: dict | None = None) -> list[str]:
    """The invariants of the W13 classification (fail closed: any hit is a policy bug)."""
    profile = DEFAULT_PROFILE if profile is None else profile
    matrix = classification_matrix(profile)
    problems: list[str] = []
    registry = R.regions()

    if set(matrix['rows'][i]['region'] for i in range(len(matrix['rows']))) != set(registry):
        problems.append('the matrix does not cover exactly the registered regions')
    for row in matrix['rows']:
        region = registry[row['region']]
        derived = row['class']
        if row['class'] == CLASS_UNRESOLVED and R.may_read(region):
            problems.append(f"{row['region']}: UNRESOLVED but readable by the frozen rules")
        if row['class'] == CLASS_UNRESOLVED and region.rva is not None:
            problems.append(f"{row['region']}: UNRESOLVED but carries an rva")
        if row['class'] == CLASS_APPROVED_READ:
            failed = [name for name, res in row['criteria'].items() if not res['pass']]
            if failed:
                problems.append(f"{row['region']}: APPROVED_READ with failed criteria {failed}")
            if not R.may_read(region):
                problems.append(f"{row['region']}: APPROVED_READ but not readable")
            if row['review'] is None or not row['review']['purpose']:
                problems.append(f"{row['region']}: APPROVED_READ without a documented purpose")
        if row['class'] == CLASS_IDENTITY_ONLY and row['criteria']['review_decision']['pass'] \
                and all(row['criteria'][name]['pass'] for name in DATA_CRITERIA) \
                and _review_class(row['region']) == CLASS_APPROVED_READ:
            problems.append(f"{row['region']}: approved-data region silently downgraded")
        if row['class'] == CLASS_STRUCTURAL_ONLY and row['readable_by_frozen_rules'] \
                and row['region'] not in KNOWN_UNSTABLE:
            problems.append(f"{row['region']}: STRUCTURAL_ONLY region in the plan path")
    if matrix['counts'][CLASS_STRUCTURAL_ONLY] != 7 \
            or len(KNOWN_UNSTABLE) != 7 \
            or 'aperture_global' not in KNOWN_UNSTABLE or 'keymgr_pool' not in KNOWN_UNSTABLE:
        problems.append('the STRUCTURAL_ONLY set changed: expected exactly aperture_global '
                        '(W9/W10), keymgr_pool (W16) and the five Track A observation windows '
                        '(docs/P4-A-OBSERVATION-WINDOWS.md), all named in KNOWN_UNSTABLE')
    for pair in _windows_overlap():
        problems.append(f'overlapping windows: {pair[0]} / {pair[1]}')
    for name in registry:
        if name not in REVIEW_DECISIONS:
            problems.append(f'{name}: no review decision (implicit promotion risk)')
    for name, decision in REVIEW_DECISIONS.items():
        if name not in registry:
            problems.append(f'{name}: review decision for an unregistered region')
        elif decision.classification != classify(registry[name], profile):
            problems.append(f'{name}: review decision says {decision.classification}, '
                            f'the data says {classify(registry[name], profile)}')
    return problems


def _review_class(name: str) -> str | None:
    decision = REVIEW_DECISIONS.get(name)
    return None if decision is None else decision.classification


def _self_test() -> list[str]:
    checks: list[str] = []
    matrix = classification_matrix()
    problems = classification_problems()
    if problems:
        checks += problems
    if matrix['counts'][CLASS_APPROVED_READ] == 0:
        checks.append('no region is APPROVED_READ')
    if matrix['counts'][CLASS_APPROVED_READ] == matrix['counts'][CLASS_IDENTITY_ONLY] == 0:
        checks.append('the classification is empty')
    approved = [row['region'] for row in matrix['rows'] if row['class'] == CLASS_APPROVED_READ]
    expected = ['amd_iommu', 'gbase_vtophys', 'code_anchor', 'copyout_prologue', 'prison0_static']
    if approved != expected:
        checks.append(f'APPROVED_READ is {approved}, expected {expected} (registry order)')
    for row in matrix['rows']:
        if row['class'] == CLASS_APPROVED_READ and not row['readable_by_frozen_rules']:
            checks.append(f"{row['region']}: APPROVED_READ but the frozen rules refuse it")
    return checks


def main(argv: list[str]) -> int:                                          # pragma: no cover
    if '--self-test' in argv:
        problems = _self_test()
        if problems:
            print('classification self-test: FAILED')
            for problem in problems:
                print(f'  - {problem}')
            return 1
        print('classification self-test: OK (4 classes, 7 criteria, no implicit promotion)')
        return 0
    print(json.dumps(classification_matrix(), indent=1, sort_keys=True))
    return 0


if __name__ == '__main__':                                                 # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
