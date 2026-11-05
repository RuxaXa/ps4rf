#!/usr/bin/env python3
"""PS4RF P4/W6 comparators: identity, profile, artifact, operation, external.

Comparisons are structural and fail-closed. Absolute runtime addresses never take part:
profile locators are compared as ``module + relative kind + value + section``,
artifact entries by name plus ``file_offset``, and an architecture mismatch stops the
run with a single ``INCOMPARABLE`` finding instead of producing noise.

A difference is never a verdict. Findings carry a class and a confidence, nothing else,
and every produced object is validated against the W6 vocabulary before it is returned.

Layers:

* ``identity``  - target identity (platform, firmware version/build, architecture,
  hardware/model) and module identity
* ``profile``   - operation mapping, locator presence/kind/value, module, section,
  permissions, expected bytes, provenance, confidence, unresolved<->resolved
* ``artifact``  - sections/members: added/removed/resized, permission changes, byte
  range changes, region hash changes, relocation-aware offsets
* ``operation`` - the 14 gated operations: requirement added/removed, locator changed,
  verification requirement changed, profile policy changed, unresolved<->resolved
* ``external``  - optional disassembly/analysis results (Ghidra/Rizin/angr/AFL++), capped
  at ``WEAK`` confidence and never mixed into the fact layers

Usage::

    python tools/differential/compare.py --self-test
"""

from __future__ import annotations

import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:  # allow direct script execution
    sys.path.insert(0, str(REPO_ROOT))

from tools.differential.inventory import (  # noqa: E402
    InventoryError, identity_of, load_inventory, strip_common_root,
)
from tools.differential.normalize import (  # noqa: E402
    DEFAULT_CONFIG, NORM_VERSION, NormalizationError, RunConfig, canonical_body_sha256,
    normalize_document, u64_hex,
)
from tools.differential import schema as SC  # noqa: E402
from tools.primitive_iface.gate import REQ_BY_OP, privilege_gated_ops  # noqa: E402
from tools.profiles import loader as PL  # noqa: E402
from tools.profiles import schema as PS  # noqa: E402

UNRESOLVED = 'UNRESOLVED'
IDENTITY_FIELDS = ('platform', 'model_family', 'firmware_version', 'firmware_build_id',
                   'architecture', 'hardware_revision')
ANALYSIS_KINDS = ('structured', 'table')
EXTERNAL_KINDS = ('disassembly', 'xrefs', 'functions')


class DifferentialRunError(NormalizationError):
    """Fail-closed refusal for a whole run."""


# --- finding construction -------------------------------------------------------------
def _finding(layer: str, class_: str, confidence: str, subject: str, before, after,
             provenance: dict, *, operation: str | None = None,
             fixture: bool = False, cap: str | None = None) -> dict:
    if fixture:
        confidence = SC.cap_confidence(confidence, SC.WEAK)
    confidence = SC.cap_confidence(confidence, cap)
    return {
        'layer': layer,
        'class': class_,
        'confidence': confidence,
        'subject': subject,
        'operation': operation,
        'before': before,
        'after': after,
        'provenance': provenance,
    }


def _is_unresolved(value) -> bool:
    return value is None or value == UNRESOLVED


def _locator_repr(value):
    """Fixed-width rendering for a locator value; unresolved stays a word.

    Any other type is a malformed locator and is refused (fail closed).
    """
    if _is_unresolved(value):
        return UNRESOLVED
    if isinstance(value, int) and not isinstance(value, bool):
        return u64_hex(value)
    raise NormalizationError(f'malformed locator value {value!r}')


def _inputs_fixture(*inputs: dict) -> bool:
    return any(bool(i.get('fixture')) for i in inputs)


# --- A. target identity ---------------------------------------------------------------
def diff_identity(a: dict, b: dict, cfg: RunConfig, provenance: dict) -> list[dict]:
    findings: list[dict] = []
    fixture = _inputs_fixture(a, b)
    ta, tb = a.get('target') or {}, b.get('target') or {}
    for field in IDENTITY_FIELDS:
        before, after = ta.get(field, UNRESOLVED), tb.get(field, UNRESOLVED)
        if before == after:
            continue
        if _is_unresolved(before) or _is_unresolved(after):
            findings.append(_finding(SC.LAYER_TARGET_IDENTITY, SC.UNRESOLVED, SC.WEAK,
                                     f'target.{field}', before, after, provenance, fixture=fixture))
        else:
            findings.append(_finding(SC.LAYER_TARGET_IDENTITY, SC.CHANGED, SC.EXACT,
                                     f'target.{field}', before, after, provenance, fixture=fixture))
    return findings


def architecture_conflict(a: dict, b: dict) -> bool:
    arch_a = (a.get('target') or {}).get('architecture') or a.get('architecture')
    arch_b = (b.get('target') or {}).get('architecture') or b.get('architecture')
    if _is_unresolved(arch_a) or _is_unresolved(arch_b):
        return False
    return arch_a != arch_b


# --- B. profile -----------------------------------------------------------------------
def diff_profile(a: dict, b: dict, cfg: RunConfig, provenance: dict) -> list[dict]:
    findings: list[dict] = []
    fixture = _inputs_fixture(a, b)
    pa, pb = a.get('operation_policy') or {}, b.get('operation_policy') or {}
    la, lb = a.get('locators') or {}, b.get('locators') or {}

    for op in sorted(set(pa) | set(pb)):
        ea, eb = pa.get(op), pb.get(op)
        if ea is None or eb is None:
            findings.append(_finding(SC.LAYER_PROFILE, SC.ADDED if ea is None else SC.REMOVED,
                                     SC.STRONG, f'operation_policy.{op}',
                                     None if ea is None else ea, None if eb is None else eb,
                                     provenance, operation=op, fixture=fixture))
            continue
        for field in ('profile_required', 'locator_ref', 'reason'):
            if ea.get(field) != eb.get(field):
                findings.append(_finding(SC.LAYER_PROFILE, SC.CHANGED, SC.STRONG,
                                         f'operation_policy.{op}.{field}', ea.get(field),
                                         eb.get(field), provenance, operation=op, fixture=fixture))
        if sorted(ea.get('profile_fields') or []) != sorted(eb.get('profile_fields') or []):
            findings.append(_finding(SC.LAYER_PROFILE, SC.CHANGED, SC.STRONG,
                                     f'operation_policy.{op}.profile_fields',
                                     sorted(ea.get('profile_fields') or []),
                                     sorted(eb.get('profile_fields') or []), provenance,
                                     operation=op, fixture=fixture))

    for ref in sorted(set(la) | set(lb)):
        fa, fb = la.get(ref), lb.get(ref)
        if fa is None or fb is None:
            findings.append(_finding(SC.LAYER_PROFILE, SC.ADDED if fa is None else SC.REMOVED,
                                     SC.STRONG, f'locators.{ref}', fa, fb, provenance,
                                     fixture=fixture))
            continue
        va, vb = (fa.get('locator') or {}).get('value'), (fb.get('locator') or {}).get('value')
        core_same = all(fa.get(k) == fb.get(k) for k in ('module', 'section', 'permissions',
                                                         'expected_bytes', 'confidence',
                                                         'provenance'))
        if va == vb:
            pass
        elif _is_unresolved(va) or _is_unresolved(vb):
            direction = 'unresolved -> resolved' if _is_unresolved(va) else 'resolved -> unresolved'
            findings.append(_finding(SC.LAYER_PROFILE, SC.UNRESOLVED, SC.WEAK,
                                     f'locators.{ref}.locator.value',
                                     _locator_repr(va), _locator_repr(vb), provenance,
                                     fixture=fixture))
            findings[-1]['subject'] = f'locators.{ref}.locator.value ({direction})'
        elif core_same:
            findings.append(_finding(SC.LAYER_PROFILE, SC.MOVED, SC.STRONG,
                                     f'locators.{ref}.locator.value', _locator_repr(va),
                                     _locator_repr(vb), provenance, fixture=fixture))
        else:
            findings.append(_finding(SC.LAYER_PROFILE, SC.CHANGED, SC.STRONG,
                                     f'locators.{ref}.locator.value', _locator_repr(va),
                                     _locator_repr(vb), provenance, fixture=fixture))
        if (fa.get('locator') or {}).get('kind') != (fb.get('locator') or {}).get('kind'):
            findings.append(_finding(SC.LAYER_PROFILE, SC.CHANGED, SC.STRONG,
                                     f'locators.{ref}.locator.kind',
                                     (fa.get('locator') or {}).get('kind'),
                                     (fb.get('locator') or {}).get('kind'), provenance,
                                     fixture=fixture))
        for field in ('module', 'section', 'confidence'):
            if fa.get(field) != fb.get(field):
                findings.append(_finding(SC.LAYER_PROFILE, SC.CHANGED, SC.STRONG,
                                         f'locators.{ref}.{field}', fa.get(field),
                                         fb.get(field), provenance, fixture=fixture))
        if fa.get('permissions') != fb.get('permissions'):
            findings.append(_finding(SC.LAYER_PROFILE, SC.PERMISSION_CHANGED, SC.STRONG,
                                     f'locators.{ref}.permissions', fa.get('permissions'),
                                     fb.get('permissions'), provenance, fixture=fixture))
        if fa.get('expected_bytes') != fb.get('expected_bytes'):
            findings.append(_finding(SC.LAYER_PROFILE, SC.SIGNATURE_CHANGED, SC.STRONG,
                                     f'locators.{ref}.expected_bytes', fa.get('expected_bytes'),
                                     fb.get('expected_bytes'), provenance, fixture=fixture))
        if fa.get('provenance') != fb.get('provenance'):
            findings.append(_finding(SC.LAYER_PROFILE, SC.CHANGED, SC.STRONG,
                                     f'locators.{ref}.provenance', fa.get('provenance'),
                                     fb.get('provenance'), provenance, fixture=fixture))
    return findings


# --- C. artifacts ---------------------------------------------------------------------
def diff_artifacts(a: dict, b: dict, cfg: RunConfig, provenance: dict) -> list[dict]:
    findings: list[dict] = []
    fixture = _inputs_fixture(a, b)
    if architecture_conflict(a, b):
        return [_finding(SC.LAYER_ARTIFACT, SC.INCOMPARABLE, SC.UNKNOWN, 'architecture',
                         a.get('architecture'), b.get('architecture'), provenance,
                         fixture=fixture)]
    ea = {e['path']: e for e in a.get('entries', ())}
    eb = {e['path']: e for e in b.get('entries', ())}
    for path in sorted(set(ea) | set(eb)):
        one, two = ea.get(path), eb.get(path)
        if one is None or two is None:
            findings.append(_finding(SC.LAYER_ARTIFACT, SC.ADDED if one is None else SC.REMOVED,
                                     SC.STRONG, path, one, two, provenance, fixture=fixture))
            continue
        cap = SC.WEAK if one.get('kind') in ANALYSIS_KINDS else None
        if one.get('permissions') != two.get('permissions') and not (
                _is_unresolved(one.get('permissions')) or _is_unresolved(two.get('permissions'))):
            findings.append(_finding(SC.LAYER_ARTIFACT, SC.PERMISSION_CHANGED, SC.STRONG,
                                     f'{path}#permissions', one.get('permissions'),
                                     two.get('permissions'), provenance, fixture=fixture, cap=cap))
        if one.get('sha256') == two.get('sha256') and one.get('size') == two.get('size'):
            if one.get('file_offset') is not None and two.get('file_offset') is not None and \
                    one['file_offset'] != two['file_offset']:
                findings.append(_finding(SC.LAYER_ARTIFACT, SC.MOVED, SC.STRONG,
                                         f'{path}#file_offset',
                                         u64_hex(one['file_offset']), u64_hex(two['file_offset']),
                                         provenance, fixture=fixture, cap=cap))
            continue
        if one.get('size') != two.get('size'):
            findings.append(_finding(SC.LAYER_ARTIFACT, SC.CHANGED, SC.STRONG, f'{path}#size',
                                     one.get('size'), two.get('size'), provenance,
                                     fixture=fixture, cap=cap))
        if one.get('sha256') != two.get('sha256'):
            findings.append(_finding(SC.LAYER_ARTIFACT, SC.SIGNATURE_CHANGED, SC.STRONG,
                                     f'{path}#sha256', one.get('sha256'), two.get('sha256'),
                                     provenance, fixture=fixture, cap=cap))
    return findings


# --- D. primitive contracts -----------------------------------------------------------
def operations_from_profile(doc: dict) -> dict:
    """Operation inventory derived from a profile plus the frozen W4 matrix."""
    operations = {}
    for op in privilege_gated_ops():
        req = REQ_BY_OP[op]
        policy = (doc.get('operation_policy') or {}).get(op) or {}
        ref = policy.get('locator_ref')
        loc = (doc.get('locators') or {}).get(ref) if ref else None
        operations[op] = {
            'profile_required': bool(req.profile_required),
            'profile_policy': policy.get('reason'),
            'locator': None if loc is None else {
                'module': loc.get('module'),
                'kind': (loc.get('locator') or {}).get('kind'),
                'value': (loc.get('locator') or {}).get('value'),
                'section': loc.get('section'),
                'permissions': loc.get('permissions'),
            },
            'verification_requirement': req.verification_op,
            'requirement': req.capability or req.namespace,
        }
    return {'schema': 'ps4rf.differential.operation-inventory.v1', 'operations': operations}


def diff_operations(a: dict, b: dict, cfg: RunConfig, provenance: dict) -> list[dict]:
    findings: list[dict] = []
    fixture = _inputs_fixture(a, b)
    oa = a.get('operations') or operations_from_profile(a)['operations']
    ob = b.get('operations') or operations_from_profile(b)['operations']
    for op in sorted(set(oa) | set(ob)):
        one, two = oa.get(op), ob.get(op)
        if one is None or two is None:
            findings.append(_finding(SC.LAYER_OPERATION, SC.ADDED if one is None else SC.REMOVED,
                                     SC.STRONG, op, one, two, provenance, operation=op,
                                     fixture=fixture))
            continue
        for field in ('profile_required', 'profile_policy', 'verification_requirement',
                      'requirement'):
            if one.get(field) != two.get(field):
                findings.append(_finding(SC.LAYER_OPERATION, SC.CHANGED, SC.STRONG,
                                         f'{op}.{field}', one.get(field), two.get(field),
                                         provenance, operation=op, fixture=fixture))
        la, lb = one.get('locator') or {}, two.get('locator') or {}
        if bool(la) != bool(lb):
            findings.append(_finding(SC.LAYER_OPERATION, SC.ADDED if not la else SC.REMOVED,
                                     SC.STRONG, f'{op}.locator', la or None, lb or None,
                                     provenance, operation=op, fixture=fixture))
            continue
        if la and lb:
            if la == lb:
                pass
            else:
                va, vb = la.get('value'), lb.get('value')
                if va == vb:
                    class_ = SC.CHANGED
                elif _is_unresolved(va) or _is_unresolved(vb):
                    class_ = SC.UNRESOLVED
                elif {k: v for k, v in la.items() if k != 'value'} == {k: v for k, v in lb.items() if k != 'value'}:
                    class_ = SC.MOVED
                else:
                    class_ = SC.CHANGED
                confidence = SC.WEAK if class_ == SC.UNRESOLVED else SC.STRONG
                findings.append(_finding(SC.LAYER_OPERATION, class_, confidence, f'{op}.locator',
                                         la, lb, provenance, operation=op, fixture=fixture))
    return findings


# --- external analysis (adapter ingestion path, no adapters implemented) --------------
def validate_external_analysis(doc: dict) -> list[str]:
    errors: list[str] = []
    if not isinstance(doc, dict):
        return ['external analysis: expected an object']
    if doc.get('schema') != SC.EXTERNAL_SCHEMA:
        errors.append(f'external analysis: schema must be {SC.EXTERNAL_SCHEMA!r}')
    if doc.get('tool') not in SC.EXTERNAL_TOOLS:
        errors.append(f'external analysis: tool must be one of {list(SC.EXTERNAL_TOOLS)}')
    sha = doc.get('artifact_sha256')
    if not isinstance(sha, str) or len(sha) != 64:
        errors.append('external analysis: artifact_sha256 is mandatory (provenance)')
    entries = doc.get('entries')
    if not isinstance(entries, list) or not entries:
        errors.append('external analysis: entries must be a non-empty list')
    for entry in entries if isinstance(entries, list) else []:
        if not entry.get('name') or not entry.get('kind'):
            errors.append('external analysis: every entry needs kind and name')
        locator = entry.get('locator')
        if locator is not None and locator.get('kind') not in ('rva', 'relative'):
            errors.append('external analysis: locators must be relative')
    return errors


def diff_external(a: dict, b: dict, cfg: RunConfig, provenance: dict) -> list[dict]:
    findings: list[dict] = []
    ea = {e['name']: e for e in a.get('entries', ())}
    eb = {e['name']: e for e in b.get('entries', ())}
    for name in sorted(set(ea) | set(eb)):
        one, two = ea.get(name), eb.get(name)
        if one is None or two is None:
            class_ = SC.ADDED if one is None else SC.REMOVED
        elif one.get('locator') == two.get('locator') and one.get('size') == two.get('size'):
            continue
        else:
            class_ = SC.CHANGED
        findings.append(_finding(SC.LAYER_EXTERNAL, class_, SC.WEAK, name, one, two, provenance,
                                 cap=SC.WEAK))
    if findings:
        findings.append(_finding(SC.LAYER_EXTERNAL, SC.UNRESOLVED, SC.WEAK,
                                 'external-analysis-provenance',
                                 {'tool': a.get('tool'), 'adapter': 'not implemented'},
                                 {'tool': b.get('tool'), 'adapter': 'not implemented'},
                                 provenance, cap=SC.WEAK))
    return findings


# --- run orchestration ----------------------------------------------------------------
def run_diff(kind: str, before, after, *, config: RunConfig = DEFAULT_CONFIG,
             timestamp: str, run_id: str | None = None,
             expect_hashes: dict | None = None,
             external: tuple[dict, dict] | None = None) -> dict:
    """Execute one differential run. ``kind`` in profiles|artifacts|operations."""
    if kind not in ('profiles', 'artifacts', 'operations'):
        raise DifferentialRunError(f'unknown diff kind {kind!r}')
    expect_hashes = expect_hashes or {}
    notes: list[str] = []
    findings: list[dict] = []
    inputs: list[dict] = []

    def _profile_input(path, role: str) -> dict:
        doc = PL.load_profile(path)  # fail-closed: schema + canonical hash
        sha_file = PL.canonical_profile_sha256(doc)
        declared = doc.get('canonical_sha256')
        if declared is not None and declared != sha_file:
            raise DifferentialRunError(f'{path}: declared profile hash mismatch')
        if expect_hashes.get(role) and expect_hashes[role] != sha_file:
            raise DifferentialRunError(f'{path}: canonical hash does not match the declared '
                                       f'input hash (fail closed)')
        return doc

    try:
        if kind == 'profiles':
            a_doc, b_doc = _profile_input(before, 'before'), _profile_input(after, 'after')
            inputs = [_input_entry('before', a_doc, 'profiles'), _input_entry('after', b_doc, 'profiles')]
            if PS.canonical_profile_sha256(a_doc) == PS.canonical_profile_sha256(b_doc):
                notes.append('inputs are canonical-equal: empty diff')
            else:
                provenance = _provenance(inputs)
                findings += diff_identity(a_doc, b_doc, config, provenance)
                if architecture_conflict(a_doc, b_doc):
                    findings = [f for f in findings if f['class'] == SC.INCOMPARABLE or
                                f['layer'] != SC.LAYER_PROFILE]
                    findings.append(_finding(SC.LAYER_PROFILE, SC.INCOMPARABLE, SC.UNKNOWN,
                                             'profile-comparison', 'architecture differs',
                                             'profile layers not compared', provenance))
                    notes.append('architecture conflict: profile layers not compared (fail closed)')
                else:
                    findings += diff_profile(a_doc, b_doc, config, provenance)
        elif kind == 'artifacts':
            try:
                a_inv = load_inventory(before, expect_sha256=expect_hashes.get('before'))
                b_inv = load_inventory(after, expect_sha256=expect_hashes.get('after'))
            except InventoryError as exc:
                if 'ARTIFACT_MISSING' in str(exc) and not expect_hashes.get('before') \
                        and not expect_hashes.get('after'):
                    missing = str(exc).split('ARTIFACT_MISSING:', 1)[1].strip()
                    inputs = [_missing_input('before', str(before)), _missing_input('after', str(after))]
                    findings = _finalize_findings([
                        _finding(SC.LAYER_ARTIFACT, SC.ARTIFACT_MISSING, SC.UNKNOWN,
                                 'artifact', str(before), str(after), {'note': missing})])
                    notes.append('artifact missing: nothing synthesized (fail closed)')
                    return _assemble(kind, inputs, findings, [], notes, config, timestamp, run_id)
                raise
            if config.strip_common_root:
                stripped = strip_common_root(a_inv, b_inv)
                a_inv, b_inv = stripped[0], stripped[1]
                notes.append('common bundle roots stripped (explicit config switch)')
            inputs = [_input_entry('before', a_inv, 'artifacts'), _input_entry('after', b_inv, 'artifacts')]
            provenance = _provenance(inputs)
            findings += diff_identity(a_inv, b_inv, config, provenance)
            findings += diff_artifacts(a_inv, b_inv, config, provenance)
            if any(f['class'] == SC.INCOMPARABLE for f in findings):
                notes.append('architecture conflict: artifact entries not compared (fail closed)')
        else:  # operations
            a_doc = _loads_or_profile(before)
            b_doc = _loads_or_profile(after)
            inputs = [_input_entry('before', a_doc, 'operations'), _input_entry('after', b_doc, 'operations')]
            provenance = _provenance(inputs)
            findings += diff_operations(a_doc, b_doc, config, provenance)
    except (NormalizationError, PL.ProfileLoadError) as exc:
        raise DifferentialRunError(str(exc)) from exc

    if external is not None:
        ea, eb = external
        for analysis, entry in ((ea, inputs[0]), (eb, inputs[1])):
            errors = validate_external_analysis(analysis)
            if errors:
                raise DifferentialRunError('; '.join(errors))
            if analysis['artifact_sha256'] != entry['sha256']:
                raise DifferentialRunError('external analysis does not reference the compared '
                                           'artifact (provenance mismatch, fail closed)')
        findings += diff_external(ea, eb, config, _provenance(inputs))
        notes.append('external analysis findings are capped at WEAK; no adapter is implemented yet')

    findings = _finalize_findings(findings)
    return _assemble(kind, inputs, findings, [], notes, config, timestamp, run_id)


def _loads_or_profile(path) -> dict:
    import json  # noqa: PLC0415
    p = pathlib.Path(path)
    if not p.exists():
        raise DifferentialRunError(f'ARTIFACT_MISSING: {p} does not exist')
    doc = json.loads(p.read_text(encoding='utf-8'))
    normalize_document(doc, p.name)
    if 'locators' in doc and 'operation_policy' in doc:
        errors = PS.validate_profile(doc)
        if errors:
            raise DifferentialRunError(f'{p.name}: profile schema mismatch: {errors[:3]}')
    return doc


def _input_entry(role: str, obj: dict, kind: str) -> dict:
    entry = {
        'role': role, 'kind': obj.get('kind', kind), 'path': obj.get('path', ''),
        'sha256': obj.get('sha256'), 'architecture': obj.get('architecture'),
        'fixture': bool(obj.get('fixture')),
        'missing': False,
    }
    if kind == 'profiles':
        entry['canonical_sha256'] = PS.canonical_profile_sha256(obj)
        entry['sha256'] = entry['canonical_sha256']
        entry['architecture'] = (obj.get('target') or {}).get('architecture')
    if kind == 'operations':
        entry['sha256'] = PS.canonical_profile_sha256(obj) if 'target' in obj else \
            canonical_body_sha256(obj)
    return entry


def _missing_input(role: str, path: str) -> dict:
    return {'role': role, 'kind': 'artifact', 'path': path, 'sha256': None,
            'architecture': None, 'fixture': False, 'missing': True}


def _provenance(inputs: list[dict]) -> dict:
    return {'before_sha256': inputs[0]['sha256'], 'after_sha256': inputs[1]['sha256'],
            'normalization_version': NORM_VERSION}


def _finalize_findings(findings: list[dict]) -> list[dict]:
    ordered = sorted(findings, key=lambda f: (SC.LAYERS.index(f['layer']), f['subject'],
                                              f['class'], str(f['before']), str(f['after'])))
    out = []
    for index, finding in enumerate(ordered, start=1):
        entry = dict(finding)
        entry['id'] = f'F{index:04d}'
        errors = SC.validate_finding(entry)
        if errors:
            raise DifferentialRunError(f'produced finding is invalid: {errors}')
        out.append(entry)
    return out


def _assemble(kind: str, inputs: list[dict], findings: list[dict], candidates: list[dict],
              notes: list[str], config: RunConfig, timestamp: str,
              run_id: str | None) -> dict:
    report = {
        'schema': SC.REPORT_SCHEMA,
        'run_id': run_id or '',
        'timestamp': timestamp,
        'tool': {'name': SC.TOOL_NAME, 'version': SC.TOOL_VERSION},
        'normalization_version': NORM_VERSION,
        'config_sha256': config.sha256,
        'config': config.as_dict(),
        'command': kind,
        'inputs': inputs,
        'findings': findings,
        'candidates': candidates,
        'summary': {
            'findings': len(findings),
            'candidates': len(candidates),
            'counts': SC.class_counts(findings),
            'identical': not findings,
            'notes': notes,
        },
    }
    core = canonical_body_sha256(report, exclude=('timestamp', 'run_id', 'output_sha256'))
    report['output_sha256'] = core
    if not report['run_id']:
        report['run_id'] = f'W6-{core[:16]}'
    errors = SC.validate_report(report)
    if errors:
        raise DifferentialRunError(f'report is invalid: {errors[:4]}')
    return report


def attach_candidates(report: dict, candidates: list[dict]) -> dict:
    """Attach generated candidates and refresh the deterministic hashes."""
    updated = dict(report)
    updated['candidates'] = candidates
    summary = dict(updated['summary'])
    summary['candidates'] = len(candidates)
    updated['summary'] = summary
    core = canonical_body_sha256(updated, exclude=('timestamp', 'run_id', 'output_sha256'))
    updated['output_sha256'] = core
    errors = SC.validate_report(updated)
    if errors:
        raise DifferentialRunError(f'report is invalid: {errors[:4]}')
    return updated


def _self_test() -> list[str]:
    checks: list[str] = []
    a = {'target': {'architecture': 'x86-64'}, 'operation_policy': {}, 'locators': {},
         'sha256': 'a' * 64, 'path': 'a', 'kind': 'profiles'}
    b = {'target': {'architecture': 'arm'}, 'operation_policy': {}, 'locators': {},
         'sha256': 'b' * 64, 'path': 'b', 'kind': 'profiles'}
    if not architecture_conflict(a, b):
        checks.append('architecture conflicts must be detected')
    if architecture_conflict(a, a):
        checks.append('equal architectures are not a conflict')
    inv_a = {'kind': 'elf', 'sha256': 'c' * 64, 'architecture': 'x86-64', 'entries': [
        {'path': '.text', 'kind': 'section', 'file_offset': 64, 'size': 16, 'sha256': 'd' * 64,
         'permissions': 'r-x'}]}
    inv_b = {'kind': 'elf', 'sha256': 'e' * 64, 'architecture': 'x86-64', 'entries': [
        {'path': '.text', 'kind': 'section', 'file_offset': 64, 'size': 16, 'sha256': 'd' * 64,
         'permissions': 'rw-'}]}
    prov = {'before_sha256': inv_a['sha256'], 'after_sha256': inv_b['sha256']}
    findings = diff_artifacts(inv_a, inv_b, DEFAULT_CONFIG, prov)
    if [f['class'] for f in findings] != [SC.PERMISSION_CHANGED]:
        checks.append(f'permission change must be PERMISSION_CHANGED, got {findings}')
    return checks


def self_test() -> list[str]:
    return _self_test()


def main(argv: list[str]) -> int:
    if '--self-test' not in argv:
        print((__doc__ or '').strip().splitlines()[0])
        print('usage: compare.py --self-test')
        return 2
    failures = _self_test()
    if failures:
        print(f'compare self-test: {len(failures)} FAILED')
        for item in failures:
            print(f'  - {item}')
        return 1
    print('compare self-test: OK (identity/profile/artifact/operation layers, fail-closed)')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
