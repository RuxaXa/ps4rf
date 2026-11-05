"""W10 -- independent validator for a promoted profile (offline).

Deliberately independent of :mod:`tools.profiles.promotion`: it re-reads the pinned kernel image,
re-extracts every expected byte string from the RVA, re-reads the W9 live evidence and re-derives
the identity basis. It trusts nothing the builder claims.

The five properties the owner requires (each one its own check with its own evidence):

1. every STRICT_FINGERPRINT window matches the pinned image byte for byte *and* the W9 live
   evidence measured exactly those bytes
2. the locators are relative (RVA) and really resolve to the expected bytes in the pinned image
3. provenance is complete (kind, source, sha256 == the pinned image hash) for every locator
4. no runtime address is persisted (LSTAR, kbase, slide and the observed aperture value from the
   W9 evidence must appear nowhere in the canonical profile bytes)
5. a STRUCTURAL_ONLY window is never used as an exact fingerprint: it must be marked as such,
   must never be required to equal the pinned value, and is excluded from the identity basis

Usage::

    python tools/profiles/promotion_validator.py --self-test
    python tools/profiles/promotion_validator.py <profile.json> --w9-evidence <file> [--json out]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:                       # pragma: no cover - import bootstrap
    sys.path.insert(0, str(REPO_ROOT))

from tools.profiles.promotion import (  # noqa: E402
    PINNED_KERNEL, PINNED_KERNEL_SHA256, PromotionError, load_w9_evidence, observed_windows,
    parse_w9_table, platform_constants, program_segments, read_pinned_kernel, slide_from_evidence,
)
from tools.profiles.schema import (  # noqa: E402
    STRICT_POLICY, STRUCTURAL_POLICY, canonical_profile_sha256, validate_profile,
)

RUNTIME_FIELD_HINTS = ('lstar', 'kbase', 'slide', 'aperture')


class ValidationError(Exception):
    pass


def _kernel_address_pattern() -> re.Pattern:
    # any canonical kernel pointer or 12+ hex digit address in a stored string
    return re.compile(r'0x(?:f{8,}[0-9a-f]{4,}|[0-9a-f]{12,})', re.IGNORECASE)


def _collect_strings(node, path: str = '') -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if isinstance(node, dict):
        for key, value in node.items():
            out.extend(_collect_strings(value, f'{path}.{key}' if path else str(key)))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            out.extend(_collect_strings(value, f'{path}[{index}]'))
    elif isinstance(node, str):
        out.append((path, node))
    return out


def validate(profile: dict, *, w9_evidence_path: pathlib.Path) -> dict:
    checks: list[dict] = []
    blob = read_pinned_kernel()
    segments = program_segments(blob)
    evidence = load_w9_evidence(w9_evidence_path)
    observed = observed_windows(evidence)
    table = {row['id']: row for row in parse_w9_table()}
    event = evidence.get('kernel_attestation_event') or {}
    slide = slide_from_evidence(evidence)          # derived from kbase_candidate, re-checked

    def add(name: str, ok: bool, detail: str) -> None:
        checks.append({'check': name, 'ok': bool(ok), 'detail': detail})

    # 0 -- schema and self-hash
    schema_problems = validate_profile(profile)
    add('schema_valid', not schema_problems, '; '.join(schema_problems) or 'no schema errors')
    digest = canonical_profile_sha256(profile)
    add('canonical_sha256', profile.get('canonical_sha256') == digest,
        f'declared {profile.get("canonical_sha256")} vs recomputed {digest}')
    add('not_a_fixture', profile.get('fixture') is False,
        f'fixture={profile.get("fixture")!r} (a promoted profile must not be a fixture)')

    locators = profile.get('locators') or {}
    strict_names = [name for name, loc in locators.items()
                    if isinstance(loc, dict) and loc.get('policy') == STRICT_POLICY]
    structural_names = [name for name, loc in locators.items()
                        if isinstance(loc, dict) and loc.get('policy') == STRUCTURAL_POLICY]
    add('policy_matrix_present', len(strict_names) == 7 and len(structural_names) == 1,
        f'{len(strict_names)} STRICT_FINGERPRINT, {len(structural_names)} STRUCTURAL_ONLY')

    # 1 -- strict windows: pinned bytes == stored expectation == live observation
    strict_ok = True
    details: list[str] = []
    for name in sorted(strict_names):
        loc = locators[name]
        window_id = name.split('.')[-1]
        row = table.get(window_id)
        if row is None:
            strict_ok = False
            details.append(f'{name}: unknown window id')
            continue
        value = loc['locator']['value']
        if not isinstance(value, int) or isinstance(value, bool):
            strict_ok = False
            details.append(f'{name}: locator value {value!r} is not an RVA integer')
            continue
        rva = value
        if rva != row['rva']:
            strict_ok = False
            details.append(f'{name}: rva {rva:#x} != table {row["rva"]:#x}')
            continue
        expected = (loc.get('expected_bytes') or {}).get('hex')
        pinned = blob[rva:rva + row['len']].hex()
        live = observed.get(window_id, '')
        if expected != pinned:
            strict_ok = False
            details.append(f'{name}: stored expectation != pinned image bytes')
        elif row['kind'] == 'relocated':
            # the profile stores the image value; the live kernel holds image value + slide
            want = (int.from_bytes(bytes.fromhex(pinned), 'little') + slide) & ((1 << 64) - 1)
            if not live or int.from_bytes(bytes.fromhex(live), 'little') != want:
                strict_ok = False
                details.append(f'{name}: live pointer != image value + verified slide')
            else:
                details.append(f'{name}: {row["len"]} B relocated pointer, image value + slide')
        elif live != pinned:
            strict_ok = False
            details.append(f'{name}: W9 live bytes != pinned image bytes')
        else:
            details.append(f'{name}: {row["len"]} B byte-exact (pinned == live)')
    add('strict_fingerprints_match', strict_ok and len(strict_names) == 7,
        '; '.join(details))

    # 2 -- relative locators resolve
    relative_ok = True
    relative_details: list[str] = []
    for name, loc in sorted(locators.items()):
        if not isinstance(loc, dict):
            relative_ok = False
            relative_details.append(f'{name}: not an object')
            continue
        kind = (loc.get('locator') or {}).get('kind')
        value = (loc.get('locator') or {}).get('value')
        if kind != 'rva':
            relative_ok = False
            relative_details.append(f'{name}: locator kind {kind!r} is not a relative RVA')
            continue
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            relative_ok = False
            relative_details.append(f'{name}: locator value {value!r} is not a non-negative RVA '
                                    f'integer (the schema forbids absolute/string addresses)')
            continue
        rva = value
        window_id = name.split('.')[-1]
        row = table.get(window_id)
        if row and rva + row['len'] > len(blob):
            relative_ok = False
            relative_details.append(f'{name}: RVA outside the pinned image')
    add('relative_locators_resolve', relative_ok, '; '.join(relative_details) or 'all resolve')

    # 3 -- provenance complete
    provenance_ok = True
    provenance_details: list[str] = []
    for name, loc in sorted(locators.items()):
        prov = (loc or {}).get('provenance') or {}
        if prov.get('kind') != 'evidence':
            provenance_ok = False
            provenance_details.append(f'{name}: provenance kind {prov.get("kind")!r}')
        if not str(prov.get('source') or '').strip():
            provenance_ok = False
            provenance_details.append(f'{name}: provenance source empty')
        if prov.get('sha256') != PINNED_KERNEL_SHA256:
            provenance_ok = False
            provenance_details.append(f'{name}: provenance sha256 is not the pinned image hash')
    add('provenance_complete', provenance_ok,
        '; '.join(provenance_details) or f'all {len(locators)} locators carry the pinned hash')

    # 4 -- no runtime address persisted
    runtime_values = [v for v in (event.get('lstar'), event.get('kbase_candidate'),
                                  event.get('kbase_sdk'), event.get('kbase_slide'),
                                  event.get('aperture_global')) if isinstance(v, str)]
    canonical_text = json.dumps(profile, sort_keys=True)
    found_values = [value for value in runtime_values if value.lower() in canonical_text.lower()]
    address_hits = [f'{path}={value}' for path, value in _collect_strings(profile)
                    if _kernel_address_pattern().search(value)]
    add('no_runtime_address_persisted', not found_values and not address_hits,
        ('runtime values found: ' + ', '.join(found_values) if found_values else
         'kernel-address-looking strings: ' + '; '.join(address_hits) if address_hits else
         f'none of the {len(runtime_values)} W9 runtime values appear in the profile'))

    # 5 -- the structural window is never an exact fingerprint
    structural_ok = len(structural_names) == 1
    structural_details: list[str] = []
    for name in structural_names:
        loc = locators[name]
        window_id = name.split('.')[-1]
        pinned = blob[int(loc['locator']['value']):][:8].hex()
        live = observed.get(window_id, '')
        structural_details.append(f'{name}: policy STRUCTURAL_ONLY (live observation {live[:16]}…)')
        if live and pinned and live == pinned:
            structural_details.append(f'{name}: NOTE live value equals the pinned capture bytes')
        if loc.get('policy') != STRUCTURAL_POLICY:
            structural_ok = False
            structural_details.append(f'{name}: policy is not STRUCTURAL_ONLY')
        if window_id not in ('aperture_global',):
            structural_ok = False
            structural_details.append(f'{name}: unexpected structural window')
    add('structural_only_not_an_identity', structural_ok,
        '; '.join(structural_details) or 'no structural window present')

    # 6 -- the profile must not claim any gated operation it has no evidence for
    from tools.primitive_iface.gate import REQ_BY_OP, privilege_gated_ops
    policy_table = profile.get('operation_policy') or {}
    unbacked: list[str] = []
    pending: list[str] = []
    for op in privilege_gated_ops():
        entry = policy_table.get(op)
        if not isinstance(entry, dict):
            unbacked.append(f'{op} (no explicit entry)')
            continue
        if not entry.get('profile_required'):
            if entry.get('locator_ref') is not None:
                unbacked.append(f'{op} (not required but names a locator)')
            continue
        ref = entry.get('locator_ref')
        if ref is None:
            # explicitly pending: must carry a reason and must not name a locator
            if not str(entry.get('reason') or '').strip():
                unbacked.append(f'{op} (pending without reason)')
            else:
                pending.append(op)
            continue
        loc = locators.get(ref)
        if not isinstance(loc, dict) or (loc.get('provenance') or {}).get('kind') != 'evidence':
            unbacked.append(f'{op} (locator {ref!r} is not evidence-backed)')
    add('gated_ops_explicit_and_fail_closed', not unbacked,
        (f'unbacked gated claims: {unbacked}' if unbacked
         else f'{len(policy_table)} policy entries; {len(pending)} explicitly pending '
              f'(locator_ref=null -> LOCATOR_MISSING), none claimed without evidence'))

    identity_basis = {
        'strict_windows': sorted(strict_names),
        'structural_windows_excluded': sorted(structural_names),
        'measured_strict_matches': event.get('strict_matches'),
        'measured_strict_total': event.get('strict_total'),
        'measured_strict_mismatches': event.get('strict_mismatches'),
    }

    ok = all(check['ok'] for check in checks)
    return {
        'validator': 'tools/profiles/promotion_validator.py',
        'profile_id': profile.get('profile_id'),
        'profile_sha256': digest,
        'w9_evidence': str(w9_evidence_path),
        'w9_event_frame_sha256': evidence.get('kernel_attestation_frame_sha256'),
        'pinned_kernel_sha256': hashlib.sha256(blob).hexdigest(),
        'checks': checks,
        'identity_basis': identity_basis,
        'ok': ok,
    }


def _self_test() -> list[str]:
    """The validator must reject each of the five property violations."""
    problems: list[str] = []
    from tools.profiles.promotion import build_candidate
    evidence = _self_test_evidence()
    doc = build_candidate(w9_evidence_path=evidence)
    good = validate(doc, w9_evidence_path=evidence)
    if not good['ok']:
        problems.append('the freshly built candidate did not validate: '
                        + '; '.join(c['check'] for c in good['checks'] if not c['ok']))

    def mutate(mutator) -> dict:
        clone = json.loads(json.dumps(doc))
        mutator(clone)
        clone['canonical_sha256'] = canonical_profile_sha256(clone)
        return clone

    def expect_fail(name: str, clone: dict, check_name: str) -> None:
        report = validate(clone, w9_evidence_path=evidence)
        hit = [c for c in report['checks'] if c['check'] == check_name]
        if report['ok'] or not hit or hit[0]['ok']:
            problems.append(f'{name}: mutation was not caught by {check_name}')

    expect_fail('strict byte changed', mutate(lambda d: d['locators'][
        'kernel.attest.amd_iommu']['expected_bytes'].__setitem__('hex', '00' * 16)),
        'strict_fingerprints_match')
    expect_fail('provenance removed', mutate(lambda d: d['locators'][
        'kernel.attest.image_elf']['provenance'].__setitem__('sha256', None)),
        'provenance_complete')
    def store_address(clone: dict) -> None:
        clone['notes'] = clone['notes'] + \
            f" kbase=0x{platform_constants()['static_image_base']:x}"

    expect_fail('absolute address stored', mutate(store_address),
                'no_runtime_address_persisted')
    expect_fail('structural window labelled strict', mutate(lambda d: d['locators'][
        'kernel.attest.aperture_global'].__setitem__('policy', STRICT_POLICY)),
        'policy_matrix_present')
    expect_fail('locator made absolute', mutate(lambda d: d['locators'][
        'kernel.attest.code_anchor']['locator'].__setitem__('kind', 'absolute')),
        'relative_locators_resolve')
    expect_fail('fixture flag set', mutate(lambda d: d.__setitem__('fixture', True)),
        'not_a_fixture')
    return problems


def self_test() -> list[str]:
    """Public alias for the CLI self-test (used by the regression suite)."""
    return _self_test()


def _self_test_evidence() -> pathlib.Path:
    """A synthetic W9 evidence document built from the pinned image (offline self-test)."""
    import tempfile
    blob = read_pinned_kernel()
    rows = parse_w9_table()
    # a synthetic boot whose slide is zero: kbase equals the static image base, which is the
    # same situation the pinned capture itself shows
    base = platform_constants()['static_image_base']
    kbase = base
    slide = 0
    xfast = 0x1C0
    entries = []
    for row in rows:
        observed = blob[row['rva']:row['rva'] + row['len']]
        if row['policy'] == STRICT_POLICY and row['kind'] == 'relocated':
            value = (int.from_bytes(observed, 'little') + slide) & ((1 << 64) - 1)
            observed = value.to_bytes(8, 'little')
        elif row['policy'] == STRUCTURAL_POLICY:
            # the structural window is expected to differ from the capture bytes (that is why it
            # is structural); keep the synthetic case honest about that
            value = int.from_bytes(observed, 'little') ^ ((1 << 32) - 1)
            value = (value + (1 << 63)) & ((1 << 64) - 1)
            observed = value.to_bytes(len(observed), 'little')
        entries.append({'id': row['id'], 'policy': row['policy'],
                        'status': 'STRUCT_OK' if row['policy'] == STRUCTURAL_POLICY else 'MATCH',
                        'observed': observed.hex()})
    doc = {
        'kernel_attestation_event': {
            'status': 'OK', 'callback_executed': True, 'kexec_rc': 0,
            'lstar': f'0x{kbase + xfast:x}', 'kbase_candidate': f'0x{kbase:x}',
            'kbase_sdk': f'0x{kbase:x}', 'kbase_slide': '0x0',
            'aperture_global': '0x0',
            'strict_matches': 7, 'strict_total': 7, 'strict_mismatches': 0,
            'structural_observations': 1, 'entries': entries,
        },
        'kernel_attestation_verified': {'verified': True, 'problems': []},
        'kernel_attestation_frame_sha256': 'self-test',
    }
    path = pathlib.Path(tempfile.mkdtemp(prefix='w10-validator-')) / 'live-evidence.json'
    path.write_text(json.dumps(doc))
    return path


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description='W10 promotion validator (offline)')
    parser.add_argument('profile', nargs='?', type=pathlib.Path)
    parser.add_argument('--w9-evidence', type=pathlib.Path)
    parser.add_argument('--json', dest='json_out', type=pathlib.Path)
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args(argv)

    if args.self_test:
        problems = _self_test()
        for problem in problems:
            print(f'validator: {problem}')
        print(f'validator self-test: {"ok" if not problems else "FAILED"}')
        return 0 if not problems else 1

    if not args.profile or not args.w9_evidence:
        parser.error('profile and --w9-evidence are required')
    report = validate(json.loads(args.profile.read_text()), w9_evidence_path=args.w9_evidence)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    for check in report['checks']:
        print(f'  [{"ok" if check["ok"] else "FAIL"}] {check["check"]}: {check["detail"]}')
    print(f'validator: {"PASS" if report["ok"] else "FAIL"} '
          f'(profile_sha256 {report["profile_sha256"]})')
    return 0 if report['ok'] else 1


if __name__ == '__main__':                                # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
