"""W10 -- promotion of the real FW13.52 profile from W9 evidence (offline, deterministic).

The promotion is a *new artefact*: the W5 fixture stays untouched, the candidate is built from
evidence only, and an independent validator (:mod:`tools.profiles.promotion_validator`) has to
pass before the result is treated as the real profile.

Inputs (all local, all pinned):

* the pinned FW13.52 kernel image (``kernel.bin``, sha256 in :data:`PINNED_KERNEL_SHA256`) --
  source of every expected byte string and of the window classification (program headers)
* the W9 live evidence (``live-evidence.json``) -- the measured attestation event, whose strict
  windows matched the pinned image byte for byte
* the audit README of the capture dossier -- source of the console identity facts
  (``PS4 Slim CUH-2116A``, model string tail ``B01Y``)

Nothing else is used. No runtime address (LSTAR, kbase, slide, aperture) enters the profile.

Usage::

    python tools/profiles/promotion.py --self-test
    python tools/profiles/promotion.py --write profiles/fw1352/profile-13.52.json \\
        --w9-evidence <live-evidence.json>
    python tools/profiles/promotion.py --check profiles/fw1352/profile-13.52.json \\
        --w9-evidence <live-evidence.json>
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import struct
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:                       # pragma: no cover - import bootstrap
    sys.path.insert(0, str(REPO_ROOT))

from tools.primitive_iface.gate import REQ_BY_OP, privilege_gated_ops  # noqa: E402
from tools.profiles.schema import (  # noqa: E402  # used by the scope check and the validator

    SCHEMA_ID, STRICT_POLICY, STRUCTURAL_POLICY, canonical_profile_sha256, validate_profile,
)

PINNED_KERNEL = pathlib.Path.home() / (
    'audits/playstation-ps4/fw1352-ps4b-20260920/kernel-dump/kernel.bin')
PINNED_KERNEL_SHA256 = 'cf157ffdbae872a20bbb9a46c8518b53d96c1ed75d4e73878466a295d92eca35'
AUDIT_README = pathlib.Path.home() / (
    'audits/playstation-ps4/fw1352-ps4b-20260920/README.md')
W9_TABLE = REPO_ROOT / 'native/target/ps4rf_attest_data.h'

#: identity facts taken from the capture dossier (evidence, not guesses). The kernel image
#: identity is content-derived: it is what the seven STRICT_FINGERPRINT windows prove.
CONSOLE_MODEL_FAMILY = 'PS4 Slim CUH-2116A'
CONSOLE_HARDWARE_REVISION = 'B01Y'
FIRMWARE_FAMILY = '13.52'
PROFILE_ID = 'fw1352-real-13.52'
PROFILE_VERSION = 1
LOCATOR_PREFIX = 'kernel.attest.'

SIGNATURE_SOURCE = ('kernel.bin (pinned FW13.52 image) + W9 live attestation (byte-exact match)')


class PromotionError(Exception):
    """The promotion cannot be performed with the given evidence (fail closed)."""


# --- inputs ---------------------------------------------------------------------------

def sha256_file(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_pinned_kernel(path: pathlib.Path | None = None) -> bytes:
    path = path or PINNED_KERNEL
    if not path.exists():
        raise PromotionError(f'pinned kernel image not found: {path}')
    digest = sha256_file(path)
    if digest != PINNED_KERNEL_SHA256:
        raise PromotionError(f'pinned kernel image hash {digest} != {PINNED_KERNEL_SHA256}')
    return path.read_bytes()


def parse_w9_table(path: pathlib.Path | None = None) -> list[dict]:
    """Independent parse of the generated W9 table (id, rva, len, kind, policy)."""
    text = (path or W9_TABLE).read_text()
    rows: list[dict] = []
    pattern = (r"\{\s*\{\s*('(?:[^']*)'(?:,\s*'[^']*')*)\s*\},\s*0x([0-9A-Fa-f]+)u,\s*(\d+)u,\s*"
               r"PS4RF_ATTEST_KIND_(\w+),\s*PS4RF_ATTEST_POLICY_(\w+),")
    for match in re.finditer(pattern, text):
        chars, rva, length, kind, policy = match.groups()
        name = ''.join(re.findall(r"'([^']*)'", chars)).replace('\\0', '')
        rows.append({'id': name, 'rva': int(rva, 16), 'len': int(length),
                     'kind': kind.lower(),
                     'policy': 'STRICT_FINGERPRINT' if policy == 'STRICT_FINGERPRINT'
                               else 'STRUCTURAL_ONLY'})
    if len(rows) != 8:
        raise PromotionError(f'expected 8 attestation windows, parsed {len(rows)}')
    strict = [row for row in rows if row['policy'] == STRICT_POLICY]
    structural = [row for row in rows if row['policy'] == STRUCTURAL_POLICY]
    if len(strict) != 7 or [row['id'] for row in structural] != ['aperture_global']:
        raise PromotionError(f'window policy not as agreed: {len(strict)} strict, '
                             f'structural {[r["id"] for r in structural]}')
    return rows


def load_w9_evidence(path: pathlib.Path) -> dict:
    if not path.exists():
        raise PromotionError(f'W9 live evidence not found: {path}')
    doc = json.loads(path.read_text())
    event = doc.get('kernel_attestation_event') or {}
    verified = doc.get('kernel_attestation_verified') or {}
    if not event.get('callback_executed'):
        raise PromotionError('the W9 evidence does not show an executed callback')
    if not verified.get('verified'):
        raise PromotionError('the W9 evidence was not verified host side')
    if event.get('strict_matches') != 7 or event.get('strict_mismatches') != 0:
        raise PromotionError('the W9 evidence does not show 7/7 strict matches')
    return doc


BOOT_IDENTITY_FILE = REPO_ROOT / 'profiles/fw1352/boot-identity.json'


def platform_constants() -> dict:
    """Address-bearing platform constants live in the boot identity artefact, with provenance."""
    if not BOOT_IDENTITY_FILE.exists():
        raise PromotionError(f'boot identity artefact not found: {BOOT_IDENTITY_FILE}')
    doc = json.loads(BOOT_IDENTITY_FILE.read_text())
    constants = doc.get('platform_constants') or {}
    base = constants.get('static_image_base')
    if not isinstance(base, str):
        raise PromotionError('boot identity artefact carries no static image base')
    return {'static_image_base': int(base, 16),
            'boottime_rva': (_candidate_rva(doc, 'kern.boottime.kernel_variable')),
            'provenance': constants.get('provenance')}


def _candidate_rva(doc: dict, candidate_id: str) -> int:
    for candidate in doc.get('boot_instance_candidates') or []:
        if candidate.get('id') == candidate_id and isinstance(candidate.get('rva'), str):
            return int(candidate['rva'], 16)
    raise PromotionError(f'boot identity artefact has no RVA for {candidate_id}')


def slide_from_evidence(evidence: dict) -> int:
    """KASLR slide, derived from the measured kbase candidate (not from a claimed field)."""
    event = evidence.get('kernel_attestation_event') or {}
    kbase = event.get('kbase_candidate')
    if not isinstance(kbase, str):
        raise PromotionError('the W9 evidence carries no kbase candidate')
    try:
        value = int(kbase, 16)
    except ValueError as exc:
        raise PromotionError(f'kbase candidate {kbase!r} is not hexadecimal') from exc
    if not (1 << 63) < value < (1 << 64):
        raise PromotionError(f'kbase candidate {kbase!r} is not a canonical kernel pointer')
    slide = (value - platform_constants()['static_image_base']) & ((1 << 64) - 1)
    claimed = event.get('kbase_slide')
    if isinstance(claimed, str) and claimed.startswith('0x'):
        if int(claimed, 16) != slide:
            raise PromotionError(f'claimed slide {claimed} != derived {slide:#x}')
    return slide


def observed_windows(evidence: dict) -> dict[str, str]:
    """window id -> observed bytes (hex) as measured on the live console."""
    out: dict[str, str] = {}
    for entry in (evidence.get('kernel_attestation_event') or {}).get('entries') or []:
        if isinstance(entry, dict) and isinstance(entry.get('id'), str) \
                and isinstance(entry.get('observed'), str):
            out[entry['id']] = entry['observed']
    return out


# --- classification --------------------------------------------------------------------

def program_segments(blob: bytes) -> list[dict]:
    if blob[:4] != b'\x7fELF':
        raise PromotionError('the pinned image is not an ELF')
    phoff = struct.unpack_from('<Q', blob, 32)[0]
    phentsize, phnum = struct.unpack_from('<HH', blob, 54)
    segments: list[dict] = []
    for index in range(phnum):
        off = phoff + index * phentsize
        p_type, p_flags = struct.unpack_from('<II', blob, off)
        p_offset, p_vaddr, _p_paddr, p_filesz = struct.unpack_from('<QQQQ', blob, off + 8)[0:4]
        if p_type != 1:                                   # PT_LOAD only
            continue
        segments.append({
            'offset': p_offset, 'filesz': p_filesz, 'flags': p_flags, 'vaddr': p_vaddr,
            'permissions': ('r' if p_flags & 4 else '-') + ('w' if p_flags & 2 else '-') +
                           ('x' if p_flags & 1 else '-'),
        })
    if not segments:
        raise PromotionError('the pinned image has no PT_LOAD segments')
    return segments


def classify_window(rva: int, length: int, segments: list[dict]) -> tuple[str, str]:
    """(section, permissions) for a window, derived from the pinned image's program headers."""
    for segment in segments:
        if segment['offset'] <= rva and rva + length <= segment['offset'] + segment['filesz']:
            section = 'text' if segment['permissions'].endswith('x') else (
                'data' if 'w' in segment['permissions'] else 'rodata')
            return section, segment['permissions']
    # outside every loadable segment: the capture holds dump-area bytes there, not loaded image
    return 'outside-loaded-image', 'r--'


# --- candidate -------------------------------------------------------------------------

def build_candidate(*, kernel_path: pathlib.Path | None = None,
                    w9_evidence_path: pathlib.Path,
                    table_path: pathlib.Path | None = None) -> dict:
    blob = read_pinned_kernel(kernel_path)
    kernel_sha = PINNED_KERNEL_SHA256
    segments = program_segments(blob)
    evidence = load_w9_evidence(w9_evidence_path)
    observed = observed_windows(evidence)
    rows = parse_w9_table(table_path)
    slide = slide_from_evidence(evidence)

    if not observed:
        raise PromotionError('the W9 evidence carries no per-entry observations')

    locators: dict[str, dict] = {}
    for row in rows:
        name = LOCATOR_PREFIX + row['id']
        rva, length = row['rva'], row['len']
        if rva + length > len(blob):
            raise PromotionError(f'{row["id"]}: RVA outside the pinned image')
        expected = blob[rva:rva + length]
        seen = observed.get(row['id'])
        if seen is None:
            raise PromotionError(f'{row["id"]}: not reported by the W9 evidence')
        live = bytes.fromhex(seen)
        # strict windows must agree with the pinned image: plain windows byte for byte,
        # relocated windows as the image value plus the (verified) KASLR slide
        if row['policy'] == STRICT_POLICY:
            if row['kind'] == 'relocated':
                want = ((int.from_bytes(expected, 'little') + slide) & ((1 << 64) - 1))
                if int.from_bytes(live, 'little') != want:
                    raise PromotionError(f'{row["id"]}: live pointer is not image value + slide')
            elif live != expected:
                raise PromotionError(f'{row["id"]}: live bytes differ from the pinned image')
        section, permissions = classify_window(rva, length, segments)
        locators[name] = {
            'module': 'kernel',
            'locator': {'kind': 'rva', 'value': rva},
            'section': section,
            'permissions': permissions,
            'expected_bytes': {'offset': 0, 'hex': expected.hex()},
            'provenance': {'kind': 'evidence', 'source': SIGNATURE_SOURCE,
                           'sha256': kernel_sha},
            'confidence': 'OBSERVED',
            'policy': row['policy'],
        }

    audit_sha = sha256_file(AUDIT_README) if AUDIT_README.exists() else None
    if audit_sha is None:
        raise PromotionError(f'audit README not found: {AUDIT_README}')

    target = {
        'platform': 'ORBIS',
        'model_family': CONSOLE_MODEL_FAMILY,
        'firmware_version': FIRMWARE_FAMILY,
        'firmware_build_id': f'kernel-sha256:{kernel_sha}',
        'architecture': 'x86-64',
        'hardware_revision': CONSOLE_HARDWARE_REVISION,
    }

    # SCOPE: this profile carries exactly what has evidence -- the kernel attestation windows.
    # The W5 schema forces every `profile_required` entry to name an existing locator, so a
    # profile that has no evidence for the gated operations must not claim them at all: the
    # W5 operation policy table stays EMPTY here. Nothing weakens because of that: the binding
    # authority for gated operations is the W4 requirement table (tools/primitive_iface/gate.py,
    # REQ_BY_OP), not the profile's own table, and the W4/W5/W7 reports in the W10 evidence show
    # the gated operations still refuse (no evidence-backed locator, no boot binding).
    # Every gated operation gets an explicit entry (the W5 schema refuses implicit defaults).
    # profile_required comes from the W4 matrix unchanged; locator_ref is None where this profile
    # has no evidence-backed locator yet, which fails closed as LOCATOR_MISSING instead of
    # claiming a value that does not exist.
    policy: dict = {}
    for op in privilege_gated_ops():
        req = REQ_BY_OP[op]
        ref = op if (req.profile_required and op in locators) else None
        policy[op] = {
            'profile_required': bool(req.profile_required),
            'locator_ref': ref,
            'profile_fields': list(req.profile_fields),
            'reason': ('profile-bound values required (W4 matrix); locator provided by this profile'
                       if ref else
                       ('profile-bound values required (W4 matrix); this profile carries no '
                        'evidence-backed locator for this operation yet (fail closed)'
                        if req.profile_required else 'profile_not_required (W4 matrix)')),
        }
    claimed = [op for op in privilege_gated_ops()
               if REQ_BY_OP[op].profile_required and op in locators]
    if claimed:
        raise PromotionError(f'gated operations claimed without evidence: {claimed}')

    doc = {
        'schema': SCHEMA_ID,
        'fixture': False,
        'profile_id': PROFILE_ID,
        'profile_version': PROFILE_VERSION,
        'target': target,
        'modules': {'kernel': {'image': 'kernel', 'locator_kind': 'rva'}},
        'locators': locators,
        'operation_policy': policy,
        'notes': (
            'Real FW13.52 profile promoted from W9 live attestation evidence (2026-10-05) plus the '
            'pinned FW13.52 research. Identity basis: seven STRICT_FINGERPRINT windows of the '
            'kernel image matched the live kernel byte for byte (host-verified), so the firmware '
            'family 13.52 is derived from kernel evidence and NOT from the userland '
            'kern.sdk_version value. No runtime address (LSTAR, kbase, KASLR slide, aperture '
            'value) is stored here: those live in runtime evidence and runtime bindings only. '
            'aperture_global is STRUCTURAL_ONLY by agreement and is never part of the identity. '
            f'Console identity from the capture dossier ({AUDIT_README}, sha256 {audit_sha}). '
            'SCOPE: this profile evidences the kernel attestation windows only. Gated '
            'operations whose locator is not evidenced here carry profile_required=true with '
            'locator_ref=null (explicitly pending) and refuse with LOCATOR_MISSING; the binding '
            'authority for them stays the W4 requirement table, and no boot binding exists yet '
            'either, so privileged providers remain deferred.'
        ),
    }
    doc['canonical_sha256'] = canonical_profile_sha256(doc)
    return doc


def check_candidate(doc: dict) -> list[str]:
    problems = validate_profile(doc)
    declared = doc.get('canonical_sha256')
    if declared is not None and declared != canonical_profile_sha256(doc):
        problems.append('canonical_sha256 does not match the canonical content')
    return problems


def _self_test() -> list[str]:
    problems: list[str] = []
    rows = {row['id']: row for row in parse_w9_table()}
    if len(rows) != 8:
        problems.append('table parse failed')
    segments = program_segments(read_pinned_kernel())

    def classify(window_id: str) -> tuple[str, str]:
        row = rows[window_id]
        return classify_window(row['rva'], row['len'], segments)

    if classify('amd_iommu') != ('text', 'r-x'):
        problems.append(f'amd_iommu should sit in text/r-x, got {classify("amd_iommu")}')
    if classify('prison0_static') != ('data', 'rw-'):
        problems.append(f'prison0_static should sit in data/rw-, got {classify("prison0_static")}')
    if classify('aperture_global')[0] != 'outside-loaded-image':
        problems.append('aperture_global should be outside the loaded image, got '
                        f'{classify("aperture_global")}')
    constants = platform_constants()
    if not (1 << 63) < constants['static_image_base'] < (1 << 64):
        problems.append('static image base from the artefact is not a kernel pointer')
    return problems


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description='W10 profile promotion (offline)')
    parser.add_argument('--w9-evidence', type=pathlib.Path,
                        help='W9 live-evidence.json of the accepted run')
    parser.add_argument('--write', type=pathlib.Path)
    parser.add_argument('--check', type=pathlib.Path)
    parser.add_argument('--show-hash', action='store_true')
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args(argv)

    if args.self_test:
        problems = _self_test()
        for problem in problems:
            print(f'promotion: {problem}')
        print(f'promotion self-test: {"ok" if not problems else "FAILED"}')
        return 0 if not problems else 1

    if args.check:
        doc = json.loads(args.check.read_text())
        problems = check_candidate(doc)
        for problem in problems:
            print(f'promotion check: {problem}')
        print(f'promotion check: {"ok" if not problems else "FAILED"} '
              f'({args.check}, sha256 {canonical_profile_sha256(doc)})')
        return 0 if not problems else 1

    if not args.w9_evidence:
        parser.error('--w9-evidence is required for --write/--show-hash')
    doc = build_candidate(w9_evidence_path=args.w9_evidence)
    if args.write:
        args.write.parent.mkdir(parents=True, exist_ok=True)
        args.write.write_text(json.dumps(doc, indent=2, sort_keys=True) + '\n')
        print(f'wrote {args.write} (profile_sha256 {doc["canonical_sha256"]})')
    if args.show_hash or not args.write:
        print(json.dumps({'profile_id': doc['profile_id'],
                          'profile_sha256': doc['canonical_sha256'],
                          'locators': sorted(doc['locators']),
                          'target': doc['target']}, indent=1))
    return 0


def self_test() -> list[str]:
    """Public alias for the CLI self-test (used by the regression suite)."""
    return _self_test()


if __name__ == '__main__':                                # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
