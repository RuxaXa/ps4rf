"""Host-side verification of the W9 kernel attestation event.

The payload reports observed bytes; the host does not take the payload's word for the match
flags. It re-derives every comparison from its own copy of the expected table (the same
generated header the payload was built from) and reports expected / observed / match as three
separate columns. That is the independent check the W9 evidence needs, and it is the reason the
expected values must come from pinned evidence rather than from the payload.
"""

from __future__ import annotations

import pathlib
import re
from typing import Any

DEFAULT_TABLE = pathlib.Path(__file__).resolve().parents[2] / 'native/target/ps4rf_attest_data.h'
STATIC_BASE = 0xFFFFFFFFD00D0000


def parse_expected_table(path: str | pathlib.Path = DEFAULT_TABLE) -> list[dict[str, Any]]:
    """Parses the generated attestation table into (id, rva, len, kind, expected bytes)."""
    text = pathlib.Path(path).read_text()
    rows: list[dict[str, Any]] = []
    for match in re.finditer(r"\{\s*\{\s*('[^']*'(?:,\s*'[^']*')*)\s*\},\s*"
                             r"0x([0-9A-F]+)u,\s*(\d+)u,\s*PS4RF_ATTEST_KIND_(\w+),\s*"
                             r"PS4RF_ATTEST_POLICY_(\w+),\s*\{\s*([^}]*)\}\s*\}", text):
        chars, rva, length, kind, policy, raw = match.groups()
        name = ''.join(re.findall(r"'([^']*)'", chars))
        name = name.replace('\\0', '').replace('\0', '')   # drop the C terminator token
        values = bytes(int(v, 16) for v in re.findall(r'0x([0-9a-f]{2})', raw))
        rows.append({'id': name, 'rva': int(rva, 16), 'len': int(length),
                     'kind': kind.lower(),
                     'policy': policy.upper().replace('_ONLY', '_ONLY'),
                     'expected': values[:int(length)]})
    for row in rows:
        row['strict'] = row['policy'] == 'STRICT_FINGERPRINT'
    return rows


def _u64(data: bytes, offset: int = 0) -> int:
    return int.from_bytes(data[offset:offset + 8], 'little', signed=False)


def verify_attestation(attestation: dict[str, Any],
                       expected: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Recomputes every comparison from the host side. Returns a report with problems."""
    expected = expected if expected is not None else parse_expected_table()
    by_id = {row['id']: row for row in expected}
    problems: list[str] = []
    report: dict[str, Any] = {
        'event': attestation.get('event'),
        'status': attestation.get('status'),
        'cb_status': attestation.get('cb_status'),
        'kexec_rc': attestation.get('kexec_rc'),
        'expected_vs_observed': [],
        'problems': problems,
    }

    def _num(key: str) -> int | None:
        value = attestation.get(key)
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.startswith('0x'):
            try:
                return int(value, 16)
            except ValueError:
                return None
        return None

    lstar = _num('lstar')
    kbase = _num('kbase_candidate')
    kbase_sdk = _num('kbase_sdk')
    slide = _num('kbase_slide')
    report['lstar'] = lstar
    report['kbase_candidate'] = kbase
    report['kbase_sdk'] = kbase_sdk
    report['kbase_slide'] = slide

    if lstar is None or kbase is None:
        problems.append('lstar/kbase_candidate missing or malformed')
    else:
        if lstar < 0xFFFF800000000000:
            problems.append(f'lstar {lstar:#x} is not a canonical kernel pointer')
        if (lstar & 0xFFF) != 0x1C0:
            problems.append(f'lstar page offset {lstar & 0xFFF:#x} != 0x1c0 (xfast syscall)')
        if kbase != lstar - 0x1C0:
            problems.append(f'kbase_candidate {kbase:#x} != lstar - 0x1c0')
        if kbase_sdk is not None and kbase_sdk != kbase:
            problems.append(f'SDK base cross-check mismatch: payload {kbase:#x} '
                            f'vs get_kernel_base() {kbase_sdk:#x}')
        expected_slide = (kbase - STATIC_BASE) & 0xFFFFFFFFFFFFFFFF
        if slide is not None and slide != expected_slide:
            problems.append(f'slide {slide:#x} != kbase - 0x{STATIC_BASE:x} '
                            f'(expected {expected_slide:#x})')

    strict_total = sum(1 for row in expected if row['strict'])
    strict_rows: list[dict[str, Any]] = []
    structural_rows: list[dict[str, Any]] = []
    entries = attestation.get('entries')
    seen: list[str] = []
    if not isinstance(entries, list) or not entries:
        problems.append('entries missing')
        entries = []
    for entry in entries:
        if not isinstance(entry, dict):
            problems.append('entry is not an object')
            continue
        entry_id = entry.get('id')
        seen.append(entry_id if isinstance(entry_id, str) else '?')
        row = by_id.get(entry_id)
        if row is None:
            problems.append(f'entry {entry_id!r} is not in the expected table')
            continue
        raw = entry.get('observed')
        if not isinstance(raw, str) or len(raw) % 2 != 0:
            problems.append(f'entry {entry_id}: observed bytes malformed')
            continue
        observed = bytes.fromhex(raw)
        if len(observed) != row['len']:
            problems.append(f'entry {entry_id}: observed {len(observed)} bytes, '
                            f'expected {row["len"]}')
        claimed = entry.get('status')
        record = {
            'id': entry_id,
            'rva': f'0x{row["rva"]:x}',
            'kind': row['kind'],
            'policy': row['policy'],
            'expected': row['expected'].hex(),
            'expected_source': 'kernel.bin (pinned FW13.52 image)',
            'observed': observed.hex(),
            'payload_status': claimed,
        }
        if not row['strict']:
            # STRUCTURAL_ONLY: an observation. Never scored, never a failure by itself, and the
            # payload must not present it as an exact fingerprint match.
            value = _u64(observed)
            in_range = value >= 0xFFFF800000000000 and (value & 0xF) == 0
            record['observation'] = 'STRUCT_OK' if in_range else 'STRUCT_BAD'
            record['counts_towards_strict_score'] = False
            record['exact_match_claim'] = False
            if entry.get('exact_match_claim') is not False:
                problems.append(f'entry {entry_id}: STRUCTURAL_ONLY window presented as an '
                                f'exact match')
            structural_rows.append(record)
            continue
        if row['kind'] == 'relocated':
            want = bytes(((int.from_bytes(row['expected'], 'little') +
                           (slide or 0)) & 0xFFFFFFFFFFFFFFFF).to_bytes(8, 'little'))
            recomputed = 'MATCH' if observed == want else 'MISMATCH'
        else:
            recomputed = 'MATCH' if observed == row['expected'] else 'MISMATCH'
        record['strict_result'] = recomputed
        record['counts_towards_strict_score'] = True
        if claimed != recomputed:
            problems.append(f'entry {entry_id}: payload says {claimed!r}, '
                            f'host recomputes {recomputed!r}')
        strict_rows.append(record)

    strict_matches = sum(1 for row in strict_rows if row['strict_result'] == 'MATCH')
    strict_mismatches = sum(1 for row in strict_rows if row['strict_result'] == 'MISMATCH')
    report['expected_vs_observed'] = strict_rows + structural_rows
    report['strict_rows'] = strict_rows
    report['structural_results'] = structural_rows
    report['strict_matches'] = f'{strict_matches}/{strict_total}'
    report['strict_matches_count'] = strict_matches
    report['strict_total'] = strict_total
    report['strict_mismatches'] = strict_mismatches
    report['structural_observations'] = len(structural_rows)

    missing = [row['id'] for row in expected if row['id'] not in seen]
    if missing:
        problems.append(f'entries not reported by the payload: {missing}')
    if len(strict_rows) != strict_total:
        problems.append(f'strict windows reported: {len(strict_rows)} of {strict_total}')
    report['entry_count_report'] = attestation.get('entry_count')
    report['read_count'] = attestation.get('read_count')
    if attestation.get('strict_matches') is not None and \
            attestation['strict_matches'] != strict_matches:
        problems.append(f'payload strict_matches {attestation.get("strict_matches")} != host '
                        f'recomputed {strict_matches}')
    if attestation.get('strict_mismatches') is not None and \
            attestation['strict_mismatches'] != strict_mismatches:
        problems.append(f'payload strict_mismatches {attestation.get("strict_mismatches")} != '
                        f'host recomputed {strict_mismatches}')
    if attestation.get('structural_observations') is not None and \
            attestation['structural_observations'] != len(structural_rows):
        problems.append(f'payload structural_observations '
                        f'{attestation.get("structural_observations")} != '
                        f'host recomputed {len(structural_rows)}')
    if strict_mismatches:
        problems.append(f'{strict_mismatches} STRICT_FINGERPRINT window(s) mismatch: '
                        + ', '.join(row['id'] for row in strict_rows
                                    if row['strict_result'] == 'MISMATCH'))
    if isinstance(attestation.get('read_count'), int) and \
            attestation['read_count'] != len(entries):
        problems.append('read_count does not equal the number of reported entries')
    report['callback_executed'] = bool(attestation.get('callback_executed'))
    if not report['callback_executed']:
        problems.insert(0, 'the payload reports that the callback did not run '
                           f"(kexec_rc={attestation.get('kexec_rc')!r}); no measurement exists")
    # Allowed to support a PROFILE_MATCH_CANDIDATE decision: the STRICT_FINGERPRINT windows plus
    # the LSTAR/kbase shape and cross checks. STRUCTURAL_ONLY observations are excluded by
    # construction, and a structural anomaly is recorded without becoming a failure.
    report['profile_evidence_basis'] = {
        'strict_fingerprints': report['strict_matches'],
        'strict_mismatches': report['strict_mismatches'],
        # the shape itself, measured from the event values (not from the problem list): the
        # positional checks above are the same three conditions
        'lstar_shape_ok': bool(lstar is not None and kbase is not None
                               and lstar >= 0xFFFF800000000000
                               and (lstar & 0xFFF) == 0x1C0
                               and kbase == lstar - 0x1C0),
        'kbase_cross_check': 'MATCH' if (kbase is not None and kbase == kbase_sdk) else 'MISMATCH',
        'structural_only_excluded': [row['id'] for row in structural_rows],
    }
    report['verified'] = not problems
    return report
