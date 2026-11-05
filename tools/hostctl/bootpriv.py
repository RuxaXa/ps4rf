"""PS4RF W11.2 -- host-side verification of the sealed privileged boot read event.

The payload reports one measured thing: the 16 raw bytes at its fixed compile-time source
(``kbase + 0x224C6C8``) plus the numbers it observed while getting there. Everything a reviewer
would otherwise have to trust is re-derived here from those raw values:

* the shape of ``lstar`` and the base candidate (host: ``lstar - 0x1C0``),
* the source RVA and the read length (must be the frozen ``0x224C6C8`` / 16),
* the hash of the raw bytes (recomputed host side, never taken from the payload),
* the ``struct timeval`` decode (host decodes the same 16 bytes itself),
* the plausibility rules (tv_sec > 0, 0 <= tv_usec < 1_000_000, boot instant not in the future),
* the canonical boot binding object, its full SHA-256 digest and the public boot id.

The payload never forms a boot id (``boot_id_claim`` is checked to be ``NONE``), the host forms it
independently and only when every check above passed -- otherwise the report is fail closed and
carries no boot id at all.

The W10 capture value (sec 1789910256, usec 860896) is compared for context only: it is historical
comparison evidence from a different boot, never an expectation for the live run.
"""

from __future__ import annotations

import hashlib
import json

from tools.profiles import bootid

EVENT_NAME = 'boot.binding.privileged'
EVENT_SCHEMA = 'ps4rf.boot.binding.privileged.v1'

SOURCE_RVA = 0x224C6C8          # pinned FW13.52 KERN_BOOTTIME (W10 evidence)
# "the payload never got to measure this" -- accepted only where the contract allows it
UNMEASURED = ('UNMEASURED', None)
XFAST_RVA = 0x1C0               # SDK K1352_XFAST_SYSCALL: the syscall entry page offset
KERNEL_MIN = 0xFFFF800000000000
READ_LEN = 16
MAX_USEC = 999_999

W10_CAPTURE = {'sec': 1789910256, 'usec': 860896}

REQUIRED_FIELDS = (
    'msg', 'event', 'schema', 'status', 'run_status', 'run_status_name', 'callback_executed',
    'cb_status', 'cb_status_name', 'kexec_rc', 'lstar', 'kbase_candidate', 'kbase_sdk',
    'cross_check', 'source_rva', 'read_length', 'raw_hex', 'tv_sec', 'tv_usec', 'wall_clock_sec',
    'validation', 'kernel_timeval_bytes', 'single_callback', 'retry', 'writes_to_kernel',
    'host_supplied_address', 'generic_read_primitive', 'boot_id_claim', 'build_id', 'label',
)  # note: the payload's no-write claim is the key 'writes_to_kernel'

# claims the payload must make for a privileged read-only single-shot operation
EXPECTED_CLAIMS = {
    'single_callback': True,
    'retry': False,
    'writes_to_kernel': False,
    'host_supplied_address': False,
    'boot_id_claim': 'NONE',
}

VALIDATION_REASONS = ('OK', 'NOT_READ', 'TV_SEC_NONPOSITIVE', 'TV_USEC_NEGATIVE',
                      'TV_USEC_OUT_OF_RANGE', 'BOOT_TIME_AFTER_WALL_CLOCK')


class BootPrivError(Exception):
    """Raised when the event body cannot even be read as the mandated contract."""


def _int(value, where: str, problems: list[str]) -> int | None:
    if isinstance(value, bool) or value is None:
        problems.append(f'{where}: missing or not a number ({value!r})')
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        try:
            if text.lower().startswith('0x'):
                return int(text, 16)
            return int(text, 10)
        except ValueError:
            problems.append(f'{where}: not a decimal or hex number ({value!r})')
            return None
    problems.append(f'{where}: not a number ({value!r})')
    return None


def decode_timeval(raw: bytes) -> tuple[int, int]:
    """Decode the pinned kernel layout: int64 tv_sec at +0, int64 tv_usec at +8, little endian."""
    if len(raw) != READ_LEN:
        raise BootPrivError(f'expected exactly {READ_LEN} raw bytes, got {len(raw)}')
    sec = int.from_bytes(raw[0:8], 'little', signed=True)
    usec = int.from_bytes(raw[8:16], 'little', signed=True)
    return sec, usec


def validate_timeval(sec: int | None, usec: int | None, wall_clock: int | None) -> str:
    """The refusal rules, re-derived host side from the decoded numbers."""
    if sec is None or usec is None:
        return 'NOT_READ'
    if sec <= 0:
        return 'TV_SEC_NONPOSITIVE'
    if usec < 0:
        return 'TV_USEC_NEGATIVE'
    if usec >= MAX_USEC + 1:
        return 'TV_USEC_OUT_OF_RANGE'
    if wall_clock and sec > wall_clock:
        return 'BOOT_TIME_AFTER_WALL_CLOCK'
    return 'OK'


def lstar_shape_ok(lstar: int | None) -> bool:
    if lstar is None:
        return False
    if lstar < KERNEL_MIN:
        return False
    return (lstar & 0xFFF) == XFAST_RVA


def verify_privileged_event(event: dict | None, *, profile: dict, profile_sha256: str,
                            host_wall_clock: int | None = None,
                            w10_capture: dict | None = W10_CAPTURE) -> dict:
    """Verify one ``boot.binding.privileged`` event; return a fail-closed report.

    The report always carries ``verified`` and ``problems``; ``binding``, ``full_digest``,
    ``boot_id`` and ``binding_view`` appear only when every check passed.
    """
    problems: list[str] = []
    report: dict = {
        'event_name': None, 'schema': None, 'verified': False, 'problems': problems,
        'boot_id_claim': None, 'payload_claimed_boot_id': None, 'callback': {}, 'kbase': {},
        'source': {}, 'timeval': {}, 'no_boot_id': True, 'labels': [],
        'w10_capture': dict(w10_capture) if w10_capture else None,
    }

    if not isinstance(event, dict):
        problems.append(f'no event body: {event!r}')
        return report

    report['event_name'] = event.get('event')
    report['schema'] = event.get('schema')
    report['labels'] = [value for value in (event.get('label'),) if isinstance(value, str)]

    missing = [field for field in REQUIRED_FIELDS if field not in event]
    if missing:
        problems.append(f'missing mandated fields: {sorted(missing)}')
    if event.get('event') != EVENT_NAME:
        problems.append(f"event name {event.get('event')!r} != {EVENT_NAME!r}")
    if event.get('schema') != EVENT_SCHEMA:
        problems.append(f"schema {event.get('schema')!r} != {EVENT_SCHEMA!r}")
    if event.get('msg') != 'EVENT':
        problems.append(f"msg {event.get('msg')!r} != 'EVENT'")

    for field, expected in EXPECTED_CLAIMS.items():
        if event.get(field) != expected:
            problems.append(f'claim {field}={event.get(field)!r}, mandate requires {expected!r}')
    report['boot_id_claim'] = event.get('boot_id_claim')
    report['payload_claimed_boot_id'] = bool(event.get('boot_id')) or (
        isinstance(event.get('boot_id_claim'), str) and event['boot_id_claim'] not in ('NONE', ''))

    # --- contract checks ----------------------------------------------------------------------
    # These are not about whether the read succeeded: they are about whether the reported numbers
    # are internally consistent and inside the frozen contract. A violation means the event cannot
    # be trusted at all, so the report stays fail closed (verified False, no boot id).
    violations: list[str] = []

    executed = event.get('callback_executed') is True
    kexec_rc = _int(event.get('kexec_rc'), 'kexec_rc', violations)
    cb_status = _int(event.get('cb_status'), 'cb_status', violations)
    cb_status_name = event.get('cb_status_name')
    if not isinstance(cb_status_name, str) or not cb_status_name:
        violations.append(f'cb_status_name {cb_status_name!r} is not a status string')

    lstar = _int(event.get('lstar'), 'lstar', violations)
    kbase_candidate = _int(event.get('kbase_candidate'), 'kbase_candidate', violations)
    kbase_sdk = _int(event.get('kbase_sdk'), 'kbase_sdk', violations)
    cross_check = event.get('cross_check')
    shape_ok = lstar_shape_ok(lstar)
    host_kbase = None if lstar is None else lstar - XFAST_RVA
    if shape_ok and host_kbase != kbase_candidate:
        violations.append(f'kbase candidate {kbase_candidate!r} != lstar - 0x1C0 ({host_kbase!r})')
    if cross_check not in ('MATCH', 'MISMATCH') + UNMEASURED:
        violations.append(f'cross_check {cross_check!r} is outside the contract')

    source_rva_raw = event.get('source_rva')
    source_rva = None
    if source_rva_raw in UNMEASURED:
        pass                                   # the callback stopped before it touched the region
    else:
        source_rva = _int(source_rva_raw, 'source_rva', violations)
    read_length = _int(event.get('read_length'), 'read_length', violations)
    if source_rva is not None and source_rva != SOURCE_RVA:
        violations.append(f'source rva {source_rva!r} != frozen {hex(SOURCE_RVA)}')
    if source_rva is None and read_length == READ_LEN:
        violations.append('a completed 16 byte read must name the frozen source rva')
    raw_hex = event.get('raw_hex')
    raw = b''
    if not isinstance(raw_hex, str) or len(raw_hex) % 2 != 0:
        violations.append(f'raw_hex is not an even-length hex string ({raw_hex!r})')
    else:
        try:
            raw = bytes.fromhex(raw_hex)
        except ValueError:
            violations.append(f'raw_hex is not valid hex ({raw_hex!r})')
    if read_length not in (0, READ_LEN):
        violations.append(f'read_length {read_length!r} is neither 0 nor {READ_LEN}')
    if read_length == READ_LEN and len(raw) != READ_LEN:
        violations.append(f'read_length says {READ_LEN} but {len(raw)} raw bytes were sent')
    if read_length == 0 and raw:
        violations.append(f'read_length says 0 but {len(raw)} raw bytes were sent')
    if read_length == READ_LEN and not shape_ok:
        violations.append('a 16 byte read is claimed although lstar fails the shape gate')
    if read_length == READ_LEN and cross_check != 'MATCH':
        violations.append('a 16 byte read is claimed although the cross check is not MATCH')
    if not executed and (read_length == READ_LEN or raw):
        violations.append('bytes are reported although the callback never executed')
    if not executed and cross_check not in UNMEASURED:
        violations.append(f'cross_check {cross_check!r} cannot be claimed without an executed '
                          'callback')
    if executed and cross_check == 'MATCH' and read_length != READ_LEN:
        violations.append('a matching cross check without the read it gates')
    if not executed and cb_status_name not in ('NOT_EXECUTED',):
        violations.append(f'cb_status_name {cb_status_name!r} claims a callback status although '
                          'the callback never executed')
    raw_sha256 = hashlib.sha256(raw).hexdigest()

    wall_clock = _int(event.get('wall_clock_sec'), 'wall_clock_sec', violations)
    sec = usec = None
    host_validation = 'NOT_READ'
    if read_length == READ_LEN and len(raw) == READ_LEN:
        sec, usec = decode_timeval(raw)
        host_validation = validate_timeval(sec, usec, wall_clock)
    payload_sec = _int(event.get('tv_sec'), 'tv_sec', violations)
    payload_usec = _int(event.get('tv_usec'), 'tv_usec', violations)
    payload_validation = event.get('validation')
    if payload_validation not in VALIDATION_REASONS:
        violations.append(f'validation status {payload_validation!r} is not a defined reason')
    if read_length == READ_LEN:
        if payload_sec != sec or payload_usec != usec:
            violations.append(f'payload claims ({payload_sec!r}, {payload_usec!r}) but the raw '
                              f'bytes decode to ({sec!r}, {usec!r})')
        if payload_validation != host_validation:
            violations.append(f'validation mismatch: host {host_validation!r} vs payload '
                              f'{payload_validation!r}')
    elif payload_validation != 'NOT_READ':
        violations.append(f'no complete read, yet validation is {payload_validation!r}')
    if event.get('kernel_timeval_bytes') != 16:
        violations.append(f"kernel_timeval_bytes {event.get('kernel_timeval_bytes')!r} != 16")

    # the run status must agree with what the host derives from the same numbers
    status_value = event.get('status')
    run_status = _int(event.get('run_status'), 'run_status', violations)
    if read_length == READ_LEN and host_validation == 'OK':
        if status_value != 'OK' or run_status != 0:
            violations.append(f'a valid timeval was reported as {status_value!r}/{run_status!r}')
    else:
        expected_run = 3 if host_validation == 'BOOT_TIME_AFTER_WALL_CLOCK' else 1
        if status_value != 'FAILED' or run_status != expected_run:
            violations.append(f'a refused read was reported as {status_value!r}/{run_status!r}, '
                              f'host classifies it as {host_validation!r} '
                              f'(run_status {expected_run})')

    report['callback'] = {
        'executed': executed, 'cb_status': cb_status, 'cb_status_name': cb_status_name,
        'kexec_rc': kexec_rc, 'shape_ok': shape_ok, 'cross_check_claim': cross_check,
        'host_kbase': host_kbase,
        'host_cross_check': ('MATCH' if (shape_ok and cross_check == 'MATCH' and
                                         kbase_sdk == kbase_candidate) else 'MISMATCH'),
    }
    report['kbase'] = {
        'lstar': lstar, 'lstar_shape_ok': shape_ok, 'host_kbase': host_kbase,
        'kbase_candidate': kbase_candidate, 'kbase_sdk': kbase_sdk,
        'cross_check_claim': cross_check,
        'candidate_matches_host': host_kbase is not None and host_kbase == kbase_candidate,
        'sdk_matches_candidate': kbase_sdk is not None and kbase_sdk == kbase_candidate,
    }
    report['source'] = {
        'source_rva': source_rva, 'rva_ok': source_rva == SOURCE_RVA, 'expected_rva': SOURCE_RVA,
        'read_length': read_length, 'read_length_ok': read_length == READ_LEN,
        'expected_read_length': READ_LEN, 'raw_len': len(raw), 'raw_hex': raw_hex,
        'raw_sha256': raw_sha256, 'host_recomputed': True,
    }
    report['timeval'] = {
        'sec': sec, 'usec': usec, 'payload_sec': payload_sec, 'payload_usec': payload_usec,
        'matches_payload': bool(read_length == READ_LEN and sec == payload_sec and
                                usec == payload_usec),
        'validation_host': host_validation, 'validation_payload': payload_validation,
        'validation_matches': host_validation == payload_validation,
        'wall_clock_sec': wall_clock, 'kernel_timeval_bytes': event.get('kernel_timeval_bytes'),
        'layout': event.get('timeval_layout'),
    }

    report['problems'].extend(violations)
    if report['problems']:
        report['outcome'] = 'CONTRACT_VIOLATION'
        return report

    # --- the outcome itself: a failed read is a valid, host-verified outcome (fail closed) -----
    if not executed:
        outcome = 'CALLBACK_NOT_EXECUTED'
    elif kexec_rc != 0:
        outcome = 'KEXEC_FAILED'
    elif not shape_ok:
        outcome = 'LSTAR_SHAPE_INVALID'
    elif cross_check != 'MATCH':
        outcome = 'KBASE_CROSS_CHECK_MISMATCH'
    elif read_length != READ_LEN:
        outcome = 'READ_INCOMPLETE'
    elif host_validation != 'OK':
        outcome = f'TIMEVAL_{host_validation}'
    else:
        outcome = 'OK'
    report['outcome'] = outcome
    report['verified'] = True
    report['no_boot_id'] = outcome != 'OK'
    if outcome != 'OK':
        report['stop_reason'] = event.get('run_status_name')
        return report

    # --- the boot identity: formed here and only here -----------------------------------------
    measured = bootid.BootTime(sec, usec)
    try:
        derived = bootid.derive_boot_id(profile_sha256, measured, profile=profile,
                                        console_now=wall_clock, host_now=host_wall_clock)
    except Exception as exc:                                   # bootid.BootIdError and friends
        report['problems'].append(f'host boot id derivation refused the measurement: {exc}')
        report['verified'] = False
        report['no_boot_id'] = True
        report['outcome'] = 'HOST_DERIVATION_REFUSED'
        return report

    report['no_boot_id'] = False
    report['binding'] = (derived.get('canonical_object') or
                         bootid.canonical_object(profile_sha256, measured))
    report['full_digest'] = derived.get('boot_digest')
    report['boot_id'] = derived['boot_id']
    report['binding_view'] = {
        'boot_id': derived['boot_id'], 'profile_sha256': profile_sha256,
        'source_event': EVENT_NAME, 'source_rva': SOURCE_RVA, 'read_length': READ_LEN,
        'raw_sha256': raw_sha256, 'valid_for_this_boot': True,
    }
    if w10_capture:
        report['w10_capture']['matches'] = (measured.sec == w10_capture.get('sec') and
                                            measured.usec == w10_capture.get('usec'))
        report['w10_capture']['note'] = ('historical comparison evidence only: the live run must '
                                         'measure its own boot instant, a different boot is '
                                         'expected to differ')
    return report


def verify_privileged_event_selftest() -> list[str]:
    """Deterministic self-test of the verification rules (no console, no payload involved).

    Two kinds of negative case are asserted separately, because they mean different things: a
    *contract violation* (the reported numbers lie or leave the contract) must leave the event
    untrusted, while a *failed read* must stay a valid, host-verified fail-closed outcome that
    carries no boot id.
    """
    problems: list[str] = []
    profile = {'platform': 'ORBIS', 'target': {'platform': 'ORBIS'}}
    sha = 'a' * 64
    sec, usec = 1789910256, 860896
    raw = sec.to_bytes(8, 'little', signed=True) + usec.to_bytes(8, 'little', signed=True)
    base = {
        'msg': 'EVENT', 'event': EVENT_NAME, 'schema': EVENT_SCHEMA, 'status': 'OK',
        'run_status': 0, 'run_status_name': 'OK', 'callback_executed': True, 'cb_status': 0,
        'cb_status_name': 'OK', 'kexec_rc': 0, 'lstar': hex(0xFFFFFFFF998F41C0),
        'kbase_candidate': hex(0xFFFFFFFF998F4000), 'kbase_sdk': hex(0xFFFFFFFF998F4000),
        'cross_check': 'MATCH', 'source_rva': hex(SOURCE_RVA), 'read_length': READ_LEN,
        'raw_hex': raw.hex(), 'tv_sec': str(sec), 'tv_usec': str(usec),
        'wall_clock_sec': str(sec + 30), 'validation': 'OK', 'kernel_timeval_bytes': 16,
        'single_callback': True, 'retry': False, 'writes_to_kernel': False,
        'host_supplied_address': False, 'generic_read_primitive': 'NONE', 'boot_id_claim': 'NONE',
        'build_id': 'f' * 32, 'label': 'ps4rfd-live-w112',
        'timeval_layout': 'int64 tv_sec at +0, int64 tv_usec at +8 (pinned FW13.52)',
    }

    def run(**changes) -> dict:
        body = dict(base)
        body.update(changes)
        return verify_privileged_event(body, profile=profile, profile_sha256=sha)

    good = run()
    if not good.get('verified') or good.get('outcome') != 'OK':
        problems.append(f'valid event rejected: {good.get("problems")}')
    elif not str(good.get('boot_id', '')).startswith('BOOT-'):
        problems.append('no boot id was formed for a valid measurement')
    elif good['timeval']['sec'] != sec or good['binding']['boottime']['sec'] != sec:
        problems.append('decoded timeval does not match the raw bytes')
    elif good['source']['read_length'] != READ_LEN or good['source']['rva_ok'] is not True:
        problems.append('source region was not verified as the frozen one')

    # --- failed reads: valid, verified, and without any boot id -------------------------------
    stopped = run(callback_executed=False, kexec_rc=-1, status='FAILED', run_status=1,
                  run_status_name='BOOT_READ_FAILED', read_length=0, raw_hex='', tv_sec='0',
                  tv_usec='0', validation='NOT_READ', lstar='0x0', kbase_candidate='0x0',
                  kbase_sdk='0x0', cross_check='UNMEASURED', source_rva='UNMEASURED',
                  cb_status_name='NOT_EXECUTED')
    if not stopped.get('verified') or not stopped.get('no_boot_id') or stopped.get('boot_id'):
        problems.append('the fail-closed non-executed path was not accepted as a valid outcome')
    elif stopped.get('outcome') != 'CALLBACK_NOT_EXECUTED':
        problems.append(f'wrong outcome for a non-executed callback: {stopped.get("outcome")!r}')

    shape = run(lstar=hex(0xFFFFFFFF998F4200), kbase_candidate='0x0', kbase_sdk='0x0',
                cross_check='UNMEASURED', source_rva='UNMEASURED', read_length=0, raw_hex='',
                tv_sec='0', tv_usec='0', validation='NOT_READ', status='FAILED', run_status=1,
                run_status_name='BOOT_READ_FAILED')
    if not shape.get('verified') or shape.get('outcome') != 'LSTAR_SHAPE_INVALID':
        problems.append(f'broken lstar shape not classified: {shape.get("outcome")!r} '
                        f'{shape.get("problems")}')

    cross = run(kbase_sdk=hex(0xFFFFFFFF998F5000), cross_check='MISMATCH', read_length=0,
                raw_hex='', tv_sec='0', tv_usec='0', validation='NOT_READ', status='FAILED',
                run_status=1, run_status_name='BOOT_READ_FAILED', source_rva=hex(SOURCE_RVA))
    if not cross.get('verified') or cross.get('outcome') != 'KBASE_CROSS_CHECK_MISMATCH':
        problems.append(f'cross-check mismatch not classified: {cross.get("outcome")!r} '
                        f'{cross.get("problems")}')

    # a matching cross check without the read it gates cannot be true: the payload reads as soon
    # as the check passes, so this combination is a contradiction, not an outcome
    contradictory = run(read_length=0, raw_hex='', tv_sec='0', tv_usec='0', validation='NOT_READ',
                        status='FAILED', run_status=1, run_status_name='BOOT_READ_FAILED',
                        source_rva=hex(SOURCE_RVA))
    if contradictory.get('verified') or contradictory.get('boot_id'):
        problems.append(f'a matching cross check without any bytes was accepted: '
                        f'{contradictory.get("problems")}')

    refused_raw = (0).to_bytes(8, 'little', signed=True) * 2
    refused = run(raw_hex=refused_raw.hex(), tv_sec='0', tv_usec='0',
                  validation='TV_SEC_NONPOSITIVE', status='FAILED', run_status=1,
                  run_status_name='BOOT_READ_FAILED')
    if not refused.get('verified') or not refused.get('no_boot_id') or \
            refused.get('outcome') != 'TIMEVAL_TV_SEC_NONPOSITIVE':
        problems.append(f'refused timeval not classified: {refused.get("outcome")!r} '
                        f'{refused.get("problems")}')

    future = run(wall_clock_sec=str(sec - 10))
    if future.get('verified') and future.get('boot_id'):
        problems.append('a boot instant after the console wall clock produced a boot id')

    # --- contract violations: the event must not be trusted -----------------------------------
    contract_cases = {
        'callback_executed=False but a read is claimed': dict(callback_executed=False),
        'a read_length outside the payload contract': dict(read_length=8,
                                                           raw_hex=raw.hex()[:16]),
        'a read without a matching cross check': dict(cross_check='MISMATCH'),
        'short raw bytes with read_length 16': dict(raw_hex=raw.hex()[:16]),
        'raw bytes disagree with the claimed sec/usec': dict(
            raw_hex=(sec + 3600).to_bytes(8, 'little', signed=True).hex() + raw.hex()[16:]),
        'a different source rva': dict(source_rva=hex(SOURCE_RVA + 8)),
        'a payload claimed boot id': dict(boot_id_claim='BOOT-deadbeefdeadbeef'),
        'a retry claim': dict(retry=True),
        'a kernel write claim': dict(writes_to_kernel=True),
        'a host supplied address claim': dict(host_supplied_address=True),
        'a non-numeric kexec_rc': dict(kexec_rc=None),
        'a validation string outside the contract': dict(validation='LOOKS_FINE'),
        'a refused value reported as OK': dict(validation='OK', raw_hex=refused_raw.hex(),
                                               tv_sec='0', tv_usec='0'),
    }
    for name, changes in contract_cases.items():
        report = run(**changes)
        if report.get('verified') or report.get('boot_id'):
            problems.append(f'contract violation accepted ({name}): {report.get("problems")}')
    missing_field = dict(base)
    del missing_field['label']
    if verify_privileged_event(missing_field, profile=profile,
                               profile_sha256=sha).get('verified'):
        problems.append('an event without a mandated field was accepted')
    if verify_privileged_event(None, profile=profile, profile_sha256=sha).get('verified'):
        problems.append('an empty event was accepted')
    return problems


def main(argv: list[str]) -> int:
    if len(argv) > 1 and argv[1] == 'selftest':
        problems = verify_privileged_event_selftest()
        print(json.dumps({'selftest': 'w11_2_privileged_boot_read',
                          'ok': not problems, 'problems': problems}, indent=2))
        return 0 if not problems else 1
    print('usage: python -m tools.hostctl.bootpriv selftest')
    return 2


if __name__ == '__main__':
    raise SystemExit(main(__import__('sys').argv))
