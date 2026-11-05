"""W11 / W11.1 host side: verify the sealed ``boot.binding`` event and derive the boot identity.

The console reports *measured* values only: for both userland access paths it sends the size-query
return code and errno, the reported length, the read return code and errno, the returned length and
the raw bytes (at most 64). The host never trusts a claim:

* it re-derives the classification of each path from the raw measured numbers (rule table below)
  and compares it with the classification the console reported,
* it re-computes the raw SHA-256 of the reported bytes,
* it refuses anything that is not a complete ``struct timeval`` (16 bytes on this ABI) -- a partial
  answer is ``BOOT_SOURCE_PARTIAL`` and never becomes a boot id,
* it refuses conflicting answers from the two paths (``BOOT_SOURCE_CONFLICT``),
* it re-checks the stability of the two readings itself, and
* it only then derives the digest with the one agreed algorithm (``tools/profiles/bootid.py``).

Rule table (measured values only; unknown errno never becomes a guess):

* size query rc != 0  -> ENOENT: name path = BOOT_SYSCTL_NAME_NOT_FOUND, MIB path =
  BOOT_SYSCTL_MIB_NOT_FOUND; EPERM/EACCES = BOOT_SYSCTL_PERMISSION; EINVAL =
  BOOT_SYSCTL_INVALID_ARGUMENT; anything else = BOOT_SYSCTL_SIZE_QUERY_FAILED
* read rc != 0        -> same errno table, otherwise BOOT_SYSCTL_READ_FAILED
* returned < 16 bytes -> BOOT_SYSCTL_SHORT_RESULT
* 16 bytes but tv_sec <= 0 or tv_usec outside 0..999999 -> BOOT_SYSCTL_MALFORMED_RESULT
* otherwise           -> BOOT_SYSCTL_SUCCESS
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:                      # pragma: no cover - import bootstrap
    sys.path.insert(0, str(REPO_ROOT))

from tools.profiles import bootid                       # noqa: E402
from tools.profiles.binding import BootBinding          # noqa: E402

EVENT_NAME = 'boot.binding'
EVENT_SCHEMA = 'ps4rf.boot.binding.diag.v1'
TIMEVAL_BYTES = 16
MAX_RAW_BYTES = 64

CLASS_NAMES = {
    0: 'BOOT_SYSCTL_SUCCESS',
    1: 'BOOT_SYSCTL_NAME_NOT_FOUND',
    2: 'BOOT_SYSCTL_MIB_NOT_FOUND',
    3: 'BOOT_SYSCTL_PERMISSION',
    4: 'BOOT_SYSCTL_INVALID_ARGUMENT',
    5: 'BOOT_SYSCTL_SIZE_QUERY_FAILED',
    6: 'BOOT_SYSCTL_READ_FAILED',
    7: 'BOOT_SYSCTL_SHORT_RESULT',
    8: 'BOOT_SYSCTL_MALFORMED_RESULT',
}
RUN_STATUS_NAMES = {
    0: 'OK', 1: 'BOOT_READ_FAILED', 2: 'BOOT_SOURCE_NOT_STABLE', 3: 'BOOT_TIME_IMPLAUSIBLE',
    4: 'BOOT_SOURCE_PARTIAL', 5: 'BOOT_SOURCE_CONFLICT',
}
ERRNO_EPERM, ERRNO_ENOENT, ERRNO_EACCES, ERRNO_EINVAL = 1, 2, 13, 22
FORBIDDEN_LABELS = (bootid.LABEL_SIMULATED_REBOOT_VECTOR, bootid.LABEL_TEST_BOOT_ID)

REQUIRED_EVENT_FIELDS = ('status', 'schema', 'source', 'source_kind', 'no_kernel_access',
                         'no_kexec', 'no_kernel_address', 'no_rva_sent_to_host', 'userland_only',
                         'run_status', 'run_status_name', 'methods', 'read1', 'read2',
                         'reads_identical', 'stability', 'timeval_sizeof', 'plausible')
REQUIRED_METHOD_FIELDS = ('method', 'size_query_attempted', 'size_query_rc', 'size_query_errno',
                          'reported_size', 'read_attempted', 'read_rc', 'read_errno',
                          'requested_size', 'returned_size', 'raw_len', 'raw_sha256', 'raw_hex',
                          'classification', 'classification_id')


def _as_int(value, where: str, problems: list[str]) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        problems.append(f'{where} is not an integer: {value!r}')
        return None


def _errno_class(errno_value: int | None, method: str) -> str | None:
    if errno_value is None:
        return None
    if errno_value == ERRNO_ENOENT:
        return 'BOOT_SYSCTL_NAME_NOT_FOUND' if method == 'sysctlbyname' else 'BOOT_SYSCTL_MIB_NOT_FOUND'
    if errno_value in (ERRNO_EPERM, ERRNO_EACCES):
        return 'BOOT_SYSCTL_PERMISSION'
    if errno_value == ERRNO_EINVAL:
        return 'BOOT_SYSCTL_INVALID_ARGUMENT'
    return None


def classify_method(key: str, method: dict, problems: list[str]) -> str | None:
    """Host-side re-derivation of the classification, from measured values only."""
    if not method.get('size_query_attempted'):
        return 'BOOT_SYSCTL_SIZE_QUERY_FAILED'
    sq_rc = _as_int(method.get('size_query_rc'), f'{key}.size_query_rc', problems)
    sq_errno = _as_int(method.get('size_query_errno'), f'{key}.size_query_errno', problems)
    if sq_rc is None:
        return None
    if sq_rc != 0:
        return _errno_class(sq_errno, key) or 'BOOT_SYSCTL_SIZE_QUERY_FAILED'
    if not method.get('read_attempted'):
        return 'BOOT_SYSCTL_SIZE_QUERY_FAILED'
    read_rc = _as_int(method.get('read_rc'), f'{key}.read_rc', problems)
    read_errno = _as_int(method.get('read_errno'), f'{key}.read_errno', problems)
    returned = _as_int(method.get('returned_size'), f'{key}.returned_size', problems)
    raw_len = _as_int(method.get('raw_len'), f'{key}.raw_len', problems)
    if read_rc is None or returned is None or raw_len is None:
        return None
    if read_rc != 0:
        return _errno_class(read_errno, key) or 'BOOT_SYSCTL_READ_FAILED'
    if returned < TIMEVAL_BYTES or raw_len < TIMEVAL_BYTES:
        return 'BOOT_SYSCTL_SHORT_RESULT'
    raw_hex = str(method.get('raw_hex', '') or '')
    try:
        raw = bytes.fromhex(raw_hex)
    except ValueError:
        problems.append(f'{key}.raw_hex is not valid hex')
        return None
    if len(raw) < TIMEVAL_BYTES:
        return 'BOOT_SYSCTL_SHORT_RESULT'
    sec = int.from_bytes(raw[0:8], 'little', signed=True)
    usec = int.from_bytes(raw[8:16], 'little', signed=True)
    if sec <= 0 or not 0 <= usec <= 999_999:
        return 'BOOT_SYSCTL_MALFORMED_RESULT'
    return 'BOOT_SYSCTL_SUCCESS'


def _check_method(key: str, method: dict, problems: list[str]) -> dict:
    info: dict = {'method': key}
    if not isinstance(method, dict):
        problems.append(f'{key} diagnostics missing')
        return info
    for field in REQUIRED_METHOD_FIELDS:
        if field not in method:
            problems.append(f'{key}: missing field {field!r}')
    raw_hex = str(method.get('raw_hex', '') or '')
    if len(raw_hex) > 2 * MAX_RAW_BYTES:
        problems.append(f'{key}: raw bytes exceed the {MAX_RAW_BYTES} byte cap')
    claimed_sha = str(method.get('raw_sha256', '') or '')
    try:
        raw = bytes.fromhex(raw_hex)
    except ValueError:
        raw = b''
        problems.append(f'{key}.raw_hex is not valid hex')
    if raw:
        if hashlib.sha256(raw).hexdigest() != claimed_sha:
            problems.append(f'{key}: raw_sha256 does not match the reported bytes')
    derived = classify_method(key, method, problems)
    claimed = str(method.get('classification', '') or '')
    if derived is not None and claimed and derived != claimed:
        problems.append(f'{key}: measured values classify as {derived}, console claimed {claimed}')
    info.update({
        'derived_class': derived,
        'console_class': claimed,
        'size_query_rc': method.get('size_query_rc'),
        'size_query_errno': method.get('size_query_errno'),
        'reported_size': method.get('reported_size'),
        'read_rc': method.get('read_rc'),
        'read_errno': method.get('read_errno'),
        'returned_size': method.get('returned_size'),
        'raw_len': method.get('raw_len'),
        'raw_hex': raw_hex,
        'raw_sha256': claimed_sha,
        'complete_timeval': derived == 'BOOT_SYSCTL_SUCCESS',
    })
    if derived == 'BOOT_SYSCTL_SUCCESS':
        info['timeval'] = {'sec': int.from_bytes(raw[0:8], 'little', signed=True),
                           'usec': int.from_bytes(raw[8:16], 'little', signed=True)}
    return info


def verify_boot_event(event: dict | None, *, profile: dict, profile_sha256: str,
                      now: int | None = None) -> dict:
    """Verify the console's boot.binding event; derive the runtime binding only when it is sound."""
    problems: list[str] = []
    report: dict = {'verified': False, 'problems': problems, 'event_name': EVENT_NAME,
                    'schema': EVENT_SCHEMA}
    if not isinstance(event, dict):
        problems.append('no boot.binding event was received')
        return report
    if event.get('event') != EVENT_NAME:
        problems.append(f"unexpected event name {event.get('event')!r}")
    if event.get('schema') != EVENT_SCHEMA:
        problems.append(f"unexpected event schema {event.get('schema')!r} (W11.1 diagnostics "
                        f"expected)")
    for field in REQUIRED_EVENT_FIELDS:
        if field not in event:
            problems.append(f'missing field {field!r}')
    for flag in ('no_kernel_access', 'no_kexec', 'no_kernel_address', 'no_rva_sent_to_host',
                 'userland_only'):
        if event.get(flag) is not True:
            problems.append(f'{flag} must be true (the W11 collector is userland only)')
    label = str(event.get('label', '') or '')
    if label.upper() in FORBIDDEN_LABELS:
        problems.append(f'event carries the simulated label {label!r}: never accepted as measured')
    if event.get('source') != bootid.SOURCE_KERN_BOOTTIME:
        problems.append(f"unexpected boot source {event.get('source')!r}")

    # ABI: the contract needs a complete 16 byte struct timeval
    tv_size = _as_int(event.get('timeval_sizeof'), 'timeval_sizeof', problems)
    report['abi'] = {'timeval_sizeof': tv_size, 'contract_bytes': TIMEVAL_BYTES,
                     'errno_observable': event.get('errno_observable')}
    if tv_size is not None and tv_size != TIMEVAL_BYTES:
        problems.append(f'ABI_MISMATCH: the target reports sizeof(struct timeval) == {tv_size}, '
                        f'the contract requires {TIMEVAL_BYTES} -- the contract must be corrected '
                        f'before any binding')

    methods = event.get('methods') or {}
    report['methods'] = {key: _check_method(key, methods.get(key), problems)
                         for key in ('sysctlbyname', 'sysctl_mib')}
    complete = [key for key, info in report['methods'].items() if info.get('complete_timeval')]
    report['complete_paths'] = complete

    # the two readings, re-parsed from the event (the host never trusts the digest either)
    first = second = None
    for key in ('read1', 'read2'):
        raw = event.get(key)
        if not isinstance(raw, dict):
            problems.append(f'{key} is missing or malformed')
            continue
        sec = _as_int(raw.get('sec'), f'{key}.sec', problems)
        usec = _as_int(raw.get('usec'), f'{key}.usec', problems)
        if sec is None or usec is None:
            continue
        if key == 'read1':
            first = bootid.BootTime(sec, usec)
        else:
            second = bootid.BootTime(sec, usec)
    if first is not None:
        report['raw_timeval'] = {'sec': first.sec, 'usec': first.usec}
    if second is not None:
        report['read2_timeval'] = {'sec': second.sec, 'usec': second.usec}

    run_status = _as_int(event.get('run_status'), 'run_status', problems)
    claimed_status = str(event.get('run_status_name', '') or '')
    report['run_status'] = {'id': run_status, 'name': RUN_STATUS_NAMES.get(run_status) if
                            run_status is not None else None, 'console_name': claimed_status}
    if run_status is not None:
        expected = RUN_STATUS_NAMES.get(run_status)
        if expected and claimed_status and expected != claimed_status:
            problems.append(f'run status name {claimed_status!r} does not match id {run_status}')

    # ---- the outcome is *derived* from the measured facts, then compared with the claim ---------
    name_info = report['methods']['sysctlbyname']
    mib_info = report['methods']['sysctl_mib']
    delivered = {key: int(info.get('raw_len') or 0) for key, info in report['methods'].items()}
    report['diagnosis'] = {
        'classes': {key: info.get('derived_class') for key, info in report['methods'].items()},
        'bytes_delivered': delivered,
    }

    if len(complete) == 2:
        same = name_info.get('raw_hex') == mib_info.get('raw_hex')
        report['paths_identical'] = same
        derived_status = 0 if same else 5
        # a *detected* conflict is the outcome of the run, not an integrity failure: it is
        # reported through the derived run status (5) and never produces a boot id
        if same:
            preferred = str(event.get('preferred_path', '') or '')
            if preferred not in ('sysctlbyname', 'sysctl_mib'):
                problems.append(f'unexpected preferred path {preferred!r} while both paths answered')
    elif len(complete) == 1:
        only = complete[0]
        other = 'sysctl_mib' if only == 'sysctlbyname' else 'sysctlbyname'
        other_class = report['methods'][other].get('derived_class')
        if delivered.get(other) and other_class in ('BOOT_SYSCTL_SHORT_RESULT',
                                                    'BOOT_SYSCTL_MALFORMED_RESULT'):
            # the sibling answered with bytes that cannot be a timeval: nothing gets bound
            report['paths_identical'] = False
            report['sibling_anomaly'] = {'path': other, 'class': other_class}
            derived_status = 5
        else:
            report['paths_identical'] = None
            derived_status = 0
            report['only_path'] = only
            if only == 'sysctl_mib':
                report['preferred_source_contract'] = (
                    'sysctl_mib (direct MIB form) -- sysctlbyname stays documented as unsupported '
                    'on this firmware (W11.1 section 9)')
    else:
        report['paths_identical'] = None
        classes = {key: info.get('derived_class') for key, info in report['methods'].items()}
        report['no_complete_timeval'] = {'classes': classes}
        derived_status = 4 if 'BOOT_SYSCTL_SHORT_RESULT' in classes.values() else 1
        if 'BOOT_SYSCTL_SUCCESS' in classes.values():
            problems.append('a path classified as SUCCESS yet no usable timeval was accepted')

    # stability -- only meaningful when a usable complete timeval exists
    unstable = False
    if derived_status == 0 and first is not None and second is not None:
        instability = bootid.stability_problems(first, second)
        unstable = bool(instability)
        console_unstable = (event.get('reads_identical') is False
                            or str(event.get('stability') or '') != 'STABLE')
        report['stability'] = {'status': 'STABLE' if not unstable else 'NOT_STABLE',
                               'reads_identical': not unstable, 'problems': instability,
                               'console_claim': event.get('stability')}
        if unstable and not console_unstable:
            problems.append('the two readings differ but the console presented them as stable')
        if unstable:
            derived_status = 2
    elif derived_status != 0:
        # W11.1 review (owner): without a complete timeval on both readings there is nothing to
        # compare, so stability is NOT_EVALUATED. The console's own claim stays a claim -- it is
        # never presented as a host-measured finding.
        report['stability'] = {
            'status': 'NOT_EVALUATED', 'reads_identical': None,
            'console_claim': event.get('stability'),
            'note': 'no complete timeval on both readings: stability is not evaluable and was not '
                    'evaluated by the host'}

    if run_status is not None and run_status != derived_status:
        problems.append(f'the console reported {RUN_STATUS_NAMES.get(run_status)!r} but the measured '
                        f'values give {RUN_STATUS_NAMES.get(derived_status)!r}')
    report['derived_run_status'] = {'id': derived_status, 'name': RUN_STATUS_NAMES.get(derived_status)}
    report['diagnosis']['run_status_name'] = RUN_STATUS_NAMES.get(derived_status)
    report['diagnosis']['complete'] = not problems

    if derived_status != 0:
        # no boot identity. W11.1: a decisive diagnosis is a successful run of this wave (section
        # 14); the absent binding is recorded, never papered over.
        report['no_boot_id'] = True
        report['derived'] = False
        report['diagnosis_only'] = True
        report['verified'] = not problems
        return report

    if first is None:
        report['derived'] = False
        return report

    # the readings must be the bytes of a path the run actually used
    if len(complete) == 2:
        expected = report['methods']['sysctlbyname'].get('timeval')
        if expected and (expected['sec'], expected['usec']) != (first.sec, first.usec):
            problems.append('read1 does not match the sysctlbyname bytes (both paths agreed, so it '
                            'must match both)')
    if len(complete) == 1:
        expected = report['methods'][complete[0]].get('timeval')
        if expected and (expected['sec'], expected['usec']) != (first.sec, first.usec):
            problems.append(f'read1 does not match the {complete[0]} bytes')
        if second is not None and expected and \
                (expected['sec'], expected['usec']) != (second.sec, second.usec):
            problems.append(f'read2 does not match the {complete[0]} bytes')

    console_wall = event.get('console_wall_sec')
    console_now = _as_int(console_wall, 'console_wall_sec', []) if console_wall is not None else None
    if event.get('wall_clock_ok') is True and console_now is None:
        problems.append('the console claimed a wall clock but sent no value')
    if event.get('boottime_after_wall_clock') is True:
        problems.append('the console reports a boot instant after its own wall clock')

    try:
        derived = bootid.derive_boot_id(profile_sha256, first, profile=profile,
                                        console_now=console_now, host_now=now)
    except bootid.BootIdError as exc:
        problems.append(str(exc))
        report['derived'] = False
        report['verified'] = False
        return report

    report['boot_binding'] = derived
    report['boot_binding_short'] = {'boot_id': derived['boot_id'],
                                    'boot_digest': derived['boot_digest'],
                                    'schema': derived['schema']}
    report['derived'] = True
    report['labels'] = ['MEASURED_THIS_BOOT']
    binding = BootBinding.from_profile(profile, derived['boot_id'])
    report['binding'] = binding
    report['binding_view'] = {'boot_id': binding.boot_id,
                              'profile_sha256': binding.profile_sha256,
                              'facts_persistent': binding.facts_persistent,
                              'valid_for_this_boot': binding.valid_for(derived['boot_id'],
                                                                      profile_sha256)}
    report['verified'] = not problems
    report['no_secret_inputs'] = derived.get('no_secret_inputs', False)
    return report


# ---------------------------------------------------------------- offline self test

def _clean_method(key: str, raw_hex: str = '', **overrides) -> dict:
    body = {'method': key, 'size_query_attempted': True, 'size_query_rc': 0, 'size_query_errno': 0,
            'reported_size': str(len(raw_hex) // 2), 'read_attempted': True, 'read_rc': 0,
            'read_errno': 0, 'requested_size': 64, 'returned_size': str(len(raw_hex) // 2),
            'raw_len': len(raw_hex) // 2, 'raw_hex': raw_hex,
            'raw_sha256': hashlib.sha256(bytes.fromhex(raw_hex)).hexdigest(),
            'classification': 'BOOT_SYSCTL_SUCCESS', 'classification_id': 0}
    body.update(overrides)
    return body


CAPTURE_HEX = 'f0dcaf6a00000000e0220d0000000000'     # 1789910256.860896 (pinned capture boot)


def verify_boot_event_selftest() -> list[str]:
    """Mutations must be rejected; the *diagnosis* outcomes of W11.1 must be accepted."""
    problems: list[str] = []
    profile = {'target': {'platform': 'ORBIS'}, 'canonical_sha256': 'a' * 64}
    base = {'msg': 'EVENT', 'event': EVENT_NAME, 'schema': EVENT_SCHEMA, 'status': 'OK',
            'source': bootid.SOURCE_KERN_BOOTTIME, 'source_kind': 'userland-sysctl-readonly',
            'no_kernel_access': True, 'no_kexec': True, 'no_kernel_address': True,
            'no_rva_sent_to_host': True, 'userland_only': True,
            'run_status': 0, 'run_status_name': 'OK', 'preferred_path': 'sysctlbyname',
            'methods': {'sysctlbyname': _clean_method('sysctlbyname', CAPTURE_HEX),
                        'sysctl_mib': _clean_method('sysctl_mib', CAPTURE_HEX)},
            'read1': {'sec': '1789910256', 'usec': '860896'},
            'read2': {'sec': '1789910256', 'usec': '860896'},
            'reads_identical': True, 'stability': 'STABLE', 'timeval_sizeof': 16,
            'plausible': True, 'boottime_after_wall_clock': False, 'wall_clock_ok': True,
            'console_wall_sec': '1789910400', 'errno_observable': True,
            'label': 'ps4rfd-live-w11'}

    def build(**changes) -> dict:
        out = dict(base)
        name_fields: dict = {'raw_hex': CAPTURE_HEX}
        mib_fields: dict = {'raw_hex': CAPTURE_HEX}
        for key, value in changes.items():
            if key.startswith('name__'):
                name_fields[key[6:]] = value
            elif key.startswith('mib__'):
                mib_fields[key[5:]] = value
            else:
                out[key] = value
        out['methods'] = {'sysctlbyname': _clean_method('sysctlbyname', **name_fields),
                          'sysctl_mib': _clean_method('sysctl_mib', **mib_fields)}
        return out

    def sha_of(method: dict) -> dict:
        entry = dict(method)
        entry['raw_sha256'] = hashlib.sha256(bytes.fromhex(str(entry.get('raw_hex', '')))).hexdigest()
        return entry

    # ---- must be rejected ----
    reject = [
        ('simulated label', build(label=bootid.LABEL_SIMULATED_REBOOT_VECTOR),
         'a simulated label was accepted'),
        ('kernel access', build(no_kernel_access=False), 'the kernel-access flag was ignored'),
        ('abi mismatch', build(timeval_sizeof=8), 'an ABI mismatch was accepted'),
        ('true conflict', build(mib__raw_hex=CAPTURE_HEX[:-16] + 'e1220d0000000000'),
         'two different complete answers were accepted'),
        ('short claimed as success',
         build(name__raw_hex=CAPTURE_HEX[:16], name__raw_len=8, name__returned_size=8,
               name__raw_sha256=None, name__classification='BOOT_SYSCTL_SUCCESS'),
         'a short result was accepted as a complete timeval'),
        ('not found claimed as success',
         build(name__size_query_rc=2, name__size_query_errno=2, name__reported_size=-1,
               name__read_attempted=False, name__read_rc=1, name__returned_size=-1,
               name__raw_hex='', name__raw_len=0, name__raw_sha256=None,
               name__classification='BOOT_SYSCTL_SUCCESS'),
         'a not-found path was claimed as success'),
        ('drift reported as stable',
         build(read2={'sec': '1789910256', 'usec': '860897'}, stability='STABLE'),
         'drifting readings were accepted as stable'),
        ('wrong run status', build(run_status=1, run_status_name='BOOT_READ_FAILED'),
         'a wrong run status was accepted'),
    ]
    for name, event, why in reject:
        payload = dict(event)
        payload['methods'] = {k: sha_of(v) for k, v in payload['methods'].items()}
        if verify_boot_event(payload, profile=profile, profile_sha256='a' * 64,
                             now=1_800_000_000)['verified']:
            problems.append(f'{name}: {why}')
    valid = verify_boot_event(dict(base), profile=profile, profile_sha256='a' * 64,
                              now=1_800_000_000)
    if not valid['verified'] or not valid.get('binding_view'):
        problems.append(f'a fully valid event was rejected: {valid["problems"]}')
    expected_id = bootid.derive_boot_id('a' * 64, bootid.BootTime(1789910256, 860896),
                                       profile=profile, console_now=1789910400,
                                       host_now=1_800_000_000)['boot_id']
    if valid.get('boot_binding_short', {}).get('boot_id') != expected_id:
        problems.append('the derived boot id does not match the one algorithm (bootid.py)')

    # ---- must be accepted as decisive diagnoses (no boot id, verified) ----
    def diag(name_class: str, name_id: int, raw_hex: str = '', run_status: int = 1,
             run_status_name: str = 'BOOT_READ_FAILED', **fields) -> dict:
        name_method = _clean_method('sysctlbyname', raw_hex, **fields)
        name_method = dict(name_method, classification=name_class, classification_id=name_id)
        name_method = sha_of(name_method)
        mib_method = sha_of(_clean_method('sysctl_mib', raw_hex='', size_query_rc=2,
                                          size_query_errno=2, reported_size=-1,
                                          read_attempted=False, read_rc=1, returned_size=-1,
                                          raw_len=0, classification='BOOT_SYSCTL_MIB_NOT_FOUND',
                                          classification_id=2))
        return dict(base, run_status=run_status, run_status_name=run_status_name,
                    preferred_path='none', methods={'sysctlbyname': name_method,
                                                    'sysctl_mib': mib_method},
                    read1={'sec': '0', 'usec': '0'}, read2={'sec': '0', 'usec': '0'},
                    reads_identical=True, stability='STABLE')

    cases = [
        ('both not found', diag('BOOT_SYSCTL_NAME_NOT_FOUND', 1, size_query_rc=2, size_query_errno=2,
                                reported_size=-1, read_attempted=False, read_rc=1,
                                returned_size=-1, raw_len=0), 1),
        ('permission', diag('BOOT_SYSCTL_PERMISSION', 3, size_query_rc=2, size_query_errno=13,
                            reported_size=-1, read_attempted=False, read_rc=1, returned_size=-1,
                            raw_len=0), 1),
        ('invalid argument', diag('BOOT_SYSCTL_INVALID_ARGUMENT', 4, size_query_rc=2,
                                  size_query_errno=22, reported_size=-1, read_attempted=False,
                                  read_rc=1, returned_size=-1, raw_len=0), 1),
        ('size query failed', diag('BOOT_SYSCTL_SIZE_QUERY_FAILED', 5, size_query_rc=2,
                                   size_query_errno=5, reported_size=-1, read_attempted=False,
                                   read_rc=1, returned_size=-1, raw_len=0), 1),
        ('partial 8 bytes', diag('BOOT_SYSCTL_SHORT_RESULT', 7, CAPTURE_HEX[:16], raw_len=8,
                                 returned_size=8, reported_size=8, run_status=4,
                                 run_status_name='BOOT_SOURCE_PARTIAL'), 4),
        ('malformed 16 bytes', diag('BOOT_SYSCTL_MALFORMED_RESULT', 8,
                                    CAPTURE_HEX[:16] + '40420f0000000000', raw_len=16,
                                    returned_size=16, reported_size=16), 1),
    ]
    for name, event, expected_status in cases:
        outcome = verify_boot_event(event, profile=profile, profile_sha256='a' * 64,
                                    now=1_800_000_000)
        if not outcome['verified'] or not outcome.get('no_boot_id'):
            problems.append(f'{name}: decisive diagnosis rejected: {outcome["problems"]}')
        elif outcome.get('derived_run_status', {}).get('id') != expected_status:
            problems.append(f'{name}: derived run status '
                            f"{outcome.get('derived_run_status')!r} != {expected_status}")
    # drift is a valid diagnosis too (BOOT_SOURCE_NOT_STABLE), it must not be a silent success
    drift = build(read2={'sec': '1789910256', 'usec': '860897'}, run_status=2,
                  run_status_name='BOOT_SOURCE_NOT_STABLE', reads_identical=False,
                  stability='BOOT_SOURCE_NOT_STABLE')
    outcome = verify_boot_event(drift, profile=profile, profile_sha256='a' * 64, now=1_800_000_000)
    if not outcome['verified'] or not outcome.get('no_boot_id'):
        problems.append(f'drifting source not handled as a diagnosis: {outcome["problems"]}')
    # a single working path (only the MIB form) is acceptable and becomes the documented contract
    only_mib = build(name__size_query_rc=2, name__size_query_errno=22, name__reported_size=-1,
                     name__read_attempted=False, name__read_rc=1, name__returned_size=-1,
                     name__raw_hex='', name__raw_len=0,
                     name__classification='BOOT_SYSCTL_INVALID_ARGUMENT',
                     name__classification_id=4, preferred_path='sysctl_mib')
    outcome = verify_boot_event(only_mib, profile=profile, profile_sha256='a' * 64,
                                now=1_800_000_000)
    if not outcome['verified'] or not outcome.get('boot_binding_short'):
        problems.append(f'only-MIB binding rejected: {outcome["problems"]}')
    elif not outcome.get('preferred_source_contract'):
        problems.append('the only-MIB case did not document the preferred source contract')
    return problems


def main(argv: list[str]) -> int:
    if '--self-test' in argv:
        problems = verify_boot_event_selftest()
        for problem in problems:
            print(f'boot: {problem}')
        print(f'hostctl.boot self-test: {"ok" if not problems else "FAILED"}')
        return 0 if not problems else 1
    print('usage: boot.py --self-test')
    return 2


if __name__ == '__main__':                                # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
