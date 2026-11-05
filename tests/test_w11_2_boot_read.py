"""W11.2 -- the fixed privileged boot read: host verification, gate and source invariants.

These tests never touch a console: they verify that the *host* re-derives everything from the raw
numbers, that the payload cannot smuggle a boot id into the evidence, and that the frozen single
source and the one-shot guard are structural, not aspirational.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:                      # pragma: no cover - import bootstrap
    sys.path.insert(0, str(REPO_ROOT))

from tools.hostctl import bootpriv                                       # noqa: E402
from tools.profiles.schema import canonical_profile_sha256                # noqa: E402

TARGET = REPO_ROOT / 'native' / 'target'
MODULE = TARGET / 'ps4rf_bootread.c'
HEADER = TARGET / 'ps4rf_bootread.h'
AGENT = TARGET / 'ps4rf_agent.c'
PROFILE_PATH = REPO_ROOT / 'profiles' / 'fw1352' / 'profile-13.52.json'


def _profile() -> dict:
    return json.loads(PROFILE_PATH.read_text())


def _event(**changes) -> dict:
    sec, usec = bootpriv.W10_CAPTURE['sec'], bootpriv.W10_CAPTURE['usec']
    raw = sec.to_bytes(8, 'little', signed=True) + usec.to_bytes(8, 'little', signed=True)
    body = {
        'msg': 'EVENT', 'event': bootpriv.EVENT_NAME, 'schema': bootpriv.EVENT_SCHEMA,
        'status': 'OK', 'run_status': 0, 'run_status_name': 'OK', 'callback_executed': True,
        'cb_status': 0, 'cb_status_name': 'OK', 'kexec_rc': 0,
        'lstar': hex(0xFFFFFFFF998F41C0), 'kbase_candidate': hex(0xFFFFFFFF998F4000),
        'kbase_sdk': hex(0xFFFFFFFF998F4000), 'cross_check': 'MATCH',
        'source_rva': hex(bootpriv.SOURCE_RVA), 'read_length': bootpriv.READ_LEN,
        'raw_hex': raw.hex(), 'tv_sec': str(sec), 'tv_usec': str(usec),
        'wall_clock_sec': str(sec + 30), 'validation': 'OK', 'kernel_timeval_bytes': 16,
        'single_callback': True, 'retry': False, 'writes_to_kernel': False,
        'host_supplied_address': False, 'generic_read_primitive': 'NONE', 'boot_id_claim': 'NONE',
        'build_id': 'f' * 32, 'label': 'ps4rfd-live-w112',
        'timeval_layout': 'int64 tv_sec at +0, int64 tv_usec at +8 (pinned FW13.52)',
    }
    body.update(changes)
    return body


def _code(path: pathlib.Path) -> str:
    """The payload module without comments: a comment is not a measurement."""
    text = path.read_text()
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
    return re.sub(r'//[^\n]*', '', text)


def _verify(**changes) -> dict:
    profile = _profile()
    return bootpriv.verify_privileged_event(_event(**changes), profile=profile,
                                            profile_sha256=canonical_profile_sha256(profile))


def test_host_verifier_selftest_is_green():
    assert bootpriv.verify_privileged_event_selftest() == []


def test_valid_event_forms_the_boot_id_host_side():
    report = _verify()
    assert report['verified'] and report['outcome'] == 'OK'
    assert report['no_boot_id'] is False
    # the id is the digest of the canonical object, computed here independently of bootid.py
    canonical = json.dumps(report['binding'], sort_keys=True, separators=(',', ':'),
                           ensure_ascii=False).encode()
    digest = hashlib.sha256(canonical).hexdigest()
    assert report['full_digest'] == digest
    assert report['boot_id'] == 'BOOT-' + digest[:16]
    assert report['binding']['boottime'] == {'sec': bootpriv.W10_CAPTURE['sec'],
                                             'usec': bootpriv.W10_CAPTURE['usec']}
    assert report['binding_view']['profile_sha256'] == canonical_profile_sha256(_profile())
    assert report['w10_capture']['matches'] is True


def test_a_different_boot_instant_gives_a_different_boot_id():
    other = _verify(raw_hex=(bootpriv.W10_CAPTURE['sec'] + 7).to_bytes(8, 'little',
                                                                      signed=True).hex() +
                            bootpriv.W10_CAPTURE['usec'].to_bytes(8, 'little', signed=True).hex(),
                    tv_sec=str(bootpriv.W10_CAPTURE['sec'] + 7))
    assert other['verified'] and other['boot_id'] != _verify()['boot_id']


def test_no_boot_id_without_a_complete_read():
    for changes in ({'callback_executed': False, 'kexec_rc': -1, 'status': 'FAILED',
                     'run_status': 1, 'read_length': 0, 'raw_hex': '', 'tv_sec': '0',
                     'tv_usec': '0', 'validation': 'NOT_READ', 'lstar': '0x0',
                     'kbase_candidate': '0x0', 'kbase_sdk': '0x0', 'cross_check': 'UNMEASURED',
                     'source_rva': 'UNMEASURED', 'cb_status_name': 'NOT_EXECUTED'},
                    {'read_length': 0, 'raw_hex': '', 'tv_sec': '0', 'tv_usec': '0',
                     'validation': 'NOT_READ', 'status': 'FAILED', 'run_status': 1,
                     'cross_check': 'MISMATCH', 'source_rva': hex(bootpriv.SOURCE_RVA)}):
        report = _verify(**changes)
        assert report['verified'], report['problems']
        assert report['no_boot_id'] is True
        assert 'boot_id' not in report and 'binding' not in report


def test_host_classification_matches_the_payload_or_the_event_is_untrusted():
    # a lying payload: bytes that decode to something else than the claimed tuple
    lying = _verify(tv_sec=str(bootpriv.W10_CAPTURE['sec'] + 5))
    assert not lying['verified'] and lying['no_boot_id'] is True
    assert any('decode to' in problem for problem in lying['problems'])


def test_payload_never_forms_or_claims_a_boot_id():
    source = MODULE.read_text()
    assert 'boot_id_claim' in source and '"NONE"' in source
    assert not re.search(r'BOOT-', source), 'the payload must not form a boot id'
    assert 'derive_boot_id' not in source


def test_the_source_region_is_frozen_and_singular():
    source = _code(MODULE)
    assert source.count('PS4RF_BOOTREAD_SOURCE_RVA 0x224C6C8u') == 1
    assert source.count('0x224C6C8') == 1
    assert _code(HEADER).count('PS4RF_BOOTREAD_READ_LEN 16u') == 1
    assert source.count('rdmsr') == 1, 'exactly one rdmsr (LSTAR)'
    assert 'wrmsr' not in source, 'no kernel write primitive'
    assert 'memcpy' not in source and 'malloc' not in source


def test_hex_encoder_leaves_room_for_the_last_byte():
    """Regression for the defect the first live run exposed (v1 event: 15 bytes sent).

    The event builder hex-encodes the 16 raw bytes into a 33 byte buffer. The loop bound must
    leave room for two digits *and* the terminator of the final byte (`o + 2u < cap`); with
    `o + 3u < cap` the last byte was dropped, and the host -- correctly -- refused an event that
    claimed a 16 byte read while sending 30 hex characters, so no boot id was formed.
    """
    source = _code(MODULE)
    assert 'o + 2u < cap' in source
    assert 'o + 3u < cap' not in source
    assert 'char hex[2u * PS4RF_BOOTREAD_READ_LEN + 1u]' in source


def test_one_shot_guard_precedes_the_single_kexec():
    source = _code(MODULE)
    guard = source.index('g_ps4rf_bootread_called = 1')
    call = source.index('kexec((void *)&ps4rf_bootread_kpayload')
    assert guard < call, 'the guard must be set before kexec'
    assert source.count('kexec(') == 2, 'one declaration plus exactly one call site'
    assert 'PS4RF_AGENT_BOOTREAD_FAILED' in (TARGET / 'ps4rf_agent.c').read_text()


def test_gate_binds_the_profile_and_keeps_kernel_read_deferred():
    from tools.profiles import w11_2_gate
    report = w11_2_gate.build_report(sec=bootpriv.W10_CAPTURE['sec'],
                                     usec=bootpriv.W10_CAPTURE['usec'])
    assert all(report['checks'].values()), report['checks']
    assert 'PROFILE_MATCH' in report['after']['w5']['codes']
    assert any('BOOT' in code for code in report['checks']['boot_binding_reason_before'])
    detail = report['kernel_read_still_deferred']
    assert any('LOCATOR' in d.upper() for d in detail['w5_detail'])
    assert detail['locator_ref'] is None and detail['profile_required'] is True
    assert report['source']['length'] == bootpriv.READ_LEN


def test_session_contract_covers_every_mandated_event_field():
    from tools.hostctl.session import (BOOT_BINDING_PRIVILEGED_REQUIRED_FIELDS,
                                       BOOT_BINDING_PRIVILEGED_SCHEMA,
                                       EVENT_BOOT_BINDING_PRIVILEGED)
    assert EVENT_BOOT_BINDING_PRIVILEGED == 'boot.binding.privileged'
    assert BOOT_BINDING_PRIVILEGED_SCHEMA == 'ps4rf.boot.binding.privileged.v1'
    for field in bootpriv.REQUIRED_FIELDS:
        assert field in BOOT_BINDING_PRIVILEGED_REQUIRED_FIELDS, field
