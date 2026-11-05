"""W11 gate report: what the boot binding resolves and what stays deferred.

Runs the same W4/W5/W7 gate path as W10, once *before* the runtime binding and once *after* a
measured boot binding exists, and states the remaining gates exactly -- in particular the
LOCATOR_MISSING triple, which the boot binding does not remove.

The boot instant used here comes from the W11 offline collector run (host stand-in at the pinned
capture instant) and is labelled as such: it is an offline stand-in, not a live console
measurement. The block *before* the binding is what the live W11 run must beat; the block *after*
is exactly what the live run will produce with a measured boottime.
"""

from __future__ import annotations

import json
import pathlib
import sys
import time

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:                      # pragma: no cover - import bootstrap
    sys.path.insert(0, str(REPO_ROOT))

from tools.profiles import bootid, w10_gate as gate                    # noqa: E402
from tools.profiles.binding import BootBinding                         # noqa: E402
from tools.profiles.schema import (                                    # noqa: E402
    LocatorRequest, canonical_profile_sha256,
)

PROFILE_PATH = REPO_ROOT / 'profiles' / 'fw1352' / 'profile-13.52.json'
LABEL_OFFLINE = 'OFFLINE_STANDIN_BOOT'
LABEL_MEASURED = 'MEASURED_THIS_BOOT'


def build_report(*, sec: int, usec: int, label: str = LABEL_OFFLINE,
                 profile_path: pathlib.Path = PROFILE_PATH) -> dict:
    profile = json.loads(profile_path.read_text())
    sha = canonical_profile_sha256(profile)
    host_now = int(time.time())
    measured = bootid.BootTime(sec, usec)
    derived = bootid.derive_boot_id(sha, measured, profile=profile, console_now=host_now,
                                    host_now=host_now)
    binding = BootBinding.from_profile(profile, derived['boot_id'])

    before_w5 = gate.w5(profile)
    after_w5 = gate.w5(profile, boot_binding=binding, current_boot_id=derived['boot_id'],
                       expected_target=profile['target'])
    gated = gate.w5(profile, requests=(LocatorRequest('kernel.read', module='kernel'),),
                    boot_binding=binding, current_boot_id=derived['boot_id'],
                    expected_target=profile['target'])

    op_policy = (profile.get('operation_policy') or {}).get('kernel.read') or {}
    missing = {
        'operation': 'kernel.read',
        'profile_fields': sorted(gate.READ_ARGS),
        'locator_ref': op_policy.get('locator_ref'),
        'profile_required': bool(op_policy.get('profile_required')),
        'reason': op_policy.get('reason'),
        'w5_detail': [d for d in gated['details'] if 'LOCATOR' in d.upper()],
        'w5_codes': gated['codes'],
    }

    report = {
        'schema': 'ps4rf.w11.gate-report.v1',
        'algorithm': bootid.BOOT_BINDING_SCHEMA,
        'boot_binding': {'boot_id': derived['boot_id'], 'boot_digest': derived['boot_digest'],
                         'raw_timeval': derived['raw_timeval'], 'labels': [label],
                         'simulated': label != LABEL_MEASURED},
        'profile_sha256': sha,
        'before': {
            'binding': None,
            'w4': gate.w4('kernel.read', None),
            'w5': before_w5,
            'w7': gate.dispatch_once('kernel.read', profile, None, gate.READ_ARGS),
        },
        'after': {
            'binding': {'boot_id': binding.boot_id, 'profile_sha256': binding.profile_sha256,
                        'facts_persistent': binding.facts_persistent,
                        'valid_for_this_boot': binding.valid_for(derived['boot_id'], sha)},
            'w4': gate.w4('kernel.read', {'profile_sha256': sha, 'boot_id': derived['boot_id']}),
            'w5': after_w5,
            'w7': gate.dispatch_once('kernel.read', profile, binding, gate.READ_ARGS),
        },
        'remaining': {
            'boot_id_unverified': any('BOOT_ID_UNVERIFIED' in c for c in after_w5['codes']) or
                                  any('BOOT_BINDING' in c for c in after_w5['codes']),
            'profile_codes_after': after_w5['codes'],
            'locator_missing': missing,
            'kernel_read_state': gate.dispatch_once('kernel.read', profile, binding,
                                                    gate.READ_ARGS)['status'],
        },
        'notes': [
            'the boot binding removes the boot reason, never the firmware facts reason',
            'kernel.read stays OPERATION_DEFERRED while its locator is pending: the boot binding '
            'does not unlock it and no workaround is applied',
        ],
    }
    report['checks'] = {
        'boot_reason_gone_after_binding': not any('BOOT' in c for c in after_w5['codes']),
        'profile_reason_before_binding': any('BOOT' in c for c in before_w5['codes']),
        'locator_missing_survives_binding': bool(missing['w5_codes']) and
                                            missing['locator_ref'] is None,
        'kernel_read_still_deferred':
            gate.dispatch_once('kernel.read', profile, binding, gate.READ_ARGS)['status'] != 'OK',
    }
    return report


def main(argv: list[str]) -> int:
    sec, usec = 1_789_910_256, 860_896
    if '--boottime' in argv:
        index = argv.index('--boottime')
        raw = argv[index + 1]
        sec, usec = (int(part) for part in raw.split('.'))
    out = None
    if '--json' in argv:
        out = pathlib.Path(argv[argv.index('--json') + 1])
    report = build_report(sec=sec, usec=usec)
    if out is not None:
        out.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'boot_id': report['boot_binding']['boot_id'],
                      'before_codes': report['before']['w5']['codes'],
                      'after_codes': report['after']['w5']['codes'],
                      'locator_missing': report['remaining']['locator_missing'],
                      'kernel_read_state': report['remaining']['kernel_read_state'],
                      'checks': report['checks']}, indent=1))
    return 0 if all(report['checks'].values()) else 1


if __name__ == '__main__':                                # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
