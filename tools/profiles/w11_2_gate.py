"""W11.2 gate report: what the privileged boot read resolves and what stays deferred.

Runs the same W4/W5/W7 gate path as W10/W11 -- once *before* a runtime binding exists and once
*after* the privileged read produced one -- and states the remaining gates exactly, in particular
that ``kernel.read`` stays ``OPERATION_DEFERRED``: the boot identity closes the boot-binding
reason, not the missing locator. No capability is promoted automatically by this wave.

The value used for the offline run is an **offline stand-in**, clearly labelled as such
(``OFFLINE_STANDIN_BOOT``): it is the pinned W10 capture instant, not a live console measurement.
The live W11.2 run must produce its own, freshly measured instant, and the gate is re-run with it.
"""

from __future__ import annotations

import json
import pathlib
import re
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

# The one frozen source of the privileged read is *not* repeated here: it is read out of the
# privileged module, so the gate can never disagree with the payload about the region.
_MODULE = (REPO_ROOT / 'native' / 'target' / 'ps4rf_bootread.c').read_text()
_SOURCE_DEFINE = re.search(r'#define PS4RF_BOOTREAD_SOURCE_RVA (0x[0-9A-Fa-f]+)u', _MODULE)
_LENGTH_DEFINE = re.search(r'#define PS4RF_BOOTREAD_READ_LEN (\d+)u',
                           (REPO_ROOT / 'native' / 'target' / 'ps4rf_bootread.h').read_text())
SOURCE_RVA = int(_SOURCE_DEFINE.group(1), 16) if _SOURCE_DEFINE else 0
READ_LENGTH = int(_LENGTH_DEFINE.group(1)) if _LENGTH_DEFINE else 0


def build_report(*, sec: int, usec: int, label: str = LABEL_OFFLINE,
                 event_outcome: str = 'OK', profile_path: pathlib.Path = PROFILE_PATH) -> dict:
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
        'wave': 'W11.2',
        'label': label,
        'profile_sha256': sha,
        'event_outcome': event_outcome,
        'source': {'rva': hex(SOURCE_RVA), 'length': READ_LENGTH, 'read_only': True,
                   'single_callback': True, 'writes': [], 'retry': False,
                   'host_supplied_address_or_length': False},
        'derived': derived,
        'binding_view': {
            'boot_id': derived['boot_id'], 'profile_sha256': sha,
            'source_event': 'boot.binding.privileged', 'source_rva': hex(SOURCE_RVA),
            'read_length': READ_LENGTH,
        },
        'before': {
            'w4': gate.w4('kernel.read', None),
            'w5': before_w5,
            'w7': gate.dispatch_once('kernel.read', profile, None, gate.READ_ARGS),
        },
        'after': {
            'w4': gate.w4('kernel.read', {'profile_sha256': sha, 'boot_id': derived['boot_id']}),
            'w5': after_w5,
            'w7': gate.dispatch_once('kernel.read', profile, binding, gate.READ_ARGS),
        },
        'kernel_read_still_deferred': missing,
        'checks': {
            'boot_binding_reason_before': [c for c in before_w5['codes'] if 'BOOT' in c],
            'boot_binding_reason_gone_after': not any('BOOT' in c for c in after_w5['codes']),
            'kernel_read_locator_missing_survives': bool(missing['w5_codes']) and
                                                   any('LOCATOR' in d.upper()
                                                       for d in missing['w5_detail']),
            'no_capability_promotion': not any('BOOT' in c for c in after_w5['codes']) and
                                       any('OPERATION_DEFERRED' in c or 'LOCATOR' in c.upper()
                                           for c in missing['w5_codes'] + missing['w5_detail']),
            'binding_binds_exactly_this_profile': binding.profile_sha256 == sha,
            'label_is_not_a_measured_boot': label != LABEL_MEASURED or event_outcome == 'OK',
        },
    }
    return report


def main(argv: list[str]) -> int:
    sec = 1789910256
    usec = 860896
    label = LABEL_OFFLINE
    outcome = 'OK'
    args = list(argv[1:])
    while args:
        flag = args.pop(0)
        if flag == '--sec':
            sec = int(args.pop(0))
        elif flag == '--usec':
            usec = int(args.pop(0))
        elif flag == '--label':
            label = args.pop(0)
        elif flag == '--outcome':
            outcome = args.pop(0)
        else:
            print(f'unknown flag {flag!r}', file=sys.stderr)
            return 2
    report = build_report(sec=sec, usec=usec, label=label, event_outcome=outcome)
    print(json.dumps(report, indent=1))
    checks = report['checks']
    ok = (checks['boot_binding_reason_gone_after'] and
          checks['kernel_read_locator_missing_survives'] and
          checks['no_capability_promotion'] and
          checks['binding_binds_exactly_this_profile'])
    print(f"# w11.2 gate: {'PASS' if ok else 'FAIL'} "
          f"(boot reason before {checks['boot_binding_reason_before']}, "
          f"after {report['after']['w5']['codes']})")
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
