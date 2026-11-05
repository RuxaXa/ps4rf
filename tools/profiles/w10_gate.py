"""W10 -- gate report before and after the profile promotion (offline, read-only).

Answers the owner's questions in one machine-readable document:

* W5 before: the W5 fixture (structurally matchable, not evidence-backed)
* W5 after: the promoted real profile -- evidence-backed, and PROFILE_MATCH as soon as a boot
  binding exists (demonstrated with a clearly labelled simulated boot id, because the W9 live run
  measured no boot instant: BOOT_ID_UNVERIFIED remains the one hard blocker)
* W5 reboot semantics: a binding from one boot is invalid in another while the profile facts stay
* W5 gated operation: an operation whose locator this profile does not evidence refuses with
  LOCATOR_MISSING (no workaround, no invented values)
* W4 before/after: the gate decision for a privileged operation plus its reasons
* W7 before/after: the dispatch result -- privileged providers stay deferred, no provider entry
* boot identity: the captured boot instant, two derived boot ids and the reboot tags

Usage::

    python tools/profiles/w10_gate.py --promoted profiles/fw1352/profile-13.52.json \\
        --w9-evidence <live-evidence.json> [--json out.json]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import struct
import sys
import time

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:                       # pragma: no cover - import bootstrap
    sys.path.insert(0, str(REPO_ROOT))

from tools.dispatch.dispatch import Dispatcher                              # noqa: E402
from tools.primitive_iface.gate import GateContext, gate_for                # noqa: E402
from tools.profiles import bootid                                            # noqa: E402
from tools.profiles.promotion import platform_constants                     # noqa: E402
from tools.profiles.binding import BootBinding                               # noqa: E402
from tools.profiles.schema import (                                          # noqa: E402
    LocatorRequest, canonical_profile_sha256, profile_preconditions,
)

FIXTURE = REPO_ROOT / 'tests/fixtures/profiles/fw1352-fixture.json'
PINNED_KERNEL = pathlib.Path.home() / (
    'audits/playstation-ps4/fw1352-ps4b-20260920/kernel-dump/kernel.bin')
SIM_BOOT = 'BOOT-0000000000000000'
#: a deliberately non-kernel address: the request is refused by the gate, not by argument shape
READ_ARGS = {'region_index': 1, 'offset': 0, 'length': 8}


def read_capture_boot_instant() -> dict:
    rva = platform_constants()['boottime_rva']     # recorded in the boot identity artefact
    with PINNED_KERNEL.open('rb') as handle:
        handle.seek(rva)
        raw = handle.read(16)
    sec, usec = struct.unpack('<QQ', raw)
    return {'rva': f'0x{rva:x}', 'boottime_sec': sec, 'boottime_usec': usec,
            'raw_hex': raw.hex(),
            'note': 'struct timeval of the boot the pinned image was captured in'}


def w5(doc: dict | None, **kwargs) -> dict:
    verdict = profile_preconditions(doc, **kwargs)
    return {'codes': list(verdict.codes), 'details': list(verdict.details),
            'matched': bool(verdict.matched), 'evidence_backed': bool(verdict.evidence_backed),
            'profile_sha256': verdict.profile_sha256}


def w4(root_op: str, profile_binding: dict | None, *, wire: str = 'ps4rfd-native-stub') -> dict:
    ctx = GateContext(profile_binding=profile_binding, session_state='ACTIVE', provider=wire)
    decision = gate_for(root_op, ctx)
    result = {name: getattr(decision, name) for name in
              ('op', 'decision', 'executable', 'wire_code', 'next_action')}
    result['reasons'] = list(decision.reasons)
    result['details'] = list(decision.details)
    return result


def dispatch_once(root_op: str, profile: dict | None, boot_binding=None,
                  arguments: dict | None = None) -> dict:
    dispatcher = Dispatcher(run_id='RUN-w10-gate', session_id='SES-w10-gate',
                            boot_id=SIM_BOOT, profile=profile, boot_binding=boot_binding,
                            require_evidence_backed=True)
    arguments = dict(arguments or {})
    binding = dispatcher.profile_binding_for(root_op)
    # REQ- ids are 32 hex chars by contract (tools/primitive_iface/validate.py)
    request_id = 'REQ-' + hashlib.sha256(f'w10-gate:{root_op}:{bool(profile)}'.encode()).hexdigest()[:32]
    result = dispatcher.dispatch({'header': {'request_id': request_id},
                                 'body': {'operation': root_op, 'arguments': arguments, 'seq': 1}})
    return {'status': result.get('status'),
            'error_code': (result.get('error') or {}).get('code'),
            'provider_entry': result.get('provider_entry'),
            'provider_state': result.get('provider_state'),
            'stopped_at': result.get('stopped_at'),
            'profile_binding': binding,
            'evidence_tail': dispatcher.evidence_records()[-1:] or []}


def _w4_summary(entry: dict) -> dict:
    tail = (entry.get('evidence_tail') or [{}])[-1]
    return {'status': entry['status'], 'error_code': entry['error_code'],
            'selected_provider': tail.get('selected_provider'),
            'provider_entry': tail.get('provider_entry'),
            'stopped_at': tail.get('stopped_at'),
            'w4_decision': tail.get('w4_decision'), 'w4_reasons': tail.get('w4_reasons')}


def build_report(promoted_path: pathlib.Path, w9_evidence: pathlib.Path) -> dict:
    fixture = json.loads(FIXTURE.read_text())
    promoted = json.loads(promoted_path.read_text())
    promoted_path = promoted_path.resolve()
    capture = read_capture_boot_instant()
    sha = canonical_profile_sha256(promoted)
    host_now = int(time.time())
    measured = bootid.BootTime(capture['boottime_sec'], capture['boottime_usec'])
    derived = bootid.derive_boot_id(sha, measured, profile=promoted, console_now=host_now,
                                    host_now=host_now)
    vector = bootid.simulated_reboot_vector(sha, measured)
    # two bindings: one for the "a valid binding exists" demonstration (labelled simulated,
    # because no live boot id exists yet) and the one that belongs to the captured boot, to show
    # that it is invalid for a *simulated* different boot (never presented as a measurement)
    binding_valid = BootBinding.from_profile(promoted, SIM_BOOT)
    binding_capture_boot = BootBinding.from_profile(promoted, derived['boot_id'])
    gated_request = (LocatorRequest('kernel.read', module='kernel'),)

    return {
        'schema': 'ps4rf.w10.gate-report.v1',
        'fixture_profile': {
            'path': str(FIXTURE.relative_to(REPO_ROOT)),
            'sha256': canonical_profile_sha256(fixture),
            'w5': w5(fixture)},
        'promoted_profile': {
            'path': str(promoted_path.relative_to(REPO_ROOT)),
            'sha256': sha,
            'w5_no_binding': w5(promoted),
            'w5_simulated_binding': w5(promoted, boot_binding=binding_valid,
                                       current_boot_id=SIM_BOOT,
                                       expected_target=promoted['target']),
            'w5_against_simulated_reboot_vector': w5(promoted, boot_binding=binding_capture_boot,
                                                     current_boot_id=vector['boot_id'],
                                                     expected_target=promoted['target']),
            'w5_gated_op_no_locator': w5(promoted, requests=gated_request,
                                         boot_binding=binding_valid, current_boot_id=SIM_BOOT,
                                         expected_target=promoted['target'])},
        'w4': {'before': w4('kernel.read', None),
               'after': w4('kernel.read',
                           dispatch_once('kernel.read', promoted, binding_valid)
                           ['profile_binding'])},
        'w7': {'before': dispatch_once('kernel.read', None, arguments=READ_ARGS),
               'after': dispatch_once('kernel.read', promoted, binding_valid,
                                      arguments=READ_ARGS)},
        'boot_identity': {
            'algorithm': bootid.BOOT_BINDING_SCHEMA,
            'capture_boot_instant': capture,
            'boot_binding': derived,
            'binding_from_capture_boot': {'boot_id': binding_capture_boot.boot_id,
                                          'profile_sha256': binding_capture_boot.profile_sha256,
                                          'valid_for_simulated_vector': binding_capture_boot.valid_for(
                                              vector['boot_id'], sha)},
            'simulated_reboot_vector': vector,
            'stability_note': ('offline: the pinned capture holds one sample; the live collector '
                               'reads twice inside one session and must see identical bytes '
                               '(BOOT_SOURCE_NOT_STABLE otherwise)'),
            'note': ('demonstration only: the W9 live run read no boot instant, so no boot id can '
                     'be bound yet -- BOOT_ID_UNVERIFIED stands and privileged providers stay '
                     'deferred. The vector above is a SIMULATED_REBOOT_VECTOR (never a measured '
                     'second boot) and is excluded from live evidence and profile provenance.'),
            'forbidden_sources': [{'source': name, 'why': why}
                                  for name, why in bootid.FORBIDDEN_SOURCES]},
        'w9_evidence': str(w9_evidence),
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description='W10 gate report (offline)')
    parser.add_argument('--promoted', type=pathlib.Path, required=True)
    parser.add_argument('--w9-evidence', type=pathlib.Path, required=True)
    parser.add_argument('--json', dest='json_out', type=pathlib.Path)
    args = parser.parse_args(argv)
    report = build_report(args.promoted, args.w9_evidence)
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(text + '\n')
    print(text)
    return 0


if __name__ == '__main__':                                # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
