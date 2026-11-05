"""W11 -- canonical boot binding for PS4RF (offline definition, then live use).

One algorithm, exactly as the W11 order defines it:

.. code-block:: text

    canonical object = {
        "schema":         "ps4rf.boot-binding.v1",
        "platform":       "orbis",
        "profile_sha256": "<real profile hash>",
        "boottime":       {"sec": <int>, "usec": <int>}
    }
    boot_digest = SHA256(JCS(canonical object))
    public id   = "BOOT-" + first 16 lowercase hex of the digest

The full digest travels in the runtime evidence; only the short id is used for binding comparisons.
No pid, no session id, no agent start time and no random value enters the object, and nothing secret
does either.

Source of ``boottime``: the userland sysctl read of ``KERN_BOOTTIME``
(``sysctl({CTL_KERN=1, KERN_BOOTTIME=21}, 2, buf, &len, NULL, 0)``), i.e. the ``struct timeval`` the
kernel initialises once per boot (W10-F7: the timeval is the boot instant; ``time_second`` and
``time_uptime`` are not). No kernel address is read, no RVA is sent to the host, and no ``kexec`` is
used for the boot identity.

Validity (fail closed, no fallback to a random or session derived id):

* ``sec <= 0`` -- uninitialised timeval
* ``usec < 0`` or ``usec >= 1e6`` -- not a valid struct timeval field
* boottime after the console's own wall clock (same clock, so no skew in play)
* plausibility floor (before 2001) plus a generous host-side skew window
* missing ``profile_sha256``, or a target identity that does not match the profile
  (the platform comparison is case-normalised, see finding W10-F1)
* the sysctl read itself failed -- the caller reports *no* boottime, never a guess

A simulated second boot exists only for offline tests and is always labelled
:data:`LABEL_SIMULATED_REBOOT_VECTOR`; it must never be presented as a measured reboot and never
enters live evidence or profile provenance.
"""

from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass

REPO_ROOT = __import__('pathlib').Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:                      # pragma: no cover - import bootstrap
    sys.path.insert(0, str(REPO_ROOT))

from core.canonical import canonical_sha256  # noqa: E402

BOOT_BINDING_SCHEMA = 'ps4rf.boot-binding.v1'
BOOT_ID_PREFIX = 'BOOT-'
BOOT_ID_HEX_CHARS = 16           # deliberate truncation: the established binding format
PLATFORM = 'orbis'               # canonical (lowercase) platform value inside the digest object

SOURCE_KERN_BOOTTIME = 'sysctl:kern.boottime'
MIB = (1, 21)                    # CTL_KERN, KERN_BOOTTIME
LABEL_SIMULATED_REBOOT_VECTOR = 'SIMULATED_REBOOT_VECTOR'
LABEL_TEST_BOOT_ID = 'TEST_BOOT_ID'

MIN_BOOTTIME_EPOCH = 1_000_000_000          # 2001-09-09; every FW13.52 boot is far later
MAX_USEC = 999_999
HOST_SKEW_SECONDS = 300                     # host clock may be off by minutes without mattering

#: what may never be used as the boot identity, with the reason (machine readable, tested)
FORBIDDEN_SOURCES = (
    ('session_id', 'per-session, not per-boot: two sessions in one boot would differ'),
    ('payload_id', 'delivery artefact identity, unrelated to the boot instance'),
    ('pid', 'per-process, reused freely within a boot'),
    ('agent_start_time', 'per-process start, not the boot instant'),
    ('random_value', 'not reproducible: the same boot would produce two identities'),
    ('profile_sha256_alone', 'identifies the firmware facts, not the boot instance'),
    ('firmware_version_alone', 'identical across every boot of this firmware'),
    ('kbase_slide_alone', 'secondary discriminator only: stated as insufficient on its own'),
    ('time_second_or_time_uptime', 'both change every second within a boot (finding W10-F7)'),
)


class BootIdError(Exception):
    """The inputs cannot form a boot identity (fail closed)."""


@dataclass(frozen=True)
class BootTime:
    """The raw ``struct timeval`` as the console reports it."""

    sec: int
    usec: int
    source: str = SOURCE_KERN_BOOTTIME

    def problems(self, *, console_now: int | None = None, host_now: int | None = None) -> list[str]:
        out: list[str] = []
        if self.source != SOURCE_KERN_BOOTTIME:
            out.append(f'source {self.source!r} is not an accepted boot instant source')
        if not isinstance(self.sec, int) or isinstance(self.sec, bool):
            out.append('sec must be an integer')
        elif self.sec <= 0:
            out.append('sec <= 0 means the timeval is not initialised; refusing it')
        elif self.sec < MIN_BOOTTIME_EPOCH:
            out.append(f'sec {self.sec} predates any FW13.52 boot')
        if not isinstance(self.usec, int) or isinstance(self.usec, bool):
            out.append('usec must be an integer')
        elif not 0 <= self.usec <= MAX_USEC:
            out.append(f'usec {self.usec} is outside 0..{MAX_USEC}')
        if console_now is not None and isinstance(self.sec, int) and self.sec > console_now:
            out.append(f'boottime {self.sec} lies after the console wall clock {console_now}')
        if host_now is not None and isinstance(self.sec, int) and \
                self.sec > host_now + HOST_SKEW_SECONDS:
            out.append(f'boottime {self.sec} lies more than {HOST_SKEW_SECONDS}s in the future of '
                       f'the host clock {host_now}')
        return out


def canonical_platform(value: str | None) -> str:
    """Normalise the platform field for the digest object (finding W10-F1)."""
    if not value:
        raise BootIdError('platform is missing')
    text = str(value).strip().lower()
    if text not in ('orbis', 'ps4'):
        raise BootIdError(f'platform {value!r} is not an Orbis platform')
    return PLATFORM


def canonical_object(profile_sha256: str, boottime: BootTime, *, platform: str = PLATFORM) -> dict:
    """The exact object the digest is computed over: four keys, no additions."""
    if not isinstance(profile_sha256, str) or len(profile_sha256) != 64 or \
            any(ch not in '0123456789abcdef' for ch in profile_sha256.lower()):
        raise BootIdError('profile_sha256 must be a 64 hex character digest')
    if boottime.problems():
        raise BootIdError('; '.join(boottime.problems()))
    return {
        'schema': BOOT_BINDING_SCHEMA,
        'platform': canonical_platform(platform),
        'profile_sha256': profile_sha256.lower(),
        'boottime': {'sec': int(boottime.sec), 'usec': int(boottime.usec)},
    }


def derive_boot_id(profile_sha256: str, boottime: BootTime, *, platform: str = PLATFORM,
                   profile: dict | None = None, console_now: int | None = None,
                   host_now: int | None = None) -> dict:
    """Derive the boot identity. Deterministic; no secrets, no fallbacks."""
    problems = boottime.problems(console_now=console_now, host_now=host_now)
    if problems:
        raise BootIdError('; '.join(problems))
    if profile is not None:
        target = profile.get('target') or {}
        profile_platform = target.get('platform')
        if canonical_platform(profile_platform) != canonical_platform(platform):
            raise BootIdError(f'target identity mismatch: profile is {profile_platform!r}, console '
                              f'reports {platform!r}')
        declared = profile.get('canonical_sha256')
        if declared and declared != profile_sha256:
            raise BootIdError('profile hash does not match the profile document')
    obj = canonical_object(profile_sha256, boottime, platform=platform)
    digest = canonical_sha256(obj)
    return {
        'schema': BOOT_BINDING_SCHEMA,
        'boot_id': BOOT_ID_PREFIX + digest[:BOOT_ID_HEX_CHARS],
        'boot_digest': digest,
        'boot_id_hex_chars': BOOT_ID_HEX_CHARS,
        'source': boottime.source,
        'canonical_object': obj,
        'raw_timeval': {'sec': int(boottime.sec), 'usec': int(boottime.usec)},
        'no_secret_inputs': True,
        'note': ('boot_id is the first %d lowercase hex of SHA256(JCS(canonical object)); the full '
                 'digest is stored in the runtime evidence and never written into a persistent '
                 'profile' % BOOT_ID_HEX_CHARS),
    }


def stability_problems(first: BootTime, second: BootTime) -> list[str]:
    """Both reads inside one session must be byte identical, or the source is not stable."""
    out: list[str] = []
    if (first.sec, first.usec) != (second.sec, second.usec):
        out.append('BOOT_SOURCE_NOT_STABLE: read1 %d.%d != read2 %d.%d'
                   % (first.sec, first.usec, second.sec, second.usec))
    return out


def simulated_reboot_vector(profile_sha256: str, boottime: BootTime, *, seconds: int = 3600,
                            platform: str = PLATFORM) -> dict:
    """A *simulated* second boot for offline tests only (never a measured reboot)."""
    shifted = BootTime(boottime.sec + int(seconds), boottime.usec, boottime.source)
    derived = derive_boot_id(profile_sha256, shifted, platform=platform)
    derived['label'] = LABEL_SIMULATED_REBOOT_VECTOR
    derived['note'] = ('simulated vector: the same timeval shifted by %d s. This is NOT a measured '
                       'second boot and must not be reported as one, and it must never enter live '
                       'evidence or profile provenance.' % int(seconds))
    return derived


def w10_draft_boot_id(target_identity: dict, boottime: BootTime) -> str:
    """The withdrawn W10 draft derivation, kept only to show how the earlier string was produced.

    The draft folded the target identity (platform/architecture/firmware/model/slide) into the
    digest and used the schema id ``ps4rf.bootid.v1``. W11 replaces it with the object above: the
    algorithm is authoritative, the old string is not.
    """
    previous = {
        'schema': 'ps4rf.bootid.v1',
        'target': {key: target_identity.get(key) for key in
                   ('platform', 'architecture', 'firmware_version', 'firmware_build_id',
                    'model_family', 'hardware_revision', 'profile_sha256')
                   if target_identity.get(key) is not None},
        'boot_instance': {'source': boottime.source, 'boottime_sec': int(boottime.sec),
                          'boottime_usec': int(boottime.usec)},
    }
    digest = canonical_sha256(previous)
    return BOOT_ID_PREFIX + digest[:BOOT_ID_HEX_CHARS]


def _self_test() -> list[str]:
    problems: list[str] = []
    now = 1_800_000_000                       # fixed clock: determinism in the self-test
    profile_sha = 'a' * 64
    good = BootTime(1_789_910_256, 860_896)
    result = derive_boot_id(profile_sha, good, console_now=now, host_now=now)
    if result['boot_id'] != 'BOOT-' + result['boot_digest'][:BOOT_ID_HEX_CHARS]:
        problems.append('boot id does not follow BOOT-<16 lowercase hex>')
    if result['boot_id'][len(BOOT_ID_PREFIX):] != result['boot_id'][len(BOOT_ID_PREFIX):].lower():
        problems.append('the hex part of the boot id must be lowercase')
    if sorted(result['canonical_object']) != ['boottime', 'platform', 'profile_sha256', 'schema']:
        problems.append(f'unexpected canonical keys: {sorted(result["canonical_object"])}')
    if result['canonical_object']['boottime'] != {'sec': 1_789_910_256, 'usec': 860_896}:
        problems.append('canonical object does not carry the raw timeval')
    if result['canonical_object']['schema'] != 'ps4rf.boot-binding.v1':
        problems.append('wrong schema id')
    if result['canonical_object']['platform'] != 'orbis':
        problems.append('platform must be canonical lower case orbis')
    if derive_boot_id(profile_sha, good, console_now=now, host_now=now)['boot_digest'] != \
            result['boot_digest']:
        problems.append('derivation is not deterministic')
    if canonical_platform('ORBIS') != 'orbis':
        problems.append('platform normalisation failed')
    try:
        derive_boot_id(profile_sha, good, platform='x86', profile={'target': {'platform': 'ORBIS'}})
        problems.append('a platform mismatch was not refused')
    except BootIdError:
        pass
    if stability_problems(good, BootTime(good.sec, good.usec)):
        problems.append('identical reads must be stable')
    if not stability_problems(good, BootTime(good.sec, good.usec + 1)):
        problems.append('a drifting source was not caught')
    vector = simulated_reboot_vector(profile_sha, good)
    if vector.get('label') != LABEL_SIMULATED_REBOOT_VECTOR:
        problems.append('simulated reboot vector is not labelled')
    if vector['boot_id'] == result['boot_id']:
        problems.append('simulated reboot vector is not distinct from the measured boot')
    for bad in (BootTime(0, 0), BootTime(-5, 0), BootTime(500_000_000, 0),
                BootTime(good.sec, -1), BootTime(good.sec, 1_000_000),
                BootTime(good.sec, good.usec, source='random-value')):
        try:
            derive_boot_id(profile_sha, bad, console_now=now, host_now=now)
            problems.append(f'invalid timeval accepted: {bad}')
        except BootIdError:
            pass
    try:
        derive_boot_id(profile_sha, BootTime(good.sec + 10, good.usec), console_now=good.sec)
        problems.append('a boottime after the console clock was accepted')
    except BootIdError:
        pass
    for bad_hash in ('', 'abc', 'z' * 64):
        try:
            derive_boot_id(bad_hash, good)
            problems.append(f'invalid profile hash accepted: {bad_hash!r}')
        except BootIdError:
            pass
    try:
        derive_boot_id(profile_sha, good, profile={'target': {'platform': 'ORBIS'},
                                                  'canonical_sha256': 'b' * 64})
        problems.append('a profile hash mismatch was not refused')
    except BootIdError:
        pass
    text = json.dumps(result['canonical_object'], sort_keys=True)
    for needle in ('pid', 'session', 'random', 'nonce', 'secret'):
        if needle in text:
            problems.append(f'canonical object contains {needle!r}')
    return problems


def self_test() -> list[str]:
    """Public alias for the CLI self-test (used by the regression suite)."""
    return _self_test()


def main(argv: list[str]) -> int:
    if '--self-test' in argv:
        problems = _self_test()
        for problem in problems:
            print(f'bootid: {problem}')
        print(f'bootid self-test: {"ok" if not problems else "FAILED"}')
        return 0 if not problems else 1
    if '--derive' in argv:
        index = argv.index('--derive')
        sec, usec, profile_sha = int(argv[index + 1]), int(argv[index + 2]), argv[index + 3]
        shown = derive_boot_id(profile_sha, BootTime(sec, usec), host_now=int(time.time()))
        print(json.dumps(shown, indent=2, sort_keys=True))
        return 0
    print('usage: bootid.py --self-test | --derive <sec> <usec> <profile_sha256>')
    return 2


if __name__ == '__main__':                                # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
