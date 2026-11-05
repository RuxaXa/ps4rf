"""W11 regressions: the canonical boot binding algorithm and its reboot semantics (offline)."""

from __future__ import annotations

import json
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.profiles import bootid                                           # noqa: E402
from tools.profiles.binding import BootBinding                              # noqa: E402

NOW = 1_800_000_000
PROFILE_SHA = 'a' * 64
#: the profile identity the W10/W11 capture was taken under (recorded in
#: docs/P4-W10-PROFILE-PROMOTION.md and the transcribed W13 owner records). The promoted profile
#: document has been revised since (W17E added the two new primitives to its operation policy), so
#: its ``canonical_sha256`` is a *current* identity. A captured boot id is a historical record:
#: it is recomputed from the identity that was authoritative at capture time, never from the
#: current one -- otherwise every profile revision would silently rewrite live evidence.
CAPTURE_PROFILE_SHA_W11 = '4a6f575c8b1aa7906d7a86d08fe5cc4e5dc1a2939a2de19fac40c7fa82771766'
#: the W10 offline capture boot (struct timeval at RVA 0x224c6c8 of the pinned image)
CAPTURE_BOOT = bootid.BootTime(1_789_910_256, 860_896)
#: recalculated with the final W11 algorithm (ps4rf.boot-binding.v1). The earlier W10 draft string
#: BOOT-bd1e2729373fc597 came from the withdrawn derivation and is not a binding authority.
CAPTURE_BOOT_ID_W11 = 'BOOT-19d2c790b0769502'
CAPTURE_BOOT_DIGEST_W11 = \
    '19d2c790b076950231b428fd938cb70f9c82b2d754bffab3e62f33db8782fbad'


def test_bootid_self_test():
    assert bootid.self_test() == []


def test_canonical_object_is_exactly_the_defined_four_keys():
    result = bootid.derive_boot_id(PROFILE_SHA, CAPTURE_BOOT, host_now=NOW)
    obj = result['canonical_object']
    assert obj == {
        'schema': 'ps4rf.boot-binding.v1',
        'platform': 'orbis',
        'profile_sha256': PROFILE_SHA,
        'boottime': {'sec': CAPTURE_BOOT.sec, 'usec': CAPTURE_BOOT.usec},
    }, 'the digest object must be exactly the four agreed keys'
    assert result['boot_id'] == 'BOOT-' + result['boot_digest'][:16]
    assert result['boot_id'][5:] == result['boot_id'][5:].lower(), 'hex part must be lowercase'
    assert result['no_secret_inputs'] is True


def test_determinism_and_algorithm_change_are_documented():
    first = bootid.derive_boot_id(PROFILE_SHA, CAPTURE_BOOT, host_now=NOW)
    again = bootid.derive_boot_id(PROFILE_SHA, CAPTURE_BOOT, host_now=NOW)
    assert first['boot_digest'] == again['boot_digest']
    # the withdrawn draft derivation produced a different string for the same input
    draft = bootid.w10_draft_boot_id({'platform': 'ORBIS', 'profile_sha256': PROFILE_SHA},
                                     CAPTURE_BOOT)
    assert draft.startswith('BOOT-') and draft != first['boot_id']
    assert 'ps4rf.bootid.v1' not in json.dumps(first['canonical_object'])


def test_w10_capture_boot_id_is_recomputed_with_the_final_algorithm():
    """The recorded capture boot id, recomputed from the *historical* profile identity."""
    result = bootid.derive_boot_id(CAPTURE_PROFILE_SHA_W11, CAPTURE_BOOT, host_now=NOW)
    assert result['boot_id'] == CAPTURE_BOOT_ID_W11
    assert result['boot_digest'] == CAPTURE_BOOT_DIGEST_W11


def test_current_profile_identity_is_not_the_historical_capture_identity():
    """The current promoted profile is a *different* identity than the one the capture used.

    Both halves are derived (the current side from the promoted document itself), so this holds
    for every future profile revision without re-pinning a string, and a profile edit can never
    rewrite the historical record above.
    """
    path = REPO_ROOT / 'profiles' / 'fw1352' / 'profile-13.52.json'
    if not path.exists():
        pytest.skip('promoted profile not built in this workspace')
    profile = json.loads(path.read_text())
    assert profile['canonical_sha256'] != CAPTURE_PROFILE_SHA_W11, \
        'the profile identity moved back to a published historical value'
    current = bootid.derive_boot_id(profile['canonical_sha256'], CAPTURE_BOOT, profile=profile,
                                    host_now=NOW)
    assert current['boot_id'] != CAPTURE_BOOT_ID_W11
    assert current['boot_id'] == 'BOOT-' + current['boot_digest'][:16]


def test_two_reads_in_one_session_must_be_identical():
    assert bootid.stability_problems(CAPTURE_BOOT, bootid.BootTime(CAPTURE_BOOT.sec,
                                                                   CAPTURE_BOOT.usec)) == []
    problems = bootid.stability_problems(CAPTURE_BOOT,
                                         bootid.BootTime(CAPTURE_BOOT.sec, CAPTURE_BOOT.usec + 1))
    assert problems and 'BOOT_SOURCE_NOT_STABLE' in problems[0]


def test_simulated_vector_is_labelled_and_distinct():
    vector = bootid.simulated_reboot_vector(PROFILE_SHA, CAPTURE_BOOT)
    assert vector['label'] == 'SIMULATED_REBOOT_VECTOR'
    assert 'NOT a measured second boot' in vector['note']
    assert vector['boot_id'] != bootid.derive_boot_id(PROFILE_SHA, CAPTURE_BOOT,
                                                      host_now=NOW)['boot_id']


@pytest.mark.parametrize('bad', [
    bootid.BootTime(0, 0),                                  # not initialised
    bootid.BootTime(-5, 0),                                 # nonsense
    bootid.BootTime(500_000_000, 0),                        # before 2001
    bootid.BootTime(CAPTURE_BOOT.sec, -1),                  # usec < 0
    bootid.BootTime(CAPTURE_BOOT.sec, 1_000_000),           # usec too large
    bootid.BootTime(CAPTURE_BOOT.sec, 0, source='random-value'),
    bootid.BootTime(CAPTURE_BOOT.sec, 0, source='time_second'),
])
def test_invalid_inputs_fail_closed(bad):
    with pytest.raises(bootid.BootIdError):
        bootid.derive_boot_id(PROFILE_SHA, bad, host_now=NOW)


def test_boottime_in_the_future_of_the_console_clock_is_refused():
    with pytest.raises(bootid.BootIdError):
        bootid.derive_boot_id(PROFILE_SHA, bootid.BootTime(CAPTURE_BOOT.sec + 60,
                                                           CAPTURE_BOOT.usec),
                              console_now=CAPTURE_BOOT.sec)


@pytest.mark.parametrize('bad_hash', ['', 'abc', 'z' * 64])
def test_missing_or_malformed_profile_hash_is_refused(bad_hash):
    with pytest.raises(bootid.BootIdError):
        bootid.derive_boot_id(bad_hash, CAPTURE_BOOT, host_now=NOW)


def test_profile_identity_and_hash_must_match():
    profile = {'target': {'platform': 'ORBIS'}, 'canonical_sha256': PROFILE_SHA}
    ok = bootid.derive_boot_id(PROFILE_SHA, CAPTURE_BOOT, profile=profile, host_now=NOW)
    assert ok['boot_id'].startswith('BOOT-')
    with pytest.raises(bootid.BootIdError):
        bootid.derive_boot_id(PROFILE_SHA, CAPTURE_BOOT,
                              profile={'target': {'platform': 'ORBIS'},
                                       'canonical_sha256': 'b' * 64}, host_now=NOW)
    with pytest.raises(bootid.BootIdError):
        bootid.derive_boot_id(PROFILE_SHA, CAPTURE_BOOT, platform='x86',
                              profile={'target': {'platform': 'ORBIS'}}, host_now=NOW)


def test_forbidden_sources_cover_the_owner_list():
    names = {name for name, _why in bootid.FORBIDDEN_SOURCES}
    for required in ('session_id', 'payload_id', 'pid', 'agent_start_time', 'random_value',
                     'profile_sha256_alone', 'firmware_version_alone', 'kbase_slide_alone',
                     'time_second_or_time_uptime'):
        assert required in names, f'{required} must be documented as unusable'


def test_new_boot_id_invalidates_the_binding_but_facts_persist():
    binding = BootBinding(boot_id=CAPTURE_BOOT_ID_W11, profile_sha256=PROFILE_SHA)
    other = bootid.derive_boot_id(PROFILE_SHA, bootid.BootTime(CAPTURE_BOOT.sec + 3600,
                                                               CAPTURE_BOOT.usec), host_now=NOW)
    assert binding.valid_for(CAPTURE_BOOT_ID_W11, PROFILE_SHA) is True
    assert binding.valid_for(other['boot_id'], PROFILE_SHA) is False
    assert binding.facts_persistent is True
