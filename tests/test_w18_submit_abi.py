"""W18: the submit family's argument ABI, as the FW13.52 image defines it.

The live runs of the previous round answered every ``0xC0184401`` with EINVAL because the policy
named the block's *size* field as the pointer field: the provider replaced the size with the
address of its staging region, and the handler's round check (``(size + 0x3fff) & ~0x3fff ==
0x4000``) rejected it.

These tests pin the recovered ABI where it is enforced offline:

* the block is ``{ u64 cpuaddr@0x00, u64 size@0x08, u32 mode@0x10, u32 pad@0x14 }``;
* the declared pointer field is 0, it matches the target's generated policy, and the experiment
  leaves it zero so that the value the device sees can only come from the provider;
* a request size outside ``(0, 0x4000]`` and an argument mode outside the proven set are refused
  before anything reaches a device.

The provider's own staging behaviour (exactly one field overwritten, the size and mode bytes kept,
the staged address on the driver's 0x4000 boundary, the payload where the field points, and the
refusal of a staging region off that boundary) is proven by the compiled harness
``tests/harness/recipe_ioctl_offline.c``, which ``tests/test_recipe_ioctl_offline.py`` runs.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from tools.experiments import contracts as C
from tools.experiments import q6, tape
from tools.experiments.device import build_ioctl_blob, load_policy

REPO = Path(__file__).resolve().parents[1]
SUBMIT = 0xC0184401
SIZE_FIELD = 8
MODE_FIELD = 0x10
SIZE_ROUND = 0x4000


def test_the_block_layout_is_the_recovered_one():
    blob = build_ioctl_blob(load_policy(), SUBMIT, ptr=0x0, size=q6.BUFFER_LEN, mode=0)
    assert len(blob) == 24
    assert int.from_bytes(blob[0:8], "little") == 0x0            # the host's value for field 0
    assert int.from_bytes(blob[8:16], "little") == SIZE_ROUND    # the request size
    assert int.from_bytes(blob[16:20], "little") == 0            # the mode word
    assert blob[20:24] == b"\x00" * 4                            # padding


def test_the_builder_carries_a_host_value_in_field_zero_verbatim():
    value = 0x1122334455667788
    blob = build_ioctl_blob(load_policy(), SUBMIT, ptr=value, size=SIZE_ROUND, mode=0)
    assert int.from_bytes(blob[0:8], "little") == value


def test_the_experiment_submits_a_zero_pointer_and_the_proven_size():
    blob = build_ioctl_blob(load_policy(), SUBMIT, ptr=0x0, size=q6.BUFFER_LEN,
                            mode=q6.SUBMIT_MODE)
    assert int.from_bytes(blob[0:8], "little") == 0
    assert int.from_bytes(blob[8:16], "little") == SIZE_ROUND
    assert q6.SUBMIT_MODE == 0


def test_the_policy_declares_the_first_u64_as_the_pointer_field():
    policy = load_policy()
    pol = policy.command(SUBMIT)
    assert pol.size_field == SIZE_FIELD
    assert pol.size_round == SIZE_ROUND
    assert pol.mode_field == MODE_FIELD
    assert tuple(pol.blob_mode_values) == (0,)
    assert C.assert_no_raw_address  # the request may still not name an address


def test_the_declared_field_matches_the_target_policy_and_the_tape():
    header = (REPO / 'native/target/ps4rf_ioctl_policy_data.h').read_text()
    row = re.search(r'\{\s*0xC0184401u,\s*(\d+)u,\s*(\d+)u,\s*(\d+)u,\s*(\d+)u,\s*(\d+)u,\s*'
                    r'(0x[0-9a-fA-F]+)u\s*\}', header)
    assert row, 'the submit row is not in the expected shape'
    blob_len, out_len, mode_present, mode, ptr_field, data_max = row.groups()
    assert (blob_len, out_len) == ('24', '0')
    assert (mode_present, mode) == ('0', '0')
    assert ptr_field == '0', 'the provider must overwrite the block\'s first u64'
    assert data_max == hex(SIZE_ROUND)
    fixture = load_policy()
    assert int(ptr_field) == tape.POINTER_FIELD[SUBMIT] == 0
    assert fixture.command(SUBMIT).blob_len == int(blob_len)


@pytest.mark.parametrize('size', [0, SIZE_ROUND + 1, 2 * SIZE_ROUND, 0x10000])
def test_a_request_size_outside_the_boundary_is_refused(size):
    policy = load_policy()
    blob = build_ioctl_blob(policy, SUBMIT, ptr=0x0, size=size, mode=0)
    with pytest.raises(C.ContractError):
        policy.validate(SUBMIT, blob, None)


@pytest.mark.parametrize('size', [1, 0x1000, SIZE_ROUND])
def test_a_size_inside_the_boundary_is_accepted(size):
    policy = load_policy()
    blob = build_ioctl_blob(policy, SUBMIT, ptr=0x0, size=size, mode=0)
    assert policy.validate(SUBMIT, blob, None).command == SUBMIT


@pytest.mark.parametrize('mode', [1, 2, 3, 0xFFFFFFFF])
def test_an_argument_mode_outside_the_proven_set_is_refused(mode):
    policy = load_policy()
    blob = build_ioctl_blob(policy, SUBMIT, ptr=0x0, size=SIZE_ROUND, mode=mode)
    with pytest.raises(C.ContractError):
        policy.validate(SUBMIT, blob, None)


def test_the_unproven_trigger_command_keeps_its_own_layout():
    blob = build_ioctl_blob(load_policy(), 0xC0184404, ptr=0x10, length=0x20, mode=1)
    assert len(blob) == 24
    assert int.from_bytes(blob[0:2], "little") == 1
    assert int.from_bytes(blob[8:16], "little") == 0x10
    assert int.from_bytes(blob[16:24], "little") == 0x20


def test_the_contract_still_refuses_to_let_a_request_name_an_address():
    with pytest.raises(C.ContractError):
        C.assert_no_raw_address({'command': SUBMIT, 'addr': 0xffffffff998f4000})
