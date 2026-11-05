"""W17E §1: the two kernel schemas stay isolated, and the op count is exactly 37.

kernel.read keeps region_index/offset/length; kernel.snapshot takes recipe_ref plus
bounded indices. Neither request shape may be accepted by the other operation, and
neither may drift through a shared schema object.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from core.rpc.registry import default_registry
from tools.primitive_iface import validate as V
from tools.primitive_iface.schema import OPS_BY_NAME

REPO = Path(__file__).resolve().parents[1]
OPTABLE = REPO / "native" / "target" / "ps4rf_optable_data.h"


def _verdict(op: str, arguments: dict) -> str:
    """PASS when the generated validator accepts; REJECT for a raise or an error list."""
    try:
        result = V.validate_arguments(op, arguments)
    except Exception:
        return "REJECT"
    return "REJECT" if result else "PASS"


def _args_of(op: str) -> tuple:
    return tuple(f.name for f in OPS_BY_NAME[op].args)


def test_kernel_read_schema_is_unchanged():
    assert _args_of("kernel.read") == ("region_index", "offset", "length")
    assert _verdict("kernel.read", {"region_index": 0, "offset": 0, "length": 16}) == "PASS"


@pytest.mark.xfail(reason="W17E R5 pending: the kernel.snapshot args revision must land together "
                          "with the W15 release/index-bound/response-form machinery", strict=True)
def test_kernel_snapshot_schema_is_the_recipe_form():
    assert _args_of("kernel.snapshot") == ("recipe_ref", "indices")
    assert _verdict("kernel.snapshot", {"recipe_ref": "q6-recipe-v3"}) == "PASS"
    assert _verdict("kernel.snapshot",
                    {"recipe_ref": "own1-recipe-v2", "indices": [0, 0]}) == "PASS"


@pytest.mark.xfail(reason="W17E R5 pending (same revision as above)", strict=True)
def test_cross_shapes_are_rejected():
    # the old explicit range form is gone: no raw address interface
    assert _verdict("kernel.snapshot", {"range": "explicit", "addr": 0xFFFFFF8000000000,
                                       "size": 16}) == "REJECT"
    # region/offset/length belong to kernel.read only
    assert _verdict("kernel.snapshot", {"region_index": 0, "offset": 0, "length": 16}) == "REJECT"
    # and a bare recipe_ref is never a kernel.read request
    assert _verdict("kernel.read", {"recipe_ref": "q6-recipe-v3"}) == "REJECT"
    assert _verdict("kernel.read", {"addr": 0xFFFFFF8000000000, "size": 16}) == "REJECT"


def test_the_two_schemas_are_separate_objects():
    read_op = OPS_BY_NAME["kernel.read"]
    snap_op = OPS_BY_NAME["kernel.snapshot"]
    assert read_op is not snap_op
    assert read_op.args is not snap_op.args
    assert read_op.args != snap_op.args


@pytest.mark.xfail(reason="W17E R5 pending: today 36 operations, kernel.snapshot still aliases "
                          "kernel.read in the frozen registry", strict=True)
def test_operation_count_is_exactly_37():
    registry = default_registry()
    ops = {op for op in OPS_BY_NAME}
    assert len(ops) == 37, sorted(ops)
    for op in ops:
        assert registry.has(op), f"{op} missing from the frozen registry"
    header = OPTABLE.read_text()
    assert "#define PS4RF_OP_TABLE_COUNT 37u" in header
    assert "#define PS4RF_OP_WIRED_COUNT 19u" in header
    assert "#define PS4RF_OP_DEFERRED_COUNT 18u" in header
    rows = [l for l in header.splitlines()
            if l.strip().startswith("{") and "PS4RF_TARGET_" in l]
    assert len(rows) == 37, "the generated table must carry exactly 37 rows"
    wired = [l for l in rows if "PS4RF_TARGET_WIRED" in l]
    assert len(wired) == 19, len(wired)


def test_new_operation_is_wired_but_never_on_the_agent_session_loop():
    header = OPTABLE.read_text()
    assert 'ioctl.invoke' in header, 'the new ioctl operation must be in the generated tables'
    assert 'kernel.snapshot.recipe' in header, 'the new recipe operation must be in the generated tables'
    assert 'kernel.snapshot' in header
    agent = (REPO / "native" / "target" / "ps4rfd_target.c").read_text()
    import re
    code = re.sub(r"/\*.*?\*/", " ", agent, flags=re.S)
    for op in ("ioctl.invoke", "kernel.snapshot"):
        assert op not in code.replace(op + ".h", ""), f"the agent session loop must not name {op}"
