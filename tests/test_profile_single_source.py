"""W17F: both FW13.52 profile documents must cover the authoritative gated operations."""

from __future__ import annotations

import json
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.primitive_iface.gate import privilege_gated_ops  # noqa: E402
from tools.profiles.schema import empty_profile  # noqa: E402
from tools.research import classification as C  # noqa: E402

DOCS = (REPO_ROOT / "profiles/fw1352/profile-13.52.json",
        REPO_ROOT / "profiles/fw1352/profile-13.52-ccp1.json")


def test_classification_loads_the_promoted_representation_profile():
    assert C.PROFILE_PATH.resolve() == DOCS[0].resolve()


def test_every_document_covers_every_gated_operation():
    for path in DOCS:
        policy = json.loads(path.read_text())["operation_policy"]
        missing = sorted(set(privilege_gated_ops()) - set(policy))
        assert missing == [], "%s: %s" % (path.name, missing)


def test_policy_projection_matches_the_derived_matrix_projection():
    derived = empty_profile("projection")["operation_policy"]
    for path in DOCS:
        policy = json.loads(path.read_text())["operation_policy"]
        for op in privilege_gated_ops():
            if op not in policy:
                continue
            if op not in ("kernel.snapshot.recipe", "ioctl.invoke"):
                continue  # the representation and the candidate may differ for historical ops
            for key in ("profile_required", "profile_fields"):
                assert policy[op][key] == derived[op][key], "%s:%s:%s" % (path.name, op, key)
