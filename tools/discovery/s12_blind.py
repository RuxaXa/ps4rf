"""P4: blind evaluation of the frozen D1/D4 rules.

The protocol is fixed *before* the run and is written into the output:

1. the detector sources and the fixture document are hashed, and the hash set is
   the frozen rule state; a different hash invalidates the evaluation;
2. the evaluation set is a reference family that was **not** used while the D1/D4
   rules were developed -- the PPPwn anchors.  That family's published claim is
   *not* an ownership claim (its stage1 uses those functions as ROP sites), so the
   correct blind answer is "no confirmed ownership defect here";
3. a control pair is evaluated in the same run: the reference matrix' known
   positive/negative labels for D1/D4, so "found nothing" cannot be confused with
   "detector does nothing";
4. nothing is changed after the numbers exist.  A miss and a false positive are
   both reported as results.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
from typing import Dict, List, Optional

from . import validate
from .patterns import (ScanContext, detect_table_slot_lifecycle,
                       detect_table_slot_lifecycle_legacy,
                       detect_use_after_release,
                       detect_use_after_release_legacy, FunctionView)
from .ownership import ROLE_ALLOC, ROLE_FREE, ROLE_REFCOUNT_RELEASE
from .s11 import discover_extent

DATA = pathlib.Path(__file__).resolve().parent / "data"
FROZEN_SOURCES = (
    "tools/discovery/memory.py",
    "tools/discovery/ownership.py",
    "tools/discovery/lifecycle.py",
    "tools/discovery/patterns.py",
    "tests/fixtures/discovery/lifecycle-fixtures.json",
    "tests/test_discovery_lifecycle.py",
)


def _sha(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def frozen_rules(root: pathlib.Path) -> Dict[str, str]:
    return {rel: _sha(root / rel) for rel in FROZEN_SOURCES if (root / rel).exists()}


def _evaluate_function(env, fw: str, rva: int, size: int, name: str) -> dict:
    image, index = env.images[fw], env.indexes[fw]
    catalog = env.ownership(fw)
    ctx = ScanContext(ownership=catalog)
    legacy_ctx = ScanContext.from_names({r.rva: r.name for r in index.named()})
    size = min(size, 0x4000)
    if size < 0x80:
        extent = discover_extent(image, rva, cap=0x1400)
        size = max(size, min(extent.size, 0x1400))
    view = FunctionView(image, rva, size, name, strict_cfg=True)
    findings = detect_use_after_release(view, ctx) + detect_table_slot_lifecycle(view, ctx)
    run = getattr(view, "_lifecycle_run", None)
    plain = FunctionView(image, rva, size, name)
    legacy = (detect_use_after_release_legacy(plain, legacy_ctx)
              + detect_table_slot_lifecycle_legacy(plain, legacy_ctx))
    return {
        "function": hex(rva),
        "name": name or "",
        "analysed_bytes": size,
        "confirmed_findings": [f.as_dict() for f in findings],
        "legacy_findings": [f.as_dict() for f in legacy],
        "legacy_count": len(legacy),
        "observation_count": len(ctx.observations),
        "observations": ctx.observations[:6],
        "stats": run.defect_stats() if run is not None else None,
    }


def run(root: pathlib.Path = pathlib.Path(".")) -> dict:
    env = validate.Environment.load(str(DATA))
    references = json.loads((DATA / "families" / "references.json").read_text(encoding="utf-8"))
    rows = references["assertions"]

    blind = []
    for row in rows:
        if not row["id"].startswith("pppwn"):
            continue
        fw = row["firmware"]
        rva = int(row["rva"], 16)
        rec = env.indexes[fw].containing(rva) or env.indexes[fw].get(rva)
        if rec is None:
            blind.append({"anchor": row["id"], "firmware": fw, "status": "NO_CONTAINING_FUNCTION"})
            continue
        result = _evaluate_function(env, fw, rec.rva, rec.size, rec.name)
        result.update({
            "anchor": row["id"],
            "anchor_rva": row["rva"],
            "firmware": fw,
            "reference_kind": row["kind"],
            "reference_claim": row.get("note", "") or row.get("source", ""),
            "ownership_claim_expected": False,
        })
        blind.append(result)

    control = []
    wanted = {"D1_use_after_release", "D4_table_slot_lifecycle"}
    for row in rows:
        if row["kind"] != "detector":
            continue
        if not (wanted & set(row.get("detectors") or [])):
            continue
        fw = row["firmware"]
        rva = int(row["function_rva"], 16)
        rec = env.indexes[fw].containing(rva) or env.indexes[fw].get(rva)
        if rec is None:
            continue
        result = _evaluate_function(env, fw, rec.rva, rec.size, rec.name)
        result.update({
            "label": row["id"],
            "firmware": fw,
            "expect": row["expect"],
            "fired": bool(result["confirmed_findings"]),
            "matches_label": (row["expect"] == "fire") == bool(result["confirmed_findings"]),
        })
        control.append(result)

    false_positives = [b for b in blind if b.get("confirmed_findings")]
    return {
        "protocol": {
            "frozen_rules": frozen_rules(root),
            "blind_family": "pppwn (not used while developing D1/D4)",
            "blind_question": "does D1/D4 claim a confirmed ownership defect at a "
                              "reference site whose published claim is not an ownership claim?",
            "no_retuning_after_run": True,
        },
        "blind": blind,
        "control": control,
        "summary": {
            "blind_anchors": len(blind),
            "blind_confirmed_findings": sum(len(b.get("confirmed_findings") or []) for b in blind),
            "blind_observations": sum(b.get("observation_count", 0) for b in blind),
            "false_positive_anchors": len(false_positives),
            "control_labels": len(control),
            "control_fired": sum(1 for c in control if c["fired"]),
            "control_agree": sum(1 for c in control if c["matches_label"]),
            "control_expected_fire": sum(1 for c in control if c["expect"] == "fire"),
            "legacy_findings_on_control": sum(c.get("legacy_count", 0) for c in control),
        },
        "verdict": "NEGATIVE_CONTROLS_HOLD" if not false_positives else "FALSE_POSITIVE_ON_BLIND",
    }
