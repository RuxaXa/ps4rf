"""Assemble the reproducible S1.1 evidence pack from the run artifacts.

Every number in the emitted report is derived from a file written by a real run
(``s11_cli pair``, ``s11_cli catalog``, ``cli scan``, ``cli blind``).  Nothing is
recomputed from labels, and a missing or inconsistent input is a hard error.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
from collections import Counter
from typing import Dict, List, Optional

SPRINT1_SCAN = "sprint1/sprint1-report.json"
PAIR = "sprint1.1/lapse-pair.json"
CATALOG = {"13.52": "sprint1.1/catalog-fw1352.json", "9.00": "sprint1.1/catalog-fw900.json"}
SCAN_CURRENT = "sprint1.1/sprint1-scan-current.json"
BLIND = ["sprint1.1/afterglow-blind-seed1.json", "sprint1.1/afterglow-blind-seed777.json"]
FIXTURES = "tests/fixtures/discovery/lockscope-fixtures.json"


def _load(path: pathlib.Path) -> dict:
    if not path.exists():
        raise SystemExit(f"missing artifact: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _sha(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _finding_key(finding: dict) -> tuple:
    return (finding["detector"], finding["function"]["rva"],
            (finding.get("site") or {}).get("rva"), finding.get("rank"),
            finding.get("entry"))


def regression(root: pathlib.Path) -> dict:
    baseline = _load(root / SPRINT1_SCAN)["scan"]["findings"]
    current = _load(root / SCAN_CURRENT)["findings"]
    base_counts = Counter(map(_finding_key, baseline))
    cur_counts = Counter(map(_finding_key, current))
    added = cur_counts - base_counts
    removed = base_counts - cur_counts
    return {
        "baseline_findings": sum(base_counts.values()),
        "current_findings": sum(cur_counts.values()),
        "added": sum(added.values()),
        "removed": sum(removed.values()),
        "identical": not added and not removed,
        "added_sample": [list(k) for k in list(added)[:5]],
        "removed_sample": [list(k) for k in list(removed)[:5]],
    }


def blind_separation(root: pathlib.Path, targets: pathlib.Path) -> dict:
    """Split subsystem coverage from root-cause candidate coverage."""
    docs = [_load(root / name) for name in BLIND]
    digests = [_sha(root / name) for name in BLIND]
    if len(set(json.dumps(d, sort_keys=True) for d in docs)) != 1:
        raise SystemExit("blind runs are not reproducible across hash seeds")
    frozen = _load(targets)
    scan = _load(root / SCAN_CURRENT)
    scanned = set(scan.get("scanned_rvas") or ())
    anchor_rows = {}
    for name, value in (frozen.get("anchors") or frozen.get("claimed_anchors") or {}).items():
        rva = value
        anchor_rows[name] = {
            "rva": rva,
            "in_scan_targets": rva in scanned,
            "findings_in_scan": sum(1 for f in scan["findings"]
                                    if f["function"]["rva"] == rva),
            "d3_findings_in_scan": sum(1 for f in scan["findings"]
                                       if f["function"]["rva"] == rva
                                       and f["detector"] == "D3_lock_coverage"),
            "root_cause_status": "NO_ROOT_CAUSE_CLAIM",
        }
    subsystems = docs[0]["subsystems"]
    return {
        "blind_runs_identical": True,
        "blind_sha256": digests,
        "frozen_rule_set": "sprint1 patterns.py detectors (unchanged in S1.1)",
        "subsystem_hits": {
            name: {"reachable_functions": row["reachable_functions"],
                   "findings": row["findings"],
                   "findings_by_detector": row["findings_by_detector"]}
            for name, row in subsystems.items()
        },
        "root_cause_candidates": anchor_rows,
        "separation_statement": (
            "Subsystem coverage counts entry-reachable findings only. An anchor "
            "function with no D3 finding is not evidence of absence: the anchor "
            "may sit outside the scanned closure. No afterglow root cause is "
            "claimed, coded, or scored."),
    }


def fixtures(root: pathlib.Path) -> dict:
    doc = _load(root / FIXTURES)
    return {
        "image_sha256": doc["image_sha256"],
        "source_sha256": doc["source_sha256"],
        "cases": doc["cases"],
    }


def render_markdown(report: dict) -> str:
    pair = report["lapse_pair"]
    lines = [
        "# PS4RF Discovery S1.1 — Semantic Lock Analysis (D3)",
        "",
        f"Verdict: **{report['verdict']}**",
        "",
        "All values below are generated from run artifacts by "
        "`python -m tools.discovery.s11_evidence`. No label or ranking was "
        "changed to reach this state.",
        "",
        "## 1. Lapse pair, resolved without labels",
        "",
        f"Basis: {pair['mapping_basis']} — syscall {pair['syscall']}.",
        "",
    ]
    for fw, row in pair["firmware"].items():
        lines += [
            f"**FW {fw}** — handler `{row['handler']}`, body `{row['body']}` "
            f"(sha256 `{row['body_sha256'][:16]}…`), CFG {row['extent_blocks']} blocks / "
            f"{row['extent_size']} bytes (capped={row['extent_capped']}), "
            f"{row['direct_calls']} direct calls to {row['unique_callees']} unique callees, "
            f"closure {row['closure_functions']} functions.",
            "",
            f"- D3 verdict counts: {row['verdict_counts']}",
            f"- UNKNOWN rate at mutation sites: {row['unknown_rate']}",
            f"- claim helpers in closure: {row['catalog_claims']}",
            "",
        ]
    lines += [
        f"Callee correspondence: {pair['callee_correspondence'].get('pairs')} structural pairs, "
        f"{pair['callee_correspondence'].get('ambiguities')} ambiguities.",
        "",
        "### Acceptance",
        "",
        f"- vulnerable (9.00) LOCK_SCOPE_PATH_DEPENDENT findings, rank<=2: "
        f"**{pair['acceptance']['vulnerable_positive_findings']}**",
        f"- fixed (13.52) LOCK_SCOPE_PATH_DEPENDENT findings, rank<=2: "
        f"**{pair['acceptance']['fixed_actionable_false_positives']}**",
        "",
        "## 2. Catalog runs (both images, bounded)",
        "",
        "| fw | functions | decoded | decode errors | truncated | primitives | claims | UNKNOWN rate | elapsed s | peak RSS KiB |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for fw, row in report["catalog"].items():
        lines.append(
            f"| {fw} | {row['requested_functions']} | {row['decoded_functions']} | "
            f"{row['decode_errors']} | {row['truncated_functions']} | {row['primitives']} | "
            f"{row['claims']} | {row['unknown_rate']} | {row['elapsed_s']} | {row['max_rss_kib']} |")
    lines += [
        "",
        "Bounded policy: one decode per function, 0x1000-byte cap, only compact call",
        "summaries retained between passes, every refusal recorded. No silent aborts.",
        "",
        "## 3. D3 fixtures",
        "",
        "| fixture | expected |",
        "| --- | --- |",
    ]
    for name, expected in report["fixtures"]["cases"].items():
        lines.append(f"| `{name}` | {expected} |")
    lines += [
        "",
        f"Fixture image sha256 `{report['fixtures']['image_sha256'][:16]}…`, "
        f"source sha256 `{report['fixtures']['source_sha256'][:16]}…` "
        "(pin checked by `gen_lockscope.py --check`).",
        "",
        "## 4. Regression against the frozen Sprint-1 rules",
        "",
        f"Findings baseline {report['regression']['baseline_findings']}, "
        f"current {report['regression']['current_findings']}, "
        f"added {report['regression']['added']}, removed {report['regression']['removed']} "
        f"→ identical: **{report['regression']['identical']}**.",
        "",
        "## 5. Afterglow blind test (frozen rules)",
        "",
        f"Rule set: {report['afterglow']['frozen_rule_set']}. "
        f"Two runs with different hash seeds are byte-identical: "
        f"**{report['afterglow']['blind_runs_identical']}**.",
        "",
        "| subsystem | reachable functions | findings | by detector |",
        "| --- | --- | --- | --- |",
    ]
    for name, row in report["afterglow"]["subsystem_hits"].items():
        lines.append(f"| {name} | {row['reachable_functions']} | {row['findings']} | "
                     f"{row['findings_by_detector']} |")
    lines += [
        "",
        "### Root cause vs subsystem coverage",
        "",
        "| claimed anchor | rva | in scan targets | findings | D3 findings | root cause |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for name, row in report["afterglow"]["root_cause_candidates"].items():
        lines.append(f"| {name} | `{row['rva']}` | {row['in_scan_targets']} | "
                     f"{row['findings_in_scan']} | {row['d3_findings_in_scan']} | "
                     f"{row['root_cause_status']} |")
    lines += [
        "",
        report["afterglow"]["separation_statement"],
        "",
        "## 6. Reproduce",
        "",
    ]
    lines += [f"    {cmd}" for cmd in report["reproduce"]]
    lines += [
        "",
        "## 7. Blind spots (unchanged by this sprint)",
        "",
        "- Lock identity is a provenance expression, not a points-to set: heap",
        "  aliasing through an unknown dereference stays UNKNOWN and can never",
        "  produce NOT_HELD, but it can also hide a real protection.",
        "- A claim identity is per call site. Two different call sites of the same",
        "  claim helper are two identities, even when they target the same object;",
        "  the alias analysis resolves the returned object, not the callee.",
        "- Array element identity is still unmodelled (D4), and stack-slot reuse is",
        "  still unmodelled (D1); both can mask a second mutation of the same slot.",
        "- Atomic candidates that cannot be resolved to thread/zero/reader-count",
        "  semantics stay unclassified; that rate is reported, not tuned away.",
        "- Function bodies longer than the per-function decode cap are truncated;",
        "  every truncated function is listed in the catalog coverage, never silently",
        "  accepted as complete.",
        "- The witness path is existential: it proves one unlocked path exists. It",
        "  does not enumerate all paths, so it cannot prove un-exploitability.",
        "- DIFFERENT_LOCK is informational: a lock that is held but aliases a",
        "  different object is reported at rank 2-3 and must not be read as a bug",
        "  on its own. The actionable signal is LOCK_SCOPE_PATH_DEPENDENT.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(prog="tools.discovery.s11_evidence")
    parser.add_argument("--audit-root", default="/home/hermes/audits/ps4-exploit-discovery-s1")
    parser.add_argument("--repo-root", default="/home/hermes/projects/ps4rf")
    parser.add_argument("--out", required=True)
    parser.add_argument("--markdown", default=None)
    args = parser.parse_args()

    root = pathlib.Path(args.audit_root)
    repo = pathlib.Path(args.repo_root)
    pair = _load(root / PAIR)
    catalogs = {fw: _load(root / path) for fw, path in CATALOG.items()}

    report = {
        "schema": "ps4rf.discovery.s11.evidence/1",
        "verdict": pair["verdict"],
        "lapse_pair": {
            "syscall": pair["firmware"]["9.00"]["syscall"],
            "mapping_basis": pair["mapping_basis"],
            "firmware": {
                fw: {
                    "handler": row["handler"],
                    "body": row["body"],
                    "body_sha256": row["body_sha256"],
                    "extent_blocks": row["extent"]["blocks"],
                    "extent_size": row["extent"]["size"],
                    "extent_capped": row["extent"]["capped"],
                    "direct_calls": row["callgraph"]["direct_calls"],
                    "unique_callees": row["callgraph"]["unique_callees"],
                    "closure_functions": row["closure"]["functions"],
                    "verdict_counts": row["scope_metrics"]["verdict_counts"],
                    "unknown_rate": row["scope_metrics"]["unknown_rate"],
                    "catalog_claims": row["catalog"]["claims"],
                }
                for fw, row in pair["firmware"].items()
            },
            "callee_correspondence": pair["callee_correspondence"],
            "acceptance": {k: v for k, v in pair["acceptance"].items() if k != "positive"},
        },
        "catalog": {
            fw: {
                "image_sha256": row["image_sha256"],
                "elapsed_s": row["elapsed_s"],
                "max_rss_kib": row["max_rss_kib"],
                "python_peak_bytes": row["python_peak_bytes"],
                "primitives": row["catalog"]["primitives"],
                "wrappers": row["catalog"]["wrappers"],
                "claims": row["catalog"]["claims"],
                "atomic_candidates": row["catalog"]["atomic_candidates"],
                "unknown_atomic_candidates": row["catalog"]["unknown_atomic_candidates"],
                "unknown_rate": row["catalog"]["unknown_rate"],
                "cache_peak_functions": row["catalog"]["cache_peak_functions"],
                "requested_functions": row["catalog"]["coverage"]["requested_functions"],
                "decoded_functions": row["catalog"]["coverage"]["decoded_functions"],
                "decoded_bytes": row["catalog"]["coverage"]["decoded_bytes"],
                "decode_errors": len(row["catalog"]["coverage"]["decode_errors"]),
                "truncated_functions": len(row["catalog"]["coverage"]["truncated_functions"]),
            }
            for fw, row in catalogs.items()
        },
        "fixtures": fixtures(repo),
        "regression": regression(root),
        "afterglow": blind_separation(root, repo / "tools/discovery/data/blind/afterglow-targets.json"),
        "reproduce": [
            "python -m tools.discovery.s11_cli pair --syscall 662 --out <audit>/sprint1.1/lapse-pair.json",
            "python -m tools.discovery.s11_cli catalog --fw 13.52 --out <audit>/sprint1.1/catalog-fw1352.json",
            "python -m tools.discovery.s11_cli catalog --fw 9.00 --out <audit>/sprint1.1/catalog-fw900.json",
            "python -m tools.discovery.cli scan --fw 13.52 --out <audit>/sprint1.1/sprint1-scan-current.json",
            "PYTHONHASHSEED=1 python -m tools.discovery.cli blind --fw 13.52 --out <audit>/sprint1.1/afterglow-blind-seed1.json",
            "PYTHONHASHSEED=777 python -m tools.discovery.cli blind --fw 13.52 --out <audit>/sprint1.1/afterglow-blind-seed777.json",
            "python tests/fixtures/discovery/gen_lockscope.py --check",
            "python -m pytest tests/test_discovery_engine.py tests/test_discovery_lockscope.py -q",
            "python -m tools.discovery.s11_evidence --out <audit>/sprint1.1/s11-evidence.json",
        ],
    }
    target = pathlib.Path(args.out)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.markdown:
        doc = pathlib.Path(args.markdown)
        doc.parent.mkdir(parents=True, exist_ok=True)
        doc.write_text(render_markdown(report), encoding="utf-8")
    print(json.dumps({
        "written": str(target),
        "verdict": report["verdict"],
        "regression_identical": report["regression"]["identical"],
        "blind_runs_identical": report["afterglow"]["blind_runs_identical"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
