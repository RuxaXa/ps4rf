"""Versioned, immutable evaluation splits for the blind-test workflow.

The rule this module enforces: **a case is blind only if its exposure history says so**, and
that history is an append-only hash chain written outside the discovery tree. A split is
created once and frozen; changing a question or an answer requires a new ``split_id``.

Nothing here contains a solution. Answers live under the evaluator root
(``/home/hermes/ps4rf-eval`` by default), which the discovery agent never reads.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import time
from typing import Dict, List, Optional

#: How much of the answer a case's context has already seen.
CONTAMINATION_LEVELS = ("none", "metadata", "root_cause", "full_solution")
#: Levels that destroy a blind claim. A case at either level is retrospective evidence only.
BLIND_FORBIDDEN = ("root_cause", "full_solution")
#: Split kinds. Only these may carry a blind claim at all.
BLIND_KINDS = ("holdback", "variant", "cross")
#: First link of the exposure hash chain.
GENESIS = "0" * 64
EXPOSURE_LOG = "exposure.log"


class SplitError(RuntimeError):
    """A split, manifest or exposure record is not what it claims to be."""


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical(payload) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _split_dir(eval_root: pathlib.Path, split_id: str) -> pathlib.Path:
    return pathlib.Path(eval_root) / "splits" / split_id


def _manifest_path(eval_root: pathlib.Path, split_id: str) -> pathlib.Path:
    return _split_dir(eval_root, split_id) / "manifest.json"


def _answers_path(eval_root: pathlib.Path, split_id: str) -> pathlib.Path:
    return pathlib.Path(eval_root) / "solutions" / split_id / "answers.json"


def _log_path(eval_root: pathlib.Path) -> pathlib.Path:
    return pathlib.Path(eval_root) / EXPOSURE_LOG


def _under(path: pathlib.Path, root: pathlib.Path) -> bool:
    try:
        pathlib.Path(path).resolve().relative_to(pathlib.Path(root).resolve())
        return True
    except ValueError:
        return False


def create_manifest(eval_root: pathlib.Path, split_id: str, kind: str,
                    cases: List[dict], discovery_root: pathlib.Path,
                    now: Optional[float] = None) -> dict:
    """Freeze a split. Refuses to reuse an id, to hide answers in the discovery tree, or to
    declare a kind that cannot carry a blind claim in the first place."""
    if kind not in ("train", "retro") + BLIND_KINDS:
        raise SplitError(f"unknown split kind {kind!r}")
    manifest_path = _manifest_path(eval_root, split_id)
    if manifest_path.exists():
        raise SplitError(f"split {split_id!r} is already frozen; use a new split_id")
    answers_path = _answers_path(eval_root, split_id)
    if _under(answers_path, discovery_root):
        raise SplitError(f"answers for {split_id!r} would live in the discovery tree: "
                         f"{answers_path}")
    if not cases:
        raise SplitError("a split without cases is not an evaluation")
    if not answers_path.exists():
        raise SplitError(f"answers file is missing: {answers_path}")

    answers = json.loads(answers_path.read_text(encoding="utf-8"))
    by_id = {entry.get("case_id"): entry for entry in (answers.get("answers") or [])}
    frozen_cases = []
    for case in cases:
        case_id = case.get("case_id")
        if not case_id:
            raise SplitError("every case needs a case_id")
        if case_id not in by_id:
            raise SplitError(f"case {case_id!r} has no answer; a question without an oracle "
                             f"cannot be scored")
        question = {key: value for key, value in case.items() if key != "case_id"}
        frozen_cases.append({
            "case_id": case_id,
            "firmware": case.get("firmware"),
            "image_sha256": case.get("image_sha256"),
            "question_sha256": hashlib.sha256(_canonical(question)).hexdigest(),
            "answer_sha256": hashlib.sha256(_canonical(by_id[case_id])).hexdigest(),
            "model_prior_risk": case.get("model_prior_risk", "unknown"),
        })

    manifest = {
        "split_id": split_id,
        "kind": kind,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "discovery_root": str(pathlib.Path(discovery_root).resolve()),
        "answers_path": str(answers_path.resolve()),
        "answers_file_sha256": sha256_file(answers_path),
        "frozen": True,
        "cases": frozen_cases,
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n",
                             encoding="utf-8")
    return manifest


def load_manifest(eval_root: pathlib.Path, split_id: str) -> dict:
    path = _manifest_path(eval_root, split_id)
    if not path.exists():
        raise SplitError(f"no such split: {split_id}")
    return json.loads(path.read_text(encoding="utf-8"))


def _read_log(eval_root: pathlib.Path) -> List[dict]:
    path = _log_path(eval_root)
    if not path.exists():
        return []
    events = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise SplitError(f"exposure.log line {number} is not JSON: {exc}") from exc
    return events


def verify_chain(eval_root: pathlib.Path) -> List[str]:
    """Replay the exposure hash chain. A rewritten or truncated log is a hard failure."""
    problems: List[str] = []
    previous = GENESIS
    for index, event in enumerate(_read_log(eval_root), start=1):
        body = {key: value for key, value in event.items() if key != "hash"}
        if event.get("seq") != index:
            problems.append(f"event {index} carries seq {event.get('seq')!r}")
        if body.get("prev") != previous:
            problems.append(f"event {index} does not chain onto its predecessor")
        if event.get("hash") != hashlib.sha256(_canonical(body)).hexdigest():
            problems.append(f"event {index} hash does not match its content")
        previous = event.get("hash") or ""
    return problems


def record_exposure(eval_root: pathlib.Path, split_id: str, case_id: str, actor: str,
                    channel: str, detail: str, contamination: str,
                    now: Optional[float] = None) -> dict:
    """Append one exposure event. Append-only by construction: the entry hashes the previous
    line, so deleting or editing an event breaks the chain that `verify_chain` replays."""
    if contamination not in CONTAMINATION_LEVELS:
        raise SplitError(f"unknown contamination level {contamination!r}")
    manifest = load_manifest(eval_root, split_id)
    if case_id not in {case["case_id"] for case in manifest["cases"]}:
        raise SplitError(f"split {split_id!r} has no case {case_id!r}")
    events = _read_log(eval_root)
    body = {
        "seq": len(events) + 1,
        "prev": events[-1]["hash"] if events else GENESIS,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "split_id": split_id,
        "case_id": case_id,
        "actor": actor,
        "channel": channel,
        "detail": detail,
        "contamination": contamination,
    }
    body["hash"] = hashlib.sha256(_canonical(body)).hexdigest()
    path = _log_path(eval_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(body, sort_keys=True) + "\n")
    return body


def exposure_by_case(eval_root: pathlib.Path) -> Dict[str, str]:
    """Worst contamination level recorded for each case, across all splits."""
    severity = {level: index for index, level in enumerate(CONTAMINATION_LEVELS)}
    worst: Dict[str, str] = {}
    for event in _read_log(eval_root):
        key = f"{event.get('split_id')}/{event.get('case_id')}"
        level = event.get("contamination") or "none"
        if key not in worst or severity.get(level, 0) > severity.get(worst[key], 0):
            worst[key] = level
    return worst


def verify(eval_root: pathlib.Path, split_id: str,
           discovery_root: pathlib.Path) -> dict:
    """Everything that can be checked mechanically about one split. `blind_claim` is derived,
    never declared: it is true only when the kind allows it and no case is contaminated."""
    manifest = load_manifest(eval_root, split_id)
    problems: List[str] = []
    answers_path = pathlib.Path(manifest["answers_path"])
    if _under(answers_path, discovery_root):
        problems.append(f"answers live inside the discovery tree: {answers_path}")
    if not answers_path.exists():
        problems.append(f"answers file is missing: {answers_path}")
    elif sha256_file(answers_path) != manifest["answers_file_sha256"]:
        problems.append("the answers file changed after the split was frozen")
    if manifest.get("frozen") is not True:
        problems.append("the split is not frozen")

    answers = {}
    if answers_path.exists():
        answers = {entry.get("case_id"): entry
                   for entry in (json.loads(answers_path.read_text(encoding="utf-8"))
                                 .get("answers") or [])}
    worst = exposure_by_case(eval_root)
    contaminated = []
    for case in manifest["cases"]:
        case_id = case["case_id"]
        if case_id not in answers:
            problems.append(f"case {case_id!r} lost its answer after the freeze")
        elif hashlib.sha256(_canonical(answers[case_id])).hexdigest() != case["answer_sha256"]:
            problems.append(f"case {case_id!r}: the answer changed after the freeze")
        level = worst.get(f"{split_id}/{case_id}", "none")
        if level in BLIND_FORBIDDEN:
            contaminated.append(case_id)

    reasons = list(problems)
    blind_claim = True
    if manifest["kind"] not in BLIND_KINDS:
        blind_claim = False
        reasons.append(f"kind {manifest['kind']!r} can never carry a blind claim")
    if contaminated:
        blind_claim = False
        reasons.append("cases with root-cause or full-solution exposure: "
                       + ", ".join(sorted(contaminated)))
    return {
        "split_id": split_id,
        "kind": manifest["kind"],
        "cases": len(manifest["cases"]),
        "blind_claim": blind_claim and not problems,
        "contaminated_cases": sorted(contaminated),
        "problems": problems,
        "reasons": reasons,
        "chain_problems": verify_chain(eval_root),
    }


def assert_blind(eval_root: pathlib.Path, split_id: str,
                 discovery_root: pathlib.Path) -> None:
    """Raise unless this split may be scored as independent evidence."""
    report = verify(eval_root, split_id, discovery_root)
    if report["chain_problems"]:
        raise SplitError("exposure log chain is broken: " + "; ".join(report["chain_problems"]))
    if not report["blind_claim"]:
        raise SplitError("split is not blind evidence: " + "; ".join(report["reasons"]))
