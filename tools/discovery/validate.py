"""Reference matrix: hard facts must pass, scanner labels are measured.

Two kinds of assertions live in ``data/families/references.json``:

* **hard facts** -- a published constant (a PPPwn 9.00 symbol offset, PSFree's
  sysent[661] slot, afterglow's gadget) that must resolve in *our* image.  A
  failure here means our image or our address arithmetic is wrong, and every
  later claim is void.
* **scanner labels** -- a detector expectation at a named function.  These are
  measured, not asserted: a label that does not fire is a *result* about the
  scanner, and it is reported with its reason instead of being tuned away.

The matrix also carries the two provenance checks that decide whether a byte
claim is even admissible: is the image kpatched (not pristine), and do the
pinned source files still hash to their recorded values?
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import inventory as inv_mod
from . import patterns
from .image import FirmwareFacts, FunctionIndex, KernelImage
from .entries import CdevswTable, SysentTable


@dataclass
class Environment:
    facts: Dict[str, FirmwareFacts]
    images: Dict[str, KernelImage]
    indexes: Dict[str, FunctionIndex]
    sysent: Dict[str, SysentTable]
    cdevsw: Dict[str, Optional[CdevswTable]]
    root: str = "."
    _ownership: Dict[str, object] = field(default_factory=dict, repr=False)

    def ownership(self, name: str):
        """The release/alloc catalog for one firmware, built once per process."""
        from .ownership import OwnershipCatalog

        cached = self._ownership.get(name)
        if cached is None:
            cached = OwnershipCatalog(self.images[name], self.indexes[name],
                                      self.facts[name].doc)
            self._ownership[name] = cached
        return cached

    @classmethod
    def load(cls, data_root: str, only: Optional[List[str]] = None) -> "Environment":
        facts, images, indexes, sysents, cdevs = {}, {}, {}, {}, {}
        fw_dir = os.path.join(data_root, "fw")
        for name in sorted(os.listdir(fw_dir)):
            if not name.endswith(".json"):
                continue
            f = FirmwareFacts.load(os.path.join(fw_dir, name))
            key = f.name
            if only and key not in only:
                continue
            facts[key] = f
            image = KernelImage.load(f.doc["image"]["path"])
            images[key] = image
            hint = (f.doc.get("inventory") or {}).get("hint")
            kind = (f.doc.get("inventory") or {}).get("kind", "sweep")
            indexes[key] = inv_mod.load(image, hint=hint, base=image.base, kind=kind)
            sysents[key] = SysentTable(image, f.rva("sysent"))
            cdev = None
            tables = f.doc.get("tables", {})
            if "cdevsw" in tables:
                cdev = CdevswTable(
                    image, int(tables["cdevsw"]["rva"], 16),
                    fields=tables["cdevsw"].get("record_fields"),
                )
            cdevs[key] = cdev
        return cls(facts=facts, images=images, indexes=indexes, sysent=sysents,
                   cdevsw=cdevs, root=data_root)


def _result(assertion: dict, status: str, observed, expected) -> dict:
    return {
        "id": assertion["id"],
        "family": assertion.get("family"),
        "kind": assertion["kind"],
        "firmware": assertion.get("firmware"),
        "status": status,
        "observed": observed,
        "expected": expected,
        "source": assertion.get("source"),
        "grade": assertion.get("grade"),
    }


def _file_backed(image: KernelImage, rva: int, length: int = 8) -> bool:
    """Is this RVA inside a segment that the file actually carries?

    The 48 MiB reference dump is a physical-memory image with an ELF header: its
    data segment is declared but the file also contains unmapped physical memory.
    Reading a kernel data structure at an RVA that is not file-backed returns
    garbage that *looks* like a pointer, so such an assertion must SKIP instead
    of PASS/FAIL.
    """
    for seg in image.segments:
        if seg.p_type == 1 and seg.offset <= rva and rva + length <= seg.offset + seg.filesz:
            return True
    return False


def evaluate(env: Environment, assertion: dict) -> dict:
    fw = assertion.get("firmware")
    if fw not in env.images:
        return _result(assertion, "SKIP", None, "firmware not loaded")
    image = env.images[fw]
    kind = assertion["kind"]

    if kind in ("bytes", "prologue", "ptr_slot", "ptr_slot_relative"):
        rva = int(assertion["rva"], 16)
        if not _file_backed(image, rva):
            return _result(assertion, "SKIP", hex(rva),
                           "RVA is not file-backed in this image (physical dump)")

    if kind == "ptr_slot_relative":
        rva = int(assertion["rva"], 16)
        value = image.u64(rva)
        expect = int(assertion["expect_rva"], 16)
        observed = {"value": hex(value), "rva_of_value": hex(image.rva(value))}
        ok = image.is_canonical_kernel_va(value) and image.rva(value) == expect
        return _result(assertion, "PASS" if ok else "FAIL", observed,
                       {"expect_rva": hex(expect)})

    if kind == "bytes":
        rva = int(assertion["rva"], 16)
        expect = assertion["expect"].lower()
        observed = image.read(rva, len(expect) // 2).hex()
        return _result(assertion, "PASS" if observed == expect else "FAIL", observed, expect)

    if kind == "prologue":
        rva = int(assertion["rva"], 16)
        head = image.read(rva, 8).hex()
        ok = any(head.startswith(p.lower()) for p in assertion["expect_any"])
        return _result(assertion, "PASS" if ok else "FAIL", head,
                       assertion["expect_any"])

    if kind == "ptr_slot":
        rva = int(assertion["rva"], 16)
        value = image.u64(rva)
        observed = hex(value)
        if "expect_value" in assertion:
            expect = assertion["expect_value"].lower()
            status = "PASS" if observed.lower() == expect else "FAIL"
            return _result(assertion, status, observed, expect)
        in_image = 0 <= image.rva(value) < image.size
        status = "PASS" if (image.is_canonical_kernel_va(value) and in_image) else "FAIL"
        return _result(assertion, status, observed, "canonical kernel pointer inside image")

    if kind == "sysent":
        table = env.sysent[fw]
        entry = table.get(int(assertion["number"]))
        if entry is None:
            return _result(assertion, "FAIL", None, "entry present")
        observed = {
            "narg": entry.narg,
            "handler_rva": hex(entry.handler_rva),
            "thrcnt": entry.thrcnt,
            "valid": entry.valid,
        }
        expect = {k[7:]: v for k, v in assertion.items() if k.startswith("expect_")}
        ok = entry.valid
        for key, want in expect.items():
            got = observed.get(key)
            if key == "handler_rva":
                ok = ok and got == want.lower()
            else:
                ok = ok and got == want
        return _result(assertion, "PASS" if ok else "FAIL", observed, expect)

    if kind == "detector":
        rva = int(assertion["function_rva"], 16)
        index = env.indexes[fw]
        rec = index.get(rva)
        size = int(assertion["size"], 16) if assertion.get("size") else (rec.size if rec is not None else 0)
        if not size:
            # fall back to the next start so the scan still has a body
            nexts = [r.rva for r in index if r.rva > rva]
            size = (min(nexts) - rva) if nexts else 0x200
        named = {r.rva: r.name for r in index.named()}
        # anchors (a named primitive on the primary firmware, a translated one on
        # the reference firmware) participate in the release/lock vocabulary, so
        # a reference image without an inventory is not silently unscannable
        anchors = (env.facts[fw].doc.get("anchors") or {})
        for name, rva_hex in anchors.items():
            try:
                named.setdefault(int(rva_hex, 16), name)
            except (TypeError, ValueError):
                continue
        ctx = patterns.ScanContext.from_names(named)
        ctx.subsystem = assertion.get("family", "")
        findings = patterns.scan_function(image, rva, size, rec.name if rec else "", ctx)
        fired = sorted({f.detector for f in findings if f.detector in assertion["detectors"]})
        fired_ranks = {
            d: min(f.rank for f in findings if f.detector == d) for d in fired
        }
        expected = assertion["expect"]
        ok = bool(fired) if expected == "fire" else not fired
        return _result(
            assertion,
            "PASS" if ok else "FAIL",
            {"fired": fired, "fired_min_rank": fired_ranks,
             "actionable": sorted(d for d, r in fired_ranks.items() if r <= 2),
             "all_detectors": sorted({f.detector for f in findings}),
             "findings": len(findings)},
            expected,
        )

    return _result(assertion, "ERROR", None, f"unknown kind {kind}")


def purity_report(env: Environment) -> dict:
    """Is the dump pristine?  A kpatched sysent[11] is the cheapest tell."""
    out = {}
    for fw, table in env.sysent.items():
        entry = table.get(11)
        patched = bool(entry and entry.valid and entry.narg == 2 and entry.thrcnt == 1)
        out[fw] = {
            "sysent11_narg": entry.narg if entry else None,
            "sysent11_handler": hex(entry.handler_rva) if entry else None,
            "sysent11_thrcnt": entry.thrcnt if entry else None,
            "kexec_patch_shape": patched,
            "verdict": "NOT_PRISTINE" if patched else "NO_KEXEC_PATCH_SEEN",
        }
    return out


def check_source_pins(families: dict, sources_root: str) -> List[dict]:
    out = []
    for family in families["families"]:
        src = family.get("source", {})
        base = os.path.join(sources_root, src.get("repo", "").split("/")[-1])
        for rel, expected in (src.get("files") or {}).items():
            path = os.path.join(base, rel)
            if not os.path.exists(path):
                out.append({"family": family["id"], "file": rel, "status": "MISSING",
                            "expected": expected, "observed": None, "path": path})
                continue
            with open(path, "rb") as fh:
                observed = hashlib.sha256(fh.read()).hexdigest()
            out.append({"family": family["id"], "file": rel,
                        "status": "PASS" if observed == expected else "FAIL",
                        "expected": expected, "observed": observed, "path": path})
    return out


def score_scanner(results: List[dict]) -> dict:
    """Two-level precision/recall over the labelled detector assertions.

    ``name_level`` counts a label as hit as soon as the named detector fires at
    any rank.  ``actionable_level`` counts it only from rank <= 2, i.e. from the
    level at which the queue admits a candidate.  The split exists because the
    two numbers say different things: a rule can notice a function without
    producing anything worth chasing, and reporting one number would hide that.
    """
    def tally(pick) -> dict:
        tp = fp = fn = tn = 0
        for r in results:
            if r["kind"] != "detector":
                continue
            observed = r["observed"] if isinstance(r["observed"], dict) else {}
            fired = bool(pick(observed))
            want_fire = r["expected"] == "fire"
            if want_fire and fired:
                tp += 1
            elif want_fire and not fired:
                fn += 1
            elif not want_fire and fired:
                fp += 1
            else:
                tn += 1
        total_pos, total_neg = tp + fn, fp + tn

        def ratio(a, b):
            return round(a / b, 4) if b else None

        return {
            "positives": total_pos, "negatives": total_neg,
            "tp": tp, "fn": fn, "fp": fp, "tn": tn,
            "recall": ratio(tp, total_pos),
            "false_positive_rate": ratio(fp, total_neg),
            "precision": ratio(tp, tp + fp),
        }

    name_level = tally(lambda o: o.get("fired"))
    actionable = tally(lambda o: o.get("actionable"))
    return {
        # name level is kept flat for backwards-compatible readers of the report
        **name_level,
        "level": "name",
        "name_level": name_level,
        "actionable_level": actionable,
    }


def run(env: Environment, references: dict) -> dict:
    results = [evaluate(env, a) for a in references["assertions"]]
    hard = [r for r in results if r["kind"] != "detector"]
    labels = [r for r in results if r["kind"] == "detector"]
    return {
        "summary": {
            "assertions": len(results),
            "hard_facts": len(hard),
            "hard_facts_pass": sum(1 for r in hard if r["status"] == "PASS"),
            "hard_facts_fail": sum(1 for r in hard if r["status"] == "FAIL"),
            "labels": len(labels),
            "labels_pass": sum(1 for r in labels if r["status"] == "PASS"),
            "labels_fail": sum(1 for r in labels if r["status"] == "FAIL"),
        },
        "scanner_score": score_scanner(results),
        "assertions": results,
    }


def derive_copy_primitives(image: KernelImage, patch_table: Dict[str, str]) -> Dict[str, dict]:
    """Locate copy primitives from a published patch table.

    A patch table names the *byte* it flips inside a function (typically the
    first byte of a `jcc` or a `mov eax, 1`), not the function entry.  Walk
    backwards to the enclosing prologue and report the window so the copy site
    can be used as an anchor with an explicit uncertainty.
    """
    out = {}
    for name, rva_hex in patch_table.items():
        rva = int(rva_hex, 16)
        start = None
        for back in range(0, 0x200):
            probe = rva - back
            if probe < 0:
                break
            if image.read(probe, 3) in (b"\x55\x48\x89\xe5", b"\x55\x48\x8b\xec"):
                start = probe
                break
        out[name] = {
            "patch_site_rva": hex(rva),
            "enclosing_prologue_rva": hex(start) if start is not None else None,
            "note": "enclosing prologue found by backward scan; not a proof that this is the "
                    "function entry (a jcc patch byte may live behind a cold block)",
        }
    return out
