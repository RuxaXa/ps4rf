"""Callee-side same-object release witnesses for semantic graph proof composition.

The release shape alone says that a function drops *some* reference. This
adapter requires a complete ownership summary with an *exact* direct argument
object key, an explicit release site and an instruction-backed direct call to a
catalogued release routine. A field object `arg0+0x18` is not `arg0`.

This module returns evidence only; it does not modify semgraph.build, and
no external firmware or hidden labels are needed to exercise its contracts.
"""
from __future__ import annotations

from typing import Callable, Optional

from . import summaries as sm
from .mustflow import ARG_REGS


def _unknown(reason: str, argument: Optional[str]) -> dict:
    return {"status": "unknown", "argument": argument,
            "witness": None, "why": reason}


def release_identity_witness(summary, view, argument: str,
                             is_release: Callable[[int], bool]) -> dict:
    """Find a verified callee-side release of the EXACT argument object.

    Preconditions are intentionally strong:
      * the summary is COMPLETE for the same decoded function;
      * an effect is attached to the direct object `("arg", i, ())`;
      * the effect is an explicit FREE with a concrete release call site;
      * the call instruction and release target match the decoded body and
        the independent release catalog.

    REFCOUNT drops and TRANSFER_OUT require separate proof of the ownership
    semantics and are deliberately not accepted as direct frees. A must-grade
    summary may produce PROVED; a witnessed may-grade free is CONDITIONAL.
    The result is not a whole-program exploit or entry authorization proof.
    """
    if argument not in ARG_REGS:
        return _unknown("argument is not a full-width ABI argument register",
                        argument)
    if summary is None or view is None or not callable(is_release):
        return _unknown("callee summary, decoded body or release catalog missing",
                        argument)
    if (getattr(summary, "rva", None) != getattr(view, "rva", None)
            or getattr(summary, "status", None) != sm.COMPLETE):
        return _unknown("callee summary is incomplete or mismatched to the body",
                        argument)
    index = ARG_REGS.index(argument)
    direct_key = ("arg", index, ())
    direct = [effect for effect in (getattr(summary, "params", ()) or ())
              if getattr(effect, "index", None) == index
              and getattr(effect, "key", None) == direct_key]
    if len(direct) != 1:
        return _unknown("no unique exact direct-argument object identity",
                        argument)
    effect = direct[0]
    if getattr(effect, "ownership", None) != sm.OWN_FREE:
        return _unknown("direct argument is not classified as an explicit FREE",
                        argument)
    strength = getattr(effect, "ownership_strength", sm.UNKNOWN)
    if strength not in ("must", "may"):
        return _unknown("callee free lacks a must/may strength classification",
                        argument)

    sites = tuple(getattr(effect, "release_sites", ()) or ())
    if len(sites) != 1 or not isinstance(sites[0], int) or sites[0] <= 0:
        return _unknown("direct FREE needs exactly one concrete release-call site",
                        argument)
    site = sites[0]

    # Check concrete call identity rather than trusting a claim in the
    # summary. A plain memory load or a refcount update is not a free call.
    insns = {ins.address: ins for ins in (getattr(view, "ins", ()) or ())}
    ins = insns.get(site)
    callee = (getattr(view, "calls", None) or {}).get(site)
    if (ins is None or str(getattr(ins, "mnemonic", "")).lower() != "call"
            or not isinstance(callee, int) or callee <= 0):
        return _unknown("the claimed release site is not a decoded direct call",
                        argument)
    try:
        valid_release = bool(is_release(callee))
    except Exception:
        valid_release = False
    if not valid_release:
        return _unknown("the decoded call target is not a verified release",
                        argument)

    # For must proofs, the summary must also identify the same instruction
    # as the ownership event. When it differs the summary and release call
    # are not necessarily the same action; a conditional claim can survive.
    ownership_site = getattr(effect, "ownership_site", 0)
    status = "proved" if strength == "must" and ownership_site in (0, site) else "conditional"
    witness = {
        "site": hex(site),
        "kind": "callee-direct-free",
        "text": f"{ins.mnemonic} {ins.op_str} releases exact arg{index}",
        "argument": argument,
        "object_key": ("arg", index, ()),
        "ownership": sm.OWN_FREE,
        "summary_strength": strength,
        "release_target": hex(callee),
        "callee": hex(summary.rva),
        "identity_relation": "same-object",
        "summary_status": sm.COMPLETE,
    }
    return {"status": status, "argument": argument,
            "witness": witness,
            "why": ("complete direct-argument free, instruction checked"
                    if status == "proved" else
                    "callee has a witnessed free but the must condition is not established")}


def combine_transfer_claim(caller: dict, callee: dict) -> dict:
    """Join two independently verified halves without guessing object aliases.

    When both are PROVED on the *same ABI argument*, return attrs suitable for
    semgraph.Graph.edge. Otherwise return an UNKNOWN/POSSIBLE claim without
    the privileged proof attributes. No graph mutation takes place here.
    """
    caller = caller or {}
    callee = callee or {}
    arg = caller.get("argument")
    caller_proved = caller.get("status") == "proved"
    cw = callee.get("witness")
    callee_status = callee.get("status")
    agreed = (arg in ARG_REGS and callee.get("argument") == arg
              and isinstance(cw, dict)
              and cw.get("argument") == arg
              and cw.get("identity_relation") == "same-object"
              and cw.get("site") and cw.get("text"))
    attrs = {"status": "unknown", "argument_proven": caller_proved,
             "callee_identity_proven": False}
    if not caller_proved or not agreed:
        return {"attrs": attrs, "why": "caller and callee identity are not both proved"}
    if callee_status == "proved":
        attrs.update(status="proved", callee_identity_proven=True,
                     callee_identity_witness=dict(cw))
        return {"attrs": attrs,
                "why": "caller must-reach and exact callee free are both proved"}
    if callee_status == "conditional":
        attrs["status"] = "possible"
        return {"attrs": attrs, "why": "callee release is path-conditional"}
    return {"attrs": attrs, "why": "callee release identity is unproved"}
