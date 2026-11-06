"""Callee ownership identity witness producer: positive and adversarial cases.

Unit tests use synthetic FunctionSummary claims and instruction-backed decodes,
not a firmware binary. The separate graph composer test checks the exact
production proof gate but is not an end-to-end blind rediscovery claim.
"""
from dataclasses import replace
from types import SimpleNamespace

import pytest

from tools.discovery import summaries as sm
from tools.discovery.calleewitness import (
    release_identity_witness, combine_transfer_claim,
)
from tools.discovery.semgraph import Graph


def effect(index=0, *, key=None, kind=sm.OWN_FREE, strength="must",
           site=0x118, release_sites=None, conditional=False):
    key = key if key is not None else ("arg", index, ())
    return sm.ParamEffect(index=index, register=sm.ARG_REGS[index],
                          key=key, label=sm.object_label(key),
                          ownership=kind, ownership_strength=strength,
                          ownership_site=site, release_conditional=conditional,
                          release_sites=((site,) if release_sites is None
                                         else tuple(release_sites)))


def summary(*effects, status=sm.COMPLETE, rva=0x100):
    return sm.FunctionSummary(rva=rva, size=0x80, status=status,
                              params=tuple(effects))


def view(*, rva=0x100, site=0x118, target=0x400, op="call"):
    instr = SimpleNamespace(address=site, mnemonic=op,
                            op_str=hex(target))
    return SimpleNamespace(rva=rva, ins=[instr], calls={site: target})


def proof(*effects, argument="rdi", status=sm.COMPLETE, vf=None, release=None):
    return release_identity_witness(
        summary(*effects, status=status),
        vf if vf is not None else view(), argument,
        release if release is not None else (lambda target: target == 0x400))


def caller(argument="rdi", status="proved", *, bound=True):
    result = {"status": status, "argument": argument, "site": "0x88",
              "generation_site": "0x60", "source_register": "rbx",
              "kind": "cfg-must-reach", "text": "CFG must-reach rbx -> rdi",
              "producer_binding": "unverified"}
    if bound:
        result["producer_binding"] = "verified"
        result["producer_witness"] = {
            "kind": "verified-object-generation",
            "generation_site": "0x60",
            "site": "0x40", "text": "independently checked producer"}
    return result


def test_complete_exact_argument_free_has_checked_release_instruction():
    result = proof(effect())
    assert result["status"] == "proved"
    witness = result["witness"]
    assert witness["site"] == "0x118"
    assert witness["object_key"] == ("arg", 0, ())
    assert witness["identity_relation"] == "same-object"
    assert witness["release_target"] == "0x400"
    assert witness["summary_status"] == sm.COMPLETE


def test_both_halves_produce_graph_accepted_proved_edge():
    callee = proof(effect())
    claim = combine_transfer_claim(caller(), callee)
    assert claim["attrs"]["status"] == "proved"
    graph = Graph()
    assert graph.edge(
        "function:0x50", "function:0x100", "transfers-reference",
        {"site": "0x88", "kind": "call", "text": "call 0x100"},
        **claim["attrs"],
    )
    edge = graph.export()["edges"][0]
    assert edge["status"] == "proved"
    assert edge["callee_identity_witness"]["site"] == "0x118"


@pytest.mark.parametrize("path", [(0x0,), (0x18,), (0x18, 0x30)])
def test_field_object_free_never_proves_direct_argument(path):
    child = effect(index=0, key=("arg", 0, path))
    result = proof(child)
    assert result["status"] == "unknown"
    assert "direct-argument" in result["why"]
    assert combine_transfer_claim(caller(), result)["attrs"]["status"] == "unknown"


@pytest.mark.parametrize("arg", ("rax", "edi", "", "arg0", "RDI"))
def test_non_abi_or_partial_width_argument_is_refused(arg):
    assert proof(effect(), argument=arg)["status"] == "unknown"


@pytest.mark.parametrize("kind", (sm.OWN_DROP_REF, sm.OWN_TRANSFER_OUT,
                                  sm.OWN_STORE_OUT, sm.OWN_NONE))
def test_other_ownership_effects_cannot_be_called_same_object_free(kind):
    assert proof(effect(kind=kind))["status"] == "unknown"


def test_unknown_strength_is_refused():
    assert proof(effect(strength="unknown"))["status"] == "unknown"


@pytest.mark.parametrize("sites", ((), (0x118, 0x120), (0,), (-1,)))
def test_missing_ambiguous_or_malformed_release_site_refused(sites):
    result = proof(effect(release_sites=sites))
    assert result["status"] == "unknown"
    assert "exactly one" in result["why"]


def test_incomplete_summary_is_refused_not_promoted():
    for grade in (sm.PARTIAL, sm.REFUSED):
        assert proof(effect(), status=grade)["status"] == "unknown"


def test_summary_and_decoded_view_must_match_function_rva():
    result = proof(effect(), vf=view(rva=0x200))
    assert result["status"] == "unknown"


def test_mismatched_release_target_cannot_prove_identity():
    assert proof(effect(), vf=view(target=0x500))["status"] == "unknown"


def test_release_target_verifier_can_fail_closed():
    assert proof(effect(), release=lambda target: False)["status"] == "unknown"

    def denied(_):
        raise ValueError("catalogue incomplete")
    assert proof(effect(), release=denied)["status"] == "unknown"


def test_non_call_instruction_refused_even_when_site_is_claimed():
    assert proof(effect(), vf=view(op="mov"))["status"] == "unknown"


def test_claimed_release_site_must_be_in_decoded_body():
    assert proof(effect(site=0x120))["status"] == "unknown"


def test_guarded_release_is_only_conditional():
    result = proof(effect(conditional=True))
    assert result["status"] == "conditional"
    attrs = combine_transfer_claim(caller(), result)["attrs"]
    assert attrs["status"] == "possible"
    assert attrs["callee_identity_proven"] is False
    assert "callee_identity_witness" not in attrs


def test_must_refcount_decrement_is_not_must_free_call():
    # A release call after a dominating refcount decrement may be gated.
    # Distinct ownership and actual free sites must never count as unconditional.
    result = proof(effect(site=0x110, release_sites=(0x118,)))
    assert result["status"] == "conditional"
    assert combine_transfer_claim(caller(), result)["attrs"]["status"] == "possible"


def test_may_direct_free_is_only_conditional():
    result = proof(effect(strength="may"))
    assert result["status"] == "conditional"


@pytest.mark.parametrize("caller_arg,callee_arg", [("rdi", "rsi"), ("rsi", "rdi")])
def test_mismatched_abi_argument_never_proves_same_object(caller_arg, callee_arg):
    result = proof(effect(index=sm.ARG_REGS.index(callee_arg)),
                   argument=callee_arg)
    attrs = combine_transfer_claim(caller(caller_arg), result)["attrs"]
    assert attrs["status"] == "unknown"


def test_unproved_caller_stays_unknown_even_with_direct_callee_free():
    attrs = combine_transfer_claim(caller(status="unknown"), proof(effect()))["attrs"]
    assert attrs["status"] == "unknown"


def test_missing_callee_witness_stays_unknown():
    attrs = combine_transfer_claim(caller(), {"argument": "rdi", "status": "proved"})["attrs"]
    assert attrs["status"] == "unknown"


def test_duplicate_conflicting_direct_argument_effects_refused():
    result = proof(effect(), effect(kind=sm.OWN_DROP_REF))
    assert result["status"] == "unknown"
    assert "unique exact" in result["why"]


def test_rsi_release_is_independently_argument_keyed():
    result = proof(effect(index=1), argument="rsi")
    assert result["status"] == "proved"
    assert result["witness"]["object_key"] == ("arg", 1, ())


def test_actual_capstone_decode_matches_claimed_release_site():
    """Real Capstone parse of a pinned assembly fixture, with model summary.

    This models the release catalog; the fixture's stub is not a production
    release routine. It proves the decoded-site check is not a string lookup.
    """
    import json
    from pathlib import Path
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from tools.discovery.patterns import FunctionView

    root = Path(__file__).resolve().parent / "fixtures" / "discovery"
    doc = json.loads((root / "a1-regressions.json").read_text())
    image_bytes = bytes.fromhex(doc["image_hex"])
    base = int(doc["base_rva"], 16)

    class Image:
        def disasm(self, addr, size, **kwargs):
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            md.detail = True
            return (list(md.disasm(
                image_bytes[addr-base:addr-base+size], addr)), md)

    rec = doc["symbols"]["pass_in_arg"]
    start = int(rec["rva"], 16)
    size = int(rec["size"], 16)
    decoded = FunctionView(Image(), start, size)
    site, target = next(iter(decoded.calls.items()))
    modeled = summary(effect(site=site), rva=start)
    result = release_identity_witness(modeled, decoded, "rdi",
                                      lambda candidate: candidate == target)
    assert result["status"] == "proved"
    assert result["witness"]["release_target"] == hex(target)
    assert release_identity_witness(
        modeled, decoded, "rdi", lambda candidate: False)["status"] == "unknown"


@pytest.mark.parametrize("removed", ("acquisition", "site", "text", "kind"))
def test_join_does_not_trust_bare_caller_proved_status(removed):
    forged = caller()
    forged.pop(removed)
    claim = combine_transfer_claim(forged, proof(effect()))
    assert claim["attrs"]["status"] == "unknown"
    assert claim["attrs"]["callee_identity_proven"] is False


@pytest.mark.parametrize("removed", ("object_key", "kind", "summary_status"))
def test_join_rejects_incomplete_callee_proof_objects(removed):
    result = proof(effect())
    witness = dict(result["witness"])
    witness.pop(removed)
    result = dict(result, witness=witness)
    claim = combine_transfer_claim(caller(), result)
    assert claim["attrs"]["status"] == "unknown"
    assert claim["attrs"]["callee_identity_proven"] is False


def test_join_rejects_callee_proof_for_wrong_same_abi_argument_key():
    result = proof(effect())
    witness = dict(result["witness"], object_key=("arg", 1, ()))
    claim = combine_transfer_claim(caller(), dict(result, witness=witness))
    assert claim["attrs"]["status"] == "unknown"


def test_unbound_load_generation_cannot_promote_exact_callee_free():
    """A must-flow LOAD is not proof that the acquire call produced it."""
    claim = combine_transfer_claim(caller(bound=False), proof(effect()))
    assert claim["attrs"]["status"] == "unknown"
    assert claim["attrs"]["argument_proven"] is False
    assert "callee_identity_witness" not in claim["attrs"]


@pytest.mark.parametrize("mutation", [
    {"producer_binding": "verified", "producer_witness": None},
    {"producer_binding": "verified", "producer_witness": {"kind": "verified-object-generation"}},
    {"producer_binding": "verified", "producer_witness": {
        "kind": "verified-object-generation", "generation_site": "0x70",
        "site": "0x40", "text": "different load"}},
    {"producer_binding": "unverified"},
])
def test_incomplete_or_mismatched_producer_binding_is_unknown(mutation):
    bad = caller(bound=False)
    bad.update(mutation)
    attrs = combine_transfer_claim(bad, proof(effect()))["attrs"]
    assert attrs["status"] == "unknown"
    assert attrs["callee_identity_proven"] is False


def test_verified_producer_binding_and_direct_free_preserve_positive():
    attrs = combine_transfer_claim(caller(bound=True), proof(effect()))["attrs"]
    assert attrs["status"] == "proved"
    assert attrs["argument_proven"] is True
    assert attrs["callee_identity_proven"] is True
