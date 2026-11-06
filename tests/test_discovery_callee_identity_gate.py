"""Callee-side identity checks for interprocedural ownership hop claims.

These synthetic controls separate releasing the object passed as argument 0
from releasing an object loaded *through* argument 0. They deliberately do
not claim full exploitability, caller CFG reachability, or a blind rediscovery.
"""
from dataclasses import replace

import pytest

from tools.discovery import summaries as sm


ARG0 = ("arg", 0, ())


def effect(key=ARG0, strength="must", release_site=0x200,
           kind=sm.OWN_DROP_REF):
    return sm.ParamEffect(index=0, register="rdi", key=key,
                          label=sm.object_label(key),
                          ownership=kind, ownership_strength=strength,
                          release_sites=((release_site,) if release_site else ()),
                          ownership_site=release_site or 0)


def summary(*effects, complete=True):
    return sm.FunctionSummary(
        rva=0x100, size=0x80,
        status=sm.COMPLETE if complete else sm.PARTIAL,
        params=(next((x for x in effects if x.key == ARG0),
                     sm.ParamEffect(index=0, register="rdi", key=ARG0,
                                    label="arg0")),),
        field_objects=tuple(x for x in effects if x.key != ARG0),
    )


def hop(callee):
    # Bypass caller-placement discovery: this test isolates *callee* identity.
    placement = {"status": sm.PROVEN, "argument": "rdi",
                 "site": 0x80, "text": "mov rdi, rbx",
                 "key": ("arg", 2, ())}
    return sm.hop_at(None, 0x84, "rbx", callee,
                     callee_rva=0x100, placement=placement)


def test_same_object_release_requires_two_concrete_witnesses():
    result = hop(summary(effect()))
    assert result.status == sm.PROVEN
    assert result.object_label_ == "arg2"
    assert len(result.witnesses) == 2
    assert result.witnesses[1]["callee"]["site"] == "0x200"
    assert result.witnesses[1]["callee"]["identity_relation"] == "same-object"


@pytest.mark.parametrize("kind", (sm.OWN_FREE, sm.OWN_DROP_REF, sm.OWN_TRANSFER_OUT))
def test_must_summary_without_release_site_never_proves_transfer(kind):
    result = hop(summary(effect(release_site=0, kind=kind)))
    assert result.status == sm.UNKNOWN
    assert "no concrete" in result.why
    assert result.witnesses[1]["callee"]["site"] is None


@pytest.mark.parametrize("path", ((0x10,), (0x20, 0x28)))
def test_field_object_release_does_not_free_same_caller_object(path):
    field = effect(key=("arg", 0, path), kind=sm.OWN_FREE)
    result = hop(summary(field))
    assert result.status == sm.UNKNOWN
    assert "not argument 0 itself" in result.why
    assert result.object_label_ == sm.object_label(("arg", 2, path))
    assert result.witnesses[1]["callee"]["identity_relation"] == "derived-or-unknown"


def test_direct_object_identity_beats_stronger_unrelated_field_effect():
    direct = effect(kind=sm.OWN_DROP_REF, strength="may", release_site=0x240)
    child = effect(key=("arg", 0, (0x30,)), kind=sm.OWN_FREE,
                   strength="must", release_site=0x220)
    for effects in ((child, direct), (direct, child)):
        result = hop(summary(*effects))
        assert result.status == sm.CONDITIONAL
        assert result.object_label_ == "arg2"
        assert result.witnesses[1]["callee"]["site"] == "0x240"


def test_field_only_summary_is_refused_even_when_must_and_complete():
    child1 = effect(key=("arg", 0, (0x10,)), kind=sm.OWN_FREE,
                    release_site=0x260)
    child2 = effect(key=("arg", 0, (0x20,)), kind=sm.OWN_FREE,
                    release_site=0x270)
    for effects in ((child1, child2), (child2, child1)):
        result = hop(summary(*effects))
        assert result.status == sm.UNKNOWN
        assert result.object_label_ == "arg2+0x10"
        assert "field-derived" in result.why


def test_ordinary_may_release_remains_conditional():
    result = hop(summary(effect(strength="may")))
    assert result.status == sm.CONDITIONAL
    assert "path only" in result.why


def test_read_only_complete_callee_remains_refuted():
    result = hop(summary())
    assert result.status == sm.REFUTED


def test_incomplete_callee_with_direct_witness_is_only_conditional():
    result = hop(summary(effect(), complete=False))
    assert result.status == sm.CONDITIONAL
