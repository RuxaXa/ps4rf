"""Synthetic positive and negative controls for offline discovery triage."""
from tools.discovery.offline_triage import shortlist

def finding(det="D3_lock_coverage", rva="0x11d7e0", rank=2):
    return {"detector": det, "function": {"rva": rva},
            "rank": rank, "site_rvas": ["0x11d80e"],
            "counter_evidence": {"lock": "unknown"}}

def chain(det="D3_lock_coverage", rva="0x11d7e0", privilege="UNKNOWN"):
    return {"primitive": {"detector": det, "function": rva},
            "entry": "entry:sysent[335]", "hop_status": "proved",
            "hop_count": 3, "requirements": {
                "entry_privilege": privilege,
                "blockers": [{"id": "BLOCK_REQ_TWO_CONTEXTS"}]}}

def test_reachable_d3_does_not_imply_unprivileged_or_race():
    report = shortlist({"findings": [finding()]},
                       {"chains": [chain()]})
    c = report["candidates"][0]
    assert report["evidence_grade"] == "STATIC_TRIAGE_ONLY"
    assert c["reachability"] == "proved"
    assert c["entry_privilege"] == "UNKNOWN"
    assert "BLOCK_REQ_UNPRIV_ENTRY" in c["open_blockers"]
    assert "BLOCK_REQ_TWO_CONTEXTS" in c["open_blockers"]
    assert "two independent contexts" in c["falsify"]

def test_positive_explicit_privilege_evidence_removes_only_privilege_blocker():
    c = shortlist({"findings": [finding()]},
                  {"chains": [chain(privilege="UNPRIVILEGED")]})["candidates"][0]
    assert "BLOCK_REQ_UNPRIV_ENTRY" not in c["open_blockers"]
    assert "BLOCK_REQ_TWO_CONTEXTS" in c["open_blockers"]

def test_d5_without_chain_is_not_claimed_reachable():
    c = shortlist({"findings": [finding("D5_release_then_indirect", "0x123")]},
                  {"chains": []})["candidates"][0]
    assert c["reachability"] == "unknown"
    assert c["entry_privilege"] == "UNKNOWN"
    assert c["provenance"].endswith("no runtime proof")

def test_dedup_and_unknown_detector():
    scan = {"findings": [finding(), finding(), finding("D99_foo", "0x55")]}
    out = shortlist(scan, {"chains": [chain()]})
    assert out["total_candidate_functions"] == 1
    assert len(out["candidates"]) == 1

def test_invalid_limit_fails():
    import pytest
    with pytest.raises(ValueError):
        shortlist({"findings": []}, {"chains": []}, 0)
