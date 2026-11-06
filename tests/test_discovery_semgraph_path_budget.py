"""Bounded, evidence-prioritized entry-path search.

The expected behavior here is not "find every path": when a finite search
budget truncates the graph, the strongest reachable evidence must not be
systematically lost because the incoming edge list happened to be ordered
the other way around.
"""
import pytest

from tools.discovery import semgraph


def _edge(src, dst, kind, status, site):
    return {"src": src, "dst": dst, "kind": kind,
            "status": status,
            "witness": {"site": site, "kind": kind, "text": f"{src} -> {dst}"}}


@pytest.mark.parametrize("reverse", (False, True))
def test_proved_route_is_explored_before_shorter_possible_route(reverse):
    start, relay = "function:0x30", "function:0x40"
    incoming = [
        _edge(relay, start, "calls", "proved", "0x10"),
        _edge("entry:weak", start, "reaches", "possible", "0x20"),
    ]
    by_dst = {
        start: list(reversed(incoming)) if reverse else incoming,
        relay: [_edge("entry:proved", relay, "reaches", "proved", "0x30")],
    }
    paths, truncated = semgraph._entry_paths(start, by_dst,
                                              ("calls", "reaches"),
                                              max_depth=4, budget=3)
    assert truncated
    assert len(paths) == 1
    assert paths[0][0]["src"] == "entry:proved"
    assert all(edge["status"] == "proved" for edge in paths[0])


def test_search_reports_truncation_when_no_root_fits_budget():
    start = "function:0x30"
    by_dst = {start: [_edge("entry:proved", start, "reaches", "proved", "0x10")]}
    paths, truncated = semgraph._entry_paths(start, by_dst,
                                             ("calls", "reaches"),
                                             max_depth=4, budget=1)
    assert paths == []
    assert truncated


def test_shortest_proved_path_wins_when_strength_is_equal():
    start, relay = "function:0x30", "function:0x40"
    by_dst = {
        start: [
            _edge(relay, start, "calls", "proved", "0x10"),
            _edge("entry:short", start, "reaches", "proved", "0x20"),
        ],
        relay: [_edge("entry:long", relay, "reaches", "proved", "0x30")],
    }
    paths, truncated = semgraph._entry_paths(start, by_dst,
                                              ("calls", "reaches"),
                                              max_depth=4, budget=3)
    assert truncated
    assert len(paths) == 1
    assert paths[0][0]["src"] == "entry:short"


def test_bounded_path_order_is_deterministic_with_shuffled_input():
    start, relay = "function:0x30", "function:0x40"
    incoming = [
        _edge(relay, start, "calls", "proved", "0x10"),
        _edge("entry:weak", start, "reaches", "possible", "0x20"),
        _edge("entry:strong", start, "reaches", "proved", "0x30"),
    ]
    route = [_edge("entry:relay", relay, "reaches", "proved", "0x40")]
    results = []
    for edges in (incoming, list(reversed(incoming))):
        paths, _ = semgraph._entry_paths(start, {start: edges, relay: route},
                                         ("calls", "reaches"),
                                         max_depth=4, budget=3)
        results.append([[edge["src"] for edge in path] for path in paths])
    assert results[0] == results[1]
