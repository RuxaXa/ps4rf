"""Cross-subsystem graph export (JSON + Graphviz DOT).

Nodes are subsystems, exploit families and primitives; edges carry the evidence
reference that justifies them.  The graph exists to make the *shared* structure
visible: two families that touch the same subsystem, or two subsystems that hand
an object to each other, are exactly where a cross-subsystem chain can start.
"""

from __future__ import annotations

from typing import Dict, Iterable, List


def build(env_report: dict, families: dict, queue: dict, negative: List[dict]) -> dict:
    nodes: Dict[str, dict] = {}
    edges: List[dict] = []

    def node(nid: str, node_kind: str, **extra):
        if nid not in nodes:
            nodes[nid] = {"id": nid, "kind": node_kind, **extra}

    def edge(a: str, b: str, relation: str, evidence: str, grade: str = "K"):
        edges.append({"from": a, "to": b, "relation": relation, "evidence": evidence,
                      "grade": grade})

    for fam in families["families"]:
        node(f"family:{fam['id']}", "family", bug_class=fam["bug_class"],
             labels=fam["labels"])
        for sub in fam["subsystems"]:
            node(f"subsystem:{sub}", "subsystem")
            edge(f"family:{fam['id']}", f"subsystem:{sub}", "touches",
                 fam.get("source", {}).get("repo", ""), "K")

    for entry in env_report.get("entries", []):
        node(f"entry:{entry['label']}", "entry", entry_kind=entry["kind"])
        if entry.get("subsystem"):
            node(f"subsystem:{entry['subsystem']}", "subsystem")
            edge(f"entry:{entry['label']}", f"subsystem:{entry['subsystem']}", "reaches",
                 entry.get("evidence", ""), "B")

    for cand in queue.get("queue", []):
        cid = f"candidate:{cand['id']}"
        node(cid, "candidate", function=cand["function"]["rva"], detector=cand["evidence"]["detector"])
        sub = cand["entry_path"].get("subsystem")
        if sub:
            node(f"subsystem:{sub}", "subsystem")
            edge(cid, f"subsystem:{sub}", "lives_in", cand["evidence"]["window"][0] if cand["evidence"].get("window") else "", "B")
        for blocker in cand["chain"].get("blockers", []):
            node(f"primitive:{blocker['id']}", "primitive", status=blocker["status"])
            edge(cid, f"primitive:{blocker['id']}", "blocked_by", blocker["why"], "A")
        if cand["chain"].get("goal"):
            node(f"goal:{cand['chain']['goal']}", "goal")
            edge(cid, f"goal:{cand['chain']['goal']}", "would_reach",
                 "; ".join(cand["chain"]["steps"][:3]), "H")

    for entry in negative:
        nid = f"negative:{entry['id']}"
        node(nid, "negative_result", claim=entry["claim"][:200])
        for sub in entry.get("subsystems", []):
            node(f"subsystem:{sub}", "subsystem")
            edge(nid, f"subsystem:{sub}", "refutes_in", entry.get("method", ""), "B")

    return {"nodes": sorted(nodes.values(), key=lambda n: n["id"]), "edges": edges}


def to_dot(graph: dict) -> str:
    shapes = {
        "family": "box",
        "subsystem": "ellipse",
        "entry": "note",
        "candidate": "hexagon",
        "primitive": "diamond",
        "goal": "doublecircle",
        "negative_result": "octagon",
    }
    lines = ["digraph ps4rf_discovery {", "  rankdir=LR;", '  node [fontname="Helvetica"];']
    for n in graph["nodes"]:
        shape = shapes.get(n["kind"], "box")
        lines.append(f'  "{n["id"]}" [shape={shape}];')
    for e in graph["edges"]:
        lines.append(f'  "{e["from"]}" -> "{e["to"]}" [label="{e["relation"]}"];')
    lines.append("}")
    return "\n".join(lines)
