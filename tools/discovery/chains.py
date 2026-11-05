"""Chain composer.

A finding is only interesting if the primitive it yields can be carried to a
goal.  The composer reasons over three sets:

* **entries** -- reachable code paths (syscalls, device nodes) taken from the
  image itself,
* **primitives** -- what a bug class can produce (``UAF``, ``DOUBLE_FREE``,
  ``HEAP_OVERFLOW``, ``UNLOCKED_WRITE``) and what each goal additionally needs,
* **facts** -- whether the required building blocks actually exist in *this*
  firmware (a gadget at a known RVA, a sysent slot that is free to take over).

Missing prerequisites are never smoothed over.  A requirement is cleared only
when offline evidence can close it; everything that needs a live console, a
scheduler observation or a second reclaim attempt stays OPEN as a ``Blocker``
with the condition that would clear it.  A chain with an open blocker is
reported as incomplete.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional

CLEARED = "CLEARED"
OPEN = "OPEN"

#: The proof ladder.  A chain sits on the highest rung whose obligations are all met, and the
#: rung above it names what is still missing.  The ladder stops where the evidence stops:
#: `CFG_REACHABLE` is a statement about control flow, not about a bug that can be used, and
#: nothing below `PRIMITIVE_VALIDATED` may be reported as an exploitable weakness.
PROOF_LEVELS = (
    "CFG_REACHABLE",
    "UNPRIV_REACHABLE",
    "OBJECT_FLOW_PROVEN",
    "PRIMITIVE_VALIDATED",
    "EXPLOIT_CHAIN_VALIDATED",
)
UNREACHED = "UNREACHED"

#: Result vocabulary for every individual proof dimension.  `CONDITIONAL` exists so that a
#: proof which holds only under a stated assumption has a name other than "proven" or "unknown".
PROVEN = "PROVEN"
CONDITIONAL = "CONDITIONAL"
UNKNOWN = "UNKNOWN"
REFUTED = "REFUTED"

#: The dimensions are evaluated independently and never gate each other: an UNKNOWN entry
#: privilege must not stop the object identity from being proved, and a proved identity must
#: not be read as an exploit.
DIMENSIONS = ("cfg", "authz", "object_identity", "ownership", "concurrency", "exploitability")


@dataclass
class Blocker:
    id: str
    why: str
    clears_with: str
    status: str = OPEN

    def as_dict(self) -> dict:
        return {"id": self.id, "why": self.why, "clears_with": self.clears_with,
                "status": self.status}


@dataclass
class Primitive:
    id: str
    provides: List[str]
    requires: List[str]
    note: str = ""

    def as_dict(self) -> dict:
        return {"id": self.id, "provides": self.provides, "requires": self.requires,
                "note": self.note}


@dataclass
class Chain:
    finding_detector: str
    finding_function: str
    bug_class: str
    entry: str
    steps: List[str] = field(default_factory=list)
    blockers: List[Blocker] = field(default_factory=list)
    goal: Optional[str] = None
    entry_privilege: str = "UNKNOWN"
    #: Highest rung of the proof ladder whose obligations are all met.
    proof_level: str = UNREACHED
    #: One entry per rung walked, each naming what was missing when it stopped.
    obligations: List[dict] = field(default_factory=list)
    #: Six independent verdicts (PROVEN/CONDITIONAL/UNKNOWN/REFUTED). A dimension that could
    #: not be established does not suppress the others -- that is the whole point of keeping
    #: them apart from the rung the chain stopped on.
    dimensions: Dict[str, dict] = field(default_factory=dict)

    @property
    def complete(self) -> bool:
        return bool(self.goal) and not any(b.status == OPEN for b in self.blockers)

    def as_dict(self) -> dict:
        return {
            "finding_detector": self.finding_detector,
            "finding_function": self.finding_function,
            "bug_class": self.bug_class,
            "entry": self.entry,
            "entry_privilege": self.entry_privilege,
            "proof_level": self.proof_level,
            "dimensions": self.dimensions,
            "obligations": self.obligations,
            "next_obligation": next((rung for rung in self.obligations
                                     if rung["status"] == "OPEN"), None),
            "steps": self.steps,
            "goal": self.goal,
            "complete": self.complete,
            "open_blockers": sum(1 for b in self.blockers if b.status == OPEN),
            "blockers": [b.as_dict() for b in self.blockers],
        }


# A requirement is cleared only when the *offline* evidence can close it.  Every
# requirement that needs a live console, a scheduler observation or a reclaim
# attempt stays OPEN -- that is the point of the composer: a chain must not read
# as "exploitable" while a physical precondition is still missing.
#
# Reachability, privilege and input control are three separate claims.  A function
# being called from some syscall or device node proves only that the CODE is
# reachable; a syscall can gate on a command id and credentials, and a cdevsw
# record can be root-only.  Collapsing the three into "an entry kind exists" is how
# an unprivileged-entry requirement gets cleared without a single permission check.
REQUIREMENTS = {
    "REQ_ENTRY_REACHABLE": {
        "text": "a proved control-flow path from a resolved entry reaches the function",
        "clears_with": "a fully proved entry-rooted path in the semantic graph",
    },
    "REQ_UNPRIV_ENTRY": {
        "text": "the reaching path is authorized for an unprivileged caller",
        "clears_with": "recorded authorization evidence: the device record's mode or a "
                       "byte-verified absence of a credential gate on the path",
    },
    "REQ_INPUT_CONTROLLED": {
        "text": "the attacker controls the value the bug acts on",
        "clears_with": "a taint/argument-provenance path from a caller field to the sink",
    },
    "REQ_SPRAY": {
        "text": "a spray that lands in the freed slot",
        "clears_with": "a measured spray-to-hole ratio on the target firmware (live console)",
    },
    "REQ_TWO_CONTEXTS": {
        "text": "two schedulable contexts on one core",
        "clears_with": "a thread/cpu-set primitive plus a measured interleaving rate",
    },
    "REQ_WIDEN": {
        "text": "a way to widen the race window",
        "clears_with": "a blocking call inside the window (soclose/thr_suspend shape) shown present",
    },
    "REQ_NO_NULL_RESET": {
        "text": "no NULL reset between the free sites",
        "clears_with": "absence of a kill on every path between the sites (checked by D2)",
    },
    "REQ_VTABLE": {
        "text": "a vtable or ops pointer in the reclaimed object",
        "clears_with": "an ops field at a known offset in the freed object",
    },
    "REQ_REFCOUNT_UNDERFLOW": {
        "text": "refcount underflow path",
        "clears_with": "an asymmetric dec that is reachable twice",
    },
    "REQ_LENGTH": {
        "text": "attacker-controlled length",
        "clears_with": "the length argument traced back to a packet field or a copyin buffer",
    },
    "REQ_COPY_SITE": {
        "text": "a reachable copy into a fixed buffer",
        "clears_with": "a copy-primitive call whose destination is a fixed-size object",
    },
    "REQ_OBJECT_FLOW": {
        "text": "the object the primitive acts on is the same one the entry supplies, "
                "and its ownership passes between functions rather than being assumed",
        "clears_with": "alias-tracked object identity plus a callee-side use of the "
                       "transferred object; a call edge alone never clears it",
    },
    "REQ_CHAIN_STABILITY": {
        "text": "the chain repeats on the target: the primitive fires reliably enough to "
                "turn a bug into control",
        "clears_with": "a measured success rate on the target firmware (live console)",
    },
    "REQ_CALL_PRIMITIVE": {
        "text": "a call primitive (sysent hijack to a jmp [rsi] gadget, or ROP)",
        "clears_with": "a verified gadget plus a writable sysent slot in this firmware",
    },
    "REQ_TARGET_STRUCTURE": {
        "text": "a target structure (ucred/prison/rootvnode)",
        "clears_with": "a resolved ucred or prison slot in this firmware",
    },
}

# bug class -> primitives it can feed
BUG_TO_PRIMITIVE = {
    "OWNERSHIP_UAF": ["PRIM_UAF_RECLAIM"],
    "AIO_KQUEUE_SLOT_UAF": ["PRIM_UAF_RECLAIM"],
    "OWNERSHIP_DOUBLE_FREE": ["PRIM_DOUBLE_FREE_RECLAIM"],
    "RACE_UNLOCKED_SHARED_WRITE": ["PRIM_RACE_WINDOW"],
    "FD_SOCKET_CLOSE_DISPATCH": ["PRIM_UAF_RECLAIM", "PRIM_CLOSE_HIJACK"],
    "REFCOUNT_IMBALANCE": ["PRIM_PREMATURE_FREE"],
    "HEAP_OVERFLOW_UNBOUNDED_COPY": ["PRIM_HEAP_OVERFLOW"],
}

PRIMITIVES = {
    "PRIM_UAF_RECLAIM": Primitive(
        id="PRIM_UAF_RECLAIM",
        provides=["controlled reallocation of a freed object", "type confusion"],
        requires=["REQ_ENTRY_REACHABLE", "REQ_UNPRIV_ENTRY", "REQ_SPRAY"],
    ),
    "PRIM_DOUBLE_FREE_RECLAIM": Primitive(
        id="PRIM_DOUBLE_FREE_RECLAIM",
        provides=["two live references to one allocation", "aliased object pair"],
        requires=["REQ_ENTRY_REACHABLE", "REQ_UNPRIV_ENTRY", "REQ_NO_NULL_RESET",
                  "REQ_SPRAY"],
    ),
    "PRIM_RACE_WINDOW": Primitive(
        id="PRIM_RACE_WINDOW",
        provides=["unlocked mutation of shared state", "double-fetch window"],
        requires=["REQ_ENTRY_REACHABLE", "REQ_UNPRIV_ENTRY", "REQ_TWO_CONTEXTS",
                  "REQ_WIDEN"],
    ),
    "PRIM_CLOSE_HIJACK": Primitive(
        id="PRIM_CLOSE_HIJACK",
        provides=["control of an fo_close/ops dispatch entry"],
        requires=["REQ_ENTRY_REACHABLE", "REQ_UNPRIV_ENTRY", "REQ_VTABLE", "REQ_SPRAY"],
    ),
    "PRIM_PREMATURE_FREE": Primitive(
        id="PRIM_PREMATURE_FREE",
        provides=["free while a reference is still live"],
        requires=["REQ_ENTRY_REACHABLE", "REQ_UNPRIV_ENTRY", "REQ_REFCOUNT_UNDERFLOW"],
    ),
    "PRIM_HEAP_OVERFLOW": Primitive(
        id="PRIM_HEAP_OVERFLOW",
        provides=["adjacent heap write", "object corruption"],
        requires=["REQ_ENTRY_REACHABLE", "REQ_UNPRIV_ENTRY", "REQ_LENGTH", "REQ_COPY_SITE"],
    ),
}

GOAL_REQUIREMENTS = {
    "KERNEL_CALL": {
        "needs": ["REQ_CALL_PRIMITIVE"],
        "blocker": "BLOCK_NO_CALL_PRIMITIVE",
        "clears_with": "a verified gadget plus a free sysent slot in this firmware",
    },
    "PRIVILEGE_ESCALATION": {
        "needs": ["REQ_CALL_PRIMITIVE", "REQ_TARGET_STRUCTURE"],
        "blocker": "BLOCK_NO_TARGET_STRUCTURE",
        "clears_with": "a resolved ucred/prison slot in this firmware plus a write primitive",
    },
}


def dimension(name: str, verdict: str, basis: str, evidence=None, why=None,
              assumption=None) -> dict:
    """One proof dimension. Every field is required to be honest about what it rests on."""
    return {"dimension": name, "verdict": verdict, "basis": basis, "evidence": evidence,
            "why": why, "assumption": assumption}


def concurrency_dimension(finding: dict) -> dict:
    """Lock-coverage evidence, evaluated on its own terms.

    A store that no lock call dominates is a race *candidate*. It becomes a race only when the
    object is shown to be shared state, which is an ownership/object-identity question and is
    usually still open -- so this dimension stops at CONDITIONAL and says why. The opposite
    finding is just as useful: when every store in the function is dominated by a lock call,
    the race hypothesis is REFUTED, which is a negative control rather than an absence.
    """
    claims = finding.get("claims") or {}
    detector = str(finding.get("detector") or "")
    bug_class = str(finding.get("bug_class") or "")
    lock_calls = claims.get("lock_calls") or []
    uncovered = claims.get("uncovered_stores") or []
    if not (detector.startswith("D3") or "RACE" in bug_class):
        return dimension("concurrency", UNKNOWN, "not a concurrency detector",
                         why="this finding makes no statement about locking")
    if lock_calls and not uncovered:
        return dimension("concurrency", REFUTED, "lock coverage complete",
                         evidence=f"all stores in the function are dominated by one of "
                                  f"{len(lock_calls)} lock calls")
    if uncovered:
        note = (finding.get("counter_evidence") or {}).get("note")
        return dimension("concurrency", CONDITIONAL, "lock coverage incomplete",
                         evidence=f"{len(uncovered)} store(s) not dominated by any of "
                                  f"{len(lock_calls)} lock calls",
                         assumption=note or "the object is not shown to be shared state, so the "
                                            "unlocked store is a race candidate only",
                         why=note)
    return dimension("concurrency", UNKNOWN, "no lock coverage computed",
                     why="the finding carries neither a covered nor an uncovered store list")


def ownership_summary_dimension(flow: dict) -> dict:
    """Ownership evidence from the S1.6 summaries, evaluated on its own inputs.

    This dimension is deliberately independent of authorization and of entry reachability: an
    unprivileged entry that is still UNKNOWN says nothing about whether a function consumes a
    reference on the object it was handed, and vice versa.

    The bar for PROVEN is a *must*-strength transfer out of a complete body with two independent
    witnesses: the site that touches the reference (a refcount field or a release call) and the
    argument placement that shows the site acts on this object and not on a copy. A conditional
    release, an unguarded decrement or a body that calls through a pointer cannot reach PROVEN,
    however suggestive the shape looks.
    """
    summary = flow.get("summary") or {}
    if not summary:
        return dimension("ownership", UNKNOWN, "no ownership summary",
                         why="this function was not summarised")
    status = summary.get("status")
    flows = summary.get("flows") or []
    if status == "refused":
        return dimension("ownership", UNKNOWN, "summary refused",
                         why=(summary.get("refusal") or {}).get("detail")
                             or "the body could not be summarised")
    proved = [f for f in flows if f.get("strength") == "must" and len(f.get("witnesses") or []) >= 2]
    conditional = [f for f in flows if f.get("strength") != "must" or
                   len(f.get("witnesses") or []) < 2]
    if proved and status == "complete":
        best = proved[0]
        return dimension("ownership", PROVEN, "argument-keyed reference transfer",
                         evidence={"parameter": best.get("param"), "kind": best.get("kind"),
                                   "witnesses": best.get("witnesses")})
    if proved:
        best = proved[0]
        return dimension("ownership", CONDITIONAL, "transfer in an incomplete body",
                         evidence={"parameter": best.get("param"), "kind": best.get("kind"),
                                   "witnesses": best.get("witnesses")},
                         assumption=f"the body is {status}"
                                    + (f" ({(summary.get('refusal') or {}).get('code')})"
                                       if summary.get("refusal") else ""),
                         why="the transfer was observed, but the body could not be walked "
                             "completely")
    if conditional:
        best = conditional[0]
        return dimension("ownership", CONDITIONAL, "conditional reference transfer",
                         evidence={"parameter": best.get("param"), "kind": best.get("kind"),
                                   "witnesses": best.get("witnesses")},
                         assumption=best.get("assumption") or "the release runs on one path only",
                         why=best.get("why"))
    # A "complete" walk that had to refuse an object access can hide the very consumption the
    # verdict would deny. Refusing to refute is the fail-closed direction: REFUTED needs the
    # absence *and* the proof that nothing was missed.
    unresolved = int(summary.get("unresolved_accesses") or 0)
    if status == "complete" and unresolved:
        return dimension("ownership", UNKNOWN, "unresolved object accesses in a complete body",
                         why=f"{unresolved} object access(es) could not be resolved "
                             f"({', '.join(sorted((summary.get('unresolved_reasons') or {}).keys()))}); "
                             f"a consumption hidden behind one of them cannot be excluded")
    if status == "complete":
        return dimension("ownership", REFUTED, "complete body without a reference transfer",
                         why="no argument is consumed, dropped, freed or passed on along any path "
                             "through this body")
    return dimension("ownership", UNKNOWN, "incomplete body without a transfer",
                     why=f"the body is {status}: the absence of a transfer is not established")


def dimensions_for(finding: dict, entry_proved: bool, auth: dict,
                   facts: dict) -> Dict[str, dict]:
    """Evaluate every proof dimension on its own inputs.

    The point of computing these separately is that the failure of one is not evidence about
    the others: 159 of the 370 chains in S1.4 have no entry-rooted path at all, and that says
    nothing about whether the object identity inside their function is proved.
    """
    flow = finding.get("object_flow") or {}
    local = flow.get("local") or flow or {}
    inter = flow.get("interprocedural") or {}

    # `finding["entry"]` is a label string, not a record: reading `.get` off it crashed every
    # entry-rooted chain in the S1.5 run. The witness lives under its own key.
    witness = finding.get("entry_witness")
    cfg = dimension(
        "cfg",
        PROVEN if entry_proved else UNKNOWN,
        "entry-rooted witnessed path" if entry_proved else "no entry-rooted path",
        evidence=witness if isinstance(witness, (str, dict)) else None,
        why=None if entry_proved else "no witnessed path from a resolved dispatch slot to this "
                                     "function in the bounded graph",
    )

    auth_status = auth.get("status") or auth.get("privilege")
    if auth_status == "UNPRIVILEGED":
        authz = dimension("authz", PROVEN, auth.get("basis") or "recorded authorization",
                          evidence=auth.get("evidence"))
    elif auth_status == "PRIVILEGED":
        authz = dimension("authz", REFUTED, auth.get("basis") or "credential gate",
                          evidence=auth.get("evidence"),
                          why="a credential gate sits on the path; unprivileged reachability is "
                              "refuted, not merely unproven")
    elif auth.get("conditional") is True:
        authz = dimension("authz", CONDITIONAL, "conditional credential gate",
                          evidence=auth.get("why"),
                          assumption="a credential context is referenced on the path, but the "
                                     "reference is not shown to be a check",
                          why="conditional gate: neither proven nor absent")
    else:
        authz = dimension("authz", UNKNOWN, "no authorization evidence",
                          why=auth.get("missing_obligation")
                          or "the entry's privilege class is not established")

    if local.get("proved") is True:
        identity = dimension("object_identity", PROVEN, "local alias + field offsets",
                             evidence=local.get("evidence"))
    elif local.get("sites"):
        identity = dimension("object_identity", CONDITIONAL, "local alias without fields",
                             evidence=local.get("evidence"),
                             assumption="the sites act on one object because every site uses an "
                                        "alias of the same base, but no shared field offset "
                                        "confirms it",
                             why=local.get("why"))
    else:
        identity = dimension("object_identity", UNKNOWN, "no local aliasing evidence",
                             why=local.get("why") or "no object-identity analysis was available")

    if flow.get("summary"):
        ownership = ownership_summary_dimension(flow)
    elif inter.get("proved") is True:
        ownership = dimension("ownership", PROVEN, "interprocedural reference transfer",
                              evidence=inter.get("evidence"))
    elif flow.get("proved") is True and not inter:
        ownership = dimension("ownership", UNKNOWN, "transfer not analysed",
                              why="a local identity proof says nothing about who owns the object "
                                  "across a call boundary")
    else:
        ownership = dimension("ownership", UNKNOWN, "no transfer evidence",
                              why=inter.get("why") or "no argument/return provenance was proved")

    race = concurrency_dimension(finding)

    exploit = dimension(
        "exploitability", UNKNOWN, "requires a measurement on the target",
        why="reliability and control of the primitive can only be measured on hardware; no "
            "offline artefact can move this dimension",
    )
    return {"cfg": cfg, "authz": authz, "object_identity": identity, "ownership": ownership,
            "concurrency": race, "exploitability": exploit}


def proof_ladder_for(bug_class: str) -> Dict[str, List[str]]:
    """Which requirements each rung adds for this bug class."""
    primitive_needs: List[str] = []
    for prim in primitives_for(bug_class):
        for req in prim.requires:
            if req not in primitive_needs:
                primitive_needs.append(req)
    base = ["REQ_ENTRY_REACHABLE", "REQ_UNPRIV_ENTRY", "REQ_OBJECT_FLOW"]

    def merge(*groups: Iterable[str]) -> List[str]:
        out: List[str] = []
        for group in groups:
            for req in group:
                if req not in out:
                    out.append(req)
        return out

    return {
        "CFG_REACHABLE": ["REQ_ENTRY_REACHABLE"],
        "UNPRIV_REACHABLE": merge(base[:2]),
        "OBJECT_FLOW_PROVEN": merge(base),
        "PRIMITIVE_VALIDATED": merge(base, primitive_needs),
        "EXPLOIT_CHAIN_VALIDATED": merge(base, primitive_needs, ["REQ_CHAIN_STABILITY"]),
    }


def proof_level_for(bug_class: str, outcomes: Dict[str, dict]) -> dict:
    """Walk the ladder and stop at the first rung that is not fully met.

    ``outcomes`` maps requirement id -> ``{"status", "why"}``.  A requirement that was never
    evaluated counts as open, which is the fail-closed direction: an unknown obligation must
    not be inherited as a met one.
    """
    ladder = proof_ladder_for(bug_class)
    reached = UNREACHED
    rungs: List[dict] = []
    for level in PROOF_LEVELS:
        missing = []
        for req in ladder[level]:
            outcome = outcomes.get(req) or {"status": OPEN, "why": "requirement not evaluated"}
            if outcome.get("status") != CLEARED:
                missing.append({"requirement": req,
                                "why": outcome.get("why", "not cleared"),
                                "clears_with": REQUIREMENTS.get(req, {}).get("clears_with", "")})
        rungs.append({"level": level,
                      "status": "MET" if not missing else "OPEN",
                      "missing": missing})
        if missing:
            break
        reached = level
    next_rung = next((rung for rung in rungs if rung["status"] == "OPEN"), None)
    return {"proof_level": reached, "obligations": rungs, "next_obligation": next_rung}


def primitives_for(bug_class: str) -> List[Primitive]:
    return [PRIMITIVES[p] for p in BUG_TO_PRIMITIVE.get(bug_class, []) if p in PRIMITIVES]


#: Authorization bases that may clear REQ_UNPRIV_ENTRY, and what each one means.  A
#: basis is only accepted together with the evidence that was actually read, so a
#: claim without provenance clears nothing.
AUTHORIZATION_BASES = {
    "cdevsw-world-accessible": "the devfs record's mode makes the node openable "
                               "by an unprivileged caller",
    "syscall-cred-gate-absent": "no credential gate exists on the handler path",
    # A gate that *was* found refutes unprivileged reachability. It is a basis in its own right
    # because the two directions of the authorization question need different evidence rules:
    # one positive observation suffices to refute, none suffices to prove.
    "syscall-cred-gate-present": "a credential gate sits on the handler path",
    "prison0-credential-gate": "the handler path reads the prison0 credential context",
}

UNPRIVILEGED = "UNPRIVILEGED"
PRIVILEGED = "PRIVILEGED"
PRIVILEGE_UNKNOWN = "UNKNOWN"


def entry_authorization(entry_evidence: Optional[dict]) -> dict:
    """Read the caller-authorization evidence for one entry.

    ``{"cleared": bool, "privilege": str, "why": str}``.  Anything that is not
    backed by recorded evidence stays unknown: reachability of code is not
    authorization for a caller.
    """
    auth = (entry_evidence or {}).get("authorization") or {}
    basis = auth.get("basis")
    evidence = auth.get("evidence")
    privileged = auth.get("unprivileged")
    conditional = auth.get("conditional")
    if basis in AUTHORIZATION_BASES and evidence:
        if conditional is True:
            # Evidence exists and points at a gate, but not hard enough to refute: this is the
            # CONDITIONAL middle, and it must not be reported as either proven or absent.
            return {"cleared": False, "privilege": PRIVILEGE_UNKNOWN, "conditional": True,
                    "why": f"{AUTHORIZATION_BASES[basis]}, but only as a conditional gate: "
                           f"{evidence}"}
        if privileged is True:
            return {"cleared": True, "privilege": UNPRIVILEGED,
                    "why": f"{AUTHORIZATION_BASES[basis]}: {evidence}"}
        if privileged is False:
            return {"cleared": False, "privilege": PRIVILEGED,
                    "why": f"the path is gated ({AUTHORIZATION_BASES[basis]}: {evidence})"}
    if basis:
        return {"cleared": False, "privilege": PRIVILEGE_UNKNOWN,
                "why": f"authorization claim '{basis}' carries no recorded evidence"}
    return {"cleared": False, "privilege": PRIVILEGE_UNKNOWN,
            "why": "no authorization evidence: code reachability is not privilege"}


def _requirement_status(req_id: str, finding: dict, entry_kind: str, facts: dict,
                        entry_proved: bool = False,
                        entry_evidence: Optional[dict] = None) -> dict:
    """Can offline evidence clear this requirement?"""
    claims = finding.get("claims") or {}
    if req_id == "REQ_ENTRY_REACHABLE":
        if entry_proved:
            return {"status": CLEARED,
                    "why": "a fully proved entry-rooted path reaches the function"}
        return {"status": OPEN,
                "why": "no proved entry-rooted path (the walk stopped or stayed possible)"}
    if req_id == "REQ_UNPRIV_ENTRY":
        auth = entry_authorization(
            entry_evidence if entry_evidence is not None
            else {"authorization": (facts or {}).get("entry_authorization")})
        if auth["cleared"]:
            return {"status": CLEARED, "why": auth["why"]}
        return {"status": OPEN, "why": auth["why"]}
    if req_id == "REQ_INPUT_CONTROLLED":
        if claims.get("input_controlled") is True and claims.get("input_evidence"):
            return {"status": CLEARED, "why": str(claims["input_evidence"])}
        return {"status": OPEN, "why": "no taint or argument-provenance path recorded"}
    if req_id == "REQ_NO_NULL_RESET":
        # D2 only emits REQ-relevant evidence when it walked every path
        if claims.get("path_between_without_kill") is True:
            return {"status": CLEARED,
                    "why": "D2 walked every path between the release sites and found no kill"}
        return {"status": OPEN, "why": "D2 did not establish kill-free reachability"}
    if req_id == "REQ_OBJECT_FLOW":
        flow = finding.get("object_flow") or {}
        if flow.get("proved") is True and flow.get("evidence"):
            return {"status": CLEARED, "why": str(flow["evidence"])}
        why = flow.get("why") or ("no object-flow analysis was run for this finding"
                                  if not flow else "the object flow is not proved")
        return {"status": OPEN, "why": why}
    if req_id == "REQ_CHAIN_STABILITY":
        return {"status": OPEN,
                "why": "reliability of the primitive on the target needs a live measurement"}
    if req_id == "REQ_CALL_PRIMITIVE":
        gadget = (facts.get("gadgets") or {}).get("jmp_qword_rsi")
        table = (facts.get("tables") or {}).get("sysent")
        if gadget and table:
            return {"status": CLEARED,
                    "why": f"jmp [rsi] at {gadget.get('rva')} and sysent at "
                           f"{table.get('rva')} are both resolved in this firmware"}
        return {"status": OPEN, "why": "gadget or sysent table not resolved"}
    # every remaining requirement needs something an offline image cannot show
    return {"status": OPEN, "why": "not decidable offline"}


def compose(finding: dict, entry: str, facts: dict, entry_kind: str = "",
            entry_proved: bool = False,
            entry_evidence: Optional[dict] = None) -> Chain:
    """Compose one chain for one finding + entry."""
    chain = Chain(
        finding_detector=finding["detector"],
        finding_function=finding["function"]["rva"],
        bug_class=finding["bug_class"],
        entry=entry,
    )
    auth = entry_authorization(
        entry_evidence if entry_evidence is not None
        else {"authorization": (facts or {}).get("entry_authorization")})
    chain.entry_privilege = auth["privilege"]
    # Every requirement the ladder can ask about gets evaluated, not only the ones the
    # primitive declares: an obligation that is never looked at must not silently read as met.
    outcomes: Dict[str, dict] = {}
    for req_id in proof_ladder_for(finding["bug_class"])["EXPLOIT_CHAIN_VALIDATED"]:
        outcomes[req_id] = _requirement_status(req_id, finding, entry_kind, facts,
                                               entry_proved=entry_proved,
                                               entry_evidence=entry_evidence)
    ladder = proof_level_for(finding["bug_class"], outcomes)
    chain.proof_level = ladder["proof_level"]
    chain.obligations = ladder["obligations"]
    chain.dimensions = dimensions_for(finding, entry_proved, auth, facts or {})
    prims = primitives_for(finding["bug_class"])
    if not prims:
        chain.blockers.append(
            Blocker(
                id="BLOCK_BUG_CLASS_WITHOUT_PRIMITIVE",
                why=f"bug class {finding['bug_class']} has no primitive mapping",
                clears_with="a modelled primitive for this class",
            )
        )
        return chain
    for prim in prims:
        chain.steps.append(f"primitive {prim.id}: {', '.join(prim.provides)}")
        for req_id in prim.requires:
            spec = REQUIREMENTS.get(req_id, {"text": req_id,
                                             "clears_with": "define the requirement"})
            outcome = _requirement_status(req_id, finding, entry_kind, facts,
                                          entry_proved=entry_proved,
                                          entry_evidence=entry_evidence)
            chain.steps.append(
                f"  requires {req_id} ({spec['text']}): {outcome['status']} -- {outcome['why']}"
            )
            if outcome["status"] == OPEN:
                chain.blockers.append(
                    Blocker(id=f"BLOCK_{req_id}",
                            why=f"{spec['text']} -- {outcome['why']}",
                            clears_with=spec["clears_with"])
                )
    for goal, spec in GOAL_REQUIREMENTS.items():
        goal_blockers = []
        for req_id in spec["needs"]:
            outcome = _requirement_status(req_id, finding, entry_kind, facts,
                                          entry_proved=entry_proved,
                                          entry_evidence=entry_evidence)
            if outcome["status"] == OPEN:
                goal_blockers.append(
                    Blocker(
                        id=f"BLOCK_{req_id}",
                        why=f"{REQUIREMENTS.get(req_id, {}).get('text', req_id)}"
                            f" -- {outcome['why']}",
                        clears_with=REQUIREMENTS.get(req_id, {}).get(
                            "clears_with", spec["clears_with"]),
                    )
                )
        if goal_blockers:
            for b in goal_blockers:
                if all(b.id != existing.id for existing in chain.blockers):
                    chain.blockers.append(b)
            continue
        chain.goal = goal
        chain.steps.append(f"goal {goal} reachable with the recorded facts")
        break
    if chain.goal is None and not chain.blockers:
        chain.blockers.append(
            Blocker(id="BLOCK_NO_MODEL", why="no goal requirement model matched this primitive set",
                    clears_with="extend GOAL_REQUIREMENTS")
        )
    # one blocker per requirement, even when two primitives share it
    seen_ids = set()
    unique = []
    for b in chain.blockers:
        if b.id in seen_ids:
            continue
        seen_ids.add(b.id)
        unique.append(b)
    chain.blockers = unique
    # The ladder is computed from the same outcomes; recompute after the primitive loop so
    # the two cannot disagree about a requirement.
    ladder = proof_level_for(finding["bug_class"], outcomes)
    chain.proof_level = ladder["proof_level"]
    chain.obligations = ladder["obligations"]
    return chain


def compose_all(findings: Iterable[dict], entry_for: Dict[str, str], facts: dict) -> List[dict]:
    out = []
    for finding in findings:
        key = finding["function"]["rva"]
        entry = entry_for.get(key, "UNKNOWN_ENTRY")
        out.append(compose(finding, entry, facts).as_dict())
    return out
