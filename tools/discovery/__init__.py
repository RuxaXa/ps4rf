"""Exploit-discovery engine (offline, read-only).

Sprint-1 scope: a *measurably verified* discovery pipeline, not a report.

Design rules (carried from the PS4RF phase history):

* Every firmware address lives in a data artefact (``tools/discovery/data/**``),
  never in code.  Code reads facts, it does not hardcode them.
* The engine is a candidate *generator*.  It never executes anything, never
  touches a console and never writes to an image.
* A rule that fires must name the instruction window it fired on, and a rule
  that is suppressed must record the counter-evidence (kill / out-parameter /
  convention) that suppressed it.
* Labels (positive/negative reference cases) come from pinned primary sources
  and from our own archived negative results; the scanner is scored against
  them, never calibrated to them.
"""

__all__ = [
    "image",
    "facts",
    "patterns",
    "entries",
    "chains",
    "validate",
    "queue",
    "graph",
]
