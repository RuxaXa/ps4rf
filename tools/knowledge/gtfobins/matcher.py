"""Deterministic matcher: enumerated binary record -> CANDIDATE records only.

Matching is a pure lookup plus context gating; it never inspects, decodes or
runs anything. The gates mirror the upstream contexts:

* ``unprivileged`` routes carry no privilege gate (the binary was enumerated;
  reachability remains a PS4RF question);
* ``sudo`` routes require the enumerated execution context ``sudo``;
* ``suid`` routes require the enumerated binary to carry the setuid bit;
* ``capabilities`` routes require the enumerated capability set to satisfy a
  declared requirement set (a capability context declared without ``list``
  means "any capability").

A function is matched when at least one of its declared routes passes its
gate; the candidate lists the matched functions plus the privilege-route
markers (``sudo``, ``suid``, ``capabilities``) whose gates passed. No match
yields an empty list -- never a guess. Version constraints are never
evaluated: they are surfaced in ``preconditions`` as unverified statements,
so applicability is never claimed. Emitted candidates carry no recipe,
command or code text by construction.
"""

from __future__ import annotations

from .models import (EnumeratedBinary, ExecutionContext, GtfobinsCandidate,
                     GtfobinsContext, GtfobinsIndex, GtfobinsIndexEntry,
                     GtfobinsTechnique, MARKER_NAMES)

_BASE_PRECONDITION = (
    "candidate only: PS4RF decides reachability, attacker control, preconditions, "
    "target compatibility and verification experiments; applicability is not claimed")

_UNPRIVILEGED_NOTE = (
    "unprivileged route requires direct execution access to the binary in the "
    "enumerated context; verify on the target")

_SUDO_NOTE = (
    "sudo route requires a sudo invocation context for this binary; verify the "
    "sudo policy on the target")

_SUID_NOTE = (
    "suid route requires a setuid binary; verify setuid bit, ownership and "
    "filesystem state on the target")


def _normalized_caps(names: list[str]) -> set[str]:
    return {name.strip().upper() for name in names if name.strip()}


def _capability_route_satisfied(entry: GtfobinsIndexEntry,
                                function_name: str,
                                record_caps: set[str]) -> bool:
    """True when one declared requirement set is covered by the record caps."""
    requirement_sets = entry.capability_requirements.get(
        GtfobinsTechnique(function_name), [])
    for required in requirement_sets:
        needed = {cap.strip().upper() for cap in required}
        if not needed:
            if record_caps:
                return True        # declared without a list: any capability
        elif needed <= record_caps:
            return True
    return False


def _capability_note(entry: GtfobinsIndexEntry, capability_functions: list[str],
                     record: EnumeratedBinary) -> str:
    parts = []
    for name in capability_functions:
        requirement_sets = entry.capability_requirements.get(
            GtfobinsTechnique(name), [])
        if not requirement_sets:
            continue
        alternatives = " | ".join(
            ", ".join(requirement) if requirement else "any declared capability"
            for requirement in requirement_sets)
        parts.append(f"{name}: {alternatives}")
    observed = ", ".join(record.capabilities) if record.capabilities else "none"
    return (
        "capabilities route requires declared Linux capabilities of the matched "
        f"functions ({'; '.join(parts)}); enumeration reports: {observed}; verify "
        "the effective capability set on the target")


def _version_notes(entry: GtfobinsIndexEntry, record: EnumeratedBinary) -> list[str]:
    notes = []
    for constraint in entry.version_constraints:
        if record.version is None:
            notes.append(
                f"version constraint '{constraint}' is unverified: the enumerated "
                "binary declares no version; confirm the constraint against the "
                "target binary")
        else:
            notes.append(
                f"version constraint '{constraint}' was not evaluated against "
                f"enumerated version '{record.version}'; confirm manually")
    return notes


def match_binary(index: GtfobinsIndex,
                 record: EnumeratedBinary) -> list[GtfobinsCandidate]:
    """Return zero or one CANDIDATE record for the enumerated binary."""
    entry = index.entries.get(record.name)
    if entry is None:
        return []
    record_caps = _normalized_caps(record.capabilities)
    matched_functions: list[str] = []
    capability_functions: list[str] = []
    applicable_routes: set[str] = set()
    for function, routes in entry.contexts.items():
        function_name = function.value
        applicable: set[str] = set()
        for route in routes:
            if route is GtfobinsContext.UNPRIVILEGED:
                applicable.add(GtfobinsContext.UNPRIVILEGED.value)
            elif route is GtfobinsContext.SUDO:
                if record.execution_context is ExecutionContext.SUDO:
                    applicable.add(GtfobinsContext.SUDO.value)
            elif route is GtfobinsContext.SUID:
                if record.suid:
                    applicable.add(GtfobinsContext.SUID.value)
            elif route is GtfobinsContext.CAPABILITIES:
                if _capability_route_satisfied(entry, function_name, record_caps):
                    applicable.add(GtfobinsContext.CAPABILITIES.value)
        if applicable:
            matched_functions.append(function_name)
            if GtfobinsContext.CAPABILITIES.value in applicable:
                capability_functions.append(function_name)
            applicable_routes |= applicable
    if not matched_functions:
        return []
    functions = sorted(set(matched_functions)
                       | {route for route in applicable_routes if route in MARKER_NAMES})
    notes = set(_version_notes(entry, record))
    if GtfobinsContext.CAPABILITIES.value in applicable_routes:
        notes.add(_capability_note(entry, capability_functions, record))
    if GtfobinsContext.SUDO.value in applicable_routes:
        notes.add(_SUDO_NOTE)
    if GtfobinsContext.SUID.value in applicable_routes:
        notes.add(_SUID_NOTE)
    if GtfobinsContext.UNPRIVILEGED.value in applicable_routes:
        notes.add(_UNPRIVILEGED_NOTE)
    preconditions = [_BASE_PRECONDITION, *sorted(notes)]
    candidate = GtfobinsCandidate(
        binary=record.name,
        functions=[GtfobinsTechnique(value) for value in functions],
        preconditions=preconditions, reference=entry.reference)
    return [candidate]


__all__ = ["match_binary"]
