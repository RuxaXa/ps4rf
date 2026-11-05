"""Strict data models and error taxonomy of the GTFOBins knowledge adapter.

The adapter is a pure-data translator: it parses an operator-provided local
GTFOBins corpus into a deterministic, hash-bound index and matches enumerated
binaries against that index. It spawns no process, accesses no network, loads
no code dynamically and runs nothing from the corpus; matching yields
CANDIDATE records only (see ``README.md`` for the pipeline rule).

Model taxonomy:

* :class:`GtfobinsIndex` / :class:`GtfobinsIndexEntry` -- the pinned index
  document (``ps4rf.knowledge.gtfobins.index/v1``).
* :class:`EnumeratedBinary` -- one binary record from PS4RF enumeration (the
  matcher input).
* :class:`GtfobinsCandidate` -- one candidate record (the matcher output); it
  carries no command/code field by construction and extra fields are refused.
"""

from __future__ import annotations

import json
from enum import Enum
from typing import Annotated, Literal, Optional

from pydantic import ConfigDict, Field, StringConstraints, model_validator

from core.models.common import Sha256, StrictModel

INDEX_SCHEMA_ID = "ps4rf.knowledge.gtfobins.index/v1"

#: Canonical public reference for one binary; inert documentation data only.
REFERENCE_TEMPLATE = "https://gtfobins.github.io/gtfobins/{binary}/"

NonEmpty = Annotated[str, StringConstraints(min_length=1)]
HttpsUrl = Annotated[str, StringConstraints(pattern=r"^https://")]


# ------------------------------------------------------------------ error taxonomy
class GtfobinsError(Exception):
    """Base class for adapter failures."""


class GtfobinsConfigError(GtfobinsError):
    """Invalid configuration or arguments."""


class GtfobinsCorpusError(GtfobinsError):
    """A corpus entry is unknown or unparsable (fail closed)."""


class GtfobinsUnknownFunction(GtfobinsCorpusError):
    """A corpus entry declares a function outside the known vocabulary."""


class GtfobinsCorpusDrift(GtfobinsError):
    """The corpus on disk no longer matches the pinned index (hashes differ)."""


class GtfobinsIndexError(GtfobinsError):
    """An index document violates the index contract (fail closed)."""


class GtfobinsStateError(GtfobinsError):
    """Index accessor used before an index was built or loaded."""


# ---------------------------------------------------------------------- vocabulary
class GtfobinsContext(str, Enum):
    """Execution contexts of the upstream GTFOBins entry format."""

    UNPRIVILEGED = "unprivileged"
    SUDO = "sudo"
    SUID = "suid"
    CAPABILITIES = "capabilities"


class GtfobinsTechnique(str, Enum):
    """Flat technique vocabulary: normalized function names plus route markers.

    Function names are the upstream names with hyphens normalized to
    underscores (``file-read`` -> ``file_read``); ``restricted_shell`` is kept
    as a legacy name for operator corpora derived from older snapshots. The
    markers ``sudo``, ``suid`` and ``capabilities`` enter the flat list from
    the per-example ``contexts`` blocks of the upstream format.
    """

    SHELL = "shell"
    COMMAND = "command"
    REVERSE_SHELL = "reverse_shell"
    BIND_SHELL = "bind_shell"
    FILE_WRITE = "file_write"
    FILE_READ = "file_read"
    UPLOAD = "upload"
    DOWNLOAD = "download"
    LIBRARY_LOAD = "library_load"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    INHERIT = "inherit"
    RESTRICTED_SHELL = "restricted_shell"
    SUDO = "sudo"
    SUID = "suid"
    CAPABILITIES = "capabilities"


class ExecutionContext(str, Enum):
    """Context in which an enumerated binary is reachable (matcher input)."""

    SUDO = "sudo"
    SUID = "suid"
    CAPABILITIES = "capabilities"
    SESSION = "session"


MARKER_NAMES = frozenset({"sudo", "suid", "capabilities"})
FUNCTION_NAMES = frozenset(t.value for t in GtfobinsTechnique) - MARKER_NAMES
CONTEXT_NAMES = frozenset(c.value for c in GtfobinsContext)


# ------------------------------------------------------------------------- index
class GtfobinsIndexEntry(StrictModel):
    """One corpus entry resolved to technique routes. Never stores recipe text."""

    relative_path: NonEmpty
    sha256: Sha256
    functions: list[GtfobinsTechnique] = Field(min_length=1)
    contexts: dict[GtfobinsTechnique, list[GtfobinsContext]] = Field(min_length=1)
    capability_requirements: dict[GtfobinsTechnique, list[list[NonEmpty]]] = Field(
        default_factory=dict)
    version_constraints: list[NonEmpty] = Field(default_factory=list)
    reference: HttpsUrl
    alias: Optional[NonEmpty] = None

    @model_validator(mode="after")
    def _coherence(self) -> "GtfobinsIndexEntry":
        values = [f.value for f in self.functions]
        if len(values) != len(set(values)):
            raise ValueError("duplicate techniques in functions")
        context_keys = [k.value for k in self.contexts]
        if any(key in MARKER_NAMES for key in context_keys):
            raise ValueError("contexts keys must be function names, not route markers")
        function_values = [v for v in values if v not in MARKER_NAMES]
        if len(function_values) != len(set(function_values)):
            raise ValueError("duplicate function entries")
        if set(context_keys) != set(function_values):
            raise ValueError("contexts must cover exactly the declared functions")
        for routes in self.contexts.values():
            if not routes:
                raise ValueError("declared function without routes")
            route_values = [r.value for r in routes]
            if len(route_values) != len(set(route_values)):
                raise ValueError("duplicate routes for a function")
        declared_markers = {v for v in values if v in MARKER_NAMES}
        context_markers = {r.value for routes in self.contexts.values()
                           for r in routes if r.value in MARKER_NAMES}
        if declared_markers != context_markers:
            raise ValueError("route markers must match the declared contexts")
        for function in self.capability_requirements:
            if function.value not in context_keys:
                raise ValueError(
                    f"capability requirements for undeclared function {function.value!r}")
        for function, routes in self.contexts.items():
            has_capabilities = any(r is GtfobinsContext.CAPABILITIES for r in routes)
            if has_capabilities != (function in self.capability_requirements):
                raise ValueError("capability requirements must match capabilities contexts")
        if len(self.version_constraints) != len(set(self.version_constraints)):
            raise ValueError("duplicate version constraints")
        return self


class GtfobinsIndex(StrictModel):
    """Deterministic, hash-bound index of one GTFOBins corpus snapshot."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_id: str = Field(alias="schema")
    corpus_sha256: Sha256
    entries: dict[str, GtfobinsIndexEntry] = Field(min_length=1)

    @model_validator(mode="after")
    def _contract(self) -> "GtfobinsIndex":
        if self.schema_id != INDEX_SCHEMA_ID:
            raise ValueError(f"unsupported index schema: {self.schema_id!r}")
        for name in self.entries:
            if not name:
                raise ValueError("index carries an empty entry name")
        return self

    def to_json(self) -> str:
        """Canonical serialization: sorted keys, no timestamps, trailing newline."""
        document = self.model_dump(mode="json", by_alias=True, exclude_none=True)
        return json.dumps(document, indent=2, sort_keys=True) + "\n"


# ----------------------------------------------------------------------- inputs
class EnumeratedBinary(StrictModel):
    """One binary record from PS4RF enumeration (the matcher input).

    ``mode`` is the octal permission string as enumerated; the setuid/setgid
    bits it carries must agree with the ``suid``/``sgid`` flags (fail closed
    on contradictory records).
    """

    binary_path: NonEmpty
    name: NonEmpty
    version: Optional[NonEmpty] = None
    owner: NonEmpty
    mode: Annotated[str, StringConstraints(pattern=r"^[0-7]{3,4}$")]
    suid: bool
    sgid: bool
    capabilities: list[NonEmpty] = Field(default_factory=list)
    execution_context: ExecutionContext

    @model_validator(mode="after")
    def _mode_bits_match_flags(self) -> "EnumeratedBinary":
        bits = int(self.mode, 8)
        if bool(bits & 0o4000) != self.suid:
            raise ValueError("mode and suid disagree on the setuid bit")
        if bool(bits & 0o2000) != self.sgid:
            raise ValueError("mode and sgid disagree on the setgid bit")
        return self


# ---------------------------------------------------------------------- outputs
class GtfobinsCandidate(StrictModel):
    """Matcher output: a knowledge candidate, never a claim, never a recipe.

    The model deliberately has no command/code/recipe field, so recipe text
    cannot leak into results by construction (extra fields are refused).
    """

    source: Literal["external_knowledge"] = "external_knowledge"
    technique: Literal["gtfobins"] = "gtfobins"
    classification: Literal["CANDIDATE"] = "CANDIDATE"
    requires_verification: Literal[True] = True
    binary: NonEmpty
    functions: list[GtfobinsTechnique] = Field(min_length=1)
    preconditions: list[NonEmpty] = Field(min_length=1)
    reference: HttpsUrl

    @model_validator(mode="after")
    def _unique_functions(self) -> "GtfobinsCandidate":
        values = [f.value for f in self.functions]
        if len(values) != len(set(values)):
            raise ValueError("duplicate techniques in candidate functions")
        return self


__all__ = [
    "INDEX_SCHEMA_ID", "REFERENCE_TEMPLATE", "NonEmpty", "HttpsUrl",
    "GtfobinsError", "GtfobinsConfigError", "GtfobinsCorpusError",
    "GtfobinsUnknownFunction", "GtfobinsCorpusDrift", "GtfobinsIndexError",
    "GtfobinsStateError", "GtfobinsContext", "GtfobinsTechnique",
    "ExecutionContext", "MARKER_NAMES", "FUNCTION_NAMES", "CONTEXT_NAMES",
    "GtfobinsIndexEntry", "GtfobinsIndex", "EnumeratedBinary",
    "GtfobinsCandidate",
]
