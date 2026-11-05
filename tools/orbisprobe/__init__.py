"""OrbisProbe integration package (adapter v0.1, offline only).

See ``adapter.py`` for the hard rules; ``ORBISPROBE-PS4RF-MAPPING.md`` in the
repo root for the verified mapping and conflict list.
"""

from .adapter import (
    AdapterRefusal,
    ArtifactHashMismatch,
    DiscoveryContext,
    EvidenceArtifact,
    EvidenceBundle,
    ExperimentIR,
    OrbisProbeAdapter,
    OrbisProbeAdapterError,
    OrbisProbeAdapterProtocol,
    ProofReport,
    RankedCandidates,
    RankedEntry,
    Reproducer,
    RunRecord,
    SessionContext,
)

__all__ = [
    "AdapterRefusal",
    "ArtifactHashMismatch",
    "DiscoveryContext",
    "EvidenceArtifact",
    "EvidenceBundle",
    "ExperimentIR",
    "OrbisProbeAdapter",
    "OrbisProbeAdapterError",
    "OrbisProbeAdapterProtocol",
    "ProofReport",
    "RankedCandidates",
    "RankedEntry",
    "Reproducer",
    "RunRecord",
    "SessionContext",
]
