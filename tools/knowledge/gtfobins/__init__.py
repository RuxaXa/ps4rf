"""GTFOBins knowledge adapter (pure data, offline, no execution).

Builds a deterministic, hash-bound index from an operator-provided local
GTFOBins corpus and matches enumerated binaries against it, yielding
CANDIDATE records only. Nothing in this package spawns a process, opens a
network connection, loads code dynamically or runs corpus content; see
``README.md`` for the pipeline rule and the corpus/index formats.
"""

from .adapter import GtfobinsAdapter, GtfobinsConfig
from .indexer import build_index, index_sha256, load_index, verify_corpus, write_index
from .matcher import match_binary
from .models import (EnumeratedBinary, ExecutionContext, GtfobinsCandidate,
                     GtfobinsConfigError, GtfobinsContext, GtfobinsCorpusDrift,
                     GtfobinsCorpusError, GtfobinsError, GtfobinsIndex,
                     GtfobinsIndexEntry, GtfobinsIndexError, GtfobinsStateError,
                     GtfobinsTechnique, GtfobinsUnknownFunction)

__all__ = [
    "GtfobinsAdapter", "GtfobinsConfig",
    "build_index", "index_sha256", "load_index", "verify_corpus", "write_index",
    "match_binary",
    "EnumeratedBinary", "ExecutionContext", "GtfobinsCandidate",
    "GtfobinsConfigError", "GtfobinsContext", "GtfobinsCorpusDrift",
    "GtfobinsCorpusError", "GtfobinsError", "GtfobinsIndex", "GtfobinsIndexEntry",
    "GtfobinsIndexError", "GtfobinsStateError", "GtfobinsTechnique",
    "GtfobinsUnknownFunction",
]
