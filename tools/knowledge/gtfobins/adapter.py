"""Public facade of the GTFOBins knowledge adapter (pure data, offline).

Pipeline rule (fixed, not configurable): this adapter NEVER runs a GTFOBins
recipe or anything else. Recon and index matching yield OBSERVATION/CANDIDATE
material only; PS4RF later decides reachability, attacker control,
preconditions, target compatibility and verification experiments.

Inputs are operator-provided: a local corpus directory (external input, never
vendored) to build an index from, and/or a pinned index document to load.
Both paths are plain data; building, loading, drift verification and matching
only read and validate files.
"""

from __future__ import annotations

from typing import Optional

from pydantic import model_validator

from core.models.common import StrictModel

from . import indexer as _indexer
from . import matcher as _matcher
from .models import (EnumeratedBinary, GtfobinsCandidate, GtfobinsConfigError,
                     GtfobinsIndex, GtfobinsStateError)


class GtfobinsConfig(StrictModel):
    """Adapter configuration: at least one of corpus_dir / index_path."""

    corpus_dir: Optional[str] = None
    index_path: Optional[str] = None

    @model_validator(mode="after")
    def _at_least_one_input(self) -> "GtfobinsConfig":
        if not self.corpus_dir and not self.index_path:
            raise ValueError("set corpus_dir and/or index_path")
        return self


class GtfobinsAdapter:
    """Fail-closed facade: build/load an index, verify drift, match records."""

    def __init__(self, config: GtfobinsConfig) -> None:
        self.config = config
        self._index: Optional[GtfobinsIndex] = None

    def build_index(self) -> GtfobinsIndex:
        """Build the index from the configured corpus directory (fail closed)."""
        if not self.config.corpus_dir:
            raise GtfobinsConfigError("corpus_dir is not configured")
        self._index = _indexer.build_index(self.config.corpus_dir)
        return self._index

    def load_index(self) -> GtfobinsIndex:
        """Load the pinned index document from the configured path."""
        if not self.config.index_path:
            raise GtfobinsConfigError("index_path is not configured")
        self._index = _indexer.load_index(self.config.index_path)
        return self._index

    def current_index(self) -> GtfobinsIndex:
        """The index built or loaded by this adapter instance."""
        if self._index is None:
            raise GtfobinsStateError("no index yet -- call build_index() or load_index() first")
        return self._index

    def verify_corpus(self) -> bool:
        """Re-hash the configured corpus against the current index (drift check)."""
        if not self.config.corpus_dir:
            raise GtfobinsConfigError("corpus_dir is not configured")
        return _indexer.verify_corpus(self.current_index(), self.config.corpus_dir)

    def match(self, record: EnumeratedBinary) -> list[GtfobinsCandidate]:
        """Match one enumerated binary record; CANDIDATE records or nothing."""
        return _matcher.match_binary(self.current_index(), record)


__all__ = ["GtfobinsConfig", "GtfobinsAdapter"]
