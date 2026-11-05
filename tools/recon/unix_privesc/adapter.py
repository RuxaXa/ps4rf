"""Fail-closed classification adapter for Unix collector documents (pure data).

Boundaries (consistent with the adapter rules of the handoff):

* **Pure parser/classifier**: reads a JSON collector document, validates it
  strictly and classifies every category against the detected target platform.
  Nothing is executed -- not on the host, not on a target and not on a console.
  There is no shell, no command runner, no network surface in this package.
* **Offline-first**: the only code that produces documents is the inert
  generator (``tools/recon/unix_privesc/mock/collector_mock.py``); every test
  runs without a target.
* **Hash-bound**: the SHA-256 of the collector document is recorded in the
  report (:class:`~tools.recon.unix_privesc.models.DocumentBinding`) and is
  re-checkable (:func:`verify_report`). An expected-hash mismatch refuses
  *before* parsing (fail closed).
* **Single attempt** per invocation, no retries, no partial output.
* **Platform-independent by construction**: ``linux_only`` and
  ``freebsd_only`` categories are recorded per target platform and never
  applied to the wrong one; on an ``unknown`` platform the classifier refuses
  platform-specific interpretation (``platform_interpretation='refused'``)
  while keeping the raw enumeration accessible. PS4/OrbisOS-specific hints go
  to a separate, deferred bucket that carries no PS4 coverage claim --
  PS4-specific checks are owned by PS4RF surface/experiment modules.

Document contract: ``ps4rf.unix_privesc.collect/v1`` (see
tools/recon/unix_privesc/README.md).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Never, Optional

from pydantic import ValidationError

from tools.recon.unix_privesc.models import (CATEGORY_SEMANTICS, SCHEMA_ID,
                                             Category, CategoryEntry,
                                             CategoryReport, CategoryStatus,
                                             CollectorDocument, DocumentBinding,
                                             PlatformInterpretation,
                                             PlatformSemantics,
                                             PlatformSpecificFindings,
                                             PlatformSpecificStatus,
                                             TargetPlatform,
                                             UnixPrivescReport,
                                             classification_status)


class UnixPrivescError(Exception):
    """Base class for adapter failures."""


class UnixPrivescConfigError(UnixPrivescError):
    """Invalid configuration or arguments (e.g. missing document)."""


class UnixPrivescHashMismatch(UnixPrivescError):
    """Document hash does not match the expected value (refused before parsing)."""


class UnixPrivescSchemaError(UnixPrivescError):
    """Document violates the ``ps4rf.unix_privesc.collect/v1`` contract."""


class UnixPrivescEvidenceError(UnixPrivescError):
    """A recorded report does not re-verify (hash, schema, classification)."""


class UnixPrivescStateError(UnixPrivescError):
    """Result accessors used before :meth:`UnixPrivescAdapter.classify` ran."""


def detect_platform(platform_hint: str) -> TargetPlatform:
    """Classify the collector's verbatim platform hint (pure mapping).

    ``orbis``/``freebsd`` (checked first, so ``OrbisOS (FreeBSD ...)`` lands
    correctly) -> ``freebsd_orbisos``; ``linux`` -> ``linux``; anything else
    (including an empty string) -> ``unknown`` -- never guessed.
    """
    token = platform_hint.strip().lower()
    if "orbis" in token or "freebsd" in token:
        return TargetPlatform.FREEBSD_ORBISOS
    if "linux" in token:
        return TargetPlatform.LINUX
    return TargetPlatform.UNKNOWN


def _platform_note(platform: TargetPlatform) -> str:
    if platform is TargetPlatform.UNKNOWN:
        return ("target platform unknown: platform-specific interpretation refused; "
                "raw enumeration preserved")
    return f"platform-specific classification applied for {platform.value}"


def _category_note(platform: TargetPlatform, semantics: PlatformSemantics,
                   status: CategoryStatus) -> str:
    if semantics is PlatformSemantics.POSIX:
        return "platform-independent (posix) category"
    if status is CategoryStatus.REFUSED:
        return (f"{semantics.value} category: interpretation refused on unknown "
                "platform; raw entries preserved")
    if status is CategoryStatus.APPLICABLE:
        return f"{semantics.value} category applies to the {platform.value} target"
    return (f"{semantics.value} category inapplicable on the {platform.value} "
            "target (recorded, not interpreted)")


def classify_document(document: CollectorDocument, *,
                      source: DocumentBinding) -> UnixPrivescReport:
    """Classify a validated collector document against its detected platform.

    Never drops a category: every declared category appears in the report even
    when the document carries no entries for it. An inapplicable category that
    carries entries is a contradiction and refuses (fail closed).
    """
    platform = detect_platform(document.target.platform_hint)
    if platform is TargetPlatform.LINUX and document.platform_specific:
        raise UnixPrivescSchemaError(
            "platform_specific findings cannot originate from a linux target "
            "(fail closed)")
    blocks = {block.category: block for block in document.categories}
    reports: list[CategoryReport] = []
    for category in Category:
        semantics = CATEGORY_SEMANTICS[category]
        block = blocks.get(category)
        raw_entries = list(block.entries) if block is not None else []
        status = classification_status(platform, semantics)
        if status is CategoryStatus.INAPPLICABLE and raw_entries:
            raise UnixPrivescSchemaError(
                f"category {category.value!r} is {semantics.value} but the target "
                f"is {platform.value}: inapplicable categories must carry no "
                "entries (fail closed)")
        reports.append(CategoryReport(
            category=category,
            platform_semantics=semantics,
            status=status,
            entries=[CategoryEntry(key=entry.key, value=entry.value)
                     for entry in raw_entries],
            note=_category_note(platform, semantics, status)))
    bucket_status = (PlatformSpecificStatus.REFUSED
                     if platform is TargetPlatform.UNKNOWN
                     else PlatformSpecificStatus.DEFERRED)
    bucket = PlatformSpecificFindings(
        findings=[CategoryEntry(key=entry.key, value=entry.value)
                  for entry in document.platform_specific],
        status=bucket_status)
    interpretation = (PlatformInterpretation.REFUSED
                      if platform is TargetPlatform.UNKNOWN
                      else PlatformInterpretation.APPLICABLE)
    return UnixPrivescReport(
        schema=SCHEMA_ID,
        source=source,
        platform=platform,
        platform_hint=document.target.platform_hint,
        platform_interpretation=interpretation,
        platform_note=_platform_note(platform),
        categories=reports,
        platform_specific=bucket)


def verify_report(report: UnixPrivescReport, document_path: str | Path) -> bool:
    """Re-verify a report against its collector document (hash + re-derivation).

    Raises :class:`UnixPrivescEvidenceError` on any mismatch, returns True
    otherwise.
    """
    def fail(message: str) -> Never:
        raise UnixPrivescEvidenceError(message)

    path = Path(document_path)
    if not path.is_file():
        fail(f"collector document missing: {path}")
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != report.source.document_sha256:
        fail(f"document hash mismatch: {digest} != {report.source.document_sha256}")
    if len(raw) != report.source.document_bytes:
        fail(f"document size mismatch: {len(raw)} != {report.source.document_bytes}")
    try:
        document = CollectorDocument.model_validate(json.loads(raw.decode("utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError) as exc:
        fail(f"document failed re-validation: {exc}")
    try:
        derived = classify_document(document, source=report.source)
    except UnixPrivescSchemaError as exc:
        fail(f"document no longer classifies: {exc}")
    if derived.model_dump(mode="json") != report.model_dump(mode="json"):
        fail("report does not re-derive from the document (drift)")
    return True


class UnixPrivescAdapter:
    """Fail-closed, single-attempt classifier for hash-bound collector documents.

    Pure data: the adapter reads and classifies; it never runs anything on the
    host, a target or a console.
    """

    def __init__(self) -> None:
        self._last: Optional[UnixPrivescReport] = None
        self.run_log: list[dict[str, object]] = []

    # ------------------------------------------------------------------ plumbing
    def hash_document(self, path: str | Path) -> str:
        """SHA-256 of a collector document's bytes (hashing only, no parsing)."""
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()

    def require_report(self) -> UnixPrivescReport:
        """Last successful report; refuses before :meth:`classify` ran."""
        if self._last is None:
            raise UnixPrivescStateError("no report yet -- call classify() first")
        return self._last

    # ------------------------------------------------------------------- methods
    def classify(self, document_path: str | Path, *,
                 expected_sha256: Optional[str] = None) -> UnixPrivescReport:
        """Read, validate and classify one collector document (single attempt).

        ``expected_sha256`` refuses *before* any parsing happens (fail closed).
        """
        path = Path(document_path)
        if not path.is_file():
            self.run_log.append({"phase": "missing", "document_path": str(path)})
            raise UnixPrivescConfigError(f"collector document not found: {path}")
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if expected_sha256 is not None and digest != expected_sha256:
            self.run_log.append({"phase": "refused", "reason": "hash-mismatch",
                                 "document_sha256": digest})
            raise UnixPrivescHashMismatch(
                f"document {digest} != expected {expected_sha256} "
                "(refused before parsing)")
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            self.run_log.append({"phase": "failed", "reason": "json",
                                 "document_sha256": digest})
            raise UnixPrivescSchemaError(
                f"collector document is not valid JSON: {exc}") from exc
        try:
            document = CollectorDocument.model_validate(payload)
        except ValidationError as exc:
            self.run_log.append({"phase": "failed", "reason": "schema",
                                 "document_sha256": digest})
            raise UnixPrivescSchemaError(
                f"collector document does not satisfy {SCHEMA_ID}: {exc}") from exc
        binding = DocumentBinding(
            document_sha256=digest,
            document_bytes=len(raw),
            collector_tool=document.collector.tool,
            collector_version=document.collector.version,
            hostname=document.target.hostname)
        try:
            report = classify_document(document, source=binding)
        except UnixPrivescSchemaError:
            self.run_log.append({"phase": "failed", "reason": "classification",
                                 "document_sha256": digest})
            raise
        self._last = report
        self.run_log.append({"phase": "classified", "document_sha256": digest,
                             "platform": report.platform.value})
        return report
