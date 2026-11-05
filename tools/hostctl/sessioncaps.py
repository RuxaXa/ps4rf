"""W14 §4/§6 -- capability derivation for a *resident* agent: once per session, never carried over.

The resident agent serves many sessions in one lifetime, which is exactly where a capability record
can go wrong: it is convenient to derive one for the first session and reuse it for the rest. This
module makes that impossible to do by accident.

What a session gets is what the frozen driver mints for it:

* the store is addressed by the evidence hash (:func:`kreadlive.derive_capability_record`) and
  rehashes the canonical bytes on load -- ``STORE_REHASH_MISMATCH`` if they moved,
* the *current* boot id and the *current* profile sha256 are checked by
  :func:`kreadlive.evidence_policy_problems`, and the verification run/session must be separate from
  the session that is about to act,
* the record is ``scope = SESSION`` and names the session it was derived for.

On top of that, a :class:`ResidentCapabilityLedger` keeps the run honest across sessions:

* one derivation per session id (a second one is refused: a session derives once, so a record that
  was minted earlier cannot be quietly re-minted),
* every record is bound to the daemon *lifetime* it was derived inside (§18 evidence), and
* :meth:`accept` refuses a record that names another session or another lifetime -- the "never carry
  Session A's record into Session B" rule, as a check that can fail a test rather than a comment.

Nothing here weakens the frozen chain: the ledger never fabricates a record, it only refuses to hand
out one that does not belong to the session that asked.
"""

from __future__ import annotations

import hashlib
import json
from typing import Mapping

from tools.hostctl import kreadstore as KS
from tools.hostctl.kreadlive import (DerivationRejected, derive_capability_record,
                                     revalidate_derivation)

#: Raised when a session tries to use a capability that is not its own.
SESSION_REUSED = 'RESIDENT_SESSION_REUSED'
LIFETIME_MISMATCH = 'RESIDENT_LIFETIME_MISMATCH'
DERIVED_TWICE = 'RESIDENT_CAPABILITY_DERIVED_TWICE'
NOT_DERIVED = 'RESIDENT_CAPABILITY_NOT_DERIVED'


def record_digest(record: Mapping) -> str:
    """A stable digest of one derived record (its identity, not its provenance)."""
    return hashlib.sha256(json.dumps(record, sort_keys=True,
                                     separators=(',', ':')).encode()).hexdigest()


class ResidentCapabilityLedger:
    """One agent lifetime's worth of derived session capabilities (§4/§6/§18)."""

    def __init__(self, *, lifetime_id: str) -> None:
        if not lifetime_id:
            raise ValueError('a resident capability ledger needs the lifetime it belongs to')
        self.lifetime_id = lifetime_id
        self.derivations: list[dict] = []
        self._by_session: dict[str, dict] = {}      # session id -> {'record', 'record_digest'}

    # ------------------------------------------------------------------ derivation
    def derive_for_session(self, store: KS.VerificationEvidenceStore, *, session_id: str,
                           evidence_sha256: str, run_id: str, profile_sha256: str, boot_id: str,
                           provider: Mapping, context: str, approval: Mapping | None = None,
                           expected: Mapping | None = None) -> dict:
        """Derive *this* session's record -- reloaded, rehashed and re-bound, every time.

        The frozen derivation does the work; the ledger only refuses to do it twice for one session
        and records what came out, so the resident flow has per-session capability evidence.
        """
        if session_id in self._by_session:
            raise DerivationRejected(
                DERIVED_TWICE,
                f'session {session_id!r} already has a capability in this lifetime: a resident '
                'session derives once, it never inherits or re-mints a record')
        record = derive_capability_record(store, evidence_sha256=evidence_sha256, read_run_id=run_id,
                                          profile_sha256=profile_sha256, boot_id=boot_id,
                                          provider=provider, context=context, session_id=session_id,
                                          approval=approval, expected=expected)
        # The record itself stays exactly what the frozen derivation minted -- it is revalidated by
        # content hash against its receipt, so *the ledger must not touch it*. The lifetime binding
        # lives here, in the ledger's own evidence: which lifetime and which session each derivation
        # happened in (the same inputs in one process are the same record; the per-session and
        # per-run separation is what the frozen derivation enforces).
        entry = {'session_id': session_id, 'lifetime_id': self.lifetime_id,
                 'evidence_sha256': evidence_sha256, 'profile_sha256': profile_sha256,
                 'boot_id': boot_id, 'run_id': run_id,
                 'receipt_id': record['derivation'].get('receipt_id'),
                 'record_digest': record_digest(record)}
        self.derivations.append(entry)
        self._by_session[session_id] = {'record': record, 'record_digest': entry['record_digest'],
                                        'run_id': run_id}
        return record

    # ------------------------------------------------------------------ use
    def accept(self, record: Mapping, *, session_id: str, store, boot_id: str,
               profile_sha256: str, read_run_id: str | None = None) -> list[str]:
        """Refuse a capability that is not this session's -- or revalidate it if it is.

        Raises :class:`DerivationRejected` with ``RESIDENT_SESSION_REUSED`` /
        ``RESIDENT_CAPABILITY_NOT_DERIVED``, or with whatever the frozen revalidation refuses
        (evidence moved, boot changed, profile changed, markers missing, ...). Returns ``[]`` when
        the record is this session's and still validates.
        """
        if record is None:
            raise DerivationRejected(NOT_DERIVED, f'session {session_id!r} has no capability record')
        if record.get('session_id') != session_id:
            raise DerivationRejected(
                SESSION_REUSED,
                f'the record belongs to session {record.get("session_id")!r}, this session is '
                f'{session_id!r}')

        verification = record.get('verification') or {}
        if verification.get('derived_for_session') != session_id:
            raise DerivationRejected(SESSION_REUSED,
                                     'the record names this session but was derived for another')
        entry = self._by_session.get(session_id)
        if entry is None or entry['record_digest'] != record_digest(record):
            raise DerivationRejected(
                NOT_DERIVED,
                f'the record presented for session {session_id!r} is not the one this lifetime '
                'derived for it (a tampered or carried-over record is refused here)')
        # the run the record was derived for is remembered here: a caller cannot forget it and get
        # a refusal for the wrong reason
        problems = revalidate_derivation(record, store=store, session_id=session_id, boot_id=boot_id,
                                         profile_sha256=profile_sha256,
                                         read_run_id=read_run_id or entry['run_id'])
        if problems:
            raise DerivationRejected(
                problems[0].split(':')[0],
                '; '.join(problems) + ' (a resident session re-derives rather than repairs)')
        return []

    # ------------------------------------------------------------------ evidence
    def evidence(self) -> dict:
        """The ledger as evidence: the lifetime, one entry per session, and the count."""
        return {'lifetime_id': self.lifetime_id, 'capability_derivations': list(self.derivations),
                'sessions_derived': len(self.derivations)}
