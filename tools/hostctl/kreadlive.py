#!/usr/bin/env python3
"""W12 two-phase live driver: PHASE A (fixed bootstrap verification) and PHASE B (generic read).

The accepted W12 flow runs as **two uploads and two sessions** and this module is the host side
of that shape. It never chains the phases: each phase is one entry point, one payload, one
session, and phase B can only run against the record phase A persisted.

PHASE A -- :func:`run_verification` (CLI ``--w12-verify-run``)
    one session, no generic provider entry at all. The frozen payload triggers its fixed
    bootstrap read right after the first ``session.status`` response; the host captures the
    sealed ``kernel.read.bounded`` event, re-derives the bytes and the sha256 itself, compares
    them against the pinned ``image_elf`` expectation (the profile's ``kernel.attest.image_elf``
    locator, 16 bytes at RVA 0), verifies the assembled read evidence through
    :mod:`tools.hostctl.kreadverify` (both the bootstrap path and the generic path with the
    pinned expectation) and persists one ``VerificationEvidence``. No capability, no grant, no
    provider entry: the bootstrap path is what makes the *first* evidence possible, so it must
    never require an already-PROVEN ``kernel.read`` (no capability circle).

PHASE B -- :func:`run_generic_read` (CLI ``--w12-read-run``)
    a **separate** upload and a **new** session. The host loads the persisted evidence and
    rehashes it (``evidence_sha256`` must match the recomputed canonical hash; a bare
    ``verified: true`` flag is never sufficient), derives a session-scoped capability record for
    the *new* session id from that evidence, and runs the mandated chain -- W4 gate, W5 profile
    binding, current boot binding, W7 provider router -- as the existing
    :func:`tools.profiles.kread_capability.decide` (this module re-implements none of it). Only a
    GRANTED decision yields exactly one provider entry, and only then is the payload's single
    generic bounded read of the same region (``image_elf`` offset 0 length 16) verified against
    the same pinned bytes.

    The pinned window's locator is relative: ``image_elf`` sits at rva 0 (``rva + offset == 0``).
    W12-RVA0-BINDING separates the two domains that used to be conflated here -- the *relative*
    locator value (zero is a valid image position) and the *runtime* address (never zero, must be
    canonical). The W5 profile binding binds the locator; the runtime address is resolved from
    the current boot's kernel base with checked arithmetic
    (``tools.profiles.regions.checked_kernel_address`` / ``resolve_runtime``) and fails closed on
    overflow, zero or a non-canonical value. The pinned window therefore walks the whole chain
    and takes exactly one provider entry (reproducible offline, see
    :func:`run_offline_simulation`).

Boundaries (each one refuses with the named reason, provider entries stay 0)
    * session: a SESSION-scoped record from run A is never carried into run B. The new session
      derives its own record; reusing the old session id is refused
      (:data:`KREADLIVE_SESSION_REUSED`) and a record derived for another session never passes
      the W4 gate (``BINDING_MISMATCH``).
    * boot: ``boot_id`` differs from the evidence -> ``KREAD_STALE_BOOT_ID``, no capability, a
      fresh verification run is required.
    * profile: the stored evidence names another ``profile_sha256`` -> ``KREAD_WRONG_PROFILE``,
      provider entries 0.
    * run separation: ``verification_run_id != read_run_id`` and
      ``verification_session_id != read_session_id``, checked before anything is sent and
      recorded in the persisted read-run record (:data:`KREADLIVE_RUN_NOT_SEPARATE`).
    * region index (D2): before the release is consumed and before the provider entry, the
      driver itself decides the requested compiled-row index --
      ``0 <= region_index < len(compiled_regions())`` against the normative *compiled* table
      (never the policy registry total, never a second index table) -- and requires the window's
      region name to resolve through that table to exactly the index the target request will
      carry. Out of range -> :data:`KREAD_REGION_INDEX_INVALID`; a region/name disagreement ->
      :data:`W13_RELEASE_WINDOW_MISMATCH`; both cost zero provider entries, consume no release
      and send no trigger, so the target is never the first thing to notice.

Region semantics are the registry's, unchanged: only ``STRICT_FINGERPRINT`` regions (or
explicitly approved bounded ones) are readable, ``aperture_global`` stays ``STRUCTURAL_ONLY``,
the boottime region stays ``DEFERRED`` and ``UNRESOLVED`` regions are never read -- the event
verifier refuses a non-STRICT region before any byte is compared, and every bound
(offset/length/region crossing/address) is the registry's own rule set.

The payload cannot be driven twice: it performs exactly one read per session and its
one-shot guard refuses a second invocation (``native/target/ps4rf_agent.c``,
``native/target/build_manifest.py`` gate facts) -- this driver therefore runs one phase per
session and never retries a read.

Offline: nothing here opens a socket by itself, and the whole flow is exercised through the
synthetic session fixtures (:class:`OfflineSession`) in :func:`run_offline_simulation`, which
is also what ``--simulate`` runs. No console, no network, no rearm.

Usage::

    python tools/hostctl/kreadlive.py --self-test
    python tools/hostctl/kreadlive.py --simulate [--store DIR]
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import sys
from collections.abc import Mapping

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:                       # pragma: no cover - import bootstrap
    sys.path.insert(0, str(REPO_ROOT))

from core.rpc.handshake import ProtocolError                                   # noqa: E402
from tools.hostctl import bootpriv, kreadverify                                # noqa: E402
from tools.hostctl.endpoint import EndpointClosed                              # noqa: E402
from tools.hostctl.evidence import canonical_sha256                            # noqa: E402
from tools.hostctl.kreadstore import (RECORD_HASH_FIELD, SCHEMA_READ_RUN,      # noqa: E402
                                      SCHEMA_RELEASE_CONSUMPTION, SCHEMA_VERIFICATION,
                                      STORE_BARE_FLAG, STORE_CONFLICT, STORE_ID_INVALID,
                                      STORE_INVALID, STORE_MISSING, STORE_REHASH_MISMATCH,
                                      STORE_UNREADABLE, StoreError, VerificationEvidenceStore,
                                      build_consumption_record, canonical_evidence_sha256,
                                      canonical_record_sha256)
from tools.hostctl.session import (EVENT_KERNEL_READ_BOUNDED,                  # noqa: E402
                                   KERNEL_READ_BOUNDED_SCHEMA, SessionError,
                                   kernel_read_bounded_problems, smoke_request_id)
from tools.profiles import bootid, kread as kread_model                        # noqa: E402
from tools.profiles import kread_capability as KC                              # noqa: E402
from tools.profiles import promotion, regions                                  # noqa: E402
from tools.profiles.binding import BootBinding                                 # noqa: E402
from tools.profiles.schema import canonical_profile_sha256                     # noqa: E402

# --- frozen identities of the flow ---------------------------------------------------------
OPERATION = 'kernel.read'
VERIFICATION_OPERATION = kreadverify.VERIFICATION_OPERATION          # verify.kernel.read
CONTEXT = 'JAILBROKEN_PROCESS'
SCOPE_SESSION = 'SESSION'

PROVIDER_NAME = 'ps4rfd-kread-privileged'
PROVIDER_TYPE = 'NATIVE'
PROVIDER_STATE_WIRED = 'WIRED'
PROVIDER_ALLOWED_TYPES = ('NATIVE',)                                 # the W4 table's allowlist

#: the frozen trigger of the payload's single bounded read (W13-C1): the ``kernel.read`` request
#: itself, carrying exactly three integers -- the index of a row of the *compiled* region table,
#: an offset and a length -- and nothing else (native/target/ps4rf_agent.c). The frozen router
#: keeps answering the operation as deferred privilege, so the read never becomes a wired
#: provider; the host supplies no address and no rva, and the index it sends is derived from the
#: normative compiled table and cross-checked against the index the payload echoes back.
TRIGGER_OPERATION = 'kernel.read'

EVENT_KIND = EVENT_KERNEL_READ_BOUNDED                               # kernel.read.bounded
EVENT_SCHEMA = KERNEL_READ_BOUNDED_SCHEMA                            # ps4rf.kernel.read.bounded.v1

#: the pinned fixed bootstrap window (registry + profile locator ``kernel.attest.image_elf``)
PINNED_REGION = kreadverify.BOOTSTRAP_REGION                         # image_elf
PINNED_OFFSET = kreadverify.BOOTSTRAP_OFFSET                         # 0
PINNED_RVA = kreadverify.BOOTSTRAP_RVA                               # 0
PINNED_LENGTH = kreadverify.BOOTSTRAP_LENGTH                         # 16
PINNED_BYTES_HEX = '7f454c46020101090000000000000000'                # the ELF header
PINNED_SHA256 = '7ef1ae261e75094d5eb5f2291a465e479dd62cfd7ae628fdd3ecefb38f90a092'
PINNED_LOCATOR = 'kernel.attest.image_elf'

#: the base derivation the payload's own cross check uses: kbase == lstar - 0x1C0
XFAST_RVA = bootpriv.XFAST_RVA
KERNEL_MIN = bootpriv.KERNEL_MIN
UNMEASURED = 'UNMEASURED'                                            # documented payload alias
MISSING = 'MISSING'                                                  # the payload's absent-read alias

PHASE_VERIFY = 'w12-verify-run'
PHASE_READ = 'w12-read-run'
PHASES = (PHASE_VERIFY, PHASE_READ)

OUTCOME_VERIFIED = 'VERIFIED'
OUTCOME_READ = 'READ'
OUTCOME_REFUSED = 'REFUSED'

RESULT_SCHEMA = 'ps4rf.kread.phase-result.v1'
EVENT_REPORT_SCHEMA = 'ps4rf.kread.live-event-report.v1'
SIMULATION_SCHEMA = 'ps4rf.kread.simulation-report.v1'

# --- refusal vocabulary (this module's codes; the reused modules keep theirs) ---------------
KREADLIVE_SESSION_MISSING = 'KREADLIVE_SESSION_MISSING'
KREADLIVE_SESSION_REUSED = 'KREADLIVE_SESSION_REUSED'
KREADLIVE_SESSION_STOPPED = 'KREADLIVE_SESSION_STOPPED'
KREADLIVE_RESPONSE_INVALID = 'KREADLIVE_RESPONSE_INVALID'
KREADLIVE_EVENT_MISSING = 'KREADLIVE_EVENT_MISSING'
KREADLIVE_EVENT_CONTRACT = 'KREADLIVE_EVENT_CONTRACT'
KREADLIVE_EVENT_NOT_EXECUTED = 'KREADLIVE_EVENT_NOT_EXECUTED'
KREADLIVE_EVENT_READ_FAILED = 'KREADLIVE_EVENT_READ_FAILED'
KREADLIVE_EVENT_CLAIM = 'KREADLIVE_EVENT_CLAIM'
KREADLIVE_REGION_MISMATCH = 'KREADLIVE_REGION_MISMATCH'
KREADLIVE_REGION_INDEX_MISMATCH = 'KREADLIVE_REGION_INDEX_MISMATCH'
KREADLIVE_REGION_NOT_COMPILED = 'KREADLIVE_REGION_NOT_COMPILED'
KREADLIVE_TRIGGER_NOT_DEFERRED = 'KREADLIVE_TRIGGER_NOT_DEFERRED'
KREADLIVE_REGION_IDENTITY = 'KREADLIVE_REGION_IDENTITY'
KREADLIVE_STRICT_IDENTITY_REQUIRED = 'KREADLIVE_STRICT_IDENTITY_REQUIRED'
KREADLIVE_OFFSET_MISMATCH = 'KREADLIVE_OFFSET_MISMATCH'
KREADLIVE_LENGTH_MISMATCH = 'KREADLIVE_LENGTH_MISMATCH'
KREADLIVE_BOUNDS_MISMATCH = 'KREADLIVE_BOUNDS_MISMATCH'
KREADLIVE_TABLE_MISMATCH = 'KREADLIVE_TABLE_MISMATCH'
KREADLIVE_KBASE_MISMATCH = 'KREADLIVE_KBASE_MISMATCH'
KREADLIVE_ADDRESS_MISMATCH = 'KREADLIVE_ADDRESS_MISMATCH'
KREADLIVE_BYTES_MISMATCH = 'KREADLIVE_BYTES_MISMATCH'
KREADLIVE_SHA256_MISMATCH = 'KREADLIVE_SHA256_MISMATCH'
KREADLIVE_NOT_MEASURED = 'KREADLIVE_NOT_MEASURED'
KREADLIVE_EXPECTATION_MISMATCH = 'KREADLIVE_EXPECTATION_MISMATCH'
KREADLIVE_PROVIDER_MISMATCH = 'KREADLIVE_PROVIDER_MISMATCH'
KREADLIVE_EVIDENCE_MISSING = 'KREADLIVE_EVIDENCE_MISSING'
KREADLIVE_EVIDENCE_INVALID = 'KREADLIVE_EVIDENCE_INVALID'
KREADLIVE_EVIDENCE_REHASH_MISMATCH = 'KREADLIVE_EVIDENCE_REHASH_MISMATCH'
KREADLIVE_EVIDENCE_BARE_FLAG = 'KREADLIVE_EVIDENCE_BARE_FLAG'
KREADLIVE_BOOTSTRAP_EXPECTATION = 'KREADLIVE_BOOTSTRAP_EXPECTATION'
KREADLIVE_RUN_NOT_SEPARATE = 'KREADLIVE_RUN_NOT_SEPARATE'
KREADLIVE_PROVIDER_ENTRY_COUNT = 'KREADLIVE_PROVIDER_ENTRY_COUNT'
KREADLIVE_WRONG_PROFILE = 'KREADLIVE_WRONG_PROFILE'
KREADLIVE_UNKNOWN_REGION = 'KREADLIVE_UNKNOWN_REGION'
KREADLIVE_LOCATOR_NOT_PROMOTED = 'KREADLIVE_LOCATOR_NOT_PROMOTED'
#: W12-A3: a PROVEN record that is not an internally generated derivation (the provider entry
#: refuses it; the store's own vocabulary is used where the store or its rehash refused)
KREADLIVE_CAPABILITY_NOT_DERIVED = 'KREADLIVE_CAPABILITY_NOT_DERIVED'
#: A read window that is not the pinned bootstrap window must be a *released* window (W13): the
#: window carries the release id it came from. Nothing else may ever be read.
KREADLIVE_WINDOW_NOT_RELEASED = 'KREADLIVE_WINDOW_NOT_RELEASED'
#: W13 one-shot: a release is consumed exactly once -- at the provider entry (see the policy text in
#: tools/hostctl/kreadstore.py). A second attempt with the same release id never reaches the provider.
KREADLIVE_RELEASE_ALREADY_CONSUMED = 'W13_RELEASE_ALREADY_CONSUMED'
#: The consumption marker could not be written; the run refuses *before* the provider entry, and the
#: attempt is remembered in-process so it cannot be repeated in this process.
KREADLIVE_RELEASE_CONSUMPTION_FAILED = 'W13_RELEASE_CONSUMPTION_FAILED'
#: A released window must name the release DOCUMENT (release_sha256) beside its release id: the
#: one-shot marker pins the document it spent, so an unbound window is refused.
KREADLIVE_RELEASE_UNBOUND = 'W13_RELEASE_UNBOUND'

#: Releases already consumed by THIS process (defence in depth beside the persisted marker): a
#: release that reached the provider entry here is spent even if the store write below failed.
_CONSUMED_RELEASES: dict[str, dict] = {}


#: store reason -> the driver's refusal code (the store's vocabulary is never renamed away)
EVIDENCE_REFUSALS = {
    STORE_MISSING: KREADLIVE_EVIDENCE_MISSING,
    STORE_UNREADABLE: KREADLIVE_EVIDENCE_INVALID,
    STORE_INVALID: KREADLIVE_EVIDENCE_INVALID,
    STORE_ID_INVALID: KREADLIVE_EVIDENCE_INVALID,
    STORE_CONFLICT: KREADLIVE_EVIDENCE_INVALID,
    STORE_BARE_FLAG: KREADLIVE_EVIDENCE_BARE_FLAG,
    STORE_REHASH_MISMATCH: KREADLIVE_EVIDENCE_REHASH_MISMATCH,
}

#: the four claims the payload makes about the read it performed (booleans, never 0/1)
READ_CLAIMS = ('single_callback', 'retry', 'writes_to_kernel', 'host_supplied_address')


# ===========================================================================================
# small shared helpers
# ===========================================================================================
class _Collector:
    """Fail-closed check/problems collector: one place, one vocabulary, no silent pass."""

    def __init__(self) -> None:
        self.checks: list[dict] = []
        self.problems: list[str] = []

    def check(self, name: str, ok: bool, reason: str, detail: str = '') -> bool:
        self.checks.append({'name': name, 'ok': bool(ok), 'reason': None if ok else reason,
                            'detail': detail})
        if not ok:
            self.problems.append(f'{reason}: {detail}' if detail else reason)
        return bool(ok)

    def fail(self, reason: str, detail: str = '') -> bool:
        return self.check(reason, False, reason, detail)

    def absorb(self, report: Mapping | None, *, prefix: str = '') -> None:
        """Copy another report's checks and problems verbatim (namespaced when asked)."""
        if not isinstance(report, Mapping):
            return
        for entry in report.get('checks') or ():
            if not isinstance(entry, Mapping):
                continue
            name = str(entry.get('name') or entry.get('check') or 'check')
            self.checks.append({'name': f'{prefix}{name}', 'ok': bool(entry.get('ok')),
                                'reason': entry.get('reason'), 'detail': entry.get('detail') or ''})
        for problem in report.get('problems') or ():
            text = f'{prefix}{problem}' if prefix else str(problem)
            if text not in self.problems:
                self.problems.append(text)

    @property
    def ok(self) -> bool:
        return not self.problems

    def failed_names(self) -> list[str]:
        return [str(c['name']) for c in self.checks if not c['ok']]


def _u64(value, where: str, problems: list[str]) -> int | None:
    """Read one payload number with the W11.2 reader (same encoding: ``0x…`` or decimal).

    ``bootpriv._int`` is the repository's single reader for the payload's number format; the W12
    event uses exactly that format, so it is reused rather than re-implemented.
    """
    return bootpriv._int(value, where, problems)


def parse_number(value) -> int | None:
    """Lenient scalar read for the verifier's comparisons (never raises; None when unreadable)."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    sink: list[str] = []
    return _u64(value, 'value', sink)


def parse_address(value) -> int | None:
    """Parse one address field; the payload's documented ``UNMEASURED``/``MISSING`` mean zero.

    ``resolved_rva`` and ``resolved_runtime_va`` are emitted as ``UNMEASURED`` when the value is
    zero (native/target/ps4rf_kread.c), and a not-executed read emits ``MISSING``; both aliases
    are read as the zero value only, never as an excuse to skip the comparison.
    """
    if value in (UNMEASURED, MISSING):
        return 0
    return parse_number(value)


def u64_hex(value: int) -> str:
    """The payload's u64 representation: ``0x`` + 16 lowercase hex digits."""
    return '0x' + format(value & 0xFFFFFFFFFFFFFFFF, '016x')


def canonical_view(doc: Mapping) -> dict:
    """A JCS-safe copy of one document: 64-bit addresses as the payload's own u64 text.

    ``core.canonical`` is JCS: a number beyond ``2**53 - 1`` is refused (``UnsafeNumber``), and a
    kernel address is far beyond it. The wire, the payload and every canonical document in this
    repository therefore carry an address as text; the two address fields of a read-evidence
    document are converted here the same way so the whole document can be hashed (and so the
    persisted record is byte-identical in meaning to what the payload reported).
    """
    view = dict(doc)
    for field in ('resolved_rva', 'resolved_runtime_va'):
        value = view.get(field)
        if isinstance(value, int) and not isinstance(value, bool):
            view[field] = u64_hex(value)
    return view


def stable_evidence_ref(value) -> str | None:
    """A location-independent evidence reference: ``<kind>/<name>.json`` from any path.

    Transcripts, phase summaries and the persisted read-run record must be byte-stable across
    runs and machines (the evidence pack is diffed, and a hash-frozen record must not embed the
    directory it happened to live in), so no absolute path ever enters them. The store root is
    reported by whoever owns it.
    """
    if not isinstance(value, str) or not value:
        return None
    parts = pathlib.Path(value).parts
    if len(parts) >= 2 and parts[-1].endswith('.json'):
        return '/'.join(parts[-2:])
    return pathlib.Path(value).name


def region_index(name: str) -> int | None:
    """The index of ``name`` in the *compiled target table* (the payload's own index space).

    ``regions.compiled_region_index`` is the single normative source: a payload compiles the
    table with the ``UNRESOLVED`` policy entries excluded, so a policy entry between two
    compiled regions may never shift an index (deviation ``W12-A-D1``).
    """
    return regions.compiled_region_index(name)


#: D2 (owner W15): the requested compiled-row index is decided by the HOST, in front of the
#: release consumption, the provider entry and the trigger. This is the code of that decision:
#: an index outside ``0 <= region_index < len(compiled_regions())`` -- against the normative
#: *compiled* table, never the policy registry total and never a second index table -- is refused
#: with it, before anything is consumed or entered.
#:
#: Vocabulary mapping (documented, so the older code is not silently lost): the pre-entry
#: *request mapping* (:func:`wire_request_for`) still names a missing, negative or boolean index
#: ``KREADLIVE_REGION_NOT_COMPILED`` exactly as it always did, and that problem stays in the
#: list; every out-of-bounds or non-integer index additionally carries
#: ``KREAD_REGION_INDEX_INVALID`` from :func:`region_index_bounds_problems`. Where a run's
#: refusal used to be the post-entry event cross-check (``KREADLIVE_TABLE_MISMATCH``: an integer
#: inside the 32 bit range but outside the compiled table was caught only *after* the provider
#: entry), the pre-entry ``KREAD_REGION_INDEX_INVALID`` is the refusal now -- the target is never
#: the first thing to notice (D2).
KREAD_REGION_INDEX_INVALID = 'KREAD_REGION_INDEX_INVALID'

#: The W13 release window vocabulary, restated: ``tools/research/release.py`` owns the string
#: (``RELEASE_WINDOW_MISMATCH``) and imports this module, so this module cannot import it back.
#: Same string, same refusal -- the release's region resolved through the compiled table must be
#: the compiled row the target request names.
W13_RELEASE_WINDOW_MISMATCH = 'W13_RELEASE_WINDOW_MISMATCH'


def region_index_bounds_problems(window: Mapping) -> list[str]:
    """D2: the pre-entry region-index decision -- bounds first, then the compiled-row agreement.

    The requested index is checked against the **compiled target table** -- the single normative
    source is :func:`tools.profiles.regions.compiled_regions` (through
    ``compiled_region_index``), never the policy registry total and never a second index table::

        0 <= region_index < len(compiled_regions())

    An index outside that half-open interval, an index that is not an integer, or a boolean is
    refused with :data:`KREAD_REGION_INDEX_INVALID`. Only an in-range index is then cross-checked
    against the window's region name: ``compiled_region_index(window['region'])`` must equal the
    index that goes into the target request (``window['region_index']`` is exactly the value
    :func:`wire_request_for` sends); a mismatch is refused with
    :data:`W13_RELEASE_WINDOW_MISMATCH`, so the target is never the first thing to notice.

    Returns the refusal problems (empty list admits the index). The caller
    (:func:`run_generic_read`) runs this in the problem collection that returns before the
    release consumption, the provider entry and the trigger. The mutant proof in
    ``tests/test_w15_index_bounds.py`` patches this function away at the point the driver uses it
    and observes the old post-entry behaviour return -- and the patch itself fails when this
    function is removed, so the test goes red if the production check disappears.
    """
    problems: list[str] = []
    table = regions.compiled_regions()
    index = window.get('region_index')
    if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < len(table):
        problems.append(
            f'{KREAD_REGION_INDEX_INVALID}: the window region index {index!r} is outside the '
            f'compiled target table: 0 <= index < {len(table)} = len(compiled_regions()); the '
            f'policy registry total ({len(regions.regions())} entries) is not the index space '
            f'and no second table is consulted')
        return problems
    name = window.get('region')
    derived = regions.compiled_region_index(name) if isinstance(name, str) else None
    if derived != index:
        problems.append(
            f'{W13_RELEASE_WINDOW_MISMATCH}: the window region {name!r} resolves to compiled row '
            f'{derived!r}, but the request would name index {index!r}; the released region and '
            f'the index the target request carries must be the same compiled row')
    return problems


def derived_run_id(kind: str, *parts: str) -> str:
    """Stable run id: ``<kind>-<sha256("ps4rf/w12/…")[:16]>`` (reproducible evidence packs)."""
    digest = hashlib.sha256('/'.join(('ps4rf/w12', kind, *parts)).encode()).hexdigest()
    return f'{kind}-{digest[:16]}'


def provider_identity(provider: Mapping | None = None) -> dict:
    """Normalise the provider identity the decision needs (name/type/state/live approval)."""
    identity = {'name': PROVIDER_NAME, 'provider_type': PROVIDER_TYPE,
                'state': PROVIDER_STATE_WIRED, 'live_approved': False}
    if isinstance(provider, Mapping):
        for key in identity:
            if key in provider:
                identity[key] = provider[key]
    return identity


def bootstrap_expectation(profile: Mapping | None = None) -> dict:
    """The pinned fixed bootstrap window, cross-checked against the registry and the profile.

    Three independent sources must agree before a byte is compared: the registry entry
    (region/rva/length/identity), the profile locator ``kernel.attest.image_elf`` (policy and
    expected bytes) and the frozen constants of this module (bytes and sha256).
    """
    problems: list[str] = []
    region = regions.get_region(PINNED_REGION)
    if region is None:
        problems.append(f'the registry has no region {PINNED_REGION!r}')
    else:
        if region.identity_status != regions.IDENTITY_STRICT:
            problems.append(f'{PINNED_REGION} is {region.identity_status}, not STRICT_FINGERPRINT')
        if region.rva != PINNED_RVA:
            problems.append(f'{PINNED_REGION} rva is {region.rva!r}, expected {PINNED_RVA!r}')
        if region.length != PINNED_LENGTH:
            problems.append(f'{PINNED_REGION} length is {region.length!r}, expected '
                            f'{PINNED_LENGTH!r}')
        if region.locator != PINNED_LOCATOR:
            problems.append(f'{PINNED_REGION} locator is {region.locator!r}, expected '
                            f'{PINNED_LOCATOR!r}')
    if regions.MAX_READ_LEN < int(PINNED_LENGTH):
        problems.append('the registry ceiling is below the pinned read length')
    if isinstance(profile, Mapping):
        locator = (profile.get('locators') or {}).get(PINNED_LOCATOR)
        if not isinstance(locator, Mapping):
            problems.append(f'the profile carries no locator {PINNED_LOCATOR!r}')
        else:
            expected_bytes = (locator.get('expected_bytes') or {})
            if expected_bytes.get('hex') != PINNED_BYTES_HEX:
                problems.append('the profile locator expected bytes differ from the pinned bytes')
            if expected_bytes.get('offset') != PINNED_OFFSET:
                problems.append('the profile locator expected offset differs from the pinned '
                                'offset')
            policy = str(locator.get('policy') or '')
            if 'STRICT' not in policy.upper():
                problems.append(f'the profile locator policy {policy!r} is not a strict policy')
    raw = bytes.fromhex(PINNED_BYTES_HEX)
    if hashlib.sha256(raw).hexdigest() != PINNED_SHA256:
        problems.append('the pinned sha256 is not the hash of the pinned bytes')
    if len(raw) != PINNED_LENGTH:
        problems.append('the pinned bytes are not the pinned length')
    if region_index(PINNED_REGION) is None:
        problems.append(f'{KREADLIVE_REGION_NOT_COMPILED}: {PINNED_REGION} is not in the compiled '
                        'target table')
    return {'region': PINNED_REGION, 'offset': PINNED_OFFSET, 'length': PINNED_LENGTH,
            'rva': PINNED_RVA, 'bytes_hex': PINNED_BYTES_HEX, 'sha256': PINNED_SHA256,
            'locator': PINNED_LOCATOR, 'region_index': region_index(PINNED_REGION),
            'problems': problems}


def window_for(region_name: str, *, bytes_hex: str, offset: int = 0, length: int = 16,
               locator: str | None = None, profile: Mapping | None = None,
               release_id: str | None = None, release_sha256: str | None = None,
               approval_sha256: str | None = None) -> dict:
    """A pinned-window dict for one registry region (the offline rehearsal uses it).

    The pinned bootstrap window is :func:`bootstrap_expectation`; this builder exists so the
    offline machinery rehearsal can run the *same* phase code against another STRICT region
    without touching the frozen constants. When ``profile`` is given, the window carries the two
    region-semantics refusals as its own problems, and phase B refuses the window on them: a
    region that is not ``STRICT_FINGERPRINT`` (``aperture_global`` stays STRUCTURAL_ONLY) and a
    region whose locator is not promoted in the profile (``boottime`` has no promoted locator and
    therefore stays DEFERRED) are never read.
    """
    problems: list[str] = []
    region = regions.get_region(region_name)
    if region is None:
        problems.append(f'{KREADLIVE_UNKNOWN_REGION}: the registry has no region '
                        f'{region_name!r}')
    raw = bytes.fromhex(bytes_hex)
    if len(raw) != length:
        problems.append(f'{len(raw)} bytes do not match the requested length {length}')
    name = locator if locator is not None else (region.locator if region is not None else None)
    if region is not None and region.identity_status != regions.IDENTITY_STRICT:
        problems.append(f'{KREADLIVE_STRICT_IDENTITY_REQUIRED}: {region_name} is '
                        f'{region.identity_status}, not {regions.IDENTITY_STRICT}; only '
                        f'{regions.IDENTITY_STRICT} regions are readable')
    if profile is not None and name is not None:
        promoted = (profile.get('locators') or {}).get(name)
        if not isinstance(promoted, Mapping) or not promoted.get('expected_bytes'):
            problems.append(f'{KREADLIVE_LOCATOR_NOT_PROMOTED}: {name} is not a promoted locator '
                            'in the profile (no expected bytes), so the region stays DEFERRED')
    index = region_index(region_name)
    if index is None:
        problems.append(f'{KREADLIVE_REGION_NOT_COMPILED}: {region_name} is not in the compiled '
                        'target table, so the request cannot name it')
    return {'region': region_name, 'offset': offset, 'length': length,
            'rva': region.rva if region is not None else None, 'bytes_hex': bytes_hex,
            'sha256': hashlib.sha256(raw).hexdigest(), 'locator': name,
            'region_index': index, 'problems': problems,
            'release_id': release_id, 'release_sha256': release_sha256,
            'approval_sha256': approval_sha256}


def profile_problems(profile: Mapping | None) -> list[str]:
    """The current profile must be the real one (fixture flag off, W5 candidate checks pass)."""
    if not isinstance(profile, Mapping):
        return [f'{KREADLIVE_WRONG_PROFILE}: no profile document was supplied']
    if profile.get('fixture') is not False:
        return [f'{KREADLIVE_WRONG_PROFILE}: the profile is not marked as the real profile '
                '(fixture is not False)']
    candidates = promotion.check_candidate(dict(profile))
    if candidates:
        return [f'{KREADLIVE_WRONG_PROFILE}: the W5 candidate checks refuse the profile: '
                f'{"; ".join(str(c) for c in candidates)}']
    return []


# ===========================================================================================
# the host-side verification of one kernel.read.bounded event
# ===========================================================================================
def verify_bounded_event(event, *, profile: Mapping | None = None,
                         expected: Mapping | None = None) -> dict:
    """Independently re-derive everything one ``kernel.read.bounded`` event claims.

    The payload is the untrusted reporter: every number is re-read from the registry (type,
    identity status, rva, length, ceiling), the returned bytes are re-hashed here, the kernel
    base is re-derived from ``lstar`` (``lstar - 0x1C0``, the same rule the payload's own cross
    check uses) and each address is re-composed and re-validated as a canonical x86-64 VA. When
    ``expected`` is given (the pinned bootstrap window) the bytes, the hash and the length must
    match it exactly -- a read that returns something else is a refusal, never a near miss.
    """
    col = _Collector()
    window = dict(expected or {})
    report: dict = {
        'schema': EVENT_REPORT_SCHEMA,
        'event_kind': EVENT_KIND,
        'event_schema': None,
        'verified': False,
        'checks': col.checks,
        'problems': col.problems,
        'checks_failed': [],
        'region': None, 'requested_region_index': None, 'region_identity': None,
        'region_rva': None, 'offset': None, 'length': None, 'returned_length': None,
        'bytes_hex': None, 'output_sha256': None, 'sha256_status': None,
        'resolved_rva': None, 'resolved_runtime_va': None, 'kbase': None, 'lstar': None,
        'callback_executed': None, 'cb_status': None, 'cb_status_name': None, 'kexec_rc': None,
        'run_status': None, 'status': None, 'cross_check': None,
        'region_count': None, 'max_read_len': None, 'claims': {},
        'expected_bytes_hex': window.get('bytes_hex'), 'expected_sha256': window.get('sha256'),
        'build_id': None, 'label': None, 'provider': None,
    }
    if not isinstance(event, Mapping):
        col.fail(KREADLIVE_EVENT_MISSING, f'no {EVENT_KIND} event was captured ({event!r})')
        report['checks_failed'] = col.failed_names()
        return report
    event = dict(event)
    report['event_schema'] = event.get('schema')
    report['build_id'] = event.get('build_id')
    report['label'] = event.get('label')
    report['provider'] = event.get('provider')

    # 0. the event contract is the session module's (single owner of the field list and types)
    contract = kernel_read_bounded_problems(event)
    col.check('event_contract_complete', not contract, KREADLIVE_EVENT_CONTRACT,
              '; '.join(contract))
    col.check('event_is_kernel_read_bounded', event.get('event') == EVENT_KIND,
              KREADLIVE_EVENT_CONTRACT, f"event={event.get('event')!r}")

    # 1. the region: from the registry, STRICT identity, and the claim must agree with it
    name = event.get('requested_region')
    region = regions.get_region(name) if isinstance(name, str) else None
    report['region'] = name
    report['region_identity'] = event.get('region_identity')
    report['requested_region_index'] = event.get('requested_region_index')
    col.check('region_known', region is not None, KREADLIVE_REGION_MISMATCH,
              f'requested_region={name!r}')
    if region is not None:
        col.check('region_strict_identity',
                  region.identity_status == regions.IDENTITY_STRICT,
                  KREADLIVE_STRICT_IDENTITY_REQUIRED,
                  f'{name} is {region.identity_status}; the generic read path needs '
                  'STRICT_FINGERPRINT')
        col.check('region_identity_claim_matches_registry',
                  event.get('region_identity') == region.identity_status,
                  KREADLIVE_REGION_IDENTITY,
                  f"claim={event.get('region_identity')!r} registry={region.identity_status!r}")
        col.check('region_index_matches_registry_order',
                  event.get('requested_region_index') == region_index(str(name)),
                  KREADLIVE_TABLE_MISMATCH,
                  f"index={event.get('requested_region_index')!r} "
                  f'registry={region_index(str(name))!r}')
    if window.get('region') is not None:
        col.check('requested_region_is_expected', name == window['region'],
                  KREADLIVE_REGION_MISMATCH, f'found={name!r} expected={window["region"]!r}')
    if window.get('region_index') is not None:
        # W13-C1: the payload reports the index it actually served; it must be the index the host
        # sent for the released region (the compiled table's row), never a different row
        col.check('requested_region_index_is_expected',
                  event.get('requested_region_index') == window['region_index'],
                  KREADLIVE_REGION_INDEX_MISMATCH,
                  f"returned index={event.get('requested_region_index')!r} "
                  f"sent={window['region_index']!r} region={window['region']!r}")

    # 2. the request window: offset/length as numbers, the expected one, and the registry bounds
    offset = parse_number(event.get('requested_offset'))
    length = parse_number(event.get('requested_length'))
    report['offset'] = offset
    report['length'] = length
    col.check('requested_offset_is_a_number', offset is not None, KREADLIVE_OFFSET_MISMATCH,
              f"requested_offset={event.get('requested_offset')!r}")
    col.check('requested_length_is_a_number', length is not None, KREADLIVE_LENGTH_MISMATCH,
              f"requested_length={event.get('requested_length')!r}")
    if window.get('offset') is not None:
        col.check('requested_offset_is_expected', offset == window['offset'],
                  KREADLIVE_OFFSET_MISMATCH, f'found={offset!r} expected={window["offset"]!r}')
    if window.get('length') is not None:
        col.check('requested_length_is_expected', length == window['length'],
                  KREADLIVE_LENGTH_MISMATCH, f'found={length!r} expected={window["length"]!r}')
    rva_expected = None
    if region is not None and offset is not None and length is not None \
            and isinstance(region.rva, int) and isinstance(region.length, int):
        end = kread_model.checked_add(offset, length)
        inside = (offset >= 0 and 1 <= length <= regions.MAX_READ_LEN and end is not None
                  and end <= region.length)
        col.check('read_within_the_region', bool(inside), KREADLIVE_BOUNDS_MISMATCH,
                  f'offset={offset} length={length} region_length={region.length} '
                  f'ceiling={regions.MAX_READ_LEN}')
        rva_expected = kread_model.checked_add(region.rva, offset)
        col.check('region_rva_matches_registry', parse_number(event.get('region_rva'))
                  == region.rva, KREADLIVE_BOUNDS_MISMATCH,
                  f"claim={event.get('region_rva')!r} registry={u64_hex(region.rva)}")
        col.check('offset_length_sum_matches_checked_add',
                  parse_number(event.get('offset_length_sum')) == end, KREADLIVE_BOUNDS_MISMATCH,
                  f"claim={event.get('offset_length_sum')!r} recomputed={u64_hex(end or 0)}")
    # The payload reports the table it *compiled*: ``regions.compiled_regions()`` is the one
    # normative source for that count (W12-A-D1: the policy total, ``len(regions.regions())``,
    # includes the UNRESOLVED entries the generator refuses by design and must never be used).
    compiled = regions.compiled_regions()
    table_ok = (event.get('max_read_len') == regions.MAX_READ_LEN
                and event.get('region_count') == len(compiled))
    report['max_read_len'] = event.get('max_read_len')
    report['region_count'] = event.get('region_count')
    col.check('generated_table_matches_registry', bool(table_ok), KREADLIVE_TABLE_MISMATCH,
              f"max_read_len={event.get('max_read_len')!r} region_count="
              f"{event.get('region_count')!r} compiled={len(compiled)} "
              f"(policy registry entries={len(regions.regions())})")

    # 3. the kernel base: re-derived from lstar, never taken from the payload
    lstar = parse_number(event.get('lstar'))
    kbase_candidate = parse_number(event.get('kbase_candidate'))
    kbase_sdk = parse_number(event.get('kbase_sdk'))
    kbase = None
    report['lstar'] = lstar
    if lstar is None or not bootpriv.lstar_shape_ok(lstar):
        col.fail(KREADLIVE_KBASE_MISMATCH, f'lstar {event.get("lstar")!r} is not the shape of the '
                                           'xfastsyscall pointer (>= 0xffff800000000000, '
                                           f'low bits 0x{XFAST_RVA:x})')
    else:
        kbase = lstar - XFAST_RVA
        report['kbase'] = kbase
        col.check('kbase_rederived_from_lstar', kbase_candidate == kbase and kbase_sdk == kbase,
                  KREADLIVE_KBASE_MISMATCH,
                  f'candidate={kbase_candidate!r} sdk={kbase_sdk!r} host={u64_hex(kbase)}')
    col.check('cross_check_matches', event.get('cross_check') == 'MATCH',
              KREADLIVE_KBASE_MISMATCH, f"cross_check={event.get('cross_check')!r}")

    # 4. the returned bytes: the host's own hash, over the bytes the event carries
    returned = None
    if isinstance(event.get('bytes_hex'), str):
        try:
            returned = bytes.fromhex(event['bytes_hex'])
        except ValueError:
            returned = None
    report['bytes_hex'] = returned.hex() if returned is not None else None
    report['returned_length'] = len(returned) if returned is not None else None
    col.check('bytes_hex_is_readable', returned is not None, KREADLIVE_EVENT_CONTRACT,
              f"bytes_hex={event.get('bytes_hex')!r}")
    recomputed = hashlib.sha256(returned).hexdigest() if returned is not None else None
    report['output_sha256'] = recomputed
    report['sha256_status'] = event.get('sha256_status')
    observed = report['returned_length']
    col.check('returned_length_is_the_requested_length',
              observed is not None and length is not None and observed == length,
              KREADLIVE_LENGTH_MISMATCH, f'returned={observed} requested={length}')
    col.check('output_sha256_is_host_recomputed',
              recomputed is not None and event.get('sha256') == recomputed,
              KREADLIVE_SHA256_MISMATCH, f"claim={event.get('sha256')!r} host={recomputed!r}")
    col.check('sha256_status_measured', event.get('sha256_status') == 'MEASURED',
              KREADLIVE_NOT_MEASURED, f"sha256_status={event.get('sha256_status')!r}")

    # 5. the addresses the payload composed (evidence-only, canonical, consistent)
    report['region_rva'] = parse_number(event.get('region_rva'))
    resolved_rva = parse_address(event.get('resolved_rva'))
    report['resolved_rva'] = resolved_rva
    resolved_va = parse_address(event.get('resolved_runtime_va'))
    report['resolved_runtime_va'] = resolved_va
    col.check('resolved_rva_matches_region_plus_offset',
              resolved_rva is not None and rva_expected is not None
              and resolved_rva == rva_expected, KREADLIVE_ADDRESS_MISMATCH,
              f"evidence={resolved_rva!r} recomputed={u64_hex(rva_expected) if rva_expected is not None else None}")
    composed = None
    if kbase is not None and rva_expected is not None:
        composed = kread_model.checked_add(kbase, rva_expected)
    col.check('resolved_runtime_va_is_canonical',
              resolved_va is not None and kread_model.is_canonical_x86_64(resolved_va),
              KREADLIVE_ADDRESS_MISMATCH,
              f'resolved_runtime_va={event.get("resolved_runtime_va")!r}')
    # W12-RVA0-BINDING: the rva may be 0, the runtime address may not be (a zero runtime
    # address is not an address; the payload composing one is a contract violation).
    col.check('resolved_runtime_va_is_nonzero',
              resolved_va is not None and resolved_va != 0,
              KREADLIVE_ADDRESS_MISMATCH,
              f'resolved_runtime_va={event.get("resolved_runtime_va")!r}')
    col.check('resolved_runtime_va_matches_kbase_plus_rva',
              resolved_va is not None and composed is not None and resolved_va == composed,
              KREADLIVE_ADDRESS_MISMATCH,
              f"evidence={resolved_va!r} recomputed={u64_hex(composed) if composed is not None else None}")

    # 6. what the read did (and did not do): the payload's own claims, checked one by one
    report['callback_executed'] = event.get('callback_executed')
    report['cb_status'] = event.get('cb_status')
    report['cb_status_name'] = event.get('cb_status_name')
    report['kexec_rc'] = event.get('kexec_rc')
    report['run_status'] = event.get('run_status')
    report['status'] = event.get('status')
    report['cross_check'] = event.get('cross_check')
    col.check('callback_executed', event.get('callback_executed') is True,
              KREADLIVE_EVENT_NOT_EXECUTED, f"callback_executed={event.get('callback_executed')!r}")
    col.check('read_reported_ok',
              event.get('run_status') == 0 and event.get('status') == 'OK'
              and event.get('cb_status') == 0 and event.get('cb_status_name') == 'OK'
              and event.get('kexec_rc') == 0,
              KREADLIVE_EVENT_READ_FAILED,
              f"run_status={event.get('run_status')!r} status={event.get('status')!r} "
              f"cb_status={event.get('cb_status')!r} kexec_rc={event.get('kexec_rc')!r}")
    claims = {name: event.get(name) for name in READ_CLAIMS}
    report['claims'] = claims
    col.check('read_claims_hold',
              claims == {'single_callback': True, 'retry': False, 'writes_to_kernel': False,
                         'host_supplied_address': False},
              KREADLIVE_EVENT_CLAIM, json.dumps(claims, sort_keys=True))

    # 7. the pinned expectation: the returned 16 bytes and their hash, exactly
    if isinstance(window.get('bytes_hex'), str):
        col.check('returned_bytes_are_the_pinned_bytes',
                  returned is not None and returned.hex() == window['bytes_hex'],
                  KREADLIVE_BYTES_MISMATCH,
                  f'returned={report["bytes_hex"]!r} pinned={window["bytes_hex"]!r}')
    if isinstance(window.get('sha256'), str):
        col.check('output_sha256_is_the_pinned_sha256',
                  recomputed is not None and recomputed == window['sha256'],
                  KREADLIVE_SHA256_MISMATCH, f'host={recomputed!r} pinned={window["sha256"]!r}')

    report['verified'] = col.ok
    report['checks_failed'] = col.failed_names()
    return report


# ===========================================================================================
# session plumbing (the W11.2 machinery: single reader, half close, BYE)
# ===========================================================================================
def captured_bounded_event(session) -> dict | None:
    """The captured ``kernel.read.bounded`` event, or None when the session holds none.

    Capture belongs to the session's single reader (``HostSession.kernel_read_bounded``); this
    driver only reads it, so no frame is ever consumed twice.
    """
    event = getattr(session, 'kernel_read_bounded', None)
    if not isinstance(event, Mapping):
        return None
    return {str(key): value for key, value in event.items()}


#: The record of one bounded read, as the *wired* provider answers it (W14 wired `kernel.read` to
#: the privileged provider, so the read no longer waits for the agent hook: the record arrives as
#: the operation's result). Recognised by its own fields -- never by a status word, because a
#: response that merely says OK without a record is not an answer to the trigger at all.
WIRED_RECORD_FIELDS = ('bytes_hex', 'sha256', 'copied_len', 'requested_region')


def wired_bounded_record(response) -> dict | None:
    """The read record a wired provider returned, or None when the answer is not one."""
    if not isinstance(response, Mapping):
        return None
    for container in (response.get('result'), response):
        if isinstance(container, Mapping) and all(field in container
                                                  for field in WIRED_RECORD_FIELDS):
            return {str(key): value for key, value in container.items()}
    return None


def accept_trigger_response(session, response, col: _Collector) -> None:
    """Accept the trigger's answer in either frozen form, or fail the phase.

    Two forms are legitimate and they are the *same* operation:

    * the deferred privilege (the frozen W12 semantics): the router answers ERROR/OPERATION_DEFERRED
      and the payload's read arrives afterwards as the captured event,
    * the wired provider (from the W14 wiring on): the record *is* the answer, and it is captured
      here so every check downstream works on the same object it always did.

    A bare ``OK`` without a record, and a deferred answer that never delivers an event, stay what
    they always were: a failure.
    """
    record = wired_bounded_record(response)
    if record is not None:
        setattr(session, 'kernel_read_bounded', record)
        col.check('trigger_answered_by_wired_provider', True, KREADLIVE_TRIGGER_NOT_DEFERRED,
                  'the wired provider returned the read record as the operation result')
        return
    status = response.get('status') if isinstance(response, Mapping) else None
    err = response.get('error') if isinstance(response, Mapping) else None
    code = err.get('code') if isinstance(err, Mapping) else None
    col.check('trigger_answered_as_deferred_privilege', status == 'ERROR'
              and code == 'OPERATION_DEFERRED', KREADLIVE_TRIGGER_NOT_DEFERRED,
              f'the {TRIGGER_OPERATION} response carried status {status!r} code {code!r} and no read '
              'record: neither the frozen deferred privilege nor the wired provider answered')


def wire_request_for(window: Mapping) -> tuple[dict, list[str]]:
    """The compact internal read request: (region_index, offset, length), never an address.

    ``region_index`` names a row of the compile-time table the payload compiles; the host derives
    it from the normative compiled table (:func:`region_index`) and the payload echoes it back in
    the event, where both are re-checked. Nothing else of the semantic request travels: no region
    name, no rva, no address, no length in bytes of any address space.
    """
    problems: list[str] = []
    index = window.get('region_index')
    if not isinstance(index, int) or isinstance(index, bool) or index < 0:
        problems.append(f'{KREADLIVE_REGION_NOT_COMPILED}: the window carries no compiled region '
                        f'index (got {index!r})')
    for field in ('offset', 'length'):
        value = window.get(field)
        if isinstance(value, bool) or not isinstance(value, int):
            problems.append(f'the window {field} is not an integer ({value!r})')
    arguments = {'region_index': index, 'offset': window.get('offset'),
                 'length': window.get('length')}
    return arguments, problems


def _trigger_read(session, *, request_id: str | None = None,
                  window: Mapping | None = None) -> tuple[dict | None, str | None]:
    """Send the frozen trigger (``kernel.read`` with its three bounded parameters).

    The payload performs its one bounded read itself right after the router has answered the
    operation as deferred privilege, so a transport failure here is recorded and the captured
    event is still verified afterwards (the agent sends the EVENT before it stops, exactly like
    the W11.1A lesson: never lose what arrived).
    """
    arguments, problems = wire_request_for(window) if isinstance(window, Mapping) else ({}, [])
    if problems:
        return None, f'{KREADLIVE_REGION_NOT_COMPILED}: ' + '; '.join(problems)
    try:
        response = session.request(TRIGGER_OPERATION, arguments, request_id=request_id
                                   or smoke_request_id(0))
        return response, None
    except (SessionError, ProtocolError, EndpointClosed) as exc:
        return None, f'{type(exc).__name__}: {exc}'


def _finish_session(session) -> dict | None:
    """Host half close (SHUT_WR) then BYE drain, tolerating a dead endpoint (best effort)."""
    endpoint = getattr(session, 'ep', None)
    shutdown = getattr(endpoint, 'shutdown_write', None)
    if callable(shutdown):
        try:
            shutdown()
        except (SessionError, ProtocolError, EndpointClosed, OSError):
            pass
    await_bye = getattr(session, 'await_bye', None)
    if not callable(await_bye):
        return None
    try:
        return await_bye('W12 phase: host half close (SHUT_WR)')
    except (SessionError, ProtocolError, EndpointClosed):
        return None


def _session_id(session) -> str | None:
    value = getattr(session, 'session_id', None)
    return value if isinstance(value, str) and value else None


def _coerce_store(store) -> VerificationEvidenceStore:
    if isinstance(store, VerificationEvidenceStore):
        return store
    if isinstance(store, (str, pathlib.Path)):
        return VerificationEvidenceStore(store)
    raise TypeError('the evidence store must be a VerificationEvidenceStore or a path')


def _result(phase: str, outcome: str, **fields) -> dict:
    result: dict = {
        'schema': RESULT_SCHEMA,
        'phase': phase,
        'outcome': outcome,
        'ok': outcome in (OUTCOME_VERIFIED, OUTCOME_READ),
        'problems': [],
        'checks': [],
        'checks_failed': [],
        'provider_entries': 0,
        'generic_provider_entries': 0,
        'verification_run_id': None,
        'verification_session_id': None,
        'read_run_id': None,
        'read_session_id': None,
        'event': None,
        'event_report': None,
        'evidence': None,
        'evidence_path': None,
        'verification': None,
        'capability': None,
        'decision': None,
        'read_evidence': None,
        'read_evidence_path': None,
        'read_run_record': None,
        'read_run_record_path': None,
        'run_separation': None,
        'bye': None,
        'notes': [],
    }
    result.update(fields)
    return result


def _finish_result(result: dict, col: _Collector) -> dict:
    result['checks'] = list(col.checks)
    result['problems'] = list(col.problems)
    result['checks_failed'] = col.failed_names()
    return result


def _decision_summary(decision) -> dict:
    return {
        'outcome': decision.outcome,
        'stopped_at': decision.stopped_at,
        'reasons': list(decision.reasons),
        'provider_entry': bool(decision.provider_entry),
        'effective_grant': dict(decision.effective_grant or {}),
        'resolved_rva': getattr(decision.resolved, 'rva', None),
        'resolved_length': getattr(decision.resolved, 'length', None),
    }


# ===========================================================================================
# PHASE A -- the fixed bootstrap verification
# ===========================================================================================
def run_verification(session, *, profile: Mapping, boot_binding, store,
                     provider: Mapping | None = None, context: str = CONTEXT,
                     verification_run_id: str | None = None, read_run_id: str | None = None,
                     request_id: str | None = None, expected: Mapping | None = None,
                     expect: Mapping | None = None) -> dict:
    """PHASE A: verify the fixed bootstrap read of this session and persist the evidence.

    One session, one read, **zero generic provider entries**: the bootstrap path needs no
    already-PROVEN ``kernel.read`` (that would be the capability circle the W12 review forbids),
    so nothing in this phase consults the capability chain. On success exactly one
    ``VerificationEvidence`` is persisted into the store; on any deviation the phase returns a
    REFUSED result carrying the named problem and writes nothing.
    """
    window = bootstrap_expectation(profile) if expected is None else dict(expected)
    if expect:
        window.update(expect)
    col = _Collector()
    identity = provider_identity(provider)
    result = _result(PHASE_VERIFY, OUTCOME_REFUSED, event_report=None)
    result['notes'].append('phase A: fixed bootstrap verify.kernel.read -- no capability chain, '
                           'no generic provider entry (the bootstrap read cannot require the '
                           'capability it exists to prove)')

    for problem in profile_problems(profile):
        col.fail(KREADLIVE_WRONG_PROFILE, problem.split(': ', 1)[-1])
    for problem in window.get('problems') or ():
        col.fail(KREADLIVE_BOOTSTRAP_EXPECTATION, problem)
    boot_id = getattr(boot_binding, 'boot_id', None)
    if boot_binding is None or not isinstance(boot_id, str) or not boot_id:
        col.fail(KREADLIVE_EVIDENCE_INVALID, 'phase A needs the current boot binding (boot id)')
        return _finish_result(result, col)
    try:
        store = _coerce_store(store)
    except TypeError as exc:
        col.fail(KREADLIVE_EVIDENCE_INVALID, str(exc))
        return _finish_result(result, col)

    # 1. session bring-up: HELLO_ACK (host-chosen session id) then the READY attestation
    try:
        session.handshake()
        session.recv_ready()
    except (SessionError, ProtocolError, EndpointClosed) as exc:
        col.fail(KREADLIVE_SESSION_STOPPED, f'{type(exc).__name__}: {exc}')
        return _finish_result(result, col)
    session_id = _session_id(session)
    if session_id is None:
        col.fail(KREADLIVE_SESSION_MISSING, 'the handshake produced no session id')
        return _finish_result(result, col)

    verification_run_id = verification_run_id or derived_run_id('VRUN', session_id)
    read_run_id = read_run_id or derived_run_id('BOOTREAD', session_id)
    result['verification_run_id'] = verification_run_id
    result['verification_session_id'] = session_id
    result['read_run_id'] = read_run_id
    result['read_session_id'] = session_id
    col.check('verification_run_differs_from_read_run', verification_run_id != read_run_id,
              KREADLIVE_RUN_NOT_SEPARATE,
              f'verification={verification_run_id} read={read_run_id}')

    # 2. the frozen trigger; the payload performs its one bounded read right after the router
    # has answered the request as deferred privilege
    response, error = _trigger_read(session, request_id=request_id, window=window)
    if error is not None:
        col.fail(KREADLIVE_SESSION_STOPPED, f'the trigger failed: {error}')
    else:
        accept_trigger_response(session, response, col)
    result['response'] = response

    # 3. drain to BYE (the EVENT -- or, with a wired provider, the record captured from the
    # response above -- and capture the one bounded read
    result['bye'] = _finish_session(session)
    event = captured_bounded_event(session)
    result['event'] = event
    report = verify_bounded_event(event, profile=profile, expected=window)
    result['event_report'] = report
    col.absorb(report, prefix='event: ')

    # 4. the read evidence, verified through the W12 verifier (bootstrap path and, with the
    #    pinned expectation, the generic path) -- only when the event itself verified
    kbase = report.get('kbase')
    if report.get('verified') and kbase is not None:
        request = {'operation': OPERATION, 'region': window['region'], 'offset': window['offset'],
                   'length': window['length']}
        try:
            resolved = regions.resolve_read(window['region'], window['offset'], window['length'])
        except kread_model.KReadReject as exc:
            col.fail(KREADLIVE_EXPECTATION_MISMATCH,
                     f'the registry refuses the pinned window: {exc}')
        else:
            # W12-RVA0-BINDING: resolve the *relative* window against the current boot's kernel
            # base before anything is persisted. The rva may be 0; the runtime address may not
            # be, must be canonical and must stay inside the pinned image window (checked).
            try:
                runtime = regions.resolve_runtime(resolved, kbase)
            except kread_model.KReadReject as exc:
                col.fail(KREADLIVE_EXPECTATION_MISMATCH,
                         f'the runtime resolution refused the window: {exc}')
                runtime = None
            if runtime is not None:
                result['runtime_resolution'] = {
                    'kbase': u64_hex(runtime.kbase),
                    'rva': u64_hex(runtime.rva),
                    'runtime_base_va': u64_hex(runtime.runtime_base_va),
                    'runtime_address': u64_hex(runtime.runtime_address),
                    'note': 'W12-RVA0-BINDING: the relative window resolved against the current '
                            'kernel base (checked, non-zero, canonical, inside the pinned image '
                            'window)',
                }
            verification_block = {
                'run_id': verification_run_id,
                'session_id': session_id,
                'operation': VERIFICATION_OPERATION,
                'outcome': 'PASS',
                'capability': OPERATION,
                'provider': identity['name'],
                'provider_type': identity['provider_type'],
                'scope': SCOPE_SESSION,
                'boot_id': boot_id,
                'separate_from_read': True,
                'evidence_session_id': session_id,
                'note': 'the host verified the captured bootstrap event and re-derived the bytes '
                        'and the sha256 itself (phase A; the payload is the untrusted reporter)',
            }
            try:
                read_evidence = KC.fixed_read_evidence(
                    request, resolved, run_id=read_run_id,
                    bytes_hex=report['bytes_hex'], runtime_kbase=kbase,
                    profile_sha256=canonical_profile_sha256(dict(profile)),
                    boot_id=boot_id,
                    provider={'name': identity['name'], 'provider_type': identity['provider_type']},
                    verification=verification_block)
            except ValueError as exc:                          # pragma: no cover - misuse guard
                col.fail(KREADLIVE_EVIDENCE_INVALID, f'the read evidence could not be assembled: '
                                                     f'{exc}')
            else:
                result['read_evidence'] = read_evidence
                bootstrap_report = kreadverify.verify_bootstrap_evidence(
                    request, read_evidence, profile=dict(profile), boot_binding=boot_binding)
                generic_report = kreadverify.verify_read_evidence(
                    request, read_evidence, profile=dict(profile), boot_binding=boot_binding,
                    expected={'region': window['region'], 'offset': window['offset'],
                              'length': window['length'], 'bytes_hex': window['bytes_hex'],
                              'sha256': window['sha256'], 'provider': identity['name'],
                              'runtime_base': kbase})
                result['verification_reports'] = {'bootstrap': bootstrap_report,
                                                  'generic': generic_report}
                col.absorb(bootstrap_report, prefix='bootstrap verification: ')
                col.absorb(generic_report, prefix='read verification: ')
    else:
        col.fail(KREADLIVE_EVENT_MISSING if event is None else KREADLIVE_EVENT_CONTRACT,
                 'the captured event did not verify; nothing is persisted')
    col.check('no_generic_provider_entry_in_phase_a', True, KREADLIVE_PROVIDER_ENTRY_COUNT,
              'phase A walks no capability chain: 0 generic provider entries, by construction')

    if not col.ok:
        return _finish_result(result, col)

    # 5. the persisted VerificationEvidence
    evidence = {
        'schema': SCHEMA_VERIFICATION,
        'verification_run_id': verification_run_id,
        'verification_session_id': session_id,
        'operation': VERIFICATION_OPERATION,
        'outcome': 'PASS',
        'capability': OPERATION,
        'provider': identity['name'],
        'provider_type': identity['provider_type'],
        'profile_sha256': canonical_profile_sha256(dict(profile)),
        'boot_id': boot_id,
        'context': context,
        'scope': SCOPE_SESSION,
        'region': window['region'],
        'offset': window['offset'],
        'length': window['length'],
        'rva': window['rva'],
        'locator': window['locator'],
        'expected_bytes_hex': window['bytes_hex'],
        'expected_sha256': window['sha256'],
        'observed_bytes_hex': report['bytes_hex'],
        'observed_sha256': report['output_sha256'],
        'resolved_rva': u64_hex(result['read_evidence']['resolved_rva']),
        'resolved_runtime_va': u64_hex(result['read_evidence']['resolved_runtime_va']),
        'read_run_id': read_run_id,
        'read_session_id': session_id,
        'source_event': {
            'kind': EVENT_KIND, 'schema': report.get('event_schema'),
            'build_id': report.get('build_id'), 'label': report.get('label'),
            'provider': report.get('provider'), 'region_index': report.get('requested_region_index'),
            'single_callback': report['claims'].get('single_callback'),
            'retry': report['claims'].get('retry'),
            'writes_to_kernel': report['claims'].get('writes_to_kernel'),
            'host_supplied_address': report['claims'].get('host_supplied_address'),
        },
        'run_separation': {
            'verification_run_id': verification_run_id,
            'read_run_id': read_run_id,
            'run_separated': verification_run_id != read_run_id,
            'verification_session_id': session_id,
            'read_session_id': session_id,
            'note': 'phase A: the host verification and the bootstrap read it verified are '
                    'different runs inside this session; the generic read phase must present a '
                    'NEW session (its read-run record carries the full separation proof)',
        },
        'provider_entries': 0,
        'note': 'the fixed bootstrap verification; no generic provider entry took part',
    }
    evidence['evidence_sha256'] = canonical_evidence_sha256(evidence)
    evidence_path = store.store_verification(evidence)
    result = _result(PHASE_VERIFY, OUTCOME_VERIFIED, event=event, event_report=report,
                     evidence=evidence, evidence_path=str(evidence_path),
                     read_evidence=result['read_evidence'],
                     verification_reports=result.get('verification_reports'),
                     verification_run_id=verification_run_id,
                     verification_session_id=session_id, read_run_id=read_run_id,
                     read_session_id=session_id, response=result.get('response'),
                     bye=result.get('bye'), notes=result['notes'],
                     run_separation=evidence['run_separation'])
    result['generic_provider_entries'] = 0
    return _finish_result(result, col)


# ===========================================================================================
# the capability record phase B derives from the persisted evidence
# ===========================================================================================
def _is_hex64(value) -> bool:
    """True when ``value`` is a sha256 hex digest (the only shape a release hash may have)."""
    return isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdefABCDEF'
                                                               for c in value)


def evidence_refusal_code(exc: StoreError) -> str:
    return EVIDENCE_REFUSALS.get(exc.reason, KREADLIVE_EVIDENCE_INVALID)


def evidence_policy_problems(evidence: Mapping, *, profile_sha256: str, boot_id: str,
                             provider: Mapping, context: str, window: Mapping) -> list[str]:
    """Policy checks on a loaded record: bindings, provider, scope and the pinned window.

    The store already rehashed the record; these are the *policy* facts the caller must match
    against the present run, each one a named refusal that stops the chain before the W4 gate.
    """
    problems: list[str] = []
    identity = provider_identity(provider)
    if evidence.get('outcome') != 'PASS':
        problems.append(f'{KREADLIVE_EVIDENCE_INVALID}: outcome {evidence.get("outcome")!r} is '
                        'not a PASS')
    if evidence.get('operation') != VERIFICATION_OPERATION:
        problems.append(f'{KREADLIVE_EVIDENCE_INVALID}: operation '
                        f'{evidence.get("operation")!r} is not {VERIFICATION_OPERATION}')
    if evidence.get('capability') != OPERATION:
        problems.append(f'{KREADLIVE_EVIDENCE_INVALID}: capability '
                        f'{evidence.get("capability")!r} is not {OPERATION}')
    if evidence.get('profile_sha256') != profile_sha256:
        problems.append(f'{KC.KREAD_WRONG_PROFILE}: the stored evidence names profile '
                        f'{evidence.get("profile_sha256")!r}, the current profile is '
                        f'{profile_sha256!r} -- the stored evidence is invalid for this profile')
    if evidence.get('boot_id') != getattr(boot_id, 'boot_id', boot_id):
        problems.append(f'{KC.KREAD_STALE_BOOT_ID}: the stored evidence belongs to boot '
                        f'{evidence.get("boot_id")!r}, the current boot is {boot_id!r} -- a fresh '
                        'verification run is required')
    if evidence.get('context') != context:
        problems.append(f'{KREADLIVE_EVIDENCE_INVALID}: context {evidence.get("context")!r} is '
                        f'not {context!r}')
    if evidence.get('scope') != SCOPE_SESSION:
        problems.append(f'{KREADLIVE_EVIDENCE_INVALID}: scope {evidence.get("scope")!r} is not '
                        f'{SCOPE_SESSION}')
    if evidence.get('provider') != identity['name'] \
            or evidence.get('provider_type') != identity['provider_type']:
        problems.append(f'{KREADLIVE_PROVIDER_MISMATCH}: the evidence was produced by '
                        f'{evidence.get("provider")!r}/{evidence.get("provider_type")!r}, this '
                        f'run acts as {identity["name"]!r}/{identity["provider_type"]!r}')
    if (evidence.get('region'), evidence.get('offset'), evidence.get('length')) \
            != (window['region'], window['offset'], window['length']):
        problems.append(f'{KREADLIVE_EXPECTATION_MISMATCH}: the evidence covers '
                        f'{evidence.get("region")!r}/{evidence.get("offset")!r}/'
                        f'{evidence.get("length")!r}, the pinned window is '
                        f'{window["region"]}/{window["offset"]}/{window["length"]}')
    if evidence.get('expected_bytes_hex') != window['bytes_hex'] \
            or evidence.get('expected_sha256') != window['sha256']:
        problems.append(f'{KREADLIVE_EXPECTATION_MISMATCH}: the evidence expectation is not the '
                        'pinned image_elf expectation')
    if evidence.get('observed_bytes_hex') != window['bytes_hex'] \
            or evidence.get('observed_sha256') != window['sha256']:
        problems.append(f'{KREADLIVE_EVIDENCE_INVALID}: the stored observation does not equal the '
                        'pinned bytes/hash (the verification proved something else)')
    return problems


#: the derivations THIS process performed (W12-A3). A receipt is written by
#: :func:`derive_capability_record` and by nothing else, so a record built by hand -- however
#: plausible its fields -- never carries a registered one, and the provider entry refuses it.
_DERIVATION_RECEIPTS: dict[str, dict] = {}
_DERIVATION_RECEIPT_LIMIT = 64


class DerivationRejected(Exception):
    """The derivation gate refused: no PROVEN record is derived from these inputs.

    ``reason`` is a named fail-closed code: the store's own vocabulary where the store or its
    rehash refused (``STORE_REHASH_MISMATCH``, ``STORE_MISSING`` ...), otherwise the W12 or W4
    code of the check that failed (``KREADLIVE_CAPABILITY_NOT_DERIVED``,
    ``KREADLIVE_RUN_NOT_SEPARATE``, ``KREAD_WRONG_PROFILE`` ...).
    """

    def __init__(self, reason: str, detail: str = '') -> None:
        super().__init__(f'{reason}: {detail}' if detail else reason)
        self.reason = reason
        self.detail = detail


def _problem_reason(problem: str) -> str:
    return problem.split(':', 1)[0].strip() or KREADLIVE_CAPABILITY_NOT_DERIVED


def _receipt_id(core: Mapping) -> str:
    payload = json.dumps(dict(core), sort_keys=True, separators=(',', ':')).encode()
    return hashlib.sha256(payload).hexdigest()


def derivation_record_sha256(record: Mapping) -> str:
    """The content hash of a derived record: everything except the receipt id itself.

    The receipt stores this hash, so a record that merely *copies* the markers and the receipt id
    of a real derivation still fails the revalidation unless its content is the derived one.
    """
    core = dict(record)
    derivation = dict(core.get('derivation') or {})
    derivation.pop('receipt_id', None)
    core['derivation'] = derivation
    return _receipt_id(core)


def derive_capability_record(store, *, evidence_sha256: str, read_run_id: str, profile_sha256: str,
                             boot_id: str, provider: Mapping, context: str, session_id: str,
                             approval: Mapping | None = None, expected: Mapping | None = None,
                             window: Mapping | None = None) -> dict:
    """Derive the SESSION-scoped PROVEN record from the STORE -- or refuse (W12-A3).

    This is the *only* constructor of a ``PROVEN`` ``kernel.read`` record, and it is addressed by
    the evidence hash, never by a document: a prepared record or a bare ``verified: true`` state is
    not an input this function can accept. Before it stamps ``assurance = PROVEN`` it
    re-establishes every fact itself:

    ============  ==========================================================================
    fact          enforced by
    ============  ==========================================================================
    load          ``VerificationEvidenceStore.load_verification_by_sha256`` (the address is the
                  hash; the file name must equal the record's run id)
    rehash        the store recomputes the canonical hash on load and compares it with the stored
                  ``evidence_sha256`` -> ``STORE_REHASH_MISMATCH``
    hash match    the loaded record's own ``evidence_sha256`` must equal the requested address
    outcome PASS  the store (``verification_rejection_reason``) and
                  :func:`evidence_policy_problems`
    capability    ``evidence_policy_problems``: ``capability == kernel.read``
    operation     ``evidence_policy_problems``: ``operation == verify.kernel.read``
    provider      ``evidence_policy_problems``: ``provider``/``provider_type`` == the acting
                  identity (``ps4rfd-kread-privileged`` / ``NATIVE``)
    profile       ``evidence_policy_problems``: ``profile_sha256`` == the current profile
    boot          ``evidence_policy_problems``: ``boot_id`` == the current boot
    separation    ``verification_run_id != read_run_id`` and the verification *session* differs
                  from the session that is about to read
    bootstrap     ``evidence_policy_problems``: region/offset/length == the pinned window
    bytes/hash    ``evidence_policy_problems``: ``expected_*`` and ``observed_*`` == the pinned
                  expectation
    separation    the derived ``verification`` block states ``separate_from_read: true`` -- backed
    flag          by the two inequalities above, never asserted on their behalf
    ============  ==========================================================================

    The returned record carries a ``derivation`` block (the markers plus the receipt id of this
    process) which :func:`revalidate_derivation` re-checks immediately before the provider entry.
    """
    if not isinstance(store, VerificationEvidenceStore):
        raise DerivationRejected(
            KREADLIVE_CAPABILITY_NOT_DERIVED,
            'the derivation needs the evidence store: a record is derived from an addressed, '
            'rehashed store record, never assembled by the caller')
    try:
        evidence = store.load_verification_by_sha256(evidence_sha256)
    except StoreError as exc:
        raise DerivationRejected(exc.reason, str(exc)) from exc
    if evidence.get('evidence_sha256') != evidence_sha256:
        raise DerivationRejected(STORE_REHASH_MISMATCH,
                                 f'the stored record carries {evidence.get("evidence_sha256")!r}, '
                                 f'the address was {evidence_sha256!r}')
    pinned = dict(expected if expected is not None else (window or {}))
    if not pinned or 'bytes_hex' not in pinned or 'sha256' not in pinned:
        raise DerivationRejected(KREADLIVE_BOOTSTRAP_EXPECTATION,
                                 'the pinned bootstrap window (region/offset/length/bytes/hash) '
                                 'is required: the derivation checks the evidence against it')
    problems = evidence_policy_problems(evidence, profile_sha256=profile_sha256, boot_id=boot_id,
                                        provider=provider, context=context, window=pinned)
    if problems:
        raise DerivationRejected(_problem_reason(problems[0]), '; '.join(problems))
    if evidence.get('verification_run_id') == read_run_id:
        raise DerivationRejected(KREADLIVE_RUN_NOT_SEPARATE,
                                 f"the verification run {evidence.get('verification_run_id')!r} "
                                 'is the read run: a read may not be authorised by its own run')
    if evidence.get('verification_session_id') == session_id:
        raise DerivationRejected(KREADLIVE_SESSION_REUSED,
                                 f"the verification happened in session {session_id!r}: the read "
                                 'needs a session the verification never used')
    identity = provider_identity(provider)
    evidence_ref = {'run_id': evidence.get('verification_run_id'),
                    'sha256': evidence.get('evidence_sha256')}
    verification = {
        'run_id': evidence.get('verification_run_id'),
        'session_id': session_id,
        'operation': evidence.get('operation'),
        'outcome': evidence.get('outcome'),
        'capability': evidence.get('capability'),
        'provider': evidence.get('provider'),
        'provider_type': evidence.get('provider_type'),
        'scope': SCOPE_SESSION,
        'boot_id': boot_id,
        'evidence_session_id': evidence.get('verification_session_id'),
        'evidence_ref': dict(evidence_ref),
        'separate_from_read': True,
        'derived_for_session': session_id,
    }
    derivation = {
        'derived_from_evidence_sha256': evidence.get('evidence_sha256'),
        'derived_from_verification_run_id': evidence.get('verification_run_id'),
        'derived_for_session_id': session_id,
        'derived_for_boot_id': boot_id,
        'derived_for_profile_sha256': profile_sha256,
        'derived_for_read_run_id': read_run_id,
    }
    record = {
        'name': OPERATION,
        'availability': 'AVAILABLE',
        'assurance': 'PROVEN',
        'context': context,
        'provider': identity['name'],
        'provider_type': identity['provider_type'],
        'scope': SCOPE_SESSION,
        'session_id': session_id,
        'boot_id': boot_id,
        'profile_sha256': profile_sha256,
        'verification': verification,
        'evidence_refs': [dict(evidence_ref)],
        'evidence_ref': dict(evidence_ref),
        'approval': dict(approval) if isinstance(approval, Mapping) else None,
        'derived_from': {'verification_run_id': evidence.get('verification_run_id'),
                         'verification_session_id': evidence.get('verification_session_id'),
                         'evidence_sha256': evidence.get('evidence_sha256')},
        'derivation': derivation,
        'note': 'derived in this run from the persisted VerificationEvidence (rehashed on load); '
                'scope SESSION and bound to this session id only',
    }
    receipt = dict(derivation, evidence_sha256=evidence.get('evidence_sha256'),
                   verification_run_id=evidence.get('verification_run_id'),
                   verification_session_id=evidence.get('verification_session_id'),
                   profile_sha256=profile_sha256, boot_id=boot_id, session_id=session_id,
                   read_run_id=read_run_id, provider=identity['name'],
                   provider_type=identity['provider_type'], context=context)
    record_sha256 = derivation_record_sha256(record)
    receipt['record_sha256'] = record_sha256
    receipt_id = _receipt_id(receipt)
    receipt['receipt_id'] = receipt_id
    record['derivation']['receipt_id'] = receipt_id
    if len(_DERIVATION_RECEIPTS) >= _DERIVATION_RECEIPT_LIMIT:
        _DERIVATION_RECEIPTS.pop(next(iter(_DERIVATION_RECEIPTS)), None)
    _DERIVATION_RECEIPTS[receipt_id] = receipt
    return record


def revalidate_derivation(capability: Mapping, *, store, session_id: str, boot_id: str,
                          profile_sha256: str, read_run_id: str | None = None) -> list[str]:
    """Re-check, immediately before the provider entry, that this record *is* a derivation.

    Runs in the productive path only: the record must carry the derivation markers of an
    internally generated derivation (registered by :func:`derive_capability_record` in this
    process), the markers must name *this* session, boot, profile and read run, and the addressed
    store record must still load, still rehash and still carry the same facts. Any deviation is a
    named refusal and the caller keeps ``provider_entries == 0``.
    """
    if not isinstance(capability, Mapping):
        return [f'{KREADLIVE_CAPABILITY_NOT_DERIVED}: no capability record']
    if capability.get('name') != OPERATION:
        return [f'{KREADLIVE_CAPABILITY_NOT_DERIVED}: the record is for '
                f'{capability.get("name")!r}, not {OPERATION}']
    problems: list[str] = []
    if str(capability.get('assurance')) != 'PROVEN':
        problems.append(f'{KREADLIVE_CAPABILITY_NOT_DERIVED}: assurance is '
                        f'{capability.get("assurance")!r}; only a derivation carries PROVEN')
    derivation = capability.get('derivation')
    if not isinstance(derivation, Mapping):
        return problems + [
            f'{KREADLIVE_CAPABILITY_NOT_DERIVED}: the record carries no derivation block: a '
            'hand-built record is never a derivation, however plausible its fields are']
    receipt_id = derivation.get('receipt_id')
    receipt = _DERIVATION_RECEIPTS.get(receipt_id) if isinstance(receipt_id, str) else None
    if receipt is None:
        return problems + [
            f'{KREADLIVE_CAPABILITY_NOT_DERIVED}: no derivation receipt {receipt_id!r} was '
            'generated by this process for this record']
    if receipt.get('record_sha256') != derivation_record_sha256(capability):
        problems.append(f'{KREADLIVE_CAPABILITY_NOT_DERIVED}: the record content does not match the '
                        f"derivation it names (receipt {receipt_id!r} was generated for another "
                        'record)')
    for field, required in (('derived_for_session_id', session_id),
                            ('derived_for_boot_id', boot_id),
                            ('derived_for_profile_sha256', profile_sha256),
                            ('derived_from_evidence_sha256', receipt['evidence_sha256']),
                            ('derived_from_verification_run_id', receipt['verification_run_id'])):
        if derivation.get(field) != required:
            problems.append(f'{KREADLIVE_CAPABILITY_NOT_DERIVED}: {field} is '
                            f'{derivation.get(field)!r}, this run requires {required!r}')
    if read_run_id is not None and derivation.get('derived_for_read_run_id') != read_run_id:
        problems.append(f'{KREADLIVE_CAPABILITY_NOT_DERIVED}: derived_for_read_run_id is '
                        f'{derivation.get("derived_for_read_run_id")!r}, this read run is '
                        f'{read_run_id!r}')
    for field in ('session_id', 'boot_id', 'profile_sha256', 'read_run_id'):
        if receipt.get(field) != {'session_id': session_id, 'boot_id': boot_id,
                                  'profile_sha256': profile_sha256,
                                  'read_run_id': read_run_id}.get(field, receipt.get(field)):
            problems.append(f'{KREADLIVE_CAPABILITY_NOT_DERIVED}: the receipt belongs to another '
                            f'{field} ({receipt.get(field)!r})')
    try:
        evidence = store.load_verification_by_sha256(derivation.get('derived_from_evidence_sha256'))
    except StoreError as exc:
        problems.append(f'{exc.reason}: the addressed evidence '
                        f'{derivation.get("derived_from_evidence_sha256")!r} no longer loads: '
                        f'{exc}')
        return problems
    for field, required in (('verification_run_id', receipt['verification_run_id']),
                            ('capability', OPERATION),
                            ('operation', VERIFICATION_OPERATION),
                            ('outcome', 'PASS'),
                            ('provider', receipt['provider']),
                            ('provider_type', receipt['provider_type']),
                            ('profile_sha256', profile_sha256),
                            ('boot_id', boot_id)):
        if evidence.get(field) != required:
            problems.append(f'{STORE_REHASH_MISMATCH}: the stored record no longer matches the derivation: '
                            f'{field} is {evidence.get(field)!r}, the derivation needs '
                            f'{required!r}')
    refs = capability.get('evidence_refs') or ()
    if not any(isinstance(ref, Mapping)
               and ref.get('run_id') == evidence.get('verification_run_id')
               and ref.get('sha256') == evidence.get('evidence_sha256') for ref in refs):
        problems.append(f'{KREADLIVE_CAPABILITY_NOT_DERIVED}: the record does not carry the '
                        'hash-bound evidence reference of its derivation')
    return problems


# ===========================================================================================
# PHASE B -- the generic bounded read in a new session
# ===========================================================================================
def run_generic_read(session, *, profile: Mapping, boot_binding, store, verification_run_id: str,
                     evidence_window: Mapping | None = None,
                     provider: Mapping | None = None, context: str = CONTEXT,
                     approval: Mapping | None = None, recovery: bool = False,
                     generic_read_run_id: str | None = None, request: Mapping | None = None,
                     request_id: str | None = None, expected: Mapping | None = None,
                     expect: Mapping | None = None, evidence_sha256: str | None = None) -> dict:
    """PHASE B: load+rehash the persisted evidence, resolve the capability, read once, verify.

    Every boundary refusal happens before the payload is triggered: a failed rehash, a boot id
    from another boot, a foreign profile, an old session id or a run id that collides with the
    verification run all return REFUSED with ``provider_entries == 0``. Only a GRANTED decision
    (W4 gate + W5 binding + current boot binding + W7 router + live approval) yields exactly one
    provider entry, and the read that follows must return exactly the pinned bytes.
    """
    window = bootstrap_expectation(profile) if expected is None else dict(expected)
    if expect:
        window.update(expect)
    # the verification the read leans on always proves the PINNED BOOTSTRAP window: the stored
    # evidence is checked against that window (A3 section 1.12/1.13), never against the window this
    # read is about. For the frozen W12 flow both windows are the same object.
    evidence_pinned = (bootstrap_expectation(profile) if evidence_window is None
                       else dict(evidence_window))
    col = _Collector()
    identity = provider_identity(provider)
    boot_id = getattr(boot_binding, 'boot_id', None)
    result = _result(PHASE_READ, OUTCOME_REFUSED)
    result['notes'].append('phase B: generic bounded kernel.read in a NEW session, only from the '
                           'persisted evidence (rehashed on load)')

    for problem in profile_problems(profile):
        col.fail(KREADLIVE_WRONG_PROFILE, problem.split(': ', 1)[-1])
    for problem in window.get('problems') or ():
        col.fail(KREADLIVE_BOOTSTRAP_EXPECTATION, problem)
    for problem in evidence_pinned.get('problems') or ():
        col.fail(KREADLIVE_BOOTSTRAP_EXPECTATION, problem)
    if window.get('release_id') and not (_is_hex64(window.get('release_sha256'))
                                         and _is_hex64(window.get('approval_sha256'))):
        col.fail(KREADLIVE_RELEASE_UNBOUND,
                 f"release {window.get('release_id')!r} carries no release_sha256/approval_sha256: "
                 'the one-shot marker must name the release document and the approval it spent, so '
                 'an unbound released window is never read')
    if window.get('region') != PINNED_REGION and not window.get('release_id'):
        col.fail(KREADLIVE_WINDOW_NOT_RELEASED,
                 f"the window reads {window.get('region')!r}, which is not the pinned bootstrap "
                 f'region {PINNED_REGION!r}, and it carries no release id: only the pinned bootstrap '
                 'window or an owner-released window may be read')
    # W13-C1: the wire request is (region_index, offset, length) and nothing else. It is built
    # here, before the provider entry, so a window that cannot be turned into such a request (no
    # compiled row for the region, a bound that is not an integer) is refused with zero provider
    # entries -- an impossible request never reaches a console.
    _, request_mapping_problems = wire_request_for(window)
    for problem in request_mapping_problems:
        col.fail(KREADLIVE_REGION_NOT_COMPILED, problem.split(': ', 1)[-1])
    # D2 (owner W15): the region-index bounds decision runs HERE -- in front of the release
    # consumption, the provider entry and the trigger. The requested index is checked against
    # the normative compiled table (regions.compiled_regions()) and the window's region name must
    # resolve to exactly the index the target request will carry, so a bad row costs zero
    # provider entries, consumes no release, sends no trigger, and the target is never the first
    # thing to notice (see region_index_bounds_problems).
    for problem in region_index_bounds_problems(window):
        col.fail(problem.split(': ', 1)[0], problem.split(': ', 1)[-1])
    if boot_binding is None or not isinstance(boot_id, str) or not boot_id:
        col.fail(KC.KREAD_STALE_BOOT_ID, 'phase B needs the current boot binding (boot id)')
    try:
        store = _coerce_store(store)
    except TypeError as exc:
        col.fail(KREADLIVE_EVIDENCE_INVALID, str(exc))
        return _finish_result(result, col)
    if not col.ok:
        return _finish_result(result, col)

    # W13 one-shot: the release may have been used already (persisted marker) or in this process.
    release_id = window.get('release_id')
    if release_id:
        prior = _CONSUMED_RELEASES.get(release_id)
        try:
            persisted = store.load_release_consumption(release_id)
        except StoreError as exc:
            col.fail(evidence_refusal_code(exc), str(exc))
            return _finish_result(result, col)
        if prior is not None or persisted is not None:
            marker = prior or persisted or {}
            col.fail(KREADLIVE_RELEASE_ALREADY_CONSUMED,
                     f'release {release_id!r} was already consumed at the provider entry '
                     f"(read run {marker.get('read_run_id')!r}); a release is usable exactly once")
            result['release_consumption'] = marker
            return _finish_result(result, col)

    profile_sha = canonical_profile_sha256(dict(profile))
    request_model = {'operation': OPERATION, 'region': window['region'],
                     'offset': window['offset'], 'length': window['length']}
    if request is not None:
        request_model.update(dict(request))
    result['request'] = request_model
    col.check('request_is_the_pinned_window',
              (request_model.get('region'), request_model.get('offset'),
               request_model.get('length')) == (window['region'], window['offset'],
                                                window['length']),
              KREADLIVE_EXPECTATION_MISMATCH, json.dumps(request_model, sort_keys=True))

    # 1. load the persisted evidence and rehash it (a bare `verified` flag is never enough)
    try:
        evidence = store.load_verification(verification_run_id)
    except StoreError as exc:
        col.fail(evidence_refusal_code(exc), str(exc))
        return _finish_result(result, col)
    result['evidence'] = evidence
    result['evidence_sha256'] = evidence.get('evidence_sha256')
    col.check('evidence_rehash_matches', True,
              KREADLIVE_EVIDENCE_REHASH_MISMATCH,
              f"evidence_sha256={evidence.get('evidence_sha256')} "
              '(recomputed by the store on load)')
    result['verification_run_id'] = evidence.get('verification_run_id')
    result['verification_session_id'] = evidence.get('verification_session_id')

    # 2. the boundary policy: profile, boot, context, provider, window (all before the gate).
    #    The window here is the window the VERIFICATION was about -- the pinned bootstrap window --
    #    not the window this read is about: a released read must not be able to relabel the evidence
    #    it leans on (A3 1.12/1.13). For the frozen W12 flow both windows are the same object.
    for problem in evidence_policy_problems(evidence, profile_sha256=profile_sha, boot_id=boot_id,
                                            provider=identity, context=context,
                                            window=evidence_pinned):
        col.fail(problem.split(': ', 1)[0], problem.split(': ', 1)[-1])
    if not col.ok:
        return _finish_result(result, col)

    # 3. the session: a NEW one. The old session id is refused outright, and the record this
    #    phase derives is bound to this session (never carried over from run A).
    try:
        session.handshake()
        session.recv_ready()
    except (SessionError, ProtocolError, EndpointClosed) as exc:
        col.fail(KREADLIVE_SESSION_STOPPED, f'{type(exc).__name__}: {exc}')
        return _finish_result(result, col)
    session_id = _session_id(session)
    if session_id is None:
        col.fail(KREADLIVE_SESSION_MISSING, 'the handshake produced no session id')
        return _finish_result(result, col)
    result['read_session_id'] = session_id
    old_sessions = {evidence.get('verification_session_id'), evidence.get('read_session_id')}
    old_sessions.discard(None)
    col.check('read_session_is_new', session_id not in old_sessions, KREADLIVE_SESSION_REUSED,
              f'session={session_id} verification session(s)={sorted(str(s) for s in old_sessions)}')

    generic_read_run_id = generic_read_run_id or derived_run_id('RUN', session_id)
    result['read_run_id'] = generic_read_run_id
    col.check('read_run_differs_from_verification_run',
              generic_read_run_id != verification_run_id, KREADLIVE_RUN_NOT_SEPARATE,
              f'read={generic_read_run_id} verification={verification_run_id}')
    separation = {
        'verification_run_id': verification_run_id,
        'generic_read_run_id': generic_read_run_id,
        'verification_session_id': evidence.get('verification_session_id'),
        'read_session_id': session_id,
        'note': 'run separation, proven by the ids themselves: the verification run and the '
                'generic read run differ, and the read happens in a session the verification '
                'never used',
    }
    separation['run_ids_distinct'] = bool(generic_read_run_id != verification_run_id)
    separation['session_ids_distinct'] = bool(session_id != evidence.get('verification_session_id'))
    separation['separated'] = bool(separation['run_ids_distinct']
                                   and separation['session_ids_distinct'])
    result['run_separation'] = separation
    if not col.ok:
        return _finish_result(result, col)

    # 4. the capability record for THIS session. W12-A3: the productive path does not accept a
    #    record from a caller -- it hands the STORE an address (the evidence hash) to the one
    #    constructor, which re-establishes every fact before it stamps PROVEN.
    if evidence_sha256 is not None and evidence_sha256 != evidence.get('evidence_sha256'):
        col.fail(STORE_REHASH_MISMATCH,
                 f'the caller addressed evidence {evidence_sha256!r}, the record loaded for '
                 f'{verification_run_id!r} carries {evidence.get("evidence_sha256")!r}')
        result['provider_entries'] = 0
        result['generic_provider_entries'] = 0
        return _finish_result(result, col)
    try:
        capability = derive_capability_record(
            store, evidence_sha256=evidence.get('evidence_sha256'),
            read_run_id=generic_read_run_id, profile_sha256=profile_sha, boot_id=boot_id,
            provider=identity, context=context, session_id=session_id, approval=approval,
            expected=evidence_pinned)
    except DerivationRejected as exc:
        col.fail(exc.reason, f'the derivation gate refused: {exc.detail or exc.reason}')
        result['provider_entries'] = 0
        result['generic_provider_entries'] = 0
        return _finish_result(result, col)
    result['capability'] = capability
    result['verification'] = capability['verification']
    result['derivation'] = capability.get('derivation')
    col.check('capability_record_is_for_the_new_session',
              capability['session_id'] == session_id
              and capability['session_id'] != evidence.get('verification_session_id'),
              KREADLIVE_SESSION_REUSED,
              f"record session={capability['session_id']} evidence session="
              f"{evidence.get('verification_session_id')}")
    for problem in revalidate_derivation(capability, store=store, session_id=session_id,
                                         boot_id=boot_id, profile_sha256=profile_sha,
                                         read_run_id=generic_read_run_id):
        col.fail(_problem_reason(problem), problem)
    if not col.ok:
        result['provider_entries'] = 0
        result['generic_provider_entries'] = 0
        return _finish_result(result, col)

    # 5. the mandated chain: W4 gate -> W5 profile binding -> current boot binding -> W7 router
    decision = KC.decide(request_model, registry=regions, profile=dict(profile),
                         boot_binding=boot_binding, context=context, capability=capability,
                         recovery=recovery, provider=identity)
    result['decision'] = _decision_summary(decision)
    result['provider_entry'] = bool(decision.provider_entry)
    if not decision.provider_entry:
        for reason in decision.reasons or ['KREADLIVE_REFUSED']:
            col.fail(reason, f'the capability chain stopped at {decision.stopped_at} '
                             f'({decision.outcome})')
        result['generic_provider_entries'] = 0
        result['provider_entries'] = 0
        return _finish_result(result, col)
    # 5b. W12-A3: immediately before the entry, the derivation is revalidated against the store
    #     -- a record that is not the one this process derived never reaches the provider.
    entry_problems = revalidate_derivation(capability, store=store, session_id=session_id,
                                           boot_id=boot_id, profile_sha256=profile_sha,
                                           read_run_id=generic_read_run_id)
    if entry_problems:
        for problem in entry_problems:
            col.fail(_problem_reason(problem), problem)
        result['provider_entries'] = 0
        result['generic_provider_entries'] = 0
        return _finish_result(result, col)
    # 5c. W13 one-shot: the release is consumed HERE, immediately before the entry -- after this
    #     point the read is granted exactly once, so a second attempt can never happen. The marker is
    #     written before the trigger, and the in-process registry is set even if the write fails
    #     (fail closed: an unwritable store never turns into a second read).
    if window.get('release_id'):
        consumption = None
        try:
            consumption = build_consumption_record(
                release_id=str(window['release_id']),
                release_sha256=str(window.get('release_sha256') or ''),
                approval_sha256=str(window.get('approval_sha256') or ''),
                profile_sha256=profile_sha, boot_id=boot_id, read_run_id=generic_read_run_id,
                read_session_id=session_id)
            store.store_release_consumption(consumption)
        except (StoreError, ValueError) as exc:
            _CONSUMED_RELEASES[str(window['release_id'])] = {}
            col.fail(KREADLIVE_RELEASE_CONSUMPTION_FAILED,
                     f'the release marker could not be persisted ({type(exc).__name__}: {exc}); '
                     'the run refuses before the provider entry and this release stays spent for '
                     'this process')
            return _finish_result(result, col)
        _CONSUMED_RELEASES[str(window['release_id'])] = consumption
        result['release_consumption'] = consumption
    # the single provider entry of this phase has now happened
    result['provider_entries'] = 1
    result['generic_provider_entries'] = 1
    col.check('exactly_one_generic_provider_entry',
              result['provider_entries'] == 1 and result['generic_provider_entries'] == 1,
              KREADLIVE_PROVIDER_ENTRY_COUNT,
              f'{decision.outcome} at {decision.stopped_at}: one provider entry, exactly once')

    # 6. the payload's single bounded read; the host re-derives and verifies everything
    # has answered the request as deferred privilege
    response, error = _trigger_read(session, request_id=request_id, window=window)
    if error is not None:
        col.fail(KREADLIVE_SESSION_STOPPED, f'the trigger failed: {error}')
    else:
        accept_trigger_response(session, response, col)
    result['response'] = response
    result['bye'] = _finish_session(session)
    event = captured_bounded_event(session)
    result['event'] = event
    report = verify_bounded_event(event, profile=profile, expected=window)
    result['event_report'] = report
    col.absorb(report, prefix='event: ')
    if not report.get('verified') or report.get('kbase') is None:
        col.fail(KREADLIVE_EVENT_MISSING if event is None else KREADLIVE_EVENT_CONTRACT,
                 'the captured read did not verify')
        return _finish_result(result, col)

    # 7. the read evidence for the granted decision, verified by the W12 verifier
    verification_block = {
        'run_id': verification_run_id,
        'session_id': session_id,
        'operation': VERIFICATION_OPERATION,
        'outcome': 'PASS',
        'capability': OPERATION,
        'provider': identity['name'],
        'provider_type': identity['provider_type'],
        'scope': SCOPE_SESSION,
        'boot_id': boot_id,
        'separate_from_read': True,
        'evidence_session_id': evidence.get('verification_session_id'),
        'evidence_ref': {'run_id': verification_run_id,
                         'sha256': evidence.get('evidence_sha256')},
        'note': 'the separate verification run of phase A, rehashed before the chain ran',
    }
    try:
        read_evidence = KC.read_evidence(request_model, decision, run_id=generic_read_run_id,
                                        bytes_hex=report['bytes_hex'],
                                        runtime_kbase=report['kbase'],
                                        verification=verification_block)
    except ValueError as exc:
        col.fail(KREADLIVE_EVIDENCE_INVALID, f'the read evidence could not be assembled: {exc}')
        return _finish_result(result, col)
    result['read_evidence'] = read_evidence
    verified_report = kreadverify.verify_read_evidence(
        request_model, read_evidence, profile=dict(profile), boot_binding=boot_binding,
        expected={'region': window['region'], 'offset': window['offset'],
                  'length': window['length'], 'bytes_hex': window['bytes_hex'],
                  'sha256': window['sha256'], 'provider': identity['name'],
                  'runtime_base': report['kbase']})
    result['verification_reports'] = {'generic': verified_report}
    col.absorb(verified_report, prefix='read verification: ')
    col.check('run_separation_visible_in_evidence',
              bool(verified_report.get('run_separate')) and separation['separated'],
              KREADLIVE_RUN_NOT_SEPARATE,
              f"verification_run={verification_run_id} read_run={generic_read_run_id} "
              f"verification_session={evidence.get('verification_session_id')} "
              f"read_session={session_id}")
    if not col.ok:
        return _finish_result(result, col)

    # 8. the read-run record: all four ids and the provider-entry count, persisted
    read_run = {
        'schema': SCHEMA_READ_RUN,
        'read_run_id': generic_read_run_id,
        'generic_read_run_id': generic_read_run_id,
        'read_session_id': session_id,
        'verification_run_id': verification_run_id,
        'verification_session_id': evidence.get('verification_session_id'),
        'verification_evidence_sha256': evidence.get('evidence_sha256'),
        # store-relative on purpose: the record is hash-frozen, and an absolute path would tie
        # its digest to the machine and directory the store happened to live in
        'verification_evidence_path': f'verification/{verification_run_id}.json',
        'request': dict(request_model),
        'read_evidence_sha256': canonical_sha256(canonical_view(read_evidence)),
        'event': {'kind': EVENT_KIND, 'schema': report.get('event_schema'),
                  'sha256': report.get('output_sha256'), 'bytes_hex': report.get('bytes_hex'),
                  'build_id': report.get('build_id'), 'label': report.get('label')},
        'read_evidence': canonical_view(read_evidence),
        'run_separation': separation,
        'provider_entries': result['provider_entries'],
        'provider_entry': {'outcome': decision.outcome, 'stopped_at': decision.stopped_at,
                           'reasons': list(decision.reasons),
                           'phase': PHASE_READ,
                           'route_operation': OPERATION},
        'capability': capability,
        'outcome': 'READ',
        'note': f'phase B: one generic bounded kernel.read of {window["region"]}/'
                f'{window["offset"]}/{window["length"]} in a new session, authorised by the '
                'rehashed VerificationEvidence of phase A',
        **({'w13_release': {'release_id': window.get('release_id'),
                            'release_sha256': window.get('release_sha256'),
                            'approval_sha256': window.get('approval_sha256'),
                            'region': window['region'],
                            'rva': hex(window['rva']) if window.get('rva') is not None else None,
                            'offset': window['offset'], 'length': window['length'],
                            'expected_sha256': window['sha256'],
                            'consumption': {'consumed': True, 'consumed_at': 'provider_entry',
                                            'record': f"releases/{window.get('release_id')}.json",
                                            'record_sha256': (result.get('release_consumption')
                                                              or {}).get('record_sha256')},
                            'note': 'the owner release record that selected this window; the '
                                    'release gate validated it before anything was contacted, and '
                                    'the one-shot marker was written at the provider entry'}}
           if window.get('release_id') else {}),
    }
    read_run[RECORD_HASH_FIELD] = canonical_record_sha256(read_run)
    read_run_path = store.store_read_run(read_run)
    result = _result(PHASE_READ, OUTCOME_READ, evidence=evidence,
                     evidence_sha256=evidence.get('evidence_sha256'),
                     evidence_path=str(store.verification_path(verification_run_id)),
                     read_evidence=read_evidence, read_run_record_path=str(read_run_path),
                     read_run_record=read_run, capability=capability,
                     verification=capability['verification'], decision=result['decision'],
                     event=event, event_report=report, request=request_model,
                     verification_reports=result.get('verification_reports'),
                     verification_run_id=verification_run_id,
                     verification_session_id=evidence.get('verification_session_id'),
                     read_run_id=generic_read_run_id, read_session_id=session_id,
                     run_separation=separation, response=result.get('response'),
                     bye=result.get('bye'), notes=result['notes'])
    result['provider_entries'] = 1
    result['generic_provider_entries'] = 1
    return _finish_result(result, col)


# ===========================================================================================
# offline fixtures: the synthetic session and the payload-shaped event (no socket anywhere)
# ===========================================================================================
class _OfflineEndpoint:
    """Stand-in for the socket endpoint: it records the half close and opens nothing."""

    def __init__(self) -> None:
        self.half_closes = 0
        self.closed = False

    def shutdown_write(self) -> None:
        self.half_closes += 1

    def close(self) -> None:
        self.closed = True


class OfflineSession:
    """Deterministic stand-in for :class:`tools.hostctl.session.HostSession` (no socket).

    It offers exactly the surface this driver consumes -- HELLO_ACK, READY, the deferred answer
    to the one ``kernel.read`` request, the sealed ``kernel.read.bounded`` event the payload sends
    right after that answer, and the BYE -- so the phase logic is exercised end to end without a
    console, a relay or a socket. The failure modes are fixtures too: ``event=None`` models a
    session that stopped before it read anything, ``stop_before_response`` models the agent
    closing before it answered. When ``expected_arguments`` is given, the trigger must carry
    exactly those three integers: a fixture that accepts any request would prove nothing about the
    request mapping (W13-C1).
    """

    def __init__(self, *, session_id: str, event: Mapping | None = None,
                 ready: Mapping | None = None, bye: Mapping | None = None,
                 response: Mapping | None = None, status: str = 'ERROR',
                 stop_before_response: bool = False,
                 expected_arguments: Mapping | None = None,
                 label: str = 'offline-synthetic') -> None:
        self.session_id = session_id
        self.label = label
        self.ep = _OfflineEndpoint()
        self._event = dict(event) if isinstance(event, Mapping) else None
        self._ready = dict(ready) if isinstance(ready, Mapping) else {
            'msg': 'READY', 'session_id': session_id, 'context': CONTEXT,
            'attestation': 'offline fixture: no target was contacted'}
        self._bye = dict(bye) if isinstance(bye, Mapping) else {
            'msg': 'BYE', 'reason': 'OK', 'cleanup': {'state': 'CLOSED'}}
        self._response = dict(response) if isinstance(response, Mapping) else {
            'header': {'in_reply_to': 'REQ-offline-0'}, 'status': status,
            'error': {'code': 'OPERATION_DEFERRED', 'detail': 'route deferred_privilege'},
            'cleanup': {'state': 'CLOSED'}}
        self._stop_before_response = stop_before_response
        self._expected_arguments = dict(expected_arguments) if isinstance(
            expected_arguments, Mapping) else None
        self.request_arguments: dict | None = None
        self.kernel_read_bounded: dict | None = None
        self.ready: dict | None = None
        self.bye: dict | None = None
        self.handshook = False
        self.ready_read = False
        self.triggered = False
        self.await_bye_note: str | None = None
        self.closed = False

    # ---------------------------------------------------------------- the session surface
    def handshake(self) -> dict:
        self.handshook = True
        return {'msg': 'HELLO_ACK', 'session_id': self.session_id, 'protocol_version': 1,
                'aead': 'AEAD_CHACHA20_POLY1305', 'nonce': '0' * 24,
                'note': 'offline fixture (no console was contacted)'}

    def recv_ready(self) -> dict:
        if not self.handshook:
            raise SessionError('no READY frame: the handshake never ran (offline fixture)')
        self.ready_read = True
        self.ready = dict(self._ready)
        return dict(self.ready)

    def request(self, op: str, arguments: dict | None = None, *,
                request_id: str | None = None) -> dict:
        if not self.handshook:
            raise SessionError('session is not in ACTIVE state (offline fixture)')
        if op != TRIGGER_OPERATION:
            raise SessionError(f'offline fixture implements only {TRIGGER_OPERATION!r}, '
                               f'not {op!r}')
        if self._expected_arguments is not None:
            seen = dict(arguments or {})
            if seen != self._expected_arguments:
                raise SessionError(f'offline fixture: the {op} trigger carried {seen!r}, the '
                                   f'released request is {self._expected_arguments!r}')
        if self._stop_before_response:
            self.bye = dict(self._bye)
            raise SessionError(f'agent closed the session (BYE {self.bye.get("reason")}) while '
                               f'waiting for the response to {op}')
        self.request_arguments = dict(arguments or {})
        self.triggered = True
        # the payload performs its one bounded read right after this response
        self.kernel_read_bounded = dict(self._event) if self._event is not None else None
        return dict(self._response)

    def await_bye(self, timeout_note: str = 'close') -> dict | None:
        self.await_bye_note = timeout_note
        self.bye = dict(self._bye)
        return dict(self.bye)

    def close(self) -> None:
        self.closed = True
        self.ep.close()


def synthetic_bounded_event(*, region: str = PINNED_REGION, offset: int = PINNED_OFFSET,
                            length: int = PINNED_LENGTH, bytes_hex: str = PINNED_BYTES_HEX,
                            runtime_kbase: int = 0xFFFFFFFF998F4000,
                            callback_executed: bool = True, cb_status: int = 0, kexec_rc: int = 0,
                            cross_check: str = 'MATCH', status: str = 'OK',
                            single_callback: bool = True, retry: bool = False,
                            writes_to_kernel: bool = False, host_supplied_address: bool = False,
                            provider: str = PROVIDER_NAME, build_id: str = 'f' * 32,
                            label: str = 'ps4rfd-w12-offline',
                            profile_decision: str = 'PROFILE_UNBOUND',
                            region_count: int | None = None,
                            max_read_len: int | None = None,
                            region_index_override: int | None = None) -> dict:
    """One ``kernel.read.bounded`` event body in exactly the payload's encoding (no console).

    Field names, types and text encodings are the ones ``ps4rf_kread_event`` emits
    (``native/target/ps4rf_kread.c``): u64 values as ``0x`` + 16 lowercase digits, the
    documented ``UNMEASURED`` alias for the zero value, small counts as decimal text, the four
    read claims as JSON booleans. ``lstar`` is composed the way the payload composes it
    (``kbase + 0x1C0``), so the host-side re-derivation has a real value to check.
    """
    raw = bytes.fromhex(bytes_hex)
    entry = regions.get_region(region)
    if entry is None:
        raise ValueError(f'unknown region {region!r} (the registry is normative)')
    # the payload reports the index it served; an override models a payload that reports a
    # different row than the one the window names (the W13-C1 refusal the host must catch)
    index = region_index(region) if region_index_override is None else region_index_override
    resolved_rva = int(entry.rva or 0) + offset
    measured = bool(callback_executed and cb_status == 0 and 1 <= len(raw)
                    <= regions.MAX_READ_LEN)
    common = {
        'msg': 'EVENT', 'event': EVENT_KIND, 'schema': EVENT_SCHEMA,
        'status': status if callback_executed else 'FAILED',
        'run_status': 0 if (callback_executed and status == 'OK') else 1,
        'run_status_name': 'OK' if (callback_executed and status == 'OK') else 'FAILED',
        'callback_executed': bool(callback_executed),
        'cb_status': cb_status,
        'cb_status_name': 'OK' if cb_status == 0 else 'FAILED',
        'kexec_rc': kexec_rc,
        'requested_region': entry.name,
        'requested_region_index': index,
        'region_identity': entry.identity_status,
        'requested_offset': str(offset), 'requested_length': str(length),
        'copied_len': len(raw) if measured else 0,
        'lstar': u64_hex(runtime_kbase + XFAST_RVA),
        'kbase_candidate': u64_hex(runtime_kbase), 'kbase_sdk': u64_hex(runtime_kbase),
        'cross_check': cross_check if callback_executed else UNMEASURED,
        'region_rva': u64_hex(int(entry.rva or 0)) if callback_executed else UNMEASURED,
        'offset_length_sum': (u64_hex(offset + length) if callback_executed else UNMEASURED),
        'resolved_rva': (UNMEASURED if resolved_rva == 0 else u64_hex(resolved_rva))
                        if callback_executed else UNMEASURED,
        'resolved_runtime_va': (u64_hex(runtime_kbase + resolved_rva)
                                if callback_executed else UNMEASURED),
        'bytes_hex': raw.hex() if measured else '',
        'sha256': hashlib.sha256(raw).hexdigest() if measured else '',
        'sha256_status': 'MEASURED' if measured else 'NOT_MEASURED',
        'max_read_len': regions.MAX_READ_LEN if max_read_len is None else max_read_len,
        'region_count': (len(regions.compiled_regions()) if region_count is None
                         else region_count),
        'single_callback': bool(single_callback), 'retry': bool(retry),
        'writes_to_kernel': bool(writes_to_kernel),
        'host_supplied_address': bool(host_supplied_address),
        'generic_read_primitive': 'NONE: one bounded region read per session; the host picks '
                                  'region index, offset and length, never an address',
        'resolved_runtime_va_note': 'the resolved address lives in this evidence only; the '
                                    'request carries no address and cannot contain one',
        'build_id': build_id, 'label': label, 'provider': provider,
        'scope': f'read-only; one bounded privileged callback per session; region table '
                 f'compile-time; max {regions.MAX_READ_LEN}; no kernel write; no generic '
                 f'primitive',
        'profile_decision': profile_decision,
    }
    if not callback_executed:
        common['requested_region'] = 'UNKNOWN'
        common['region_identity'] = UNMEASURED
        common['cb_status_name'] = 'NOT_EXECUTED'
    return common


# ===========================================================================================
# the offline end-to-end simulation: RUN A -> persisted evidence -> RUN B
# ===========================================================================================
SIM_SESSION_A = 'SES-00000000000000000000000000000a1b'
SIM_SESSION_B = 'SES-00000000000000000000000000000b2a'
SIM_VERIFICATION_RUN = 'VRUN-w12-sim-verify'
SIM_BOOT_READ_RUN = 'RUN-w12-sim-bootread'
SIM_GENERIC_RUN = 'RUN-w12-sim-generic'
#: The release id of the offline rehearsal (a simulation, not an owner release).
SIM_REHEARSAL_RELEASE_ID = 'SIM-REHEARSAL-RELEASE'
SIM_KBASE = 0xFFFFFFFF998F4000
#: the W10 capture the W11.2 boot identity is derived from (bootpriv.W10_CAPTURE)
SIM_BOOT_TIME = bootpriv.W10_CAPTURE
SIM_APPROVAL = {'approved': True, 'state': 'APPROVED', 'id': 'CMR-w12-offline-simulation'}
#: the machinery rehearsal runs on a nonzero-RVA STRICT region (the frozen W5 addr domain)
SIM_REHEARSAL_REGION = 'amd_iommu'
SIM_REHEARSAL_SESSION_A = 'SES-00000000000000000000000000000c3d'
SIM_REHEARSAL_SESSION_B = 'SES-00000000000000000000000000000d4e'
SIM_REHEARSAL_VERIFICATION_RUN = 'VRUN-w12-sim-rehearsal'
SIM_REHEARSAL_BOOT_READ_RUN = 'RUN-w12-sim-rehearsal-bootread'
SIM_REHEARSAL_GENERIC_RUN = 'RUN-w12-sim-rehearsal-generic'


def synthetic_profile():
    """The real FW13.52 profile (``fixture: false``) and its canonical hash."""
    profile = json.loads((REPO_ROOT / 'profiles' / 'fw1352' / 'profile-13.52.json').read_text())
    return profile, canonical_profile_sha256(profile)


def synthetic_boot_binding(profile: Mapping, *, boot_time: Mapping | None = None) -> BootBinding:
    """The boot binding of the simulation: derived from the profile and the W10 boottime."""
    profile_sha = canonical_profile_sha256(dict(profile))
    stamp = dict(boot_time or SIM_BOOT_TIME)
    boot_id = bootid.derive_boot_id(profile_sha, bootid.BootTime(int(stamp['sec']),
                                                                int(stamp['usec'])),
                                    profile=dict(profile))['boot_id']
    return BootBinding.from_profile(dict(profile), boot_id)


def sim_provider(*, live_approved: bool = True) -> dict:
    return {'name': PROVIDER_NAME, 'provider_type': PROVIDER_TYPE, 'state': PROVIDER_STATE_WIRED,
            'live_approved': bool(live_approved)}


def rehearsal_evidence(window: Mapping, *, verification_run_id: str, read_run_id: str,
                       verification_session_id: str, profile_sha256: str, boot_id: str,
                       provider: Mapping | None = None, context: str = CONTEXT,
                       runtime_kbase: int = SIM_KBASE) -> dict:
    """A synthetic ``VerificationEvidence`` for the offline rehearsal (phase A's own shape).

    Phase A's real verification path is exercised in the pinned scenario; its W12 verifier call is
    pinned to ``image_elf`` (``kreadverify.verify_bootstrap_evidence`` hardcodes the bootstrap
    region), so the rehearsal builds the record phase A would persist directly, without bending
    the pinned path or pretending a second window is the bootstrap window.
    """
    identity = provider_identity(provider)
    raw = bytes.fromhex(window['bytes_hex'])
    resolved_rva = int(window['rva'] or 0) + int(window['offset'])
    evidence = {
        'schema': SCHEMA_VERIFICATION,
        'verification_run_id': verification_run_id,
        'verification_session_id': verification_session_id,
        'operation': VERIFICATION_OPERATION,
        'outcome': 'PASS',
        'capability': OPERATION,
        'provider': identity['name'],
        'provider_type': identity['provider_type'],
        'profile_sha256': profile_sha256,
        'boot_id': boot_id,
        'context': context,
        'scope': SCOPE_SESSION,
        'region': window['region'],
        'offset': window['offset'],
        'length': window['length'],
        'rva': window['rva'],
        'locator': window.get('locator'),
        'expected_bytes_hex': window['bytes_hex'],
        'expected_sha256': window['sha256'],
        'observed_bytes_hex': raw.hex(),
        'observed_sha256': hashlib.sha256(raw).hexdigest(),
        'resolved_rva': u64_hex(resolved_rva),
        'resolved_runtime_va': u64_hex(runtime_kbase + resolved_rva),
        'read_run_id': read_run_id,
        'read_session_id': verification_session_id,
        'source_event': {'kind': 'offline rehearsal fixture', 'synthetic': True},
        'run_separation': {'verification_run_id': verification_run_id, 'read_run_id': read_run_id,
                           'run_separated': verification_run_id != read_run_id,
                           'verification_session_id': verification_session_id,
                           'read_session_id': verification_session_id,
                           'note': 'offline rehearsal fixture'},
        'provider_entries': 0,
        'note': 'offline rehearsal fixture: the record phase A persists for a nonzero-RVA window',
    }
    evidence['evidence_sha256'] = canonical_evidence_sha256(evidence)
    return evidence


def _phase_summary(result: Mapping) -> dict:
    event_report = result.get('event_report') or {}
    evidence = result.get('evidence') or {}
    return {
        'phase': result.get('phase'),
        'outcome': result.get('outcome'),
        'ok': bool(result.get('ok')),
        'provider_entries': result.get('provider_entries'),
        'generic_provider_entries': result.get('generic_provider_entries'),
        'problems': list(result.get('problems') or ()),
        'checks_failed': list(result.get('checks_failed') or ()),
        'verification_run_id': result.get('verification_run_id'),
        'verification_session_id': result.get('verification_session_id'),
        'read_run_id': result.get('read_run_id'),
        'read_session_id': result.get('read_session_id'),
        'observed_bytes_hex': event_report.get('bytes_hex'),
        'observed_sha256': event_report.get('output_sha256'),
        'resolved_rva': event_report.get('resolved_rva'),
        'resolved_runtime_va': event_report.get('resolved_runtime_va'),
        'evidence_sha256': evidence.get('evidence_sha256'),
        'evidence_path': stable_evidence_ref(result.get('evidence_path')),
        'decision': result.get('decision'),
        'run_separation': result.get('run_separation'),
    }


def run_offline_simulation(*, store_root: str | pathlib.Path | None = None,
                           keep_store: bool = False) -> dict:
    """RUN A -> persisted evidence -> RUN B, deterministically, with no socket and no console.

    Three scenarios run in order, all against the same entry points the live driver uses:

    * **RUN A (pinned window)** -- one synthetic session, the payload-shaped ``image_elf`` event,
      the host re-derivation and the ``VerificationEvidence`` in the store. Zero provider entries.
    * **RUN B (pinned window, the accepted contract)** -- a second synthetic session with a new
      id; the host loads and rehashes the record, derives the capability for the new session and
      walks the whole chain. The pinned window's locator is the relative rva 0 (``image_elf`` sits
      at the image base), which the W5 binding accepts after W12-RVA0-BINDING; the runtime address
      is resolved from the current boot base with checked arithmetic. The phase therefore grants:
      exactly one provider entry, the pinned bytes back, the read-run record written.
    * **RUN B rehearsal (nonzero-RVA STRICT region)** -- the *same* phase-B code on a synthetic
      window for ``amd_iommu`` (rva > 0): grant, exactly one provider entry, event capture, byte
      and hash verification, the read-run record and the run-separation proof. This is a wiring
      rehearsal, not the accepted live window (the frozen payload only reads ``image_elf``).

    A final boundary probe replays phase B with run A's session id: it must be refused with
    ``KREADLIVE_SESSION_REUSED``, zero entries and no store write.
    """
    import tempfile

    profile, profile_sha = synthetic_profile()
    binding = synthetic_boot_binding(profile)
    transcript: list[dict] = []
    checks: list[dict] = []
    temporary = None
    if store_root is None:
        temporary = tempfile.TemporaryDirectory(prefix='ps4rf-w12-simulation-')
        store_root = temporary.name
    store = VerificationEvidenceStore(store_root)
    window = bootstrap_expectation(profile)
    # the transcript and the report are diffed across runs: where the store lives is reported as
    # a label, never as the absolute path a particular run happened to use
    store_label = '<temporary directory>' if temporary is not None else str(store_root)

    def record(name: str, ok: bool, detail: str = '') -> bool:
        checks.append({'name': name, 'ok': bool(ok), 'detail': detail})
        return bool(ok)

    def step(name: str, **fields) -> None:
        transcript.append({'step': name, **fields})

    step('environment', profile='profiles/fw1352/profile-13.52.json', profile_sha256=profile_sha,
         boot_id=binding.boot_id, store_root=store_label, provider=PROVIDER_NAME,
         context=CONTEXT, console='none (offline simulation)')

    # ---------------------------------------------------------------- RUN A (pinned window)
    session_a = OfflineSession(session_id=SIM_SESSION_A,
                               event=synthetic_bounded_event(runtime_kbase=SIM_KBASE))
    phase_a = run_verification(session_a, profile=profile, boot_binding=binding, store=store,
                               provider=sim_provider(live_approved=False),
                               verification_run_id=SIM_VERIFICATION_RUN,
                               read_run_id=SIM_BOOT_READ_RUN)
    event_a = phase_a.get('event_report') or {}
    step('RUN A: one session, the fixed bootstrap read',
         session_id=SIM_SESSION_A, verification_run_id=SIM_VERIFICATION_RUN,
         read_run_id=SIM_BOOT_READ_RUN, outcome=phase_a['outcome'],
         observed_bytes_hex=event_a.get('bytes_hex'), observed_sha256=event_a.get('output_sha256'),
         expected_bytes_hex=PINNED_BYTES_HEX, expected_sha256=PINNED_SHA256,
         kbase=event_a.get('kbase'), resolved_rva=event_a.get('resolved_rva'),
         provider_entries=phase_a['provider_entries'],
         generic_provider_entries=phase_a['generic_provider_entries'],
         problems=phase_a['problems'])
    record('RUN A: the pinned 16 bytes were re-derived and matched',
           bool(event_a.get('verified')) and event_a.get('bytes_hex') == PINNED_BYTES_HEX
           and event_a.get('output_sha256') == PINNED_SHA256,
           f"observed={event_a.get('bytes_hex')}")
    record('RUN A: the VerificationEvidence was persisted',
           bool(phase_a.get('evidence_path')) and phase_a['outcome'] == OUTCOME_VERIFIED,
           stable_evidence_ref(phase_a.get('evidence_path')) or 'no path recorded')
    record('RUN A: zero generic provider entries',
           phase_a['provider_entries'] == 0 and phase_a['generic_provider_entries'] == 0,
           f"entries={phase_a['provider_entries']}")
    record('RUN A: no capability circle (no capability record, no decision, nothing consulted)',
           phase_a['ok'] and not phase_a.get('capability') and not phase_a.get('decision'),
           'phase A ran without a capability record or a decision')
    persisted = store.load_verification(SIM_VERIFICATION_RUN)
    record('the persisted evidence rehashes on load',
           persisted['evidence_sha256'] == canonical_evidence_sha256(persisted),
           f"evidence_sha256={persisted['evidence_sha256']}")

    # ---------------------------------------------------------------- RUN B (pinned window)
    session_b = OfflineSession(session_id=SIM_SESSION_B,
                               event=synthetic_bounded_event(runtime_kbase=SIM_KBASE))
    phase_b = run_generic_read(session_b, profile=profile, boot_binding=binding, store=store,
                               verification_run_id=SIM_VERIFICATION_RUN,
                               provider=sim_provider(), approval=SIM_APPROVAL,
                               generic_read_run_id=SIM_GENERIC_RUN)
    step('RUN B: a separate upload, a new session, the pinned window',
         session_id=SIM_SESSION_B, verification_session_id=SIM_SESSION_A,
         verification_run_id=SIM_VERIFICATION_RUN, read_run_id=SIM_GENERIC_RUN,
         outcome=phase_b['outcome'], provider_entries=phase_b['provider_entries'],
         decision=phase_b.get('decision'), problems=phase_b['problems'])
    record('RUN B: the evidence was loaded and rehashed before anything was sent',
           phase_b.get('evidence_sha256') == persisted['evidence_sha256'],
           f"evidence_sha256={phase_b.get('evidence_sha256')}")
    record('RUN B: the capability record was derived for the NEW session (never carried over)',
           (phase_b.get('capability') or {}).get('session_id') == SIM_SESSION_B,
           f"record session={(phase_b.get('capability') or {}).get('session_id')}")
    decision_b = phase_b.get('decision') or {}
    unbind_problems = [str(p) for p in phase_b['problems'] if str(p).startswith('PROFILE_UNBOUND')]
    runtime_va_b = (phase_b.get('read_evidence') or {}).get('resolved_runtime_va')
    step('RUN B: the pinned rva-0 locator through the W5 binding (W12-RVA0-BINDING)',
         stage=decision_b.get('stopped_at'), reasons=decision_b.get('reasons'),
         note='image_elf sits at the image base: the W5 binding binds the *locator* (rva 0 is a '
              'valid image position) and the runtime address is resolved from the current boot '
              'base with checked arithmetic (non-zero, canonical, inside the pinned window)')
    record('RUN B (pinned window): the rva-0 locator passes the W5 binding (no PROFILE_UNBOUND)',
           not unbind_problems and decision_b.get('reasons') == [],
           '; '.join(unbind_problems) or 'the locator was bound (reasons empty)')
    record('RUN B (pinned window): exactly one provider entry and the pinned bytes came back',
           phase_b['outcome'] == OUTCOME_READ and phase_b['provider_entries'] == 1
           and phase_b.get('event') is not None,
           f"outcome={phase_b['outcome']} entries={phase_b['provider_entries']}")
    record('RUN B (pinned window): the runtime address was resolved against the boot base '
           '(non-zero, canonical)',
           runtime_va_b is not None and runtime_va_b != 0
           and kread_model.is_canonical_x86_64(runtime_va_b),
           f"resolved_runtime_va={u64_hex(runtime_va_b) if runtime_va_b is not None else None}")

    # ------------------------------------------------- RUN B rehearsal (nonzero-RVA region)
    rehearsal_root = pathlib.Path(store_root) / 'rehearsal'
    rehearsal_store = VerificationEvidenceStore(rehearsal_root)
    rehearsal_bytes = '11' * 16
    # the rehearsal reads a NON-bootstrap region, so it goes through the release gate: an offline
    # release id marks it exactly like a real owner release does (`KREADLIVE_WINDOW_NOT_RELEASED`
    # refuses any other window in the productive path).
    # the simulation is an isolated episode: an earlier simulation in the same process does not
    # spend this one's release (the one-shot rule itself is unconditional for real releases)
    _CONSUMED_RELEASES.pop(SIM_REHEARSAL_RELEASE_ID, None)
    rehearsal_window = window_for(SIM_REHEARSAL_REGION, bytes_hex=rehearsal_bytes,
                                  profile=profile, release_id=SIM_REHEARSAL_RELEASE_ID,
                                  release_sha256=hashlib.sha256(
                                      f'{SIM_REHEARSAL_RELEASE_ID}|{rehearsal_bytes}'.encode()
                                  ).hexdigest(),
                                  # a simulated approval binding (the offline simulation has no
                                  # approval document; the live path always carries the real hash)
                                  approval_sha256=hashlib.sha256(
                                      b'SIM-REHEARSAL-APPROVAL').hexdigest())
    rehearsal_record = rehearsal_evidence(
        rehearsal_window, verification_run_id=SIM_REHEARSAL_VERIFICATION_RUN,
        read_run_id=SIM_REHEARSAL_BOOT_READ_RUN,
        verification_session_id=SIM_REHEARSAL_SESSION_A, profile_sha256=profile_sha,
        boot_id=binding.boot_id, provider=sim_provider(live_approved=False))
    rehearsal_store.store_verification(rehearsal_record)
    session_r_b = OfflineSession(session_id=SIM_REHEARSAL_SESSION_B,
                                 event=synthetic_bounded_event(
                                     region=SIM_REHEARSAL_REGION, bytes_hex=rehearsal_bytes,
                                     runtime_kbase=SIM_KBASE))
    rehearsal_b = run_generic_read(session_r_b, profile=profile, boot_binding=binding,
                                   store=rehearsal_store,
                                   verification_run_id=SIM_REHEARSAL_VERIFICATION_RUN,
                                   provider=sim_provider(), approval=SIM_APPROVAL,
                                   generic_read_run_id=SIM_REHEARSAL_GENERIC_RUN,
                                   expected=rehearsal_window,
                                   evidence_window=rehearsal_window)
    step('RUN B rehearsal: the same phase-B code on a nonzero-RVA STRICT region',
         region=SIM_REHEARSAL_REGION, rva=rehearsal_window['rva'],
         evidence='synthetic record (phase A shape), hashed and persisted like the real one',
         evidence_sha256=rehearsal_record['evidence_sha256'],
         verification_run_id=SIM_REHEARSAL_VERIFICATION_RUN,
         read_run_id=SIM_REHEARSAL_GENERIC_RUN, verification_session_id=SIM_REHEARSAL_SESSION_A,
         read_session_id=SIM_REHEARSAL_SESSION_B, outcome=rehearsal_b['outcome'],
         provider_entries=rehearsal_b['provider_entries'],
         decision=(rehearsal_b.get('decision') or {}).get('outcome'),
         observed_bytes_hex=(rehearsal_b.get('event_report') or {}).get('bytes_hex'),
         problems=rehearsal_b['problems'],
         note='wiring rehearsal only: the frozen payload reads image_elf, so this scenario proves '
              'the entry counting, the verification and the record, not the live window')
    record('rehearsal: the generic read granted and took exactly one provider entry',
           rehearsal_b['outcome'] == OUTCOME_READ and rehearsal_b['provider_entries'] == 1
           and rehearsal_b['generic_provider_entries'] == 1,
           f"outcome={rehearsal_b['outcome']} entries={rehearsal_b['provider_entries']}")
    rehearsal_event = rehearsal_b.get('event_report') or {}
    record('rehearsal: the returned bytes were verified against the rehearsal window',
           bool(rehearsal_event.get('verified'))
           and rehearsal_event.get('bytes_hex') == rehearsal_bytes
           and rehearsal_event.get('output_sha256')
           == hashlib.sha256(bytes.fromhex(rehearsal_bytes)).hexdigest(),
           f"observed={rehearsal_event.get('bytes_hex')}")
    separation = rehearsal_b.get('run_separation') or {}
    record('run separation: verification_run_id != read_run_id',
           separation.get('verification_run_id') == SIM_REHEARSAL_VERIFICATION_RUN
           and separation.get('generic_read_run_id') == SIM_REHEARSAL_GENERIC_RUN
           and separation.get('run_ids_distinct') is True,
           f"{separation.get('verification_run_id')} vs {separation.get('generic_read_run_id')}")
    record('run separation: verification_session_id != read_session_id',
           separation.get('verification_session_id') == SIM_REHEARSAL_SESSION_A
           and separation.get('read_session_id') == SIM_REHEARSAL_SESSION_B
           and separation.get('session_ids_distinct') is True,
           f"{separation.get('verification_session_id')} vs {separation.get('read_session_id')}")
    record('the W12 verifier confirmed the run separation in the read evidence',
           bool((rehearsal_b.get('verification_reports') or {})
                .get('generic', {}).get('run_separate')),
           'kreadverify.verify_read_evidence.run_separate')
    read_run = rehearsal_store.load_read_run(SIM_REHEARSAL_GENERIC_RUN)
    record('the read-run record is persisted with all four ids and the entry count',
           read_run['verification_run_id'] == SIM_REHEARSAL_VERIFICATION_RUN
           and read_run['read_run_id'] == SIM_REHEARSAL_GENERIC_RUN
           and read_run['verification_session_id'] == SIM_REHEARSAL_SESSION_A
           and read_run['read_session_id'] == SIM_REHEARSAL_SESSION_B
           and read_run['provider_entries'] == 1
           and read_run['record_sha256'] == canonical_record_sha256(read_run),
           f"record_sha256={read_run['record_sha256']}")

    # ---------------------------------------------------------------- the session boundary
    session_old = OfflineSession(session_id=SIM_SESSION_A,
                                 event=synthetic_bounded_event(runtime_kbase=SIM_KBASE))
    probe = run_generic_read(session_old, profile=profile, boot_binding=binding, store=store,
                             verification_run_id=SIM_VERIFICATION_RUN, provider=sim_provider(),
                             approval=SIM_APPROVAL, generic_read_run_id=SIM_GENERIC_RUN)
    step('boundary probe: run A\'s session id in phase B',
         session_id=SIM_SESSION_A, outcome=probe['outcome'], problems=probe['problems'],
         provider_entries=probe['provider_entries'],
         note='the SESSION-scoped record of run A is never carried over: the new session derives '
              'its own, and the old session id is refused')
    record('the old session id is refused in phase B (KREADLIVE_SESSION_REUSED, zero entries)',
           probe['outcome'] == OUTCOME_REFUSED and probe['provider_entries'] == 0
           and any(str(p).startswith(KREADLIVE_SESSION_REUSED) for p in probe['problems']),
           '; '.join(probe['problems']))
    record('the refused probe wrote nothing (only the granted pinned read did)',
           store.read_run_ids() == [SIM_GENERIC_RUN]
           and store.verification_run_ids() == [SIM_VERIFICATION_RUN]
           and rehearsal_store.read_run_ids() == [SIM_REHEARSAL_GENERIC_RUN],
           f"pinned store: {store.verification_run_ids()}/{store.read_run_ids()}")

    accepted_contract_met = bool(phase_a['ok'] and phase_b['outcome'] == OUTCOME_READ
                                 and phase_b['provider_entries'] == 1)
    integration_finding = {
        'id': 'W12-RVA0-BINDING',
        'root_cause': 'the W5 profile binding validated a *relative* locator value (rva) against '
                      'the runtime address domain (addr > 0); W5 bound the unslid resolved address '
                      'into an address field',
        'impact': 'the valid image_elf locator rva 0 was refused as PROFILE_UNBOUND before any '
                  'runtime resolution, so the accepted RUN B window could never be bound and '
                  'never entered the provider (0 provider entries)',
        'fix': 'locator values are validated by their declared kind (relative: 0 <= rva < 2**64, '
               'zero is a valid image position); the runtime address keeps its own non-zero, '
               'canonical domain and is resolved later from the current boot base with checked '
               'arithmetic (kbase + rva, then + offset; overflow, zero and non-canonical values '
               'fail closed)',
        'owner_files': ['tools/profiles/schema.py (FIELD_DOMAINS: rva + runtime_va, '
                        'validate_locator_value, module_locator_kind)',
                        'tools/profiles/kread_capability.py (W5 binding binds the locator)',
                        'tools/profiles/regions.py (checked_kernel_address, resolve_runtime)',
                        'tools/profiles/binding.py (runtime binding uses the checked primitive)'],
        'fixed_in_this_run': True,
        'payload_unchanged': True,
        'profile_unchanged': canonical_profile_sha256(dict(profile)),
    }
    report = {
        'schema': SIMULATION_SCHEMA,
        'ok': all(entry['ok'] for entry in checks),
        'accepted_contract_met': accepted_contract_met,
        'blocker': None,
        'integration_finding': integration_finding,
        'checks': checks,
        'checks_failed': [entry['name'] for entry in checks if not entry['ok']],
        'store_root': store_label,
        'store': {'verification_run_ids': store.verification_run_ids(),
                  'read_run_ids': store.read_run_ids(),
                  'verification_evidence_sha256': persisted['evidence_sha256']},
        'rehearsal_store': {'store_root': f'{store_label}/rehearsal',
                            'evidence_sha256': rehearsal_record['evidence_sha256'],
                            'verification_run_ids': rehearsal_store.verification_run_ids(),
                            'read_run_ids': rehearsal_store.read_run_ids(),
                            'read_run_record_sha256': read_run['record_sha256']},
        'profile_sha256': profile_sha,
        'boot_id': binding.boot_id,
        'ids': {'verification_run_id': SIM_VERIFICATION_RUN,
                'read_run_id': SIM_GENERIC_RUN,
                'verification_session_id': SIM_SESSION_A,
                'read_session_id': SIM_SESSION_B},
        'pinned': dict(window),
        'phase_a': _phase_summary(phase_a),
        'phase_b': _phase_summary(phase_b),
        'rehearsal_phase_b': _phase_summary(rehearsal_b),
        'boundary_probe': _phase_summary(probe),
        'one_shot_guard': {
            'cited': ['native/target/ps4rf_agent.c (one bounded read per session; the guard is set '
                      'before the privileged call)',
                      'native/target/build_manifest.py (the kread gate facts)'],
            'note': 'not re-proven here: the driver runs one phase per session and never retries '
                    'a read',
        },
        'transcript': transcript,
    }
    if temporary is not None and not keep_store:
        temporary.cleanup()
    return report


def run_phase(phase: str, session, *, profile: Mapping, boot_binding, store, provider=None,
              context: str = CONTEXT, verification_run_id: str | None = None,
              run_id: str | None = None, read_run_id: str | None = None,
              approval: Mapping | None = None, recovery: bool = False,
              request: Mapping | None = None, request_id: str | None = None,
              expected: Mapping | None = None) -> dict:
    """Dispatch one W12 phase to its entry point. One call, one phase, never a chain.

    ``phase`` is :data:`PHASE_VERIFY` (``--w12-verify-run``) or :data:`PHASE_READ`
    (``--w12-read-run``). Phase B refuses to run without the ``verification_run_id`` of the
    persisted record, which is exactly the "phase A must have passed first" rule.
    """
    if phase == PHASE_VERIFY:
        return run_verification(session, profile=profile, boot_binding=boot_binding, store=store,
                                provider=provider, context=context,
                                verification_run_id=verification_run_id or run_id,
                                read_run_id=read_run_id, request_id=request_id,
                                expected=expected)
    if phase == PHASE_READ:
        if not verification_run_id:
            raise ValueError('phase B needs the verification_run_id of the persisted '
                             'VerificationEvidence (phase A must have passed first)')
        return run_generic_read(session, profile=profile, boot_binding=boot_binding, store=store,
                                verification_run_id=verification_run_id, provider=provider,
                                context=context, approval=approval, recovery=recovery,
                                generic_read_run_id=run_id or read_run_id, request=request,
                                request_id=request_id, expected=expected)
    raise ValueError(f'unknown W12 phase {phase!r} (expected one of {PHASES})')


# --- self test -----------------------------------------------------------------------------
def _self_test() -> list[str]:
    """Deterministic offline checks: the pins, the event verifier, the whole simulation."""
    problems: list[str] = []
    profile, _ = synthetic_profile()
    window = bootstrap_expectation(profile)
    problems.extend(window['problems'])
    event = synthetic_bounded_event(runtime_kbase=SIM_KBASE)
    contract = kernel_read_bounded_problems(event)
    if contract:
        problems.append('the synthetic event fails the session contract: ' + '; '.join(contract))
    report = verify_bounded_event(event, profile=profile, expected=window)
    if not report['verified']:
        problems.append('the synthetic event did not verify: ' + '; '.join(report['problems']))
    tampered = dict(event, bytes_hex='00' * PINNED_LENGTH,
                    sha256=hashlib.sha256(bytes(PINNED_LENGTH)).hexdigest(),
                    copied_len=PINNED_LENGTH)
    tampered_report = verify_bounded_event(tampered, profile=profile, expected=window)
    if tampered_report['verified']:
        problems.append('the verifier accepted bytes that are not the pinned bytes')
    elif not any(str(p).startswith(KREADLIVE_BYTES_MISMATCH)
                 for p in tampered_report['problems']):
        problems.append('tampered bytes were refused, but not as a pinned-bytes mismatch')
    missing = verify_bounded_event(None, profile=profile, expected=window)
    if missing['verified']:
        problems.append('the verifier accepted a missing event')
    simulation = run_offline_simulation()
    if not simulation['ok']:
        problems.append('the offline simulation failed: ' + '; '.join(simulation['checks_failed']))
    return problems


def main(argv: list[str]) -> int:
    argv = list(argv)
    store_root = None
    if '--store' in argv:
        index = argv.index('--store')
        if index + 1 >= len(argv):
            print('--store needs a directory')
            return 2
        store_root = argv[index + 1]
    if '--simulate' in argv:
        report = run_offline_simulation(store_root=store_root, keep_store=bool(store_root))
        print(json.dumps({key: value for key, value in report.items() if key != 'transcript'},
                         indent=1, sort_keys=True))
        print(json.dumps(report['transcript'], indent=1, sort_keys=True))
        return 0 if report['ok'] else 1
    if '--self-test' in argv:
        problems = _self_test()
        for problem in problems:
            print(f'kread live: {problem}')
        print(f'kread live self-test: {"ok" if not problems else "FAILED"} '
              '(pins, event verifier, offline RUN A -> RUN B simulation)')
        return 0 if not problems else 1
    print((__doc__ or '').strip().splitlines()[0])
    print('usage: kreadlive.py --self-test | --simulate [--store DIR]')
    return 2


if __name__ == '__main__':                                # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
