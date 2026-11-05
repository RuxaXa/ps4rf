#!/usr/bin/env python3
"""W16 binding match -- the authorization model for the CCP/keymgr binding windows.

**Why this exists.** The promotion precondition of the CCP profile revision
(`docs/P4-CCP-ACCEPTANCE-REQ.md` section 7) is a *live byte match* of the revision's binding
windows. Those windows cannot travel through the W13 research read path, and that is not an
oversight: the W13 review classifies them `IDENTITY_ONLY` -- they are fingerprints of the pinned
image, not research targets -- and the W13 release refuses every region that is not
`APPROVED_READ` (`W13_RELEASE_NOT_APPROVED_READ`). Matching a fingerprint and *reading research
data* are different authorizations, so W16 needs its own one.

**The model.** One section-70 approval, scope `w16-binding-match`, that pins the revision
candidate's canonical hash, the payload identity, the boot id and the *exact* window set (the
five STRICT windows of the CCP provenance, derived from the registry and the candidate -- never
retyped here). Each window may be read **once per lifetime**; the ledger is bound to the revision
and the window set, so a different revision starts empty and a half-finished set cannot be
mistaken for a complete one. The verdict of a window is exactly one thing: the returned bytes
equal the pinned bytes (through the existing bounded-event verifier, which owns that contract).

**The missing link, stated honestly.** No read path in the repository may serve these windows
today, and the reason is a deliberate rule, not an omission:

* `tools/hostctl/kreadlive.py` (`run_generic_read`) refuses a window that is neither the pinned
  bootstrap region nor carries a release id -- "only the pinned bootstrap window or an
  owner-released window may be read";
* `tools/research/release.py` refuses a release for any region that is not `APPROVED_READ`, and
  the W13 review keeps these five windows `IDENTITY_ONLY` on purpose;
* `tools/research/approval.py` allows exactly one read scope (`w13-research-read`), which makes a
  release mandatory.

So this module can *authorise and judge* a binding match, and it does so completely offline, but
wiring it to a live read is an owner decision: either the read path grows a second, narrower
authorization (this model), or the payload reads the windows itself at bootstrap the way W11.2
already reads the boot window, or the project builds the `kernel.snapshot` provider whose frozen
contract ("range policy -> read -> SHA-256 -> compare -> only on match are data released",
`docs/P4-PRIMITIVE-INTERFACES.md`) is the designed vehicle for exactly this comparison. Until
that decision is made, nothing here touches a console.

**What this module never does.** It does not touch a console, does not build a request, does not
choose a window at run time (the set is fixed and pinned), does not authorise a research read,
and never accepts a release. A research approval and a binding-match approval cannot produce each
other's documents: `approval_problems` refuses the research scope here, and the wave sheet refuses
a binding-match approval for a research read.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:  # allow direct script execution
    sys.path.insert(0, str(REPO_ROOT))

from tools.hostctl import kreadlive as KL                                        # noqa: E402
from tools.hostctl.kreadstore import canonical_bytes                            # noqa: E402
from tools.profiles import regions as R                                          # noqa: E402


def canonical_sha256(document: dict) -> str:
    """The canonical (JCS) sha256 of a document -- the same rule the trust objects use."""
    return hashlib.sha256(canonical_bytes(document)).hexdigest()

#: The one scope a binding-match approval may declare. Deliberately *not* the research scope.
SCOPE_BINDING_MATCH = 'w16-binding-match'
SCHEMA_APPROVAL = 'ps4rf.w16.binding-match-approval.v1'

#: The revision candidate that carries the windows, from the registry's own provenance.
CANDIDATE_PROFILE = R.CCP_PROVENANCE[0]

SCOPE_MISMATCH = 'W16_SCOPE_MISMATCH'
APPROVAL_INVALID = 'W16_APPROVAL_INVALID'
WINDOW_NOT_IN_SET = 'W16_WINDOW_NOT_IN_SET'
ALREADY_READ = 'W16_WINDOW_ALREADY_READ'
MISMATCH = 'W16_BINDING_MISMATCH'
SET_INCOMPLETE = 'W16_BINDING_SET_INCOMPLETE'

REFUSALS = (SCOPE_MISMATCH, APPROVAL_INVALID, WINDOW_NOT_IN_SET, ALREADY_READ, MISMATCH,
            SET_INCOMPLETE)

LEDGER_SCHEMA = 'ps4rf.w16.binding-match-ledger.v1'


# ---------------------------------------------------------------------------------------------
# the window set
# ---------------------------------------------------------------------------------------------

def binding_window_names() -> tuple[str, ...]:
    """The STRICT windows of the CCP provenance, in compiled order -- derived, never listed."""
    names = [region.name for region in R.compiled_regions()
             if region.provenance == R.CCP_PROVENANCE and region.identity_status == R.IDENTITY_STRICT]
    return tuple(names)


def binding_windows(candidate: dict | None = None) -> list[dict]:
    """The pinned window set, in the shape the bounded-event verifier expects.

    Every value comes from a repository document: the name/index/rva from the canonical registry,
    the offset and the bytes from the revision candidate's own locator. A missing locator, a
    locator without pinned bytes or a byte length that disagrees with the registry row is a hard
    error -- an incomplete window set must never look like a smaller valid one.
    """
    if candidate is None:
        candidate = json.loads((REPO_ROOT / CANDIDATE_PROFILE).read_text())
    locators = candidate.get('locators') or {}
    windows: list[dict] = []
    for name in binding_window_names():
        region = R.get_region(name)
        assert region is not None and region.locator, f'{name}: no registry locator'
        locator = locators.get(region.locator)
        if not isinstance(locator, dict):
            raise ValueError(f'{APPROVAL_INVALID}: the candidate pins no locator {region.locator!r}')
        pinned = locator.get('expected_bytes')
        pinned = pinned if isinstance(pinned, dict) else {}
        hex_bytes = pinned.get('hex')
        if not isinstance(hex_bytes, str) or not hex_bytes:
            raise ValueError(f'{APPROVAL_INVALID}: {region.locator!r} pins no bytes')
        raw = bytes.fromhex(hex_bytes)
        if len(raw) != region.length:
            raise ValueError(f'{APPROVAL_INVALID}: {region.locator!r} pins {len(raw)} bytes, the '
                             f'registry row {name} is {region.length}')
        pointed_at = (locator.get('locator') or {}).get('value') if isinstance(
            locator.get('locator'), dict) else None
        if pointed_at != int(region.rva or -1):
            raise ValueError(f'{APPROVAL_INVALID}: {region.locator!r} points at '
                             f"{locator.get('locator', {}).get('value')}, the registry row {name} "
                             f'at {region.rva}')
        windows.append({
            'region': name,
            'region_index': R.compiled_region_index(name),
            'offset': int(pinned.get('offset') or 0),
            'length': len(raw),
            'bytes_hex': hex_bytes,
            'sha256': hashlib.sha256(raw).hexdigest(),
        })
    return windows


def window_set_sha256(windows: list[dict]) -> str:
    """The canonical identifier of a window set (JCS over the tuples that define a window)."""
    return canonical_sha256({'schema': LEDGER_SCHEMA, 'windows': [
        {key: window[key] for key in ('region', 'region_index', 'offset', 'length', 'bytes_hex',
                                      'sha256')} for window in windows]})


def window_by_region(windows: list[dict], region: str) -> dict | None:
    for window in windows:
        if window['region'] == region:
            return window
    return None


def window_set_problems(windows: list[dict]) -> list[str]:
    """Re-check a window set against the canonical registry and the candidate ([] when it holds)."""
    problems: list[str] = []
    expected = binding_windows()
    if [window['region'] for window in windows] != [window['region'] for window in expected]:
        problems.append(f'{SET_INCOMPLETE}: the window set is not the registry\'s STRICT CCP set '
                        f"({[window['region'] for window in windows]})")
    for window, want in zip(windows, expected):
        for field in ('region_index', 'offset', 'length', 'bytes_hex', 'sha256'):
            if window.get(field) != want.get(field):
                problems.append(f"{WINDOW_NOT_IN_SET}: {window.get('region')} {field}="
                                f"{window.get(field)!r}, the candidate pins {want.get(field)!r}")
        hex_bytes = window.get('bytes_hex')
        if isinstance(hex_bytes, str) and hex_bytes:
            if window.get('sha256') != hashlib.sha256(bytes.fromhex(hex_bytes)).hexdigest():
                problems.append(f"{MISMATCH}: {window.get('region')} bytes do not hash to its own "
                                'sha256')
    return problems


# ---------------------------------------------------------------------------------------------
# the approval
# ---------------------------------------------------------------------------------------------

def approval_problems(approval: dict, *, windows: list[dict], revision_sha256: str,
                      payload: dict, boot_id: str, verification_run_id: str,
                      evidence_sha256: str) -> list[str]:
    """The exact reasons a binding-match approval cannot authorise this wave ([] when it can).

    The rules are the project's usual ones -- pin everything, refuse anything unstated -- plus the
    separation rule: the research scope belongs to the research read and is refused here.
    """
    problems: list[str] = []
    if not isinstance(approval, dict):
        return [f'{APPROVAL_INVALID}: the approval is not an object']
    scope = str(approval.get('read_scope') or '').strip().lower()
    if scope != SCOPE_BINDING_MATCH:
        problems.append(f'{SCOPE_MISMATCH}: read_scope={approval.get("read_scope")!r}, a binding '
                        f'match declares {SCOPE_BINDING_MATCH!r} (a research approval never '
                        'authorises these windows)')
    if approval.get('schema') != SCHEMA_APPROVAL:
        problems.append(f'{APPROVAL_INVALID}: schema {approval.get("schema")!r}')
    if approval.get('state') != 'APPROVED' or approval.get('approved') is not True:
        problems.append(f'{APPROVAL_INVALID}: state={approval.get("state")!r} '
                        f'approved={approval.get("approved")!r}')
    if str(approval.get('revision_sha256') or '').lower() != revision_sha256.lower():
        problems.append(f'{APPROVAL_INVALID}: revision_sha256={approval.get("revision_sha256")!r}, '
                        f'the candidate is {revision_sha256}')
    if str(approval.get('window_set_sha256') or '') != window_set_sha256(windows):
        problems.append(f'{WINDOW_NOT_IN_SET}: window_set_sha256 does not name this window set')
    if [w.get('region') for w in approval.get('windows') or []] != [w['region'] for w in windows]:
        problems.append(f'{WINDOW_NOT_IN_SET}: the approval lists '
                        f"{[w.get('region') for w in approval.get('windows') or []]}")
    named = {w.get('region'): w.get('sha256') for w in approval.get('windows') or []}
    for window in windows:
        if named.get(window['region']) != window['sha256']:
            problems.append(f"{MISMATCH}: the approval pins {named.get(window['region'])!r} for "
                            f"{window['region']}, the candidate pins {window['sha256']}")
    if any(field in approval for field in ('release', 'release_id', 'release_sha256')):
        problems.append(f'{SCOPE_MISMATCH}: the approval carries a release field; a binding match '
                        'never consumes a release')
    if str(approval.get('boot_id') or '') != boot_id:
        problems.append(f'{APPROVAL_INVALID}: boot_id={approval.get("boot_id")!r}, expected '
                        f'{boot_id}')
    if str(approval.get('verification_run_id') or '') != verification_run_id:
        problems.append(f'{APPROVAL_INVALID}: verification_run_id mismatch')
    if str(approval.get('evidence_sha256') or '') != evidence_sha256:
        problems.append(f'{APPROVAL_INVALID}: evidence_sha256 mismatch')
    if not isinstance(approval.get('payload'), dict) or any(
            (approval['payload'].get(key) or '') != (payload.get(key) or '')
            for key in ('bin_sha256', 'elf_sha256', 'build_manifest_sha256', 'build_id', 'label')):
        problems.append(f'{APPROVAL_INVALID}: the approval is not bound to this payload '
                        f'({approval.get("payload")!r})')
    return problems


def approval_sha256(approval: dict) -> str:
    """The immutable identifier of a binding-match approval (JCS bytes, nothing excluded)."""
    return hashlib.sha256(canonical_bytes(approval)).hexdigest()


# ---------------------------------------------------------------------------------------------
# the one-shot ledger
# ---------------------------------------------------------------------------------------------

def new_ledger(*, revision_sha256: str, window_set: str) -> dict:
    return {'schema': LEDGER_SCHEMA, 'revision_sha256': revision_sha256,
            'window_set_sha256': window_set, 'consumed': [], 'reads': [],
            'verdict': 'INCOMPLETE'}


def ledger_problems(ledger: dict, *, revision_sha256: str, window_set: str) -> list[str]:
    problems: list[str] = []
    if not isinstance(ledger, dict) or ledger.get('schema') != LEDGER_SCHEMA:
        return [f'{APPROVAL_INVALID}: not a binding-match ledger']
    if str(ledger.get('revision_sha256') or '').lower() != revision_sha256.lower():
        problems.append(f'{SCOPE_MISMATCH}: the ledger belongs to revision '
                        f'{ledger.get("revision_sha256")!r}, this wave matches {revision_sha256}')
    if str(ledger.get('window_set_sha256') or '') != window_set:
        problems.append(f'{WINDOW_NOT_IN_SET}: the ledger was opened for another window set')
    return problems


def consume(ledger: dict, window: dict, *, observed_sha256: str | None = None) -> list[str]:
    """Spend one window. An already spent window is refused; nothing is repaired or defaulted."""
    region = window.get('region')
    if region in (ledger.get('consumed') or []):
        return [f'{ALREADY_READ}: {region} was already read in this lifetime']
    ledger.setdefault('consumed', []).append(region)
    ledger.setdefault('reads', []).append({'region': region, 'sha256': observed_sha256})
    return []


def ledger_verdict(ledger: dict, *, windows: list[dict]) -> dict:
    done = [w for w in windows if w['region'] in (ledger.get('consumed') or [])]
    verdict = 'COMPLETE' if len(done) == len(windows) else 'INCOMPLETE'
    ledger['verdict'] = verdict
    return {'verdict': verdict, 'read': len(done), 'windows': len(windows),
            'missing': [w['region'] for w in windows if w['region'] not in
                        (ledger.get('consumed') or [])]}


def load_ledger(path: str | pathlib.Path) -> dict:
    return json.loads(pathlib.Path(path).read_text())


def save_ledger(path: str | pathlib.Path, ledger: dict) -> str:
    target = pathlib.Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(ledger, indent=1, sort_keys=True) + '\n')
    return canonical_sha256(ledger)


# ---------------------------------------------------------------------------------------------
# the match
# ---------------------------------------------------------------------------------------------

def match_window(window: dict, event: dict | None, *, profile: dict | None = None) -> dict:
    """Byte-match one window against one captured event, through the bounded-event verifier.

    The verifier owns the event contract (index, identity, bounds, the re-derivation of kbase and
    addresses) and the byte comparison; this function only reduces its report to the one claim the
    binding match is allowed to make. A read of another region, a partial read or a same-length
    read with different bytes all end as ``match: False`` with the verifier's own problems.
    """
    report = KL.verify_bounded_event(event, profile=profile, expected=window)
    checks = {check.get('name'): check.get('ok') for check in report.get('checks') or []}
    problems = list(report.get('problems') or [])
    if report.get('region') != window.get('region'):
        problems.append(f"{WINDOW_NOT_IN_SET}: the event served {report.get('region')!r}, the "
                        f"window is {window.get('region')!r}")
    observed = report.get('bytes_hex')
    same_bytes = (isinstance(observed, str) and isinstance(window.get('bytes_hex'), str)
                  and observed.lower() == window['bytes_hex'].lower())
    match = bool(report.get('verified') and same_bytes
                 and report.get('output_sha256') == window.get('sha256'))
    if report.get('region') == window.get('region') and isinstance(observed, str) and not same_bytes:
        problems.append(f"{MISMATCH}: {window.get('region')} returned "
                        f"{report.get('output_sha256')!r}, the pinned bytes hash to "
                        f"{window.get('sha256')!r}")
    return {'region': window.get('region'), 'region_index': window.get('region_index'),
            'match': match, 'verified_event': bool(report.get('verified')),
            'observed_sha256': report.get('output_sha256'),
            'expected_sha256': window.get('sha256'), 'observed_bytes_hex': observed,
            'provider_entries': None, 'checks_failed': report.get('checks_failed') or [],
            'problems': problems, 'report': report}


def match_report(windows: list[dict], matches: list[dict]) -> dict:
    """The wave's verdict: complete only when every window of the set has a match."""
    by_region = {m.get('region'): m for m in matches}
    rows = [by_region.get(w['region']) or {'region': w['region'], 'match': False,
                                           'problems': [f'{SET_INCOMPLETE}: no read']}
            for w in windows]
    matched = [row for row in rows if row.get('match')]
    return {'windows': len(windows), 'read': len([r for r in rows if r.get('problems') !=
                                                  [f'{SET_INCOMPLETE}: no read']]),
            'matched': len(matched), 'complete': len(matched) == len(windows),
            'rows': rows,
            'problems': [problem for row in rows for problem in (row.get('problems') or [])]}


# ---------------------------------------------------------------------------------------------
# self test (offline; every claim re-derived from the repository)
# ---------------------------------------------------------------------------------------------

def self_test() -> list[str]:
    problems: list[str] = []
    windows = binding_windows()
    if len(windows) != 5:
        problems.append(f'expected the five STRICT CCP windows, got {len(windows)}')
    for window in windows:
        region = R.get_region(window['region'])
        if window['region_index'] != R.compiled_region_index(window['region']):
            problems.append(f"{window['region']}: index is not the compiled one")
        if region is None or window['length'] != region.length:
            problems.append(f"{window['region']}: length disagrees with the registry")
        if window['sha256'] != hashlib.sha256(bytes.fromhex(window['bytes_hex'])).hexdigest():
            problems.append(f"{window['region']}: sha256 is not the hash of its bytes")
    synthetic = KL.synthetic_bounded_event(
        region=windows[0]['region'], offset=windows[0]['offset'], length=windows[0]['length'],
        bytes_hex=windows[0]['bytes_hex'])
    if not match_window(windows[0], synthetic)['match']:
        problems.append('a synthetic event carrying the pinned bytes did not match')
    tampered = KL.synthetic_bounded_event(
        region=windows[0]['region'], offset=windows[0]['offset'], length=windows[0]['length'],
        bytes_hex='00' * windows[0]['length'])
    if match_window(windows[0], tampered)['match']:
        problems.append('a tampered event matched')
    if match_window(windows[0], None)['match']:
        problems.append('a missing event matched')
    ledger = new_ledger(revision_sha256='0' * 64, window_set=window_set_sha256(windows))
    if consume(ledger, windows[0]):
        problems.append('the first read of a window was refused')
    if not consume(ledger, windows[0]):
        problems.append('a second read of the same window was not refused')
    sets = {window_set_sha256([{**windows[0], 'bytes_hex': '00' * windows[0]['length']}
                               if w is windows[0] else w for w in windows])}
    if window_set_sha256(windows) in sets:
        problems.append('the window set hash ignored a changed window')
    return problems


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--windows', action='store_true')
    args = parser.parse_args(argv)
    if args.windows:
        windows = binding_windows()
        print(json.dumps({'window_set_sha256': window_set_sha256(windows), 'windows': windows},
                         indent=1, sort_keys=True))
        return 0
    problems = self_test()
    print(json.dumps({'self_test': 'PASS' if not problems else 'FAIL', 'problems': problems,
                      'windows': len(binding_window_names()),
                      'window_set_sha256': window_set_sha256(binding_windows())},
                     indent=1, sort_keys=True))
    return 1 if problems else 0


if __name__ == '__main__':
    raise SystemExit(main())
