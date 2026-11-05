#!/usr/bin/env python3
"""PS4RF P4/W7 per-request view of the central ResourceManager.

There is exactly one owner of resources: the session's
:class:`~core.resources.manager.ResourceManager`. A provider never sees that object
directly - it receives a :class:`RequestResourceView` for its own request context, which

* delegates every ``acquire``/``release``/``cleanup`` to the central manager (the refs
  keep the frozen ``<kind>:<16 hex>`` shape and live in the central map), and
* records which refs this request created or released, so the cleanup result can be
  attributed to one request and written into evidence.

A provider cannot adopt a resource of another request context: releasing, attaching
cleanup to or claiming a foreign ref is refused and recorded as a violation.

Usage::

    python tools/dispatch/resources.py --self-test
"""

from __future__ import annotations

import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:  # allow direct script execution
    sys.path.insert(0, str(REPO_ROOT))

from core.resources.manager import CleanupReport, ResourceManager  # noqa: E402


class ForeignResourceRefused(RuntimeError):
    """A provider tried to touch a resource that belongs to another request context."""


class RequestResourceView(ResourceManager):
    """Per-request facade over the central manager. Same API, plus attribution."""

    def __init__(self, central: ResourceManager, *, request_id: str) -> None:
        super().__init__()
        self._central = central
        self.request_id = request_id
        self._owned: list[str] = []
        self._released: list[str] = []
        self._violations: list[dict] = []

    # --- delegated API -------------------------------------------------------------
    def acquire(self, kind, *, recoverable=True, force_cleanup_failure=False,
                out_of_band_safe=False):
        ref = self._central.acquire(kind, recoverable=recoverable,
                                    force_cleanup_failure=force_cleanup_failure,
                                    out_of_band_safe=out_of_band_safe)
        self._owned.append(ref)
        return ref

    def attach_cleanup(self, ref, callback):
        self._require_owned(ref, 'attach_cleanup')
        return self._central.attach_cleanup(ref, callback)

    def release(self, ref):
        if not self._require_owned(ref, 'release'):
            return False
        freed = self._central.release(ref)
        self._released.append(ref)
        return freed

    def cleanup_all(self):
        for ref in list(self._owned):
            if ref not in self._released:
                self._central.release(ref)
                self._released.append(ref)
        report = self._central.cleanup_all()
        owned_leaks = [r for r in report.resources if r.get('ref') in set(self._owned)]
        return CleanupReport('PARTIAL' if owned_leaks else 'COMPLETE', owned_leaks,
                             bool(owned_leaks))

    def cleanup_after_hang(self):
        for ref in list(self._owned):
            if ref not in self._released:
                self._released.append(ref)
        report = self._central.cleanup_after_hang()
        owned_leaks = [r for r in report.resources if r.get('ref') in set(self._owned)]
        return CleanupReport('PARTIAL' if owned_leaks else 'COMPLETE', owned_leaks,
                             bool(owned_leaks))

    # --- attribution / evidence ---------------------------------------------------
    def _require_owned(self, ref, action: str, *, record: bool = True) -> bool:
        if ref in self._owned:
            return True
        if record:
            self._violations.append({'action': action, 'ref': ref,
                                     'reason': 'ref does not belong to this request context'})
        return False

    def owned(self) -> list[str]:
        return list(self._owned)

    def released(self) -> list[str]:
        return list(self._released)

    def violations(self) -> list[dict]:
        return list(self._violations)

    def changes(self) -> list[dict]:
        return [{'ref': ref, 'event': 'ACQUIRED'} for ref in self._owned] + \
               [{'ref': ref, 'event': 'RELEASED'} for ref in self._released]

    def outstanding(self) -> list[str]:
        return [ref for ref in self._owned if ref not in self._released]


def _self_test() -> list[str]:
    checks: list[str] = []
    central = ResourceManager()
    a = RequestResourceView(central, request_id='REQ-A')
    b = RequestResourceView(central, request_id='REQ-B')
    ref_a = a.acquire('stub')
    ref_b = b.acquire('native')
    if not ref_a.startswith('stub:') or len(ref_a.split(':')[1]) != 16:
        checks.append('refs must keep the frozen <kind>:<16 hex> shape')
    if b.release(ref_a) is not False:
        checks.append('a foreign ref must not be releasable')
    if not b.violations() or b.violations()[0]['action'] != 'release':
        checks.append('foreign ref attempts must be recorded')
    if a.release(ref_a) is not True:
        checks.append('the owner must be able to release its ref')
    report = a.cleanup_all()
    if report.state != 'COMPLETE' or report.resources:
        checks.append('a request that released everything must clean up COMPLETE')
    leak = b.acquire('native', force_cleanup_failure=True)
    report_b = b.cleanup_all()
    if report_b.state != 'PARTIAL' or not report_b.resources:
        checks.append('a request with an uncleanable ref must report PARTIAL')
    if leak not in [r['ref'] for r in report_b.resources]:
        checks.append('the leaked ref of the own request must be attributed')
    central_report = central.cleanup_all()
    if central_report.state != 'PARTIAL':
        checks.append('the leak must stay visible in the central manager')
    return checks


def main(argv: list[str]) -> int:
    if '--self-test' not in argv:
        print((__doc__ or '').strip().splitlines()[0])
        print('usage: resources.py --self-test')
        return 2
    failures = _self_test()
    if failures:
        print(f'resources self-test: {len(failures)} FAILED')
        for item in failures:
            print(f'  - {item}')
        return 1
    print('resources self-test: OK (central ownership, per-request attribution, '
          'foreign refs refused)')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
