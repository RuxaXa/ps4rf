#!/usr/bin/env python3
"""PS4RF P4/W6 normalization: canonical forms, hashes, determinism rules.

Every input enters the differential harness through this module: it is hashed,
canonicalized and checked against the harness rules *before* anything is compared.

Rules (all fail-closed):

* a runtime address may never enter a comparison - absolute-address fields are refused
  outright, locators must be relative (``rva``/``relative``), and file offsets are
  named ``file_offset`` so they can never be mistaken for an address;
* u64 quantities are rendered fixed width (``0x`` + 16 hex digits, lower case);
* ordering is deterministic everywhere (sorted keys, sorted findings);
* canonicalization of documents uses the frozen core canonicalizer
  (``core.canonical.canonical_bytes``: JCS + safe-number policy), so one rule set
  covers profiles, diff reports and wire frames;
* an unknown ``normalization_version`` is refused: no silent best-effort matching.

The ``config_sha256`` of a run covers exactly the switches that can change an outcome
(comparison layers enabled, root-stripping, confidence caps), so two runs with the same
functionally relevant config hash are comparable.

Usage::

    python tools/differential/normalize.py --self-test
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys
from dataclasses import dataclass, field

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:  # allow direct script execution
    sys.path.insert(0, str(REPO_ROOT))

from core.canonical import canonical_bytes, canonical_sha256  # noqa: E402

NORM_VERSION = 'ps4rf.normalize.v1'
KNOWN_NORM_VERSIONS = (NORM_VERSION,)
U64_MAX = 2 ** 64 - 1

# fields that would smuggle a runtime address into a comparison
FORBIDDEN_KEYS = ('runtime_address', 'absolute_address', 'abs_addr', 'slide',
                  'runtime_base', 'load_base', 'base_address')
RELATIVE_LOCATOR_KINDS = ('rva', 'relative')


class NormalizationError(Exception):
    """Fail-closed refusal inside normalization."""


@dataclass(frozen=True)
class RunConfig:
    """The switches that can change a differential outcome."""
    layers: tuple[str, ...] = ('identity', 'profile', 'artifact', 'operation', 'external')
    strip_common_root: bool = False
    confidence_cap: str | None = None

    def as_dict(self) -> dict:
        return {'layers': sorted(self.layers), 'strip_common_root': self.strip_common_root,
                'confidence_cap': self.confidence_cap, 'normalization_version': NORM_VERSION}

    @property
    def sha256(self) -> str:
        return canonical_sha256(self.as_dict())


DEFAULT_CONFIG = RunConfig()


def sha256_file(path: str | pathlib.Path) -> str:
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def u64_hex(value: int) -> str:
    """Fixed-width u64 rendering (no runtime meaning, pure formatting)."""
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= U64_MAX:
        raise NormalizationError(f'{value!r} is not a u64')
    return f'0x{value:016x}'


def check_normalization_version(version: str | None) -> None:
    if version is None:
        return
    if version not in KNOWN_NORM_VERSIONS:
        raise NormalizationError(f'unknown normalization_version {version!r}; '
                                 f'known: {list(KNOWN_NORM_VERSIONS)}')


def find_forbidden_keys(obj, path: str = '') -> list[str]:
    """Every absolute-address-style field anywhere in a document."""
    hits: list[str] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            where = f'{path}.{key}' if path else str(key)
            if key in FORBIDDEN_KEYS:
                hits.append(where)
            hits.extend(find_forbidden_keys(value, where))
    elif isinstance(obj, (list, tuple)):
        for index, value in enumerate(obj):
            hits.extend(find_forbidden_keys(value, f'{path}[{index}]'))
    return hits


def check_relative_locators(doc: dict, where: str) -> None:
    """Locators inside a document must be relative; anything else is refused."""
    for name, loc in (doc.get('locators') or {}).items():
        inner = (loc or {}).get('locator') or {}
        kind = inner.get('kind')
        if kind not in RELATIVE_LOCATOR_KINDS:
            raise NormalizationError(f'{where}: locators.{name}.locator.kind {kind!r} is not '
                                     f'relative ({list(RELATIVE_LOCATOR_KINDS)})')


def normalize_document(doc: dict, where: str) -> dict:
    """Fail-closed input check shared by every layer."""
    if not isinstance(doc, dict):
        raise NormalizationError(f'{where}: expected an object')
    forbidden = find_forbidden_keys(doc)
    if forbidden:
        raise NormalizationError(f'{where}: runtime-address fields are not comparable: {forbidden}')
    return doc


def canonical_dump(obj) -> str:
    """Deterministic JSON text for reports and outputs."""
    return json.dumps(obj, indent=1, sort_keys=True, ensure_ascii=False) + '\n'


def canonical_body_sha256(report: dict, *, exclude: tuple[str, ...] = ()) -> str:
    """Hash of a report body minus the named volatile fields."""
    body = {k: v for k, v in report.items() if k not in exclude}
    return canonical_sha256(body)


@dataclass
class Determinism:
    """Collected evidence that a run is reproducible."""
    normalization_version: str = NORM_VERSION
    config_sha256: str = DEFAULT_CONFIG.sha256
    notes: list[str] = field(default_factory=list)


def _self_test() -> list[str]:
    checks: list[str] = []
    if u64_hex(0x1000) != '0x0000000000001000':
        checks.append('u64 rendering must be fixed width')
    if not find_forbidden_keys({'a': {'runtime_address': 1}}):
        checks.append('forbidden runtime-address keys must be detected')
    if find_forbidden_keys({'locator': {'kind': 'rva', 'value': 4096}}):
        checks.append('a relative locator must not be flagged')
    try:
        check_relative_locators({'locators': {'x': {'locator': {'kind': 'absolute'}}}}, 't')
    except NormalizationError:
        pass
    else:
        checks.append('absolute locator kinds must be refused')
    try:
        check_normalization_version('ps4rf.normalize.v9')
    except NormalizationError:
        pass
    else:
        checks.append('unknown normalization versions must be refused')
    if canonical_body_sha256({'a': 1, 'ts': 'x'}, exclude=('ts',)) != canonical_body_sha256({'a': 1}):
        checks.append('excluded fields must not influence the body hash')
    if canonical_dump({'b': 1, 'a': 2}) != canonical_dump({'a': 2, 'b': 1}):
        checks.append('canonical dumps must be order independent')
    return checks


def main(argv: list[str]) -> int:
    if '--self-test' not in argv:
        print((__doc__ or '').strip().splitlines()[0])
        print('usage: normalize.py --self-test')
        return 2
    failures = _self_test()
    if failures:
        print(f'normalize self-test: {len(failures)} FAILED')
        for item in failures:
            print(f'  - {item}')
        return 1
    print(f'normalize self-test: OK ({NORM_VERSION}, canonical via core.canonical, '
          'runtime addresses refused)')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
