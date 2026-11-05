#!/usr/bin/env python3
"""Generate (and gate) the W12 compile-time ``kernel.read`` region table.

Usage:
    python3 native/target/gen_kread_regions.py --write     # (re)generate ps4rf_kread_regions.h
    python3 native/target/gen_kread_regions.py --check     # verify the checked-in file (gate)
    python3 native/target/gen_kread_regions.py --self-test # no registry needed

The registry is ``tools/profiles/regions.py`` (the canonical W12 registry) and implements the
frozen interface::

    Region(name, rva, length, identity_status, sources, notes)     # rva/length may be None
    IDENTITY_STRICT = 'STRICT_FINGERPRINT'
    IDENTITY_STRUCTURAL_ONLY = 'STRUCTURAL_ONLY'
    IDENTITY_UNRESOLVED = 'UNRESOLVED'
    MAX_READ_LEN = <the one read bound; the registry is its only owner>
    regions() -> dict[str, Region]

Until that file is on disk, the generator falls back to the committed PROVISIONAL bootstrap
``native/target/ps4rf_kread_regions_bootstrap.py`` (same interface, already-proven FW13.52
windows only) and marks the generated header PROVISIONAL. The manifest gate runs this script
in --check mode: a header that still comes from the bootstrap once the canonical registry
exists, or that drifted from a fresh generation, is a build failure.

The generator refuses (exit non-zero), for the canonical registry and the bootstrap alike:

* an empty registry, or a registry with no readable (resolved) region,
* a duplicate region name or a Region.name that disagrees with its dict key,
* a duplicate rva/length pair (two byte windows the same -> two identity notions),
* length 0, rva/length outside 32 bit, rva + length beyond 32 bit (the provider composes the
  address with 32 bit checks),
* a name that does not fit PS4RF_KREAD_REGION_NAME_MAX (24 with terminator),
* the registry does not expose a positive integer MAX_READ_LEN, or its own registry_problems()
  report a problem (the registry is the single owner of the read bound and of region policy, so
  the generator carries its value into the header instead of defining one of its own).

UNRESOLVED entries never reach the payload table. The registry keeps them as documentation
(they carry no usable rva/length and ``resolve_read`` refuses them host side with
``KREAD_UNRESOLVED_REGION``); the generator excludes them from the table, records their names
in the header as *refused by design*, and hard-refuses an UNRESOLVED entry that carries usable
numbers (an inconsistent registry state).

The output is deterministic: no timestamps, the registry's insertion order defines the region
indices, and every number is printed exactly as the C constant that carries it.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.util
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
OUT = HERE / 'ps4rf_kread_regions.h'
CANONICAL = REPO_ROOT / 'tools' / 'profiles' / 'regions.py'
BOOTSTRAP = HERE / 'ps4rf_kread_regions_bootstrap.py'
MODULE_HEADER = HERE / 'ps4rf_kread.h'

NAME_MAX = 24
IDENTITIES = {'STRICT_FINGERPRINT', 'STRUCTURAL_ONLY', 'UNRESOLVED'}


def sha256_file(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_registry(path: pathlib.Path):
    """Load a registry module and return (module, registry_dict, source_label)."""
    label = str(path.relative_to(REPO_ROOT)) if path.is_relative_to(REPO_ROOT) else str(path)
    if path == CANONICAL:
        sys.path.insert(0, str(REPO_ROOT))
        try:
            module = importlib.import_module('tools.profiles.regions')
        except Exception as exc:                                # pragma: no cover - registry bug
            raise SystemExit(f'cannot import the canonical registry {label}: {exc}')
    else:
        spec = importlib.util.spec_from_file_location('ps4rf_kread_regions_bootstrap', path)
        if spec is None or spec.loader is None:
            raise SystemExit(f'cannot load registry {path}')
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module      # dataclasses() resolves the module by name
        spec.loader.exec_module(module)
    regions_fn = getattr(module, 'regions', None)
    if regions_fn is None:
        raise SystemExit(f'registry {label} does not implement regions()')
    registry = regions_fn()
    if not isinstance(registry, dict):
        raise SystemExit(f'registry {label}: regions() must return dict[str, Region]')
    return module, registry, label


def compile_registry(registry: dict, module, source_label: str) -> tuple[dict, list, list]:
    """Split the registry into (compiled table entries, refused-by-design names, problems).

    Every refusal rule lives here; a comment is not a check.
    """
    problems: list[str] = []
    compiled: dict = {}
    refused: list[str] = []
    if len(registry) == 0:
        problems.append(f'{source_label}: empty registry: a bounded kernel.read table with no '
                        'regions cannot serve the W12 allowlist (§3)')
    # The registry owns the read bound; this generator only carries it into the header. Its own
    # registry_problems() report is the authority on that bound and on region policy.
    module_max = getattr(module, 'MAX_READ_LEN', None)
    if not isinstance(module_max, int) or isinstance(module_max, bool) or module_max < 1:
        problems.append(f'{source_label}: MAX_READ_LEN is {module_max!r}; the registry must '
                        'expose a positive integer read bound (it is the single owner)')
    owner_problems = getattr(module, 'registry_problems', None)
    if callable(owner_problems):
        for problem in owner_problems() or ():
            problems.append(f'{source_label} (registry owner check): {problem}')
    seen_pairs: dict[tuple[int, int], str] = {}
    for key, region in registry.items():
        name = getattr(region, 'name', None)
        rva = getattr(region, 'rva', None)
        length = getattr(region, 'length', None)
        identity = getattr(region, 'identity_status', None)
        if not isinstance(name, str) or name != key:
            problems.append(f'{source_label}: region key {key!r} does not match Region.name '
                            f'{name!r}')
            continue
        if not re.fullmatch(r'[A-Za-z0-9_]+', name):
            problems.append(f'{source_label}: region {name!r}: name must be [A-Za-z0-9_]+')
        if len(name) + 1 > NAME_MAX:
            problems.append(f'{source_label}: region {name!r}: name does not fit '
                            f'PS4RF_KREAD_REGION_NAME_MAX ({NAME_MAX} with terminator)')
        if identity not in IDENTITIES:
            problems.append(f'{source_label}: region {name!r}: identity_status {identity!r} is '
                            'not one of ' + ', '.join(sorted(IDENTITIES)))
            continue
        if identity == 'UNRESOLVED':
            # An unproven region can never be compiled into the payload. The registry's own
            # invariant lets it carry no usable numbers; if it does, that state is refused.
            if rva is not None or length is not None:
                problems.append(f'{source_label}: region {name!r} is UNRESOLVED but carries '
                                f'rva={rva!r}/length={length!r}; an unproven region must not '
                                'carry usable numbers and is never compiled in')
            else:
                refused.append(name)
            continue
        if not isinstance(rva, int) or isinstance(rva, bool) or not 0 <= rva <= 0xFFFFFFFF:
            problems.append(f'{source_label}: region {name!r}: rva {rva!r} outside 32 bit')
            continue
        if not isinstance(length, int) or isinstance(length, bool) or length < 1:
            problems.append(f'{source_label}: region {name!r}: length {length!r} is not >= 1')
            continue
        if rva + length > 0xFFFFFFFF:
            problems.append(f'{source_label}: region {name!r}: rva + length exceeds 32 bit '
                            '(the provider composes the address with 32 bit checks)')
        pair = (rva, length)
        if pair in seen_pairs:
            problems.append(f'{source_label}: duplicate rva/length pair {rva:#x}/{length} '
                            f'shared by {seen_pairs[pair]!r} and {name!r}')
        seen_pairs[pair] = name
        if not getattr(region, 'sources', None):
            problems.append(f'{source_label}: region {name!r}: no evidence sources recorded')
        compiled[name] = region
    if not compiled:
        problems.append(f'{source_label}: no readable region after the UNRESOLVED refusal; '
                        'a registry without a single readable region cannot serve (§3)')
    return compiled, refused, problems


def _c_ident(name: str) -> str:
    return name.upper().replace('-', '_')


def binding_window_indices(compiled: dict, names: list, module) -> list:
    """The compiled indices of the revision candidate's STRICT binding windows, in table order.

    Selected by provenance, never by a hand-written list: a row that is not a STRICT window of
    the candidate simply is not in the set, and ``keymgr_pool`` -- STRUCTURAL_ONLY, runtime slot
    state -- can never enter it (a structural observation is not a byte fingerprint). The module
    addresses the windows through the generated neutral names because the subsystem scan in
    ``build_manifest.gate_kread`` reads ``ps4rf_kread.c`` for the row names themselves.
    """
    provenance = getattr(module, 'CCP_PROVENANCE', ()) or ()
    candidate = provenance[0] if provenance else ''
    if not candidate:
        return []
    return [index for index, name in enumerate(names)
            if compiled[name].identity_status == 'STRICT_FINGERPRINT'
            and candidate in tuple(getattr(compiled[name], 'sources', ()) or ())]


def observation_window_indices(compiled: dict, names: list, module) -> list:
    """The compiled indices of the Track A observation windows, in table order.

    Selected by provenance, never by a hand-written list in the module: a row of the observation
    set carries ``A_OBS_PROVENANCE[0]``, or it is a STRUCTURAL_ONLY row of the W16 revision
    candidate (that is the keymgr slot pool -- runtime state, an observation by agreement). The
    registry's own ``registry_problems()`` refuses an observation row that is not STRUCTURAL_ONLY,
    so the payload's observation step can only ever see runtime-state windows; an identity row
    cannot enter it.
    """
    candidate = (getattr(module, 'CCP_PROVENANCE', ()) or ('',))[0]
    observation = (getattr(module, 'A_OBS_PROVENANCE', ()) or ('',))[0]
    if not observation:
        return []
    selected: list[int] = []
    for index, name in enumerate(names):
        region = compiled[name]
        sources = tuple(getattr(region, 'sources', ()) or ())
        if observation in sources:
            selected.append(index)
            continue
        if candidate and candidate in sources \
                and getattr(region, 'identity_status', None) == 'STRUCTURAL_ONLY':
            selected.append(index)
    return selected


def render(compiled: dict, refused: list, module, source_label: str, source_sha: str,
           provisional: bool) -> str:
    names = list(compiled.keys())
    bound = getattr(module, 'MAX_READ_LEN', None)     # the registry owns it; we only carry it
    lines: list[str] = []
    lines.append('/* Generated by gen_kread_regions.py -- do not edit by hand.')
    lines.append(' *')
    lines.append(' * W12 compile-time bounded kernel.read region table.')
    lines.append(' *')
    lines.append(f' * registry:        {source_label}')
    lines.append(f' * registry sha256: {source_sha}')
    lines.append(f' * regions:         {len(names)}')
    lines.append(f' * refused-by-design UNRESOLVED entries: {len(refused)}')
    lines.append(f' * max read length: PS4RF_KREAD_MAX_LEN = {bound} (owned by '
                 f'{source_label}:MAX_READ_LEN; the payload compiles this define)')
    lines.append(' * identity:        0 = STRICT_FINGERPRINT, 1 = STRUCTURAL_ONLY')
    lines.append(' *')
    lines.append(' * The request model carries no address: the provider composes')
    lines.append(' * kbase + region_rva + offset inside its single privileged callback, bounded')
    lines.append(' * by the max read length, the 32 bit checked add and the region containment')
    lines.append(' * rule. UNRESOLVED entries and duplicate rva/length pairs are refused by the')
    lines.append(' * generator and can never be compiled in.')
    if refused:
        lines.append(' *')
        lines.append(' * UNRESOLVED entries refused by the generator (registered, never'
                     ' readable):')
        for name in refused:
            lines.append(f' *   - {name}')
    if provisional:
        lines.append(' *')
        lines.append(' * PROVISIONAL: generated from native/target/ps4rf_kread_regions_bootstrap.py')
        lines.append(' * because tools/profiles/regions.py was not on disk yet. REGENERATE with')
        lines.append(' * "native/target/gen_kread_regions.py --write" as soon as the canonical')
        lines.append(' * registry lands; the manifest gate fails a PROVISIONAL header once the')
        lines.append(' * canonical registry exists.')
    lines.append(' */')
    lines.append('')
    lines.append('#ifndef PS4RF_KREAD_REGIONS_H')
    lines.append('#define PS4RF_KREAD_REGIONS_H')
    lines.append('')
    lines.append('#include <stdint.h>')
    lines.append('')
    lines.append(f'#define PS4RF_KREAD_MAX_LEN {bound}u')
    lines.append('#define PS4RF_KREAD_REGION_COUNT ' + f'{len(names)}u')
    lines.append(f'#define PS4RF_KREAD_REGION_REFUSED_UNRESOLVED {len(refused)}u')
    lines.append(f'#define PS4RF_KREAD_REGION_NAME_MAX {NAME_MAX}u')
    lines.append('')
    lines.append('#define PS4RF_KREAD_IDENTITY_STRICT_FINGERPRINT 0u')
    lines.append('#define PS4RF_KREAD_IDENTITY_STRUCTURAL_ONLY 1u')
    lines.append('')
    lines.append('typedef struct {')
    lines.append('  uint32_t index;')
    lines.append('  char name[PS4RF_KREAD_REGION_NAME_MAX];')
    lines.append('  uint32_t rva;')
    lines.append('  uint32_t length;')
    lines.append('  uint32_t identity_status;')
    lines.append('} ps4rf_kread_region;')
    lines.append('')
    lines.append('static const ps4rf_kread_region')
    lines.append('    PS4RF_KREAD_REGIONS[PS4RF_KREAD_REGION_COUNT] = {')
    for index, name in enumerate(names):
        region = compiled[name]
        identity = {'STRICT_FINGERPRINT': 'PS4RF_KREAD_IDENTITY_STRICT_FINGERPRINT',
                    'STRUCTURAL_ONLY': 'PS4RF_KREAD_IDENTITY_STRUCTURAL_ONLY'}[
                        region.identity_status]
        lines.append(f'  /* {index}: {name} -- {region.identity_status}; '
                     f'rva 0x{region.rva:X}, length {region.length} */')
        lines.append(f'  {{ {index}u, "{name}", 0x{region.rva:X}u, {region.length}u, {identity} }},')
        for source in region.sources:
            lines.append(f'  /*   source: {source} */')
        if getattr(region, 'notes', ''):
            lines.append(f'  /*   note:   {region.notes} */')
    lines.append('};')
    lines.append('')
    for index, name in enumerate(names):
        lines.append(f'#define PS4RF_KREAD_REGION_IDX_{_c_ident(name)} {index}u')
    binding = binding_window_indices(compiled, names, module)
    if binding:
        lines.append('')
        lines.append('/* W16 binding windows: the STRICT rows of the revision candidate, as indices')
        lines.append(' * only, so the module never spells a row name itself (the subsystem scan in')
        lines.append(' * build_manifest.gate_kread reads ps4rf_kread.c for those names). */')
        lines.append(f'#define PS4RF_KREAD_BINDING_WINDOW_COUNT {len(binding)}u')
        for slot, index in enumerate(binding):
            lines.append(f'#define PS4RF_KREAD_BINDING_WINDOW_{slot} {index}u')
    observation = observation_window_indices(compiled, names, module)
    if observation:
        obs_max = max(compiled[name].length for name in
                      (names[index] for index in observation))
        lines.append('')
        lines.append('/* Track A observation windows: the STRUCTURAL_ONLY rows of the observation')
        lines.append(' * set (runtime state -- occupancy, tags, gates -- never an identity source),')
        lines.append(' * as indices only. The payload\'s observation step reads exactly ONE of')
        lines.append(' * them per session, on its own lifetime cursor, and the host records the')
        lines.append(' * bytes as an observation; no byte of them is ever matched as an identity.')
        lines.append(f' * Largest window: {obs_max} bytes (PS4RF_KREAD_OBS_MAX_LEN). */')
        lines.append(f'#define PS4RF_KREAD_OBS_WINDOW_COUNT {len(observation)}u')
        for slot, index in enumerate(observation):
            lines.append(f'#define PS4RF_KREAD_OBS_WINDOW_{slot} {index}u')
        lines.append(f'#define PS4RF_KREAD_OBS_MAX_LEN {obs_max}u')
    lines.append('')
    lines.append('#endif /* PS4RF_KREAD_REGIONS_H */')
    return '\n'.join(lines) + '\n'


def resolve_source(explicit: str | None = None) -> tuple[pathlib.Path, bool]:
    """(registry path, provisional). The canonical registry wins the moment it exists."""
    if explicit:
        path = pathlib.Path(explicit).resolve()
        return path, path != CANONICAL
    if CANONICAL.exists():
        return CANONICAL, False
    return BOOTSTRAP, True


def generate(out: pathlib.Path | None = None, registry: str | None = None) -> tuple[str, pathlib.Path, bool, list]:
    path, provisional = resolve_source(registry)
    module, registry_map, label = load_registry(path)
    compiled, refused, problems = compile_registry(registry_map, module, label)
    if problems:
        for problem in problems:
            print(f'REGISTRY REFUSED: {problem}', file=sys.stderr)
        raise SystemExit(1)
    return render(compiled, refused, module, label, sha256_file(path), provisional), \
        path, provisional, refused


def self_test() -> int:
    """Refusal rules, hermetically (no registry file needed)."""
    class Fake:
        def __init__(self, name, rva, length, identity, sources=('selftest',), notes=''):
            self.name, self.rva, self.length = name, rva, length
            self.identity_status, self.sources, self.notes = identity, sources, notes

    class FakeModule:
        MAX_READ_LEN = 4096          # the *registry's* value: the generator only carries it

    good = {'image_elf': Fake('image_elf', 0x0, 16, 'STRICT_FINGERPRINT'),
            'aperture_global': Fake('aperture_global', 0x23D3DF8, 8, 'STRUCTURAL_ONLY')}
    cases = [
        ('good', good, 0, 0),
        ('empty', {}, 1, 0),
        ('well-formed UNRESOLVED is refused from the table, not an error',
         {**good, 'mystery': Fake('mystery', None, None, 'UNRESOLVED')}, 0, 1),
        ('numbered UNRESOLVED is a hard error',
         {**good, 'mystery': Fake('mystery', 0x1000, 8, 'UNRESOLVED')}, 1, 0),
        ('only UNRESOLVED -> nothing readable',
         {'mystery': Fake('mystery', None, None, 'UNRESOLVED')}, 1, 1),
        ('bad identity', {**good, 'x': Fake('x', 0x1000, 8, 'PROBABLY')}, 1, 0),
        ('duplicate rva/len', {**good, 'clone': Fake('clone', 0x0, 16, 'STRICT_FINGERPRINT')},
         1, 0),
        ('duplicate name/key mismatch',
         {'image_elf': Fake('other', 0x1000, 8, 'STRICT_FINGERPRINT')}, 1, 0),
        ('zero length', {**good, 'z': Fake('z', 0x1000, 0, 'STRICT_FINGERPRINT')}, 1, 0),
        ('rva+len overflow', {**good, 'w': Fake('w', 0xFFFFFFF0, 0x20, 'STRICT_FINGERPRINT')},
         1, 0),
        ('name too long', {**good, 'n' * 30: Fake('n' * 30, 0x1000, 8, 'STRICT_FINGERPRINT')},
         1, 0),
        ('no sources', {**good, 's': Fake('s', 0x1000, 8, 'STRICT_FINGERPRINT', sources=())},
         1, 0),
        ('registry without a usable bound', good, 1, 0,
         type('M', (), {'MAX_READ_LEN': None})()),
        ('registry owner check fails', good, 1, 0,
         type('M', (), {'MAX_READ_LEN': 4096,
                        'registry_problems': staticmethod(lambda: ['MAX_READ_LEN must stay 4096'])})()),
    ]
    failures = 0
    for case in cases:
        name, registry, want_problems, want_refused = case[0], case[1], case[2], case[3]
        module = case[4] if len(case) > 4 else FakeModule()
        compiled, refused, problems = compile_registry(registry, module, 'selftest')
        ok = ((len(problems) == 0) == (want_problems == 0)) and len(refused) == want_refused
        if not ok:
            failures += 1
            print(f'SELF-TEST FAIL: {name}: problems={problems} refused={refused} '
                  f'expected {want_problems} problem(s), {want_refused} refused')
    print(f'self-test: {len(cases)} cases, {failures} problem(s)')
    return 1 if failures else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--write', action='store_true')
    ap.add_argument('--check', action='store_true')
    ap.add_argument('--self-test', action='store_true')
    ap.add_argument('--out', default=None,
                    help='header to write/check (default native/target/ps4rf_kread_regions.h); '
                         'the manifest gate always uses the default')
    ap.add_argument('--registry', default=None,
                    help='registry module to read (default: the canonical tools/profiles/'
                         'regions.py, or the PROVISIONAL bootstrap while it is absent)')
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()
    out = pathlib.Path(args.out).resolve() if args.out else OUT
    text, path, provisional, refused = generate(out, args.registry)
    suffix = f'{" (PROVISIONAL)" if provisional else ""}' + \
        (f', {len(refused)} UNRESOLVED refused' if refused else '')
    shown = out.relative_to(REPO_ROOT) if out.is_relative_to(REPO_ROOT) else out
    if args.write:
        out.write_text(text)
        print(f'wrote {shown} ({len(text)} bytes) from {path}{suffix}')
        return 0
    if args.check:
        if not out.exists():
            print(f'{shown} is missing: run gen_kread_regions.py --write', file=sys.stderr)
            return 1
        current = out.read_text()
        if current != text:
            print(f'{shown} does NOT match a fresh generation of the registry (drift): '
                  'regenerate with gen_kread_regions.py --write', file=sys.stderr)
            return 1
        print(f'{shown}: up to date with {path}{suffix}')
        return 0
    print(text[:2000])
    return 0


if __name__ == '__main__':
    sys.exit(main())
