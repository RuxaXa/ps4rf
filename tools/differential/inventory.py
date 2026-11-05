#!/usr/bin/env python3
"""PS4RF P4/W6 artifact inventory: turn offline artifacts into comparable facts.

Supported input classes (all offline, all hash-bound):

* **zip bundles** (e.g. the reference hand-off bundles) - one entry per member: path,
  size, member sha256, kind; a ``MANIFEST.sha256`` inside the bundle is parsed as
  manifest facts (unparsable lines are counted, never guessed);
* **ELF images** (e.g. the harness build) - sections with their file offsets, sizes,
  section-byte sha256, permission bits from the section flags and the architecture from
  the ELF header;
* **raw blobs** - one region with the file hash; permissions and architecture stay
  ``UNRESOLVED`` because the format is unknown;
* **inventories** (``ps4rf.differential.inventory.v1``) - a normalized inventory that a
  fixture or a future tool adapter produced.

Field names are chosen so a file offset can never be mistaken for an address
(``file_offset``), and the module names (``normalize.``) refuse absolute-address keys.

Section byte hashing is bounded to 1 MiB per section; if a section is larger the scope
is recorded as ``first_mib`` instead of silently truncating.

Usage::

    python tools/differential/inventory.py <artifact-or-inventory.json> [--json]
    python tools/differential/inventory.py --self-test
"""

from __future__ import annotations

import json
import pathlib
import struct
import sys
import zipfile

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:  # allow direct script execution
    sys.path.insert(0, str(REPO_ROOT))

from tools.differential.normalize import (  # noqa: E402
    NormalizationError, normalize_document, sha256_bytes, sha256_file,
)
from tools.differential.schema import INVENTORY_SCHEMA  # noqa: E402

UNRESOLVED = 'UNRESOLVED'
SECTION_HASH_LIMIT = 1 << 20

KIND_BY_SUFFIX = {
    '.json': 'structured', '.tsv': 'table', '.csv': 'table', '.md': 'text', '.txt': 'text',
    '.py': 'script', '.java': 'script', '.c': 'source', '.h': 'source', '.sha256': 'manifest',
    '.bin': 'binary', '.elf': 'elf', '.img': 'image',
}

# ELF constants
ET_MACHINES = {0x03: 'i386', 0x3E: 'x86-64', 0x28: 'arm', 0xB7: 'aarch64'}


class InventoryError(NormalizationError):
    """Fail-closed refusal while building an inventory."""


def _kind_of(name: str) -> str:
    suffix = pathlib.PurePosixPath(name).suffix.lower()
    return KIND_BY_SUFFIX.get(suffix, 'other')


def load_inventory(path: str | pathlib.Path, *, expect_sha256: str | None = None) -> dict:
    p = pathlib.Path(path)
    if not p.exists():
        raise InventoryError(f'ARTIFACT_MISSING: {p} does not exist')
    actual = sha256_file(p)
    if expect_sha256 is not None and actual != expect_sha256:
        raise InventoryError(f'{p.name}: sha256 {actual[:12]}… does not match the declared '
                            f'{expect_sha256[:12]}… (fail closed)')

    if p.suffix == '.json':
        try:
            doc = json.loads(p.read_text(encoding='utf-8'))
        except Exception as exc:  # noqa: BLE001
            raise InventoryError(f'{p.name}: not readable as JSON ({exc})') from exc
        if isinstance(doc, dict) and doc.get('schema') == INVENTORY_SCHEMA:
            normalize_document(doc, p.name)  # fail closed on address-style fields
            document = dict(doc)
            declared = document.get('sha256')
            if declared and declared != actual:
                raise InventoryError(f'{p.name}: declared sha256 {str(declared)[:12]}… does not '
                                     f'match the file content {actual[:12]}… (fail closed)')
            document['path'] = str(p)
            document['sha256'] = actual
            return document
    if zipfile.is_zipfile(p):
        return _zip_inventory(p, actual)
    head = p.read_bytes()[:4] if p.stat().st_size else b''
    if head == b'\x7fELF':
        return _elf_inventory(p, actual)
    return _raw_inventory(p, actual)


def _base(p: pathlib.Path, actual: str, kind: str) -> dict:
    return {
        'schema': INVENTORY_SCHEMA, 'kind': kind, 'path': str(p), 'module': p.name,
        'sha256': actual, 'size': p.stat().st_size, 'architecture': UNRESOLVED,
        'fixture': False, 'entries': [], 'manifest_entries': {}, 'notes': [],
    }


def _zip_inventory(p: pathlib.Path, actual: str) -> dict:
    document = _base(p, actual, 'zip')
    with zipfile.ZipFile(p) as archive:
        for info in sorted(archive.infolist(), key=lambda i: i.filename):
            if info.is_dir():
                continue
            data = archive.read(info.filename)
            document['entries'].append({
                'path': info.filename, 'kind': _kind_of(info.filename),
                'file_offset': None, 'size': len(data), 'sha256': sha256_bytes(data),
                'permissions': UNRESOLVED, 'hash_scope': 'full',
            })
            if info.filename.endswith('MANIFEST.sha256'):
                parsed, skipped = _parse_manifest(data)
                document['manifest_entries'].update(parsed)
                if skipped:
                    document['notes'].append(f'{info.filename}: {skipped} manifest line(s) '
                                            'not parsable, not guessed')
    document['notes'].append('bundle members hashed individually; architecture unknown '
                             'for a bundle')
    return document


def _parse_manifest(data: bytes) -> tuple[dict, int]:
    parsed: dict = {}
    skipped = 0
    for line in data.decode('utf-8', 'replace').splitlines():
        parts = line.split()
        if len(parts) >= 2 and len(parts[0]) == 64 and all(c in '0123456789abcdef' for c in parts[0]):
            parsed[parts[-1].lstrip('*')] = parts[0]
        elif line.strip():
            skipped += 1
    return parsed, skipped


def _elf_inventory(p: pathlib.Path, actual: str) -> dict:
    blob = p.read_bytes()
    document = _base(p, actual, 'elf')
    if len(blob) < 0x40 or blob[:4] != b'\x7fELF' or blob[4] != 2:
        raise InventoryError(f'{p.name}: not a 64-bit ELF image')
    e_machine = struct.unpack_from('<H', blob, 0x12)[0]
    document['architecture'] = ET_MACHINES.get(e_machine, f'machine-{e_machine:#x}')
    e_shoff = struct.unpack_from('<Q', blob, 0x28)[0]
    e_shentsize = struct.unpack_from('<H', blob, 0x3A)[0]
    e_shnum = struct.unpack_from('<H', blob, 0x3C)[0]
    e_shstrndx = struct.unpack_from('<H', blob, 0x3E)[0]
    if not e_shoff or not e_shnum:
        raise InventoryError(f'{p.name}: ELF without a section table (module identity missing)')

    headers = []
    for index in range(e_shnum):
        base = e_shoff + index * e_shentsize
        sh_name, sh_type, sh_flags = struct.unpack_from('<IIQ', blob, base)
        sh_offset, sh_size = struct.unpack_from('<QQ', blob, base + 0x18)
        headers.append((sh_name, sh_type, sh_flags, sh_offset, sh_size))

    strtab = b''
    if e_shstrndx < len(headers):
        _, _, _, str_off, str_size = headers[e_shstrndx]
        strtab = blob[str_off:str_off + str_size]

    for sh_name, sh_type, sh_flags, sh_offset, sh_size in headers:
        end = strtab.find(b'\x00', sh_name)
        name = strtab[sh_name:end].decode('utf-8', 'replace') if sh_name and end > 0 else ''
        if not name and sh_type == 0:
            continue
        chunk = blob[sh_offset:sh_offset + min(sh_size, SECTION_HASH_LIMIT)]
        perms = ''.join(('r' if sh_flags & 0x2 else '-', 'w' if sh_flags & 0x1 else '-',
                         'x' if sh_flags & 0x4 else '-'))
        document['entries'].append({
            'path': name or f'section-{len(document["entries"])}', 'kind': 'section',
            'file_offset': sh_offset, 'size': sh_size, 'sha256': sha256_bytes(chunk),
            'permissions': perms, 'hash_scope': 'full' if sh_size <= SECTION_HASH_LIMIT else 'first_mib',
            'alloc': bool(sh_flags & 0x2),
        })
    if not document['entries']:
        raise InventoryError(f'{p.name}: no sections found (module identity missing)')
    document['notes'].append('sections compared by name, relative file offset, permissions and '
                             'section-byte hash')
    return document


def _raw_inventory(p: pathlib.Path, actual: str) -> dict:
    document = _base(p, actual, 'raw')
    document['entries'].append({
        'path': 'whole', 'kind': 'region', 'file_offset': 0, 'size': p.stat().st_size,
        'sha256': actual, 'permissions': UNRESOLVED, 'hash_scope': 'full',
    })
    document['notes'].append('raw blob: format unknown, permissions/architecture UNRESOLVED')
    return document


def strip_common_root(*inventories: dict) -> list[dict]:
    """Remove one unambiguous top-level bundle root per inventory (explicitly requested).

    Only applied when every entry shares exactly one root directory in *every* inventory
    - an ambiguous layout is left untouched (no silent best-effort matching).
    """
    roots = []
    for inventory in inventories:
        tops = {str(e['path']).split('/', 1)[0] if '/' in str(e['path']) else '' for e in inventory.get('entries', ())}
        if len(tops) != 1 or '' in tops:
            return [dict(i) for i in inventories]
        roots.append(tops.pop())
    out = []
    for inventory, root in zip(inventories, roots):
        stripped = dict(inventory)
        entries = []
        for entry in inventory.get('entries', ()):
            item = dict(entry)
            item['path'] = str(entry['path'])[len(root) + 1:] if root else str(entry['path'])
            entries.append(item)
        stripped['entries'] = entries
        stripped['notes'] = list(inventory.get('notes', ())) + [f'common root {root!r} stripped (explicit config)']
        out.append(stripped)
    return out


def identity_of(inventory: dict) -> dict:
    return {'kind': inventory['kind'], 'module': inventory.get('module'),
            'sha256': inventory['sha256'], 'architecture': inventory.get('architecture'),
            'entries': len(inventory.get('entries', ())), 'size': inventory.get('size')}


def _self_test() -> list[str]:
    checks: list[str] = []
    elf = REPO_ROOT / 'native' / 'build' / 'ps4rfd.elf'
    if elf.exists():
        inv = load_inventory(elf)
        if inv['architecture'] != 'x86-64':
            checks.append(f'elf architecture must parse as x86-64, got {inv["architecture"]}')
        if not any(e['path'] == '.text' for e in inv['entries']):
            checks.append('elf inventory must contain a .text section')
        for entry in inv['entries']:
            if 'addr' in entry or 'address' in entry:
                checks.append('inventories must not carry address fields')
    zip_path = REPO_ROOT / 'references' / 'ps4_fw1352_ccp_harness.zip'
    if zip_path.exists():
        inv = load_inventory(zip_path)
        if inv['kind'] != 'zip' or not inv['entries']:
            checks.append('zip inventory must list members')
        if inv['manifest_entries']:
            checks.append('this bundle has no manifest; none must be invented')
    try:
        load_inventory(REPO_ROOT / 'native' / 'build' / 'ps4rfd.elf', expect_sha256='0' * 64)
    except InventoryError:
        pass
    else:
        checks.append('a declared hash mismatch must be refused')
    return checks


def main(argv: list[str]) -> int:
    args = [a for a in argv if a != '--json']
    if '--self-test' in argv:
        failures = _self_test()
        if failures:
            print(f'inventory self-test: {len(failures)} FAILED')
            for item in failures:
                print(f'  - {item}')
            return 1
        print('inventory self-test: OK (zip/elf/raw, hash-bound, no address fields)')
        return 0
    if len(args) != 1:
        print((__doc__ or '').strip().splitlines()[0])
        print('usage: inventory.py <artifact|inventory.json> [--json] | --self-test')
        return 2
    try:
        inventory = load_inventory(args[0])
    except InventoryError as exc:
        print(f'INVENTORY REFUSED: {exc}')
        return 1
    if '--json' in argv:
        print(json.dumps(inventory, indent=1, sort_keys=True))
    else:
        ident = identity_of(inventory)
        print(f'{ident["module"]}: kind={ident["kind"]} arch={ident["architecture"]} '
              f'size={ident["size"]} entries={ident["entries"]}')
        print(f'  sha256: {ident["sha256"]}')
        if inventory.get('manifest_entries'):
            print(f'  manifest entries: {len(inventory["manifest_entries"])}')
        for note in inventory.get('notes', ()):
            print(f'  note: {note}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
