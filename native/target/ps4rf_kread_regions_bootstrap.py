#!/usr/bin/env python3
"""PROVISIONAL bootstrap registry for the W12 ``kernel.read`` region table.

``tools/profiles/regions.py`` (the canonical registry, owned by the tools-side W12 task) is not
on disk yet. Until it lands, ``gen_kread_regions.py`` falls back to *this* file -- and only to
this file -- so the compile-time table, the build gate and the offline harness can be exercised
end to end. Nothing here is invented: every entry is an already-proven FW13.52 read window.

Sources of truth used below (read-only):

* ``profiles/fw1352/profile-13.52.json`` -- the active W5 profile. Its ``locators`` map carries
  the eight byte-exact W9/W10-verified windows (7 STRICT_FINGERPRINT + 1 STRUCTURAL_ONLY) with
  integer RVAs, expected bytes and the pinned kernel image hash
  ``cf157ffdbae872a20bbb9a46c8518b53d96c1ed75d4e73878466a295d92eca35``.
* the W10 boot-identity evidence and the W11.2 live run -- the KERN_BOOTTIME ``timeval`` at RVA
  ``0x224C6C8`` (16 bytes), read live by the accepted W11.2 payload.

When the canonical registry exists, this file is *ignored*: a header generated from it carries a
``PROVISIONAL`` marker, and the manifest gate fails until the header is regenerated from
``tools/profiles/regions.py``. The generator refuses any registry (this one included) that
carries an UNRESOLVED entry or a duplicate rva/length pair.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Tuple

IDENTITY_STRICT = 'STRICT_FINGERPRINT'
IDENTITY_STRUCTURAL_ONLY = 'STRUCTURAL_ONLY'
IDENTITY_UNRESOLVED = 'UNRESOLVED'

MAX_READ_LEN = 4096

PROFILE = 'profiles/fw1352/profile-13.52.json'
IMAGE_SHA = 'cf157ffdbae872a20bbb9a46c8518b53d96c1ed75d4e73878466a295d92eca35'
W10_SOURCE = ('profiles/fw1352/boot-identity.json + W10 boot identity evidence '
              '(RVA 0x224c6c8, struct timeval)')
W112_SOURCE = ('W11.2 live run (ps4rf W11.2 accepted, 16 bytes at kbase + 0x224c6c8, '
               'sha256 of the copied bytes host-verified)')


@dataclass(frozen=True)
class Region:
    name: str
    rva: int
    length: int
    identity_status: str
    sources: Tuple[str, ...] = field(default_factory=tuple)
    notes: str = ''


def _p(locator: str) -> str:
    return f'{PROFILE} locator {locator} (expected_bytes hex, pinned image {IMAGE_SHA[:16]}...)'


def regions() -> Dict[str, "Region"]:
    """The provisional registry, in the profile's locator order + the W10/W11.2 boottime."""
    rows = [
        Region('amd_iommu', 0x7CE9E9, 16, IDENTITY_STRICT,
               (_p('kernel.attest.amd_iommu'),), 'phase-9 anchor A1 (AMD IOMMU string table), '
               'section text, r-x, confidence OBSERVED'),
        Region('aperture_global', 0x23D3DF8, 8, IDENTITY_STRUCTURAL_ONLY,
               (_p('kernel.attest.aperture_global'),), 'boot dependent value; STRUCTURAL_ONLY, '
               'never a strict identity source; outside the loaded image, r--'),
        Region('code_anchor', 0x4CF6A0, 24, IDENTITY_STRICT,
               (_p('kernel.attest.code_anchor'),), 'phase-9 anchor A3 (text, gbase_vtophys '
               'region), section text, r-x, confidence OBSERVED'),
        Region('copyout_prologue', 0x2BD6A0, 8, IDENTITY_STRICT,
               (_p('kernel.attest.copyout_prologue'),), 'SDK fw_defines.h K1352_COPYOUT '
               'prologue, section text, r-x, confidence OBSERVED'),
        Region('gbase_vtophys', 0x815BBC, 16, IDENTITY_STRICT,
               (_p('kernel.attest.gbase_vtophys'),), 'phase-9 anchor A2 (Sony gbase_vtophys), '
               'section text, r-x, confidence OBSERVED'),
        Region('image_elf', 0x0, 16, IDENTITY_STRICT,
               (_p('kernel.attest.image_elf'),), 'kernel image identity (ELF header at the image '
               'base), section text, r-x, confidence OBSERVED'),
        Region('prison0_static', 0x111FA18, 8, IDENTITY_STRICT,
               (_p('kernel.attest.prison0_static'),), 'SDK fw_defines.h K1352_PRISON_0; the '
               'image holds the unslid pointer value, section data, rw-, confidence OBSERVED'),
        Region('xfast_entry', 0x1C0, 8, IDENTITY_STRICT,
               (_p('kernel.attest.xfast_entry'),), 'SDK fw_defines.h K1352_XFAST_SYSCALL; LSTAR '
               'must point here, section text, r-x, confidence OBSERVED'),
        Region('boottime', 0x224C6C8, 16, IDENTITY_STRICT,
               (W10_SOURCE, W112_SOURCE), 'KERN_BOOTTIME struct timeval (tv_sec at +0, tv_usec at '
               '+8); the region the accepted W11.2 live read measured'),
    ]
    return {row.name: row for row in rows}
