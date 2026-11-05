#!/usr/bin/env python3
"""Build manifest and artefact gates for the PS4 target agent (P4/W8).

The manifest is the "what exactly is this binary" record the owner asked for before any
deployment: ELF/BIN hashes, compiler and linker versions, section table, entrypoint,
required runtime dependencies, undefined symbols, and the result of every static gate.

Gates (all fail closed -- the manifest is not written when one fails):

* ``relocations``       zero ``R_X86_64`` entries: the loader applies no ELF relocations,
                        so an artefact that needs one would fault on the console
* ``forbidden_symbols`` no privileged helper is linked in (kexec and friends)
* ``forbidden_code``    no CR0 access, no ``syscall`` with number 11, no kernel-space
                        immediate in code or constants
* ``loader_port``       the BinLoader port constant is absent from .rodata/.data -- the
                        payload never talks to the loader
* ``host_target``       exactly one host/port pair is present, and it is the configured one
* ``bootread``          W11.2 (profile ``w11.2``, built with ``PS4RF_TARGET_BOOTREAD=1``):
                        the single privileged boot read. Checks the linked ELF and the sources:
                        one payload-owned ``kexec`` call site in the user section
                        (``ps4rf_bootread_run``) and nothing outside the documented SDK
                        allowance; one privileged callback symbol (``ps4rf_bootread_kpayload``,
                        W9 attestation symbols absent); one fixed kernel read region (the
                        ``0x224c6c8`` immediate only inside the callback; no other
                        kernel-section immediate >= 1 MiB beyond the documented non-address
                        constants); read length exactly 16 (loop bound ``$0x10`` and
                        ``PS4RF_BOOTREAD_READ_LEN``); exactly one payload-owned ``rdmsr`` (in
                        ``ps4rf_bootread_k_readmsr``; the SDK's ``kpayload_kbase`` kpayload is an
                        explicit allowance) and zero ``wrmsr``; callback calls restricted to the
                        module's own kernel-section leaves, no indirect call; no host-supplied
                        address or length (kernel kexec args ABI, fixed info layout, fixed event
                        key set, parameterless ``session.status`` trigger, frozen wire sources);
                        the one-shot guard provably set before the single kexec call site; a fixed
                        96 byte result block with a compile-time ``sizeof`` assertion and the
                        packed read_count/read_len store; and the reproducibility hook
                        (``--repro-elf``; build_ps4.sh already cmp's the two builds). Every check
                        reports its exact observed numbers, addresses and offsets; any failure is
                        a problem that flips the verdict to FAIL.

Usage: build_manifest.py --elf E --bin B --out M.json --source-root R --sdk SDK [--label ...]
"""

# W14-D1 / W15 §10: ``agent_version_gate()`` below keeps the build identity string honest. It is
# driven by the suite on the shipped tree and on deliberately deviant copies of it.
from __future__ import annotations

from typing import Any

import argparse
import hashlib
import json
import pathlib
import re
import struct
import subprocess
import sys

FORBIDDEN_SYMBOLS = (
    'kexec', 'jailbreak', 'disable_aslr', 'get_kernel_base', 'get_memory_dump',
    'kernel_set_memory_protection', 'kernel_copyin', 'kernel_copyout', 'patch_',
)
# Instructions that would mean privileged state manipulation (mov to/from CR0-CR4).
FORBIDDEN_OPCODES = (b'\x0f\x20', b'\x0f\x22')      # mov r32,CRn / mov CRn,r32
# W9 uses exactly two SDK entry points and nothing else: kexec() as the single privileged
# transition and get_kernel_base() as the userland cross-check value. Both are recorded in the
# manifest as an explicit allowance; every other helper stays forbidden.
W9_ALLOWED_SYMBOLS = ('kexec', 'get_kernel_base')
LOADER_PORT = 9090


def run(cmd: list[str]) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def gate_elf(elf: pathlib.Path) -> dict:
    header = run(['readelf', '-hW', str(elf)])
    info = {}
    for key, pattern in (('type', r'Type:\s+(\S+)'), ('machine', r'Machine:\s+(.+?)\s*$'),
                         ('entry', r'Entry point address:\s+(\S+)'),
                         ('class', r'Class:\s+(\S+)')):
        m = re.search(pattern, header, re.M)
        info[key] = m.group(1).strip() if m else None

    reloc_raw = run(['readelf', '-rW', str(elf)])
    relocations = [line.strip() for line in reloc_raw.splitlines()
                   if re.search(r'\bR_X86_64\w*\b', line)]
    sections = []
    sec_raw = run(['readelf', '-SW', str(elf)])
    for line in sec_raw.splitlines():
        m = re.match(r'\s*\[\s*\d+\]\s+(\S+)\s+(\S+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)', line)
        if not m:
            continue
        name, stype, addr, off, size, _flags = m.groups()
        sections.append({'name': name, 'type': stype, 'addr': int(addr, 16),
                         'offset': int(off, 16), 'size': int(size, 16)})

    symbols = run(['nm', '-P', str(elf)]).splitlines()
    defined = []
    undefined = []
    for line in symbols:
        parts = line.split()
        if len(parts) < 3:
            continue
        name, kind = parts[0], parts[1]
        if kind == 'U':
            undefined.append(name)
        else:
            defined.append(name)

    program_headers = run(['readelf', '-lW', str(elf)])
    load_segments = len(re.findall(r'^\s*LOAD\s', program_headers, re.M))
    return {'info': info, 'relocations': relocations, 'sections': sections,
            'defined_symbols': sorted(set(defined)), 'undefined_symbols': sorted(set(undefined)),
            'load_segments': load_segments, 'size': elf.stat().st_size,
            'sha256': sha256_file(elf)}


def gate_code_and_data(binary: pathlib.Path, header: dict, *, expect_host: str,
                       expect_port: int, profile: str = 'w8') -> dict:
    blob = binary.read_bytes()
    findings: dict[str, object] = {'forbidden_code': [], 'forbidden_symbols': [],
                                   'loader_port': [], 'host_target': {}}
    names_in_file = {section['name'] for section in header['sections']}
    for required in ('.text', '.rodata'):
        if required not in names_in_file:
            findings['forbidden_code'].append(f'missing section {required}')
    data_sections = [s for s in header['sections']
                     if s['name'].startswith(('.rodata', '.data')) and s['type'] == 'PROGBITS']

    # W11.2 carries the privileged callback its own gate inspects (gate_bootread), so the
    # privileged-entry allowance applies to w9 and w11.2 alike. W12 (gate_kread) does the same
    # for its single bounded kernel.read callback.
    allowed = W9_ALLOWED_SYMBOLS if profile in ('w9', BOOTREAD_PROFILE, KREAD_PROFILE) else ()
    findings['allowed_privileged_entry'] = [n for n in header['defined_symbols']
                                            if n in allowed] if allowed else []
    for name in header['defined_symbols']:
        if name in allowed:
            continue
        for bad in FORBIDDEN_SYMBOLS:
            if name == bad or name.startswith(bad):
                findings['forbidden_symbols'].append(name)
                break

    # Code checks run on the *disassembly*, not on raw bytes: a byte pair like 0f 22 can
    # appear inside an unrelated immediate, an instruction cannot.
    disassembly = run(['objdump', '-d', '--no-show-raw-insn', str(binary)])
    if 'mov' in disassembly and '%cr' in disassembly:
        for line in disassembly.splitlines():
            if re.search(r'%cr[0-9]', line):
                findings['forbidden_code'].append('control-register access: ' + line.strip())
    lines = disassembly.splitlines()
    if profile not in ('w9', BOOTREAD_PROFILE, KREAD_PROFILE):
        # W9/W11.2/W12 legitimately contain the SDK's kexec wrapper (and their single privileged
        # callback); gate_attestation()/gate_bootread()/gate_kread() then check the section-aware
        # rule (syscall 11 only in the SDK wrapper, never in payload/kernel sections), so the
        # flat rule only applies to the userland-only artefacts.
        for index, line in enumerate(lines):
            if re.search(r'\bsyscall\b', line):
                window = ' '.join(lines[max(0, index - 3):index])
                if re.search(r'\$0xb\b', window) or re.search(r'\$11\b', window):
                    findings['forbidden_code'].append('syscall 11 (kexec) sequence: ' + line.strip())

    for section in data_sections:
        window = blob[section['offset']:section['offset'] + section['size']]
        if b'9090' in window or bytes([LOADER_PORT & 0xff, LOADER_PORT >> 8]) in window:
            findings['loader_port'].append(section['name'])

    # The single endpoint: the host literal must be the only IPv4-looking string in the
    # artefact, and the port must appear as an immediate or a constant in the payload.
    ip = expect_host.encode()
    port_variants = (bytes([expect_port & 0xff, (expect_port >> 8) & 0xff]),
                     bytes([expect_port & 0xff, (expect_port >> 8) & 0xff, 0, 0]))
    all_strings = set()
    for section in header['sections']:
        if section['type'] != 'PROGBITS' or section['size'] == 0:
            continue
        window = blob[section['offset']:section['offset'] + section['size']]
        all_strings.update(m.group(0).decode() for m in
                           re.finditer(rb'\b(?:\d{1,3}\.){3}\d{1,3}\b', window))
    host_hits = len(re.findall(re.escape(ip), blob))
    code_port = sum(any(variant in blob[s['offset']:s['offset'] + s['size']]
                        for variant in port_variants)
                    for s in header['sections'] if s['type'] == 'PROGBITS' and s['size'])
    findings['host_target'] = {'host_strings_in_artefact': sorted(all_strings),
                               'host_occurrences': host_hits, 'port_occurrences': code_port,
                               'expected_host': expect_host, 'expected_port': expect_port,
                               'ok': host_hits >= 1 and code_port >= 1 and all_strings == {expect_host}}
    return findings


def gate_bootid(elf: pathlib.Path, profile: str) -> dict[str, Any]:
    """W11 gates for the read-only boot binding artefact.

    The W11 artefact must contain no privileged primitive at all: no rdmsr, no wrmsr, no kexec
    reference anywhere in the image, and no kernel range constant. The only source of the boot
    instant is the userland sysctl read in the platform layer.
    """
    findings: dict[str, Any] = {'profile': profile, 'problems': []}
    text = subprocess.run(['objdump', '-d', '--no-show-raw-insn', str(elf)],
                          capture_output=True, text=True, check=True).stdout
    rdmsr = sum(1 for line in text.splitlines() if '\trdmsr' in line or line.strip().endswith('rdmsr'))
    wrmsr = sum(1 for line in text.splitlines() if '\twrmsr' in line or line.strip().endswith('wrmsr'))
    findings['rdmsr_count'] = rdmsr
    findings['wrmsr_count'] = wrmsr
    if rdmsr or wrmsr:
        findings['problems'].append(f'W11 artefact contains privileged msr access: rdmsr={rdmsr} '
                                    f'wrmsr={wrmsr}')
    symbols = subprocess.run(['nm', str(elf)], capture_output=True, text=True, check=True).stdout
    kexec_refs = [line for line in symbols.splitlines() if 'kexec' in line]
    findings['kexec_references'] = kexec_refs
    if kexec_refs:
        findings['problems'].append('W11 artefact references kexec: the live boot binding must not '
                                    'use a privileged transition')
    for name in ('ps4rf_boot_collect', 'ps4rf_boot_event', 'ps4rf_boot_status_name'):
        if name not in symbols:
            findings['problems'].append(f'{name} missing from the artefact')
    findings['boot_symbols'] = [line.split()[-1] for line in symbols.splitlines()
                                if 'ps4rf_boot_' in line]
    # kernel-range literals are only a problem inside the W11 module itself: there they would
    # mean the collector carries an address. The rest of the image may hold u64 masks.
    # all-ones constants are sign sentinels and bit masks (e.g. the -1 initialiser of the wall
    # clock variable), never addresses; any other kernel-range literal would be an address
    allowed = {'0xffffffffffffffff', '0xffffffff', '0xffff', '0xfffffffffffffffe'}
    in_module = False
    module_literals: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.endswith('>:'):
            in_module = any(name in stripped for name in
                            ('ps4rf_boot_collect', 'ps4rf_boot_event',
                             'ps4rf_boot_status_name'))
            continue
        if not in_module:
            continue
        for literal in re.findall(r'0xffff[0-9a-f]*', line):
            if literal not in allowed:
                module_literals.append(stripped)
                break
    findings['module_kernel_range_literals'] = module_literals
    if module_literals:
        findings['problems'].append(
            f'{len(module_literals)} kernel range literal(s) inside the W11 module')
    privileged_entry = findings.get('allowed_privileged_entry') or []
    findings['privileged_entry_symbols'] = privileged_entry
    if privileged_entry:
        findings['problems'].append(
            'the W11 artefact must not contain a privileged entry point: '
            + ', '.join(str(entry) for entry in privileged_entry))
    # W11.1: no raw syscall instruction may sit in the boot/diagnostics code. The console reaches
    # the sysctl wrappers through the libPS4 function pointers, i.e. through indirect calls, so an
    # own `syscall` here would mean an unvetted transition (e.g. syscall 11) sneaked in.
    module_names = ('ps4rf_boot_collect', 'ps4rf_boot_event', 'ps4rf_boot_status_name',
                    'ps4rf_boot_class_name', 'ps4rf_boot_method_name', 'ps4_diag_one',
                    'ps4_diag_read', 'ps4_boot_diag', 'classify', 'set_method_object',
                    'ps4rf_boot_class_name')
    whole_image = [line.strip() for line in text.splitlines() if line.strip().startswith('syscall')]
    in_module = False
    module_syscalls: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.endswith('>:'):
            in_module = any(name in stripped for name in module_names)
            continue
        if in_module and stripped.startswith('syscall'):
            module_syscalls.append(stripped)
    findings['syscall_instructions_whole_image'] = len(whole_image)
    findings['syscall_instructions_in_boot_module'] = module_syscalls
    if module_syscalls:
        findings['problems'].append(
            f'{len(module_syscalls)} raw syscall instruction(s) inside the boot diagnostics module')
    # W11.1: the bounded read buffer is fixed at 64 bytes by the shared constant
    repo_root = pathlib.Path(__file__).resolve().parents[2]
    header = (repo_root / 'native' / 'target' / 'ps4rf_platform.h').read_text()
    match = re.search(r'#define\s+PS4RF_BOOTDIAG_MAX_BYTES\s+(\d+)', header)
    findings['max_read_buffer_bytes'] = int(match.group(1)) if match else None
    if match is None or int(match.group(1)) != 64:
        findings['problems'].append('the documented maximum read buffer is not 64 bytes')
    boot_src = (repo_root / 'native' / 'target' / 'ps4rf_boot.c').read_text()
    findings['boot_source_paths'] = ['sysctlbyname', 'sysctl_mib']
    if 'boot_diag' not in boot_src:
        findings['problems'].append('the boot collector does not use the instrumented diagnostics')
    findings['ok'] = not findings['problems']
    return findings


# ------------------------------------------------------------------ W11.2 bootread gates
#
# The W11.2 artefact (profile ``w11.2``, built by build_ps4.sh with PS4RF_TARGET_BOOTREAD=1)
# carries the only privileged callback of the wave: ps4rf_bootread_kpayload, reached through
# exactly one kexec() call, reading exactly one fixed 16 byte kernel region (kbase + 0x224C6C8).
# gate_bootread() verifies every W11.2 rule on the built ELF (objdump/nm) AND the sources and
# reports the exact observed numbers (counts, addresses, offsets). Fail closed: every deviating
# observation is appended to ``problems`` and flips the manifest verdict to FAIL.
#
# Scope decisions (kept in the findings as ``brief_scope_notes``):
#
# * "exactly one kexec call site / one rdmsr in the whole image": the linked image also carries
#   the SDK's own transition machinery. get_kernel_base() -- required by the W11.2 cross-check --
#   is a libPS4 function that internally calls kexec() with its own kpayload (kpayload_kbase,
#   35 rdmsr). Both sites are explicit SDK allowances; the gate fails if any kexec call site or
#   rdmsr appears outside the payload-owned site(s) plus those allowances, and always fails
#   unless the payload-owned kexec site count is exactly one, in ps4rf_bootread_run (the user
#   section of ps4rf_bootread.c).
# * the callback may call only the module's own kernel-section leaves
#   (ps4rf_bootread_k_readmsr / _read8 / _lstar_ok -- gcc -Os keeps the third out of line; the
#   brief named the two weak leaves, recorded as a note). An allocator, a lock, memcpy/memset,
#   any external helper or any indirect call fails.
# * the args struct must match the kernel kexec ABI that libPS4 (payload_utils.h) and the W9
#   harness implement: { void *syscall_handler; <info> *info; }. A single-field struct reads the
#   kernel's syscall handler as the info pointer -- on a magic mismatch the callback would write
#   cb_status into kernel memory, which the W11.2 read-only rule forbids.
# * the result block must carry a compile-time sizeof assertion pinning its derived layout (the
#   layout itself is additionally verified against the built binary).
# * reproducibility: build_ps4.sh builds twice and cmp's ELF+BIN before the manifest runs;
#   --repro-elf <second ELF> additionally records the byte comparison in the manifest.

BOOTREAD_PROFILE = 'w11.2'
BOOTREAD_FIXED_RVA = 0x224C6C8          # pinned FW13.52 KERN_BOOTTIME (W10): the ONE read region
BOOTREAD_FIXED_LEN = 16                 # the ONE read length
BOOTREAD_CALLBACK = 'ps4rf_bootread_kpayload'
BOOTREAD_KERNEL_SYMBOLS = ('ps4rf_bootread_kpayload', 'ps4rf_bootread_k_lstar_ok',
                           'ps4rf_bootread_k_readmsr', 'ps4rf_bootread_k_read8')
BOOTREAD_WEAK_LEAVES = ('ps4rf_bootread_k_readmsr', 'ps4rf_bootread_k_read8')
# The callback may call the module's own kernel-section leaves and nothing else. gcc -Os keeps
# ps4rf_bootread_k_lstar_ok out of line even though it is called once, so the module-owned shape
# gate is allowed explicitly and every call target is reported; the brief named only the two
# weak leaves, which stays recorded as a scope note. Anything else (allocator, lock,
# memcpy/memset, external helper, indirect call) fails the gate.
BOOTREAD_CALLBACK_ALLOWED_CALLS = BOOTREAD_WEAK_LEAVES + ('ps4rf_bootread_k_lstar_ok',)
# SDK-internal privileged sites the W11.2 design drags in: get_kernel_base() is the required
# cross-check and libPS4 implements it with its own kexec call and its own kpayload
# (kpayload_kbase, 35 rdmsr). These exact sites are explicit allowances; anything else fails.
BOOTREAD_SDK_KEXEC_ALLOWANCE = ('get_kernel_base',)
BOOTREAD_SDK_RDMSR_ALLOWANCE = ('kpayload_kbase',)
BOOTREAD_SDK_KPAYLOAD_ALLOWANCE = ('kpayload_kbase',)
# Kernel-section immediates that are documented non-address constants (sources: ps4rf_bootread).
BOOTREAD_KERNEL_IMMEDIATE_ALLOWLIST = {
    0x224C6C8: 'PS4RF_BOOTREAD_SOURCE_RVA: the single fixed read region',
    0xC0000082: 'PS4RF_BOOTREAD_LSTAR_MSR: MSR selector number, not a kernel address',
    0x57524B43: 'PS4RF_BOOTREAD_MAGIC_IN',
    0x57524B44: 'PS4RF_BOOTREAD_MAGIC_OUT',
    0x5053345246415431: 'PS4RF_BOOTREAD_GUARD: struct end canary',
    0x1000000001: 'packed store: read_count=1 (low half) | read_len=16 (high half)',
    0xFFFFFFFF: '32-bit -1 (error return)',
    0xFFFFFFFFFFFFFFFF: '64-bit -1 (error return)',
    0xFFFF7FFF_FFFFFFFF: 'PS4RF_BOOTREAD_KERNEL_MIN - 1 (0xffff800000000000 - 1): the '
                         'canonical-range compare form',
}
BOOTREAD_EXPECTED_INFO_FIELDS = (
    ('magic_in', 'uint32_t'), ('cb_status', 'uint32_t'), ('read_count', 'uint32_t'),
    ('read_len', 'uint32_t'), ('kexec_rc', 'int32_t'), ('reserved', 'uint32_t'),
    ('lstar', 'uint64_t'), ('kbase_candidate', 'uint64_t'), ('kbase_sdk', 'uint64_t'),
    ('source_rva', 'uint64_t'), ('cross_check', 'uint64_t'), ('raw', 'uint8_t'),
    ('magic_out', 'uint64_t'), ('guard', 'uint64_t'))
# The kernel kexec ABI, as written by the console kernel and mirrored by every SDK payload
# (libPS4 include/payload_utils.h: struct kpayload_*_args) and by the W9 harness
# (tests/harness/attest_offline.c): { void *syscall_handler; <info> *info; }.
BOOTREAD_EXPECTED_ARGS_FIELDS = (('void *', 'syscall_handler'), ('ps4rf_bootread_info *', 'info'))
# The fixed event schema of ps4rf_bootread_event (an addition or removal changes the wire body).
BOOTREAD_EXPECTED_EVENT_KEYS = frozenset({
    'msg', 'event', 'schema', 'status', 'run_status', 'run_status_name', 'callback_executed',
    'cb_status', 'cb_status_name', 'kexec_rc', 'lstar', 'kbase_candidate', 'kbase_sdk',
    'cross_check', 'source_rva', 'read_length', 'raw_hex', 'tv_sec', 'tv_usec',
    'wall_clock_sec', 'validation', 'kernel_timeval_bytes', 'timeval_layout',
    'single_callback', 'retry', 'writes_to_kernel', 'host_supplied_address',
    'generic_read_primitive', 'boot_id_claim', 'boot_id_note', 'build_id', 'label',
    'provider', 'scope', 'profile_decision'})


# W12: one bounded kernel.read provider. The image carries exactly one privileged callback
# reached through exactly one kexec() call, one bounded region table generated from the canonical
# registry (tools/profiles/regions.py), and one request model that carries no address at all.
# The argument-block shape is the console's: ps4rf_attest.h / the W9 live run / W11.2 all show the
# kernel wrapping the caller's pointer as { void *syscall_handler; <payload> } and calling the
# payload with a pointer to the wrapper, so the payload's block sits in the SECOND field.
KREAD_PROFILE = 'w12'

# ---------------------------------------------------------------------------------------------
# W17F: the privileged drivers. The W12 wave introduced exactly one payload-owned privileged
# transition (the bounded region read). W17 adds a second one (the bounded snapshot recipe) and a
# userland device call that makes no privileged transition at all (ioctl.invoke). The rules from
# the W12 gate stay identical -- one call site per driver, one callback symbol per driver, one
# declared kernel section per driver, no retry around a transition, no indirect call in a kernel
# section -- they are simply stated per driver instead of once for the image, and every driver
# that is compiled in is checked.
# ---------------------------------------------------------------------------------------------
KREAD_CALLBACK = 'ps4rf_kread_kpayload'
KREAD_KERNEL_SYMBOLS = ('ps4rf_kread_kpayload', 'ps4rf_kread_k_lstar_ok',
                        'ps4rf_kread_k_readmsr', 'ps4rf_kread_k_read8')
KREAD_WEAK_LEAVES = ('ps4rf_kread_k_readmsr', 'ps4rf_kread_k_read8')
KREAD_CALLBACK_ALLOWED_CALLS = KREAD_WEAK_LEAVES + ('ps4rf_kread_k_lstar_ok',)
RECIPE_CALLBACK = 'ps4rf_recipe_kpayload'
RECIPE_KERNEL_SYMBOLS = ('ps4rf_recipe_kpayload', 'ps4rf_recipe_k_read8')
RECIPE_MODULE = 'ps4rf_recipe_target.c'
RECIPE_PROBE_MODULE = 'ps4rf_recipe.c'
IOCTL_MODULE = 'ps4rf_ioctl.c'
IOCTL_LEAVES = ('ps4rf_ioctl_invoke', 'ps4rf_ioctl_policy_check', 'ps4rf_ioctl_stage')
IOCTL_PLATFORM_MODULE = 'ps4rf_ioctl_ps4.c'
IOCTL_PLATFORM_LEAVES = ('ps4_call', 'ps4_open', 'ps4_close', 'ps4_transfer')
PRIVILEGED_DRIVERS = (
    {'name': 'kread', 'run': 'ps4rf_kread_run', 'callback': KREAD_CALLBACK,
     'kernel_prefix': 'ps4rf_kread_k', 'kernel_symbols': tuple(sorted(KREAD_KERNEL_SYMBOLS)),
     'module': 'ps4rf_kread.c'},
    {'name': 'recipe', 'run': 'ps4rf_recipe_read_run', 'callback': RECIPE_CALLBACK,
     'kernel_prefix': 'ps4rf_recipe_k', 'kernel_symbols': tuple(sorted(RECIPE_KERNEL_SYMBOLS)),
     'module': RECIPE_MODULE},
)


def driver_present(defined_set: set, driver: dict) -> bool:
    """A driver is in the image when its callback or one of its kernel leaves is defined."""
    if driver['callback'] in defined_set:
        return True
    return any(sym in defined_set for sym in driver['kernel_symbols'])

def kernel_section_symbol(name: str, driver: dict) -> bool:
    """A kernel-section symbol of a driver: the callback itself, or a declared kernel leaf named
    with the module's kernel prefix plus an underscore. The underscore keeps user-section helpers
    with a coincidental prefix (ps4rf_recipe_kva_ok) out of the kernel section."""
    if name in driver['kernel_symbols']:
        return True
    return name.startswith(driver['kernel_prefix'] + '_')

KREAD_SDK_KEXEC_ALLOWANCE = ('get_kernel_base',)
KREAD_SDK_RDMSR_ALLOWANCE = ('kpayload_kbase',)
KREAD_SDK_KPAYLOAD_ALLOWANCE = ('kpayload_kbase',)
KREAD_INFO_SIZE = 4256
# Rule ownership, printed in the gate's detail so a later drift is visible:
#   the read bound (1..MAX_READ_LEN, zero length refused) and the checked arithmetic /
#   containment / canonical rules are owned by the host module tools/profiles/kread.py;
#   the value of MAX_READ_LEN and the region policy are owned by tools/profiles/regions.py,
#   which the generator reads and carries into the generated header. The payload only
#   compiles what that header says, and this gate only compares.
KREAD_BOUND_OWNER = 'tools/profiles/regions.py:MAX_READ_LEN (registry, single owner)'
KREAD_BOUNDS_RULE_OWNER = 'tools/profiles/kread.py (checked add, 1..MAX_READ_LEN, containment, canonical)'
KREAD_REGION_POLICY_OWNER = 'tools/profiles/regions.py (region table, identity status, policy)'
KREAD_REQUEST_MODEL_OWNER = 'tools/profiles/kread.py:parse_request (the request carries region, offset, length)'
KREAD_GUARD = 0x50533452464B5231              # "PS4RFKR1"
KREAD_MAGIC_IN = 0x44524B43                   # "CKRD"
KREAD_MAGIC_OUT = 0x44524B44                  # "DKRD"
KREAD_LSTAR_MSR = 0xC0000082
KREAD_KERNEL_MIN = 0xFFFF800000000000
KREAD_LSTAR_PAGE_OFFSET = 0x1C0               # kbase = LSTAR - 0x1C0 (W9 relation)
# Kernel-section immediates >= 1 MiB that are documented non-address constants (the leaf source
# is ps4rf_kread.h). Every region RVA lives in the generated table (.rodata), never as an
# immediate: a second read source would have to appear here.
KREAD_KERNEL_IMMEDIATE_ALLOWLIST = {
    KREAD_MAGIC_IN: 'PS4RF_KREAD_MAGIC_IN (caller marker)',
    KREAD_MAGIC_OUT: 'PS4RF_KREAD_MAGIC_OUT (callback marker)',
    KREAD_LSTAR_MSR: 'PS4RF_KREAD_LSTAR_MSR: MSR selector number, not a kernel address',
    KREAD_GUARD: 'PS4RF_KREAD_GUARD: struct end canary',
    KREAD_KERNEL_MIN - 1: 'PS4RF_KREAD_KERNEL_MIN - 1: the canonical-range compare form',
    0xFFFFFFFF: '32-bit -1 (error return / u32 max)',
    0xFFFFFFFFFFFFFFFF: '64-bit -1 (error return)',
}
KREAD_EXPECTED_ARGS_FIELDS = (('void *', 'syscall_handler'), ('ps4rf_kread_info *', 'info'))
# The request half of the result block: region index, offset and length -- and the caller marker
# plus the payload-filled SDK base. No address, no pointer, nothing the host could steer.
KREAD_REQUEST_FIELDS = ('magic_in', 'region_index', 'offset', 'length', 'kbase_sdk')
KREAD_EXPECTED_INFO_FIELDS = (
    ('magic_in', 'uint32_t'), ('cb_status', 'uint32_t'), ('run_status', 'uint32_t'),
    ('region_index', 'uint32_t'), ('offset', 'uint32_t'), ('length', 'uint32_t'),
    ('copied_len', 'uint32_t'), ('sha256_status', 'uint32_t'), ('flags', 'uint32_t'),
    ('kexec_rc', 'int32_t'), ('reserved0', 'uint32_t'), ('reserved1', 'uint32_t'),
    ('lstar', 'uint64_t'), ('kbase_candidate', 'uint64_t'), ('kbase_sdk', 'uint64_t'),
    ('region_rva', 'uint64_t'), ('resolved_rva', 'uint64_t'),
    ('resolved_runtime_va', 'uint64_t'), ('offset_length_sum', 'uint64_t'),
    ('cross_check', 'uint64_t'), ('bytes', 'uint8_t'), ('sha256', 'uint8_t'),
    ('magic_out', 'uint64_t'), ('guard', 'uint64_t'))
# The fixed event schema of ps4rf_kread_event (an addition or removal changes the wire body).
KREAD_EXPECTED_EVENT_KEYS = frozenset({
    'msg', 'event', 'schema', 'status', 'run_status', 'run_status_name', 'callback_executed',
    'cb_status', 'cb_status_name', 'kexec_rc', 'requested_region', 'requested_region_index',
    'region_identity', 'region_rva', 'requested_offset', 'requested_length', 'copied_len',
    'offset_length_sum', 'lstar', 'kbase_candidate', 'kbase_sdk', 'cross_check', 'resolved_rva',
    'resolved_runtime_va', 'bytes_hex', 'sha256', 'sha256_status', 'max_read_len', 'region_count',
    'single_callback', 'retry', 'writes_to_kernel', 'host_supplied_address',
    'generic_read_primitive', 'resolved_runtime_va_note', 'build_id', 'label', 'provider',
    'scope', 'profile_decision'})
# Review checklist item 10: the runtime VA lives in evidence only. These are the only event keys
# allowed to look like an address; every other one would be a request-side address input.
KREAD_EVIDENCE_ONLY_ADDRESS_KEYS = frozenset({'resolved_rva', 'resolved_runtime_va',
                                              'resolved_runtime_va_note',
                                              'host_supplied_address'})
KREAD_ADDRESS_KEY_PATTERN = re.compile(r'(?i)(address|\bva\b|_va($|_)|ptr|pointer)')
# Subsystems the wave still forbids in the artefact (checklist item 13 / doc §16).
KREAD_FORBIDDEN_SUBSYSTEMS = ('mrsamu', 'samu', 'gpuvm', 'keymgr', 'ccp', 'sflash', 'emc',
                              'syscon', 'nvram', 'pup', 'eap', 'sbram')
# Allocation, locking, persistence and host-I/O helpers: never called from the module.
KREAD_FORBIDDEN_CALL_TARGETS = (
    'malloc', 'calloc', 'realloc', 'free', 'kmalloc', 'operator', 'mutex', 'pthread',
    'spin_lock', 'spinlock', 'dlopen', 'dlsym', 'system', 'execve', 'fork', 'open', 'write',
    'read', 'socket', 'connect', 'wrmsr', 'sysent', 'syscall_table')
# The offline case matrix the harness must carry (review items 1-3 and the wave checklist).
KREAD_HARNESS_CASES = ('A', 'B', 'C', 'D', 'E', 'E2', 'F', 'G', 'H', 'I', 'J', 'B2', 'D2', 'E3',
                       'K', 'L', 'M')
KREAD_GENERATOR = 'native/target/gen_kread_regions.py'
KREAD_REGIONS_HEADER = 'native/target/ps4rf_kread_regions.h'
# Files referenced for parity only (their semantics stay where they are; W12 does not restate
# or duplicate the W4/W5/W7 decisions).
KREAD_PARITY_FILES = ('tools/dispatch/matrix.py', 'tools/profiles/kread.py',
                      'tools/profiles/kread_capability.py', 'tools/profiles/regions.py',
                      'tools/profiles/promotion.py', 'tools/hostctl/cli.py',
                      'tests/test_live_health.py',
                      'tests/test_profile_promotion.py', 'tests/harness/kread_offline.c',
                      'tests/test_kread_offline.py')


def _strip_c_comments(text: str) -> str:
    text = re.sub(r'/\*.*?\*/', ' ', text, flags=re.S)
    return re.sub(r'//[^\n]*', ' ', text)


def _disasm_rows(text: str) -> list[tuple[str, int, str]]:
    """(function, address, instruction) for every instruction of an objdump -d dump."""
    rows = []
    current = '?'
    for line in text.splitlines():
        header = re.match(r'^([0-9a-f]+) <([^>]+)>:', line)
        if header:
            current = header.group(2)
            continue
        insn = re.match(r'^\s*([0-9a-f]+):\s+(.*)$', line)
        if insn:
            rows.append((current, int(insn.group(1), 16), insn.group(2).strip()))
    return rows


def _hex_immediates(insn: str) -> list[int]:
    """Hex immediates/offsets of one instruction (branch-target comments are dropped)."""
    text = re.sub(r'<[^>]*>', ' ', insn).split('#')[0]
    return [int(token, 16) for token in re.findall(r'0x([0-9a-f]+)', text)]


def _sysv_layout(fields: list[tuple[str, int, int]]) -> dict[str, Any]:
    """x86-64 SysV struct layout derived from (name, size, alignment) rows."""
    offset = 0
    max_align = 1
    offsets: dict[str, int] = {}
    for name, size, align in fields:
        offset = ((offset + align - 1) // align) * align
        offsets[name] = offset
        offset += size
        max_align = max(max_align, align)
    size = ((offset + max_align - 1) // max_align) * max_align
    return {'size': size, 'offsets': offsets, 'align': max_align}


def gate_bootread(elf: pathlib.Path, profile: str, *, sdk: pathlib.Path | None = None,
                  repro_elf: pathlib.Path | None = None) -> dict[str, Any]:
    """W11.2 gates: one privileged callback, one kexec site, one fixed read region.

    Every number is measured from the linked ELF (objdump/nm) and the sources; the module
    docstring documents the scope decisions and the SDK allowances.
    """
    repo_root = pathlib.Path(__file__).resolve().parents[2]
    tgt = repo_root / 'native' / 'target'
    findings: dict[str, Any] = {'profile': profile, 'problems': [], 'brief_scope_notes': []}
    problems: list[str] = findings['problems']

    module_c = (tgt / 'ps4rf_bootread.c').read_text()
    module_h = (tgt / 'ps4rf_bootread.h').read_text()
    module_c_code = _strip_c_comments(module_c)
    module_h_code = _strip_c_comments(module_h)
    agent_c = (tgt / 'ps4rf_agent.c').read_text()
    findings['source_sha256'] = {
        'native/target/ps4rf_bootread.c': sha256_file(tgt / 'ps4rf_bootread.c'),
        'native/target/ps4rf_bootread.h': sha256_file(tgt / 'ps4rf_bootread.h'),
    }

    disassembly = run(['objdump', '-d', '--no-show-raw-insn', str(elf)])
    rows = _disasm_rows(disassembly)
    by_func: dict[str, list[tuple[int, str]]] = {}
    for func, addr, insn in rows:
        by_func.setdefault(func, []).append((addr, insn))
    defined_set: set[str] = set()
    for line in run(['nm', '-P', str(elf)]).splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1] != 'U':
            defined_set.add(parts[0])

    # source constants the checks below are pinned to
    len_define = re.search(r'#define\s+PS4RF_BOOTREAD_READ_LEN\s+(\d+)', module_h_code)
    read_len_src = int(len_define.group(1)) if len_define else None
    guard_define = re.search(r'#define\s+PS4RF_BOOTREAD_GUARD\s+0x([0-9a-fA-F]+)', module_h_code)
    guard_value = int(guard_define.group(1), 16) if guard_define else None
    magic_out_define = re.search(r'#define\s+PS4RF_BOOTREAD_MAGIC_OUT\s+0x([0-9a-fA-F]+)',
                                 module_h_code)
    magic_out_value = int(magic_out_define.group(1), 16) if magic_out_define else None

    # --- 1. exactly one kexec call site, in the user section of ps4rf_bootread.c ------------
    kexec_calls = [(func, addr, insn) for func, addr, insn in rows
                   if re.search(r'\bcallq?\s+[0-9a-f]+\s+<kexec>', insn)]
    payload_kexec = [site for site in kexec_calls if site[0].startswith('ps4rf_')]
    sdk_kexec = [site for site in kexec_calls if site[0] in BOOTREAD_SDK_KEXEC_ALLOWANCE]
    kernel_kexec = [site for site in kexec_calls if site[0].startswith('ps4rf_bootread_k')]
    findings['kexec'] = {
        'image_call_sites': [{'addr': hex(addr), 'function': func} for func, addr, _ in kexec_calls],
        'payload_call_sites': [{'addr': hex(addr), 'function': func} for func, addr, _ in payload_kexec],
        'sdk_allowances': [{'addr': hex(addr), 'function': func,
                            'reason': 'libPS4 get_kernel_base() internal transition '
                                      '(the required cross-check drags it in)'}
                           for func, addr, _ in sdk_kexec],
    }
    if len(payload_kexec) != 1:
        problems.append(f'W11.2 kexec: {len(payload_kexec)} payload-owned call site(s) '
                        '(expected exactly one, in ps4rf_bootread_run)')
    elif payload_kexec[0][0] != 'ps4rf_bootread_run':
        problems.append(f'W11.2 kexec: the payload-owned call site is in {payload_kexec[0][0]!r} '
                        '(expected the user section of ps4rf_bootread.c: ps4rf_bootread_run)')
    if kernel_kexec:
        problems.append('W11.2 kexec: call site inside the kernel section: '
                        + ', '.join(f'{f}@{hex(a)}' for f, a, _ in kernel_kexec))
    outside = [site for site in kexec_calls if not site[0].startswith('ps4rf_')
               and site[0] not in BOOTREAD_SDK_KEXEC_ALLOWANCE]
    if outside:
        problems.append('W11.2 kexec: call site outside the payload and the documented SDK '
                        'allowance: ' + ', '.join(f'{f}@{hex(a)}' for f, a, _ in outside))
    findings['brief_scope_notes'].append(
        f'kexec: whole image has {len(kexec_calls)} call site(s) = {len(payload_kexec)} '
        f'payload-owned + {len(sdk_kexec)} SDK allowance; the W11.2 rule counts the payload-owned '
        'site(s) and fails on anything not attributable to {payload, get_kernel_base}')
    if payload_kexec:
        site_func, site_addr, _ = payload_kexec[0]
        site_rows = by_func.get(site_func, [])
        idx = next((i for i, (a, _t) in enumerate(site_rows) if a == site_addr), 0)
        window = ' ; '.join(t for _a, t in site_rows[max(0, idx - 6):idx])
        findings['kexec']['callback_pointer_window'] = window
        if 'lea' not in window or f'<{BOOTREAD_CALLBACK}>' not in window:
            problems.append('W11.2 kexec: the call site does not pass &' + BOOTREAD_CALLBACK
                            + ' (no lea of the callback in the 6 instructions before the call)')
    # the single privileged instruction path: one syscall 11 site, the SDK kexec wrapper
    syscall_rows = [(func, addr) for func, addr, insn in rows if re.match(r'syscall\b', insn)]
    sites11 = []
    for i, (_func, _addr, insn) in enumerate(rows):
        if re.search(r'mov\s+\$0xb,%r(?:ax|eax)\b', insn):
            nxt = rows[i + 1][2] if i + 1 < len(rows) else ''
            if 'syscall_macro' in nxt:
                sites11.append((_func, _addr))
    findings['kexec']['syscall_instructions'] = [{'addr': hex(a), 'function': f}
                                                 for f, a in syscall_rows]
    findings['kexec']['syscall11_sites'] = [{'addr': hex(a), 'function': f} for f, a in sites11]
    if len(sites11) != 1 or sites11[0][0] != 'kexec':
        problems.append(f'W11.2 kexec: syscall 11 sites {[(f, hex(a)) for f, a in sites11]} '
                        '(expected exactly one, the SDK kexec wrapper)')
    stray_syscalls = [f'{f}@{hex(a)}' for f, a in syscall_rows if f.startswith('ps4rf_')]
    if stray_syscalls:
        problems.append('W11.2: raw syscall instruction in payload code: ' + ', '.join(stray_syscalls))

    # --- 2. exactly one privileged callback symbol, no other kernel-section entry -----------
    kernel_syms = sorted(name for name in defined_set if name.startswith('ps4rf_bootread_k'))
    kpayload_syms = sorted(name for name in defined_set if 'kpayload' in name)
    attest_syms = sorted(name for name in defined_set if name.startswith('ps4rf_attest'))
    findings['symbols'] = {
        'kernel_section_defined': kernel_syms,
        'expected_kernel_section': sorted(BOOTREAD_KERNEL_SYMBOLS),
        'kpayload_named_defined': kpayload_syms,
        'attest_symbols': attest_syms,
        'callback_defined': BOOTREAD_CALLBACK in defined_set,
    }
    if kernel_syms != sorted(BOOTREAD_KERNEL_SYMBOLS):
        problems.append('W11.2 kernel section symbols: ' + ','.join(kernel_syms) + ' (expected '
                        + ','.join(sorted(BOOTREAD_KERNEL_SYMBOLS)) + ')')
    if BOOTREAD_CALLBACK not in defined_set:
        problems.append('W11.2 callback symbol missing: ' + BOOTREAD_CALLBACK)
    ps4rf_kpayloads = [name for name in kpayload_syms if name.startswith('ps4rf_')]
    if ps4rf_kpayloads != [BOOTREAD_CALLBACK]:
        problems.append('W11.2 callback symbols: ' + ','.join(ps4rf_kpayloads) + ' (expected '
                        'exactly ' + BOOTREAD_CALLBACK + ')')
    stray_payloads = [name for name in kpayload_syms if not name.startswith('ps4rf_')
                      and name not in BOOTREAD_SDK_KPAYLOAD_ALLOWANCE]
    if stray_payloads:
        problems.append('W11.2 kernel payload symbols outside the SDK allowance: '
                        + ','.join(stray_payloads))
    if attest_syms:
        problems.append('W11.2 image contains W9 attestation symbols: ' + ','.join(attest_syms))
    if sdk is not None and (sdk / 'libPS4.a').exists():
        archive = run(['nm', str(sdk / 'libPS4.a')])
        findings['symbols']['sdk_archive_defines'] = {
            name: bool(re.search(r'\bT ' + re.escape(name) + r'\b', archive))
            for name in ('kexec', 'get_kernel_base', 'kpayload_kbase')}

    # --- 3. exactly one fixed kernel data read region ---------------------------------------
    rva_sites = [(func, addr, insn) for func, addr, insn in rows
                 if re.search(r'\b0x224c6c8\b', insn)]
    outside_cb = [site for site in rva_sites if site[0] != BOOTREAD_CALLBACK]
    findings['fixed_region'] = {
        'rva': hex(BOOTREAD_FIXED_RVA),
        'occurrences': [{'addr': hex(a), 'function': f, 'insn': t} for f, a, t in rva_sites],
        'occurrences_outside_callback': [{'addr': hex(a), 'function': f} for f, a, _ in outside_cb],
    }
    if not rva_sites:
        problems.append('W11.2 fixed region: the 0x224c6c8 immediate is absent from the image')
    if outside_cb:
        problems.append('W11.2 fixed region: 0x224c6c8 appears outside ' + BOOTREAD_CALLBACK
                        + ': ' + ', '.join(f'{f}@{hex(a)}' for f, a, _ in outside_cb))
    source_uses = sum(1 for line in module_c_code.splitlines()
                      if 'PS4RF_BOOTREAD_SOURCE_RVA' in line
                      and not line.strip().startswith('#define'))
    findings['fixed_region']['source_macro_uses'] = source_uses
    observed_imm: list[dict[str, str]] = []
    unexpected_imm: list[str] = []
    for func, addr, insn in rows:
        if not func.startswith('ps4rf_bootread_k'):
            continue
        for value in _hex_immediates(insn):
            if value >= 0x100000:
                observed_imm.append({'addr': hex(addr), 'function': func, 'value': hex(value)})
                if value not in BOOTREAD_KERNEL_IMMEDIATE_ALLOWLIST:
                    unexpected_imm.append(f'{hex(value)} in {func}@{hex(addr)}')
    findings['fixed_region']['kernel_section_immediates_ge_1mib'] = observed_imm
    findings['fixed_region']['kernel_section_immediate_allowlist'] = {
        hex(value): why for value, why in BOOTREAD_KERNEL_IMMEDIATE_ALLOWLIST.items()}
    if unexpected_imm:
        problems.append('W11.2 fixed region: unexpected kernel-section immediate(s) >= 1 MiB '
                        '(possible second read source): ' + '; '.join(unexpected_imm))
    for leaf in BOOTREAD_WEAK_LEAVES:
        callers = sorted({func for func, _a, insn in rows
                          if f'<{leaf}>' in insn and re.search(r'\bcallq?\b', insn)})
        findings['fixed_region'][leaf + '_callers'] = callers
        if callers != [BOOTREAD_CALLBACK]:
            problems.append(f'W11.2 {leaf}: called from {callers} (expected only '
                            + BOOTREAD_CALLBACK + ')')
    cb_rows = by_func.get(BOOTREAD_CALLBACK, [])
    read8_idx = next((i for i, (_a, t) in enumerate(cb_rows)
                      if '<ps4rf_bootread_k_read8>' in t), None)
    if read8_idx is not None:
        findings['fixed_region']['read8_context'] = [t for _a, t
                                                     in cb_rows[max(0, read8_idx - 3):read8_idx + 2]]

    # --- 4. read length exactly 16 ----------------------------------------------------------
    bound = [(hex(a), t) for a, t in cb_rows
             if re.search(r'\bcmpq?\s+\$0x10\b', t)]
    packed = None
    for i, (a, t) in enumerate(cb_rows):
        m = re.search(r'movabs\s+\$0x([0-9a-f]+),', t)
        if m and i + 1 < len(cb_rows) and re.search(r'mov\s+%rax,0x8\(%rbx\)', cb_rows[i + 1][1]):
            packed = (int(m.group(1), 16), a)
    findings['read_len'] = {
        'header_define': read_len_src,
        'expected': BOOTREAD_FIXED_LEN,
        'callback_loop_bound_sites': [{'addr': a, 'insn': t} for a, t in bound],
        'callback_read8_calls': [hex(a) for a, t in cb_rows if '<ps4rf_bootread_k_read8>' in t],
        'packed_count_len_store': {'value': hex(packed[0]), 'addr': hex(packed[1])}
        if packed else None,
    }
    if read_len_src != BOOTREAD_FIXED_LEN:
        problems.append(f'W11.2 read length: PS4RF_BOOTREAD_READ_LEN == {read_len_src} '
                        f'(expected {BOOTREAD_FIXED_LEN})')
    if not bound:
        problems.append('W11.2 read length: no cmp $0x10 loop bound found in ' + BOOTREAD_CALLBACK)
    if packed is not None and (packed[0] & 0xffffffff) == 1:
        written_len = (packed[0] >> 32) & 0xffffffff
        if written_len != BOOTREAD_FIXED_LEN:
            problems.append(f'W11.2 read length: read_len field written as {written_len} '
                            f'(expected {BOOTREAD_FIXED_LEN})')

    # --- 5. msr access: one payload rdmsr, zero wrmsr ---------------------------------------
    rdmsr_sites = [(func, addr) for func, addr, insn in rows if re.search(r'\brdmsr\b', insn)]
    wrmsr_sites = [(func, addr) for func, addr, insn in rows if re.search(r'\bwrmsr\b', insn)]
    rdmsr_by_func: dict[str, int] = {}
    for func, _a in rdmsr_sites:
        rdmsr_by_func[func] = rdmsr_by_func.get(func, 0) + 1
    payload_rdmsr = [(f, a) for f, a in rdmsr_sites if f.startswith('ps4rf_')]
    findings['msr'] = {
        'rdmsr_total_image': len(rdmsr_sites),
        'rdmsr_by_function': rdmsr_by_func,
        'rdmsr_payload_sites': [f'{f}@{hex(a)}' for f, a in payload_rdmsr],
        'rdmsr_sdk_allowance': sorted({f for f, _a in rdmsr_sites
                                       if f in BOOTREAD_SDK_RDMSR_ALLOWANCE}),
        'wrmsr_total_image': len(wrmsr_sites),
    }
    if wrmsr_sites:
        problems.append(f'W11.2 msr: {len(wrmsr_sites)} wrmsr instruction(s) in the image: '
                        + ', '.join(f'{f}@{hex(a)}' for f, a in wrmsr_sites))
    if [f for f, _a in payload_rdmsr] != ['ps4rf_bootread_k_readmsr']:
        problems.append('W11.2 msr: payload rdmsr sites '
                        + ', '.join(f'{f}@{hex(a)}' for f, a in payload_rdmsr)
                        + ' (expected exactly one, in ps4rf_bootread_k_readmsr)')
    if rdmsr_by_func.get('ps4rf_bootread_k_readmsr', 0) != 1:
        problems.append('W11.2 msr: ps4rf_bootread_k_readmsr holds '
                        + str(rdmsr_by_func.get('ps4rf_bootread_k_readmsr', 0))
                        + ' rdmsr instruction(s) (expected 1)')
    non_allowed = [(f, a) for f, a in rdmsr_sites
                   if f != 'ps4rf_bootread_k_readmsr' and f not in BOOTREAD_SDK_RDMSR_ALLOWANCE]
    if non_allowed:
        problems.append('W11.2 msr: rdmsr outside the payload leaf and the SDK allowance: '
                        + ', '.join(f'{f}@{hex(a)}' for f, a in non_allowed))
    findings['brief_scope_notes'].append(
        f'rdmsr: whole image has {len(rdmsr_sites)} = {len(payload_rdmsr)} payload-owned + '
        f'{len(rdmsr_sites) - len(payload_rdmsr)} SDK allowance (libPS4 kpayload_kbase); '
        'the W11.2 rule counts the payload-owned instruction (1)')

    # --- 6. callback calls: module leaves only, no indirect ---------------------------------
    allowed_calls = set(BOOTREAD_CALLBACK_ALLOWED_CALLS)
    call_targets: dict[str, list[str]] = {}
    indirect: list[str] = []
    for addr, insn in cb_rows:
        if re.search(r'\b(callq?|jmpq?)\s+\*', insn):
            indirect.append(f'{hex(addr)} {insn}')
        m = re.search(r'\bcallq?\s+[0-9a-f]+\s+<([^>]+)>', insn)
        if m:
            call_targets.setdefault(m.group(1).split('+')[0], []).append(hex(addr))
    findings['callback_calls'] = {
        'targets': {t: sites for t, sites in sorted(call_targets.items())},
        'allowed_targets': sorted(allowed_calls),
        'indirect_calls': indirect,
    }
    bad_targets = [t for t in sorted(call_targets) if t not in allowed_calls]
    missing_calls = [t for t in BOOTREAD_WEAK_LEAVES if t not in call_targets]
    if bad_targets:
        problems.append('W11.2 callback: call target(s) outside the allowed module leaves '
                        '(no allocator, no locking, no memcpy/memset, no external helper): '
                        + ', '.join(bad_targets))
    if missing_calls:
        problems.append('W11.2 callback: missing expected call to ' + ', '.join(missing_calls))
    if indirect:
        problems.append('W11.2 callback: indirect call/jump: ' + '; '.join(indirect))
    extra_calls = sorted(set(call_targets) - set(BOOTREAD_WEAK_LEAVES))
    if extra_calls:
        findings['brief_scope_notes'].append(
            'callback calls: the brief named the two weak leaves; the image also calls '
            + ', '.join(extra_calls) + ' (module-owned kernel-section leaf, kept out of line by '
            'gcc -Os; allowed)')

    # --- 7. no host-controlled address or length --------------------------------------------
    args_block = re.search(r'struct\s+ps4rf_bootread_args\s*\{(.*?)\}\s*;', module_h, re.S)
    args_members: list[tuple[str, str]] = []
    if args_block:
        for line in args_block.group(1).splitlines():
            code = line.split(';')[0].strip()
            if not code or code.startswith('/*') or code.startswith('*'):
                continue
            m = re.match(r'^(.*\*)\s*(\w+)$', code)
            if m:
                args_members.append((' '.join(m.group(1).split()), m.group(2)))
    findings['host_input'] = {
        'args_fields': [{'type': t, 'name': n} for t, n in args_members],
        'expected_args_fields': [{'type': t, 'name': n}
                                 for t, n in BOOTREAD_EXPECTED_ARGS_FIELDS],
    }
    if [n for _t, n in args_members] != [n for _t, n in BOOTREAD_EXPECTED_ARGS_FIELDS]:
        problems.append(
            'W11.2 args ABI: struct ps4rf_bootread_args members '
            + str([n for _t, n in args_members]) + ' do not match the kernel kexec ABI '
            + str([n for _t, n in BOOTREAD_EXPECTED_ARGS_FIELDS]) + ' (the kernel builds the args '
            'struct {syscall_handler, <pointer passed to kexec>} and hands the payload a pointer '
            'to it: libPS4 source/payload_utils.c:45 kpayload_kbase(struct thread *, struct '
            'kpayload_kbase_args *) with payload_utils.h:54 '
            '{ void *syscall_handler; struct kpayload_kbase_info *...; }, and get_kernel_base() '
            'passes its own info pointer to kexec() the same way this module does; the W9 harness '
            'tests/harness/attest_offline.c documents the same ABI). A single-field struct reads '
            'syscall_handler as the info pointer: the magic check would read kernel code and, on '
            'mismatch, write cb_status into kernel memory -- not read-only; the fix is to declare '
            'void *syscall_handler; first and keep <info> second')
    if sdk is not None and (sdk / 'include' / 'payload_utils.h').exists():
        sdk_payload_h = (sdk / 'include' / 'payload_utils.h').read_text()
        findings['host_input']['sdk_abi_evidence'] = {
            'file': str(sdk / 'include' / 'payload_utils.h'),
            'args_structs_with_syscall_handler_first': len(re.findall(
                r'struct\s+kpayload_\w+_args\s*\{\s*void\s*\*\s*syscall_handler\s*;',
                sdk_payload_h))}

    info_block = re.search(r'typedef\s+struct\s*\{(.*?)\}\s*ps4rf_bootread_info\s*;',
                           module_h, re.S)
    observed_fields: list[tuple[str, str]] = []
    observed_raw_len = None
    if info_block:
        for line in info_block.group(1).splitlines():
            m = re.match(r'\s*(u?int(?:8|16|32|64)_t)\s+(\w+)\s*(\[[^\]]*\])?\s*;', line)
            if m:
                observed_fields.append((m.group(2), m.group(1)))
                if m.group(3) == '[PS4RF_BOOTREAD_READ_LEN]':
                    observed_raw_len = read_len_src
    findings['host_input']['info_fields'] = [{'name': n, 'type': t} for n, t in observed_fields]
    if [(n, t) for n, t in observed_fields] != [(n, t) for n, t in BOOTREAD_EXPECTED_INFO_FIELDS]:
        problems.append('W11.2 info layout: observed fields '
                        + str([(n, t) for n, t in observed_fields]) + ' (expected '
                        + str(list(BOOTREAD_EXPECTED_INFO_FIELDS)) + ')')
    if observed_raw_len != BOOTREAD_FIXED_LEN:
        problems.append('W11.2 info layout: raw[] length ' + str(observed_raw_len)
                        + ' (expected ' + str(BOOTREAD_FIXED_LEN) + ')')

    event_keys = re.findall(r'jval_obj_set\(event,\s*"([^"]+)"', module_c)
    findings['host_input'].update({
        'event_key_count': len(event_keys),
        'event_keys': sorted(event_keys),
        'event_keys_missing': sorted(BOOTREAD_EXPECTED_EVENT_KEYS - set(event_keys)),
        'event_keys_added': sorted(set(event_keys) - BOOTREAD_EXPECTED_EVENT_KEYS),
    })
    if findings['host_input']['event_keys_added'] or findings['host_input']['event_keys_missing']:
        problems.append('W11.2 event schema: keys changed (added: '
                        + ','.join(findings['host_input']['event_keys_added']) + '; missing: '
                        + ','.join(findings['host_input']['event_keys_missing']) + ')')
    if 'jval_get' in module_c_code:
        problems.append('W11.2 host input: ps4rf_bootread.c reads a jval (no host input may '
                        'reach the module)')
    if 'kbase_sdk = get_kernel_base();' not in module_c_code:
        problems.append('W11.2 host input: kbase_sdk is not filled from get_kernel_base()')
    start = agent_c.find('if (!bootread_done')
    block = ''
    if start >= 0:
        end = agent_c.find('#endif', start)
        block = agent_c[start:end if end > 0 else start + 4000]
    findings['host_input']['agent_bootread_block_found'] = bool(block)
    if not block:
        problems.append('W11.2 agent: no bootread trigger block found in ps4rf_agent.c')
    else:
        guard_pos = block.find('bootread_done = 1;')
        call_pos = block.find('ps4rf_bootread_run(')
        checks = {
            'trigger_is_session_status': 'ps4rf_op_is(request_op, "session.status")' in block,
            'one_shot_set_before_run': 0 <= guard_pos < call_pos,
            'no_request_field_read': 'jval_get' not in block,
            'run_call_shape': 'ps4rf_bootread_run(&g_bootread_info, wall)' in block,
        }
        findings['host_input']['agent_block_checks'] = checks
        for name, ok in checks.items():
            if not ok:
                problems.append('W11.2 agent: bootread block check failed: ' + name)
    wire_mentions = [name for name in ('ps4rf_protocol.c', 'ps4rf_protocol.h')
                     if 'bootread' in (repo_root / 'native' / 'src' / name)
                     .read_text().lower()]
    findings['host_input']['frozen_wire_bootread_mentions'] = wire_mentions
    if wire_mentions:
        problems.append('W11.2 wire protocol: frozen wire sources mention bootread: '
                        + ','.join(wire_mentions))

    # --- 8. one-shot guard set before the single kexec call, no retry -----------------------
    assignments = re.findall(r'g_ps4rf_bootread_called\s*=\s*(\d+)', module_c_code)
    guard_set_pos = module_c_code.find('g_ps4rf_bootread_called = 1;')
    kexec_call_pos = module_c_code.find('= kexec(')
    source_call_sites = len(re.findall(r'=\s*kexec\s*\(', module_c_code))
    findings['one_shot'] = {
        'source_assignments': assignments,
        'source_kexec_call_sites': source_call_sites,
        'guard_set_before_kexec_in_source': 0 <= guard_set_pos < kexec_call_pos,
        'goto_in_module': bool(re.search(r'\bgoto\b', module_c_code)),
    }
    if assignments != ['0', '1']:
        problems.append('W11.2 one-shot: g_ps4rf_bootread_called assignments ' + str(assignments)
                        + ' (expected exactly the declaration 0 and the one guard set 1; a reset '
                        'would allow a retry)')
    if not findings['one_shot']['guard_set_before_kexec_in_source']:
        problems.append('W11.2 one-shot: the guard is not set before kexec in the source')
    if source_call_sites != 1:
        problems.append('W11.2 one-shot: ' + str(source_call_sites)
                        + ' kexec call site(s) in the module source (expected exactly 1)')
    if findings['one_shot']['goto_in_module']:
        problems.append('W11.2 one-shot: goto in the module (a retry path)')
    guard_refs = [(func, addr, insn) for func, addr, insn in rows
                  if '<g_ps4rf_bootread_called>' in insn]
    guard_writes = [r for r in guard_refs if re.search(r'\bmov\w*\s+\$0x1,', r[2])]
    guard_reads = [r for r in guard_refs if re.search(r'\bcmp', r[2])]
    findings['one_shot']['binary'] = {
        'symbol_references': [{'function': f, 'addr': hex(a), 'insn': t}
                              for f, a, t in guard_refs],
        'writes': len(guard_writes),
        'reads': len(guard_reads),
    }
    if len(guard_writes) != 1:
        problems.append('W11.2 one-shot: ' + str(len(guard_writes))
                        + ' store(s) to the guard symbol in the image (expected 1)')
    if payload_kexec and guard_writes:
        call_func, call_addr, _ = payload_kexec[0]
        guard_func, guard_addr, _t = guard_writes[0]
        if not (guard_func == call_func and guard_addr < call_addr):
            problems.append('W11.2 one-shot: the guard store does not sit before the kexec call '
                            '(guard ' + guard_func + '@' + hex(guard_addr) + ', kexec '
                            + call_func + '@' + hex(call_addr) + ')')

    # --- 9. bounded result block: derived layout vs binary, compile-time assert -------------
    sizes = {'uint32_t': 4, 'int32_t': 4, 'uint64_t': 8, 'int64_t': 8, 'uint8_t': 1, 'int8_t': 1}
    field_rows: list[tuple[str, int, int]] = []
    for name, typ in BOOTREAD_EXPECTED_INFO_FIELDS:
        size = observed_raw_len if (name == 'raw' and observed_raw_len) else sizes[typ]
        align = 8 if size == 8 else (4 if size == 4 else 1)
        field_rows.append((name, size, align))
    layout = _sysv_layout(field_rows)
    run_rows = by_func.get('ps4rf_bootread_run', [])
    clear_bound = [(hex(a), t) for a, t in run_rows
                   if re.search(r'\bcmpq?\s+\$0x' + format(layout['size'], 'x') + r'\b', t)]
    guard_store_offset = None
    if guard_value is not None:
        for i, (_a, t) in enumerate(cb_rows):
            if f'${hex(guard_value)}' in t:
                for _a2, t2 in cb_rows[i + 1:i + 3]:
                    m = re.search(r'mov\s+%rax,0x([0-9a-f]+)\(%rbx\)', t2)
                    if m:
                        guard_store_offset = int(m.group(1), 16)
                        break
    magic_out_store_offset = None
    if magic_out_value is not None:
        for _a, t in cb_rows:
            m = re.search(r'movq\s+\$0x' + format(magic_out_value, 'x')
                          + r',0x([0-9a-f]+)\(%rbx\)', t)
            if m:
                magic_out_store_offset = int(m.group(1), 16)
                break
    rbx_offsets = sorted({int(m, 16) for _a, t in cb_rows
                          for m in re.findall(r'0x([0-9a-f]+)\(%rbx', t)})
    assert_hits = []
    for rel in ('native/target/ps4rf_bootread.c', 'native/target/ps4rf_bootread.h',
                'native/target/ps4rf_agent.c'):
        text = (repo_root / rel).read_text()
        for m in re.finditer(r'sizeof\s*\(\s*ps4rf_bootread_info\s*\)', text):
            context = text[max(0, m.start() - 300):m.end() + 300]
            if ('_Static_assert' in context or 'static_assert' in context
                    or re.search(r'typedef\s+char\s+\w+\s*\[', context)):
                assert_hits.append(f'{rel}:{text[:m.start()].count(chr(10)) + 1}')
    findings['result_block'] = {
        'derived_size': layout['size'],
        'derived_offsets': {name: hex(off) for name, off in layout['offsets'].items()},
        'binary_clear_bound_sites': [{'addr': a, 'insn': t} for a, t in clear_bound],
        'binary_guard_store_offset': hex(guard_store_offset) if guard_store_offset is not None else None,
        'binary_magic_out_store_offset': hex(magic_out_store_offset)
        if magic_out_store_offset is not None else None,
        'callback_rbx_offsets': [hex(o) for o in rbx_offsets],
        'compile_time_asserts': assert_hits,
    }
    if not clear_bound:
        problems.append('W11.2 layout: no cmp $0x' + format(layout['size'], 'x')
                        + ' zeroing-loop bound in ps4rf_bootread_run (the '
                        + str(layout['size']) + ' byte block clear)')
    if guard_store_offset is not None and guard_store_offset != layout['offsets']['guard']:
        problems.append('W11.2 layout: guard stored at +' + hex(guard_store_offset)
                        + ', derived offset +' + hex(layout['offsets']['guard']))
    if magic_out_store_offset is not None and magic_out_store_offset != layout['offsets']['magic_out']:
        problems.append('W11.2 layout: magic_out stored at +' + hex(magic_out_store_offset)
                        + ', derived offset +' + hex(layout['offsets']['magic_out']))
    if rbx_offsets and rbx_offsets[-1] >= layout['size']:
        problems.append('W11.2 layout: callback writes/reads +' + hex(rbx_offsets[-1])
                        + ' past the ' + str(layout['size']) + ' byte block')
    if not assert_hits:
        problems.append('W11.2 result block: no compile-time sizeof assertion for '
                        'ps4rf_bootread_info (checked ps4rf_bootread.c/.h and ps4rf_agent.c); add '
                        'e.g. "typedef char ps4rf_bootread_info_is_' + str(layout['size'])
                        + '[(sizeof(ps4rf_bootread_info) == ' + str(layout['size'])
                        + ') ? 1 : -1];"')
    repro: dict[str, Any] = {
        'checked': False,
        'note': "build_ps4.sh builds twice and cmp's ELF+BIN (a REPRO FAIL stops the build before "
                'the manifest); pass --repro-elf <second ELF> to record the comparison here',
    }
    if repro_elf is not None:
        same = sha256_file(elf) == sha256_file(repro_elf) and elf.read_bytes() == repro_elf.read_bytes()
        repro = {'checked': True, 'identical': same, 'elf_sha256': sha256_file(elf),
                 'repro_elf': str(repro_elf), 'repro_elf_sha256': sha256_file(repro_elf)}
        if not same:
            problems.append('W11.2 reproducibility: ' + str(repro_elf)
                            + ' is not byte-identical to ' + str(elf))
    findings['reproducibility'] = repro

    findings['ok'] = not problems
    return findings


KREAD_STORE_ALLOWED_BASES_CALLBACK = ('info', 'stack')
KREAD_NON_STORE_MNEMONICS = ('cmp', 'cmpq', 'cmpl', 'cmpb', 'cmpw', 'test', 'testq', 'testl',
                             'testb', 'lea', 'lea q', 'nop', 'nopl', 'nopw', 'ret', 'retq',
                             'call', 'callq', 'jmp', 'jmpq', 'je', 'jne', 'jb', 'jbe', 'ja',
                             'jae', 'js', 'jns', 'jl', 'jle', 'jg', 'jge', 'jz', 'jnz')


def _kread_stores(rows: list[tuple[int, str]]) -> list[dict[str, str]]:
    """Every instruction that stores to memory, with the base register of its destination.

    In AT&T syntax the destination is the last operand; an operand carrying '(' and not starting
    with '$' is a memory destination. Compares, tests and lea carry memory operands without
    storing, and are excluded; push writes the payload's own frame, which is recorded as such.
    """
    stores: list[dict[str, str]] = []
    for addr, insn in rows:
        parts = insn.split(' ', 1)
        mnemonic = parts[0]
        operands = parts[1] if len(parts) > 1 else ''
        if mnemonic == 'push':
            stores.append({'addr': hex(addr), 'insn': insn, 'base': 'rsp',
                           'kind': 'own-frame'})
            continue
        if mnemonic in KREAD_NON_STORE_MNEMONICS or mnemonic.startswith('j'):
            continue
        last = operands.split(',')[-1].strip()
        if '(' not in last or last.startswith('$'):
            continue
        base = re.search(r'\(%(\w+)', last)
        base_reg = base.group(1) if base else '?'
        stores.append({'addr': hex(addr), 'insn': insn, 'base': base_reg,
                       'kind': 'frame' if base_reg in ('rsp', 'rbp') else 'memory'})
    return stores


def gate_w17(elf: pathlib.Path, profile: str, *, sdk: pathlib.Path | None = None,
             repro_elf: pathlib.Path | None = None,
             providers: frozenset[str] = frozenset()) -> dict[str, Any]:
    """W17 gates: the two generic research primitives really reach their providers.

    The wave rule is that route metadata alone is NOT a wiring: this gate reads the linked image and
    the sources and requires (a) the dispatch to name both operations, (b) the stub's handlers to
    call the providers, (c) the provider platform seams to keep the architecture's rules -- no
    syscall, no privileged transition in the device path, exactly one open/ioctl/close per request,
    a provider-owned transfer buffer in .bss whose address is the only pointer the device sees --
    and (d) the request surface to stay address free: neither operation accepts an address, and
    neither accepts a function/selector that could become a generic kernel call.
    """
    repo_root = pathlib.Path(__file__).resolve().parents[2]
    tgt = repo_root / 'native' / 'target'
    findings: dict[str, Any] = {'profile': profile, 'problems': [], 'notes': [],
                                'providers': sorted(providers)}
    problems: list[str] = findings['problems']
    want_recipe = 'recipe' in providers
    want_ioctl = 'ioctl' in providers
    binding_gate = 'binding' in providers
    findings['binding_gate'] = binding_gate
    if (want_recipe or want_ioctl) and not binding_gate:
        findings['notes'].append('provider build without the lifetime boot-binding gate: the wave '
                                 'reports the binding as an observation (see the W15R3 evidence)')
    if not (want_recipe or want_ioctl):
        findings['notes'].append('the build does not declare the W17 providers '
                                 '(no recipe, no ioctl): the W17 wiring gate did not run')
        return findings
    if not (tgt / 'ps4rf_recipe_target.c').exists():
        findings['notes'].append('W17 modules absent: the gate did not run')
        return findings
    findings['requested'] = {'recipe': want_recipe, 'ioctl': want_ioctl}

    disassembly = run(['objdump', '-d', '--no-show-raw-insn', str(elf)])
    rows = _disasm_rows(disassembly)
    by_func: dict[str, list[tuple[int, str]]] = {}
    for func, addr, insn in rows:
        by_func.setdefault(func, []).append((addr, insn))
    defined = set()
    for line in run(['nm', str(elf)]).splitlines():
        parts = line.split()
        if len(parts) >= 3:
            defined.add(parts[2])

    def call_targets(func: str) -> set[str]:
        """Direct call and tail-jump targets of a function (a leaf that tail-calls keeps its
        single call site's meaning)."""
        out = set()
        for _a, insn in by_func.get(func, []):
            m = re.search(r'\b(callq?|jmpq?)\s+[0-9a-f]+\s+<([^>]+)>', insn)
            if m:
                out.add(m.group(2).split('+')[0])
        return out

    stub_c = _strip_c_comments((tgt / 'ps4rf_stub.c').read_text())
    recipe_c = _strip_c_comments((tgt / 'ps4rf_recipe.c').read_text())
    recipe_target_c = _strip_c_comments((tgt / 'ps4rf_recipe_target.c').read_text())
    ioctl_c = _strip_c_comments((tgt / 'ps4rf_ioctl.c').read_text())
    ioctl_ps4_c = _strip_c_comments((tgt / 'ps4rf_ioctl_ps4.c').read_text())
    optable = (tgt / 'ps4rf_optable_data.h').read_text()

    # --- (a) the dispatch names both operations ------------------------------------------------
    findings['routes'] = {op: [ln.strip() for ln in optable.splitlines()
                               if '"%s"' % op in ln and 'PS4RF_ROUTE' in ln]
                          for op in ('kernel.snapshot.recipe', 'ioctl.invoke')}
    for op in ('kernel.snapshot.recipe', 'ioctl.invoke'):
        row = [ln for ln in optable.splitlines() if '"%s"' % op in ln and 'PS4RF_ROUTE' in ln]
        if not row:
            problems.append('W17 route: no op table row for ' + op)
            continue
        if 'PS4RF_ROUTE_PRIVILEGED_PROVIDER' not in row[0]:
            problems.append('W17 route: ' + op + ' is not routed to a privileged provider: '
                            + row[0].strip())
        if 'PS4RF_TARGET_WIRED' not in row[0]:
            problems.append('W17 route: ' + op + ' is not wired in the target table: '
                            + row[0].strip())
        if op not in stub_c:
            problems.append('W17 dispatch: the stub does not name ' + op)
        if op not in optable:
            problems.append('W17 dispatch: the generated table does not carry ' + op)

    handlers = {'kernel.snapshot.recipe': 'op_kernel_snapshot_recipe',
                'ioctl.invoke': 'op_ioctl_invoke'}
    for op, handler in handlers.items():
        if handler not in stub_c:
            problems.append('W17 dispatch: the stub defines no handler ' + handler + ' for ' + op)
    invoke_calls = call_targets('ps4rf_stub_invoke')
    findings['stub_invoke_calls'] = sorted(invoke_calls)
    findings['handlers_inlined'] = {h: (h not in defined) for h in handlers.values()}
    for handler in handlers.values():
        # -Os inlines a handler into the dispatch; the requirement is that the dispatch path
        # reaches the provider, which is checked below either way
        if handler not in defined and handler not in invoke_calls:
            findings['notes'].append(handler + ' is inlined into the dispatch (its provider call '
                                      'is checked below)')
    required = []
    if want_recipe:
        required += [('ps4rf_recipe_run', 'the recipe provider'),
                     ('ps4rf_recipe_target_kbase', 'the platform kernel base'),
                     ('ps4rf_recipe_target_read_fn', 'the read seam')]
    if want_ioctl:
        required += [('ps4rf_ioctl_invoke', 'the ioctl provider'),
                     ('ps4rf_ioctl_stage', 'the provider-owned staging'),
                     ('ps4rf_ioctl_target_ops', 'the platform layer')]
    for provider, note in tuple(required):
        reached = provider in invoke_calls or provider in call_targets('op_kernel_snapshot_recipe') \
            or provider in call_targets('op_ioctl_invoke')
        findings.setdefault('provider_calls', {})[provider] = reached
        if not reached:
            problems.append('W17 dispatch: ' + note + ' (' + provider
                            + ') is not called on the dispatch path')

    # --- (b) the request surface stays address free and offers no generic kernel call ----------
    arg_rows = re.findall(r'\{"(\w+)",\s*PS4RF_T_\w+,\s*[01]\},\s*/\*\s*([a-z0-9_.]+)\s*\*/',
                          optable)
    args_by_op: dict[str, list[str]] = {}
    for name, op in arg_rows:
        args_by_op.setdefault(op, []).append(name)
    findings['args'] = {op: args_by_op.get(op, []) for op in handlers}
    expected_args = {}
    if want_recipe:
        expected_args['kernel.snapshot.recipe'] = ['recipe_ref', 'indices']
    if want_ioctl:
        expected_args['ioctl.invoke'] = ['command', 'blob', 'mode', 'data']
    for op, names in expected_args.items():
        have = args_by_op.get(op, [])
        if sorted(have) != sorted(names):
            problems.append('W17 request surface: ' + op + ' args ' + repr(have)
                            + ' (expected exactly ' + repr(names) + ')')
    addressish = [f'{op}:{n}' for op, names in args_by_op.items() if op in handlers
                  for n in names if KREAD_ADDRESS_KEY_PATTERN.search(n)]
    findings['addressish_args'] = addressish
    if addressish:
        problems.append('W17 request surface: address-like argument(s): ' + ','.join(addressish))
    forbidden_names = re.compile(r'(func|fn|call|kexec|syscall|sysret|msr|opcode|shellcode|'
                                 r'payload|inject|write_?kernel|wrmsr|cr[0-9]|select)', re.I)
    generic = [f'{op}:{n}' for op, names in args_by_op.items() if op in handlers
               for n in names if forbidden_names.search(n)]
    findings['generic_call_args'] = generic
    if generic:
        problems.append('W17 request surface: argument(s) that could turn into a generic kernel '
                        'call: ' + ','.join(generic))

    # --- (c) the ioctl platform seam: one device call per request, no privilege ---------------
    platform_funcs = {'ps4_open': ('open',), 'ps4_call': ('ioctl',), 'ps4_close': ('close',)} \
        if want_ioctl else {}
    for func, expected in platform_funcs.items():
        if func not in defined:
            problems.append('W17 platform: ' + func + ' is not defined in the image')
            continue
        targets = call_targets(func)
        for want in expected:
            if want not in targets:
                problems.append('W17 platform: ' + func + ' does not call ' + want)
    platform_rows = [insn for _a, insn in by_func.get('ps4_call', [])]
    platform_rows += [insn for _a, insn in by_func.get('ps4_open', [])]
    platform_rows += [insn for _a, insn in by_func.get('ps4_close', [])]
    privileged = [insn for insn in platform_rows
                  if re.search(r'\b(rdmsr|wrmsr|syscall|sysret)\b', insn)]
    findings['platform_privileged_sites'] = privileged
    if privileged:
        problems.append('W17 platform: privileged instruction in the device path: '
                        + '; '.join(privileged))
    sizes = {m.group(3): (int(m.group(1), 16), int(m.group(2), 16))
             for m in re.finditer(r'^([0-9a-f]+)\s+([0-9a-f]+)\s+[bB]\s+(\w+)$',
                                  run(['nm', '-S', str(elf)]), re.M)}
    transfer = sizes.get('g_transfer')
    ioctl_h = (tgt / 'ps4rf_ioctl.h').read_text()
    want_bytes = int(re.search(r'#define\s+PS4RF_IOCTL_MAX_DATA\s+0x([0-9a-fA-F]+)',
                               ioctl_h).group(1), 16)
    block_offset = int(re.search(r'#define\s+PS4RF_IOCTL_MAX_DATA\s+0x([0-9a-fA-F]+)',
                                 ioctl_h).group(1), 16)
    align = int(re.search(r'#define\s+PS4RF_IOCTL_ALIGN\s+0x([0-9a-fA-F]+)u',
                          ioctl_h).group(1), 16)
    _do = re.search(r'#define\s+PS4RF_IOCTL_DATA_OFFSET\s+(0x[0-9a-fA-F]+|\d+)u?', ioctl_h)
    data_offset = int(_do.group(1), 0) if _do else 0
    _bo = re.search(r'#define\s+PS4RF_IOCTL_BLOCK_OFFSET\s+(0x[0-9a-fA-F]+|\d+)u?', ioctl_h)
    if _bo:
        block_offset = int(_bo.group(1), 0)
    elif 'PS4RF_IOCTL_BLOCK_OFFSET' in ioctl_h:
        problems.append('W18 platform: the block offset is not a literal this gate can read')
    want_bytes += block_offset
    # W18: the driver holds the staged address to a 0x4000 boundary (gpuvm map: cpuaddr alignment)
    # before it maps one unit of that size. The provider therefore aligns the payload region at run
    # time inside the transfer object (and refuses a request that would not fit behind the
    # boundary), which is what keeps the object PS4RF_IOCTL_XFER_BYTES bytes.
    if data_offset >= align:
        problems.append('W18 platform: the payload region starts at ' + hex(data_offset)
                        + ', which is not inside the first ' + hex(align) + ' boundary')
    if '& ~(uintptr_t)(PS4RF_IOCTL_ALIGN - 1u)' not in (tgt / 'ps4rf_ioctl.c').read_text():
        problems.append('W18 provider: the staged payload region is not aligned to PS4RF_IOCTL_ALIGN')
    if 'static uint8_t g_transfer[PS4RF_IOCTL_XFER_BYTES] PS4RF_IOCTL_ALIGNED' in ioctl_ps4_c:
        problems.append('W18 platform: the transfer object carries a compile-time alignment, which '
                        'no longer matches the run-time alignment the provider performs')
    findings['transfer_buffer'] = {'symbol': bool(transfer), 'bytes': transfer[1] if transfer else 0,
                                   'required': want_bytes}
    if not transfer:
        problems.append('W17 platform: no provider-owned transfer buffer in .bss')
    elif transfer[1] < want_bytes:
        problems.append('W17 platform: the transfer buffer is ' + hex(transfer[1])
                        + ' bytes (expected at least ' + hex(want_bytes) + ')')
    if not want_ioctl:
        findings['transfer_buffer']['note'] = 'the ioctl provider is not part of this build'
    elif 'static uint8_t g_transfer[PS4RF_IOCTL_XFER_BYTES]' not in ioctl_ps4_c:
        problems.append('W17 platform: the transfer buffer is not the documented compile-time '
                        'object of the platform layer')
    if 'static const ps4rf_ioctl_ops' in ioctl_ps4_c or 'static const ps4rf_ioctl_ops' in \
            (tgt / 'ps4rf_ioctl_host.c').read_text():
        problems.append('W17 platform: the ops table is const data (a function pointer table in '
                        '.data.rel.ro forces a dynamic relocation into an artefact without a '
                        'loader)')
    if '(uint8_t)(((uint64_t)region >> (8u * i)) & 0xffu)' not in ioctl_c or \
            'uintptr_t region = ((uintptr_t)buf' not in ioctl_c:
        problems.append('W18 provider: the pointer field is not filled from the address of the '
                        'provider-owned, boundary-aligned payload region')
    if 'ptr' in re.sub(r'PS4RF_IOCTL_NO_PTR_FIELD|ptr_field|data_max|_ptr_|no pointer',
                       '', ioctl_c) and 'rule->ptr_field' not in ioctl_c:
        problems.append('W17 provider: the pointer field handling is not the documented one')
    if 'blob + ' in ioctl_c or 'memcpy(buf + PS4RF_IOCTL_BLOCK_OFFSET, blob, blob_len)' not in ioctl_c:
        problems.append('W17 provider: the argument block is not copied into the provider-owned '
                        'buffer')
    leaf_syscalls = [f'{f}@{hex(a)}' for f, a, insn in rows
                     if f in IOCTL_LEAVES + IOCTL_PLATFORM_LEAVES
                     and re.search(r'\b(syscall|rdmsr|wrmsr|kexec)\b', insn)]
    findings['ioctl_forbidden_sites'] = leaf_syscalls
    if leaf_syscalls:
        problems.append('W17 provider/platform: privileged or raw call in the device path: '
                        + ','.join(leaf_syscalls))

    # --- (d) the recipe driver's kernel section ------------------------------------------------
    cb_rows = by_func.get(RECIPE_CALLBACK, [])
    findings['recipe_callback'] = {'rows': len(cb_rows)}
    if not cb_rows:
        problems.append('W17 recipe: no disassembly for ' + RECIPE_CALLBACK)
    else:
        targets: dict[str, list[str]] = {}
        indirect: list[str] = []
        for addr, insn in cb_rows:
            if re.search(r'\b(callq?|jmpq?)\s+\*', insn):
                indirect.append(f'{hex(addr)} {insn}')
            m = re.search(r'\bcallq?\s+[0-9a-f]+\s+<([^>]+)>', insn)
            if m:
                targets.setdefault(m.group(1).split('+')[0], []).append(hex(addr))
        findings['recipe_callback'] = {'targets': sorted(targets), 'indirect': indirect,
                                       'read8_sites': targets.get('ps4rf_recipe_k_read8', [])}
        bad = [t for t in targets if t not in ('ps4rf_recipe_k_read8',)]
        if bad:
            problems.append('W17 recipe callback: call target(s) outside the declared leaf: '
                            + ','.join(bad))
        if 'ps4rf_recipe_k_read8' not in targets:
            problems.append('W17 recipe callback: no call to its declared read leaf')
        if len(targets.get('ps4rf_recipe_k_read8', [])) != 1:
            problems.append('W17 recipe callback: '
                            + str(len(targets.get('ps4rf_recipe_k_read8', [])))
                            + ' read leaf call site(s) (expected exactly one bounded copy loop)')
        if indirect:
            problems.append('W17 recipe callback: indirect call/jump: ' + '; '.join(indirect))
        for bad_target in KREAD_FORBIDDEN_CALL_TARGETS:
            if any(t.lower().startswith(bad_target) for t in targets):
                problems.append('W17 recipe callback: forbidden helper ' + bad_target)
    msr_in_recipe = [f'{f}@{hex(a)}' for f, a, insn in rows
                     if f.startswith('ps4rf_recipe') and re.search(r'\b(rdmsr|wrmsr)\b', insn)]
    findings['recipe_msr_sites'] = msr_in_recipe
    if msr_in_recipe:
        problems.append('W17 recipe: msr access in the recipe modules (the base comes from the '
                        'platform): ' + ','.join(msr_in_recipe))
    seam_sites = recipe_target_c.count('kexec((void *)')
    findings['seam_kexec_sites'] = seam_sites
    if seam_sites != 1:
        problems.append('W17 recipe: the read seam holds ' + str(seam_sites)
                        + ' kexec call site(s) (expected exactly 1)')
    if 'PS4RF_RECIPE_XFER_BUDGET' not in recipe_target_c:
        problems.append('W17 recipe: the per-request transition budget is not enforced in the seam')
    if 'PS4RF_RECIPE_INDEX_SLOTS' not in stub_c:
        problems.append('W17 recipe: the dispatch does not bound the index list')
    if 'recipe->first' not in stub_c:
        problems.append('W17 recipe: the dispatch does not resolve the recipe name to a table slice')
    if 'ps4rf_recipe_target_kbase' not in stub_c:
        problems.append('W17 recipe: the dispatch does not obtain the kernel base from the platform')
    findings['source_sha256'] = {
        'native/target/ps4rf_recipe.c': sha256_file(tgt / 'ps4rf_recipe.c'),
        'native/target/ps4rf_recipe_target.c': sha256_file(tgt / 'ps4rf_recipe_target.c'),
        'native/target/ps4rf_ioctl.c': sha256_file(tgt / 'ps4rf_ioctl.c'),
        'native/target/ps4rf_ioctl_ps4.c': sha256_file(tgt / 'ps4rf_ioctl_ps4.c'),
        'native/target/ps4rf_ioctl_policy_data.h': sha256_file(tgt / 'ps4rf_ioctl_policy_data.h'),
        'native/target/ps4rf_recipe_data.h': sha256_file(tgt / 'ps4rf_recipe_data.h'),
    }
    return findings


def gate_kread(elf: pathlib.Path, profile: str, *, sdk: pathlib.Path | None = None,
               repro_elf: pathlib.Path | None = None) -> dict[str, Any]:
    """W12 gates: one bounded kernel.read provider, one privileged callback, one region table.

    Every number is measured from the linked ELF (objdump/nm) and from the sources; the checks the
    wave checklist names explicitly are marked with their item number.
    """
    repo_root = pathlib.Path(__file__).resolve().parents[2]
    tgt = repo_root / 'native' / 'target'
    findings: dict[str, Any] = {'profile': profile, 'problems': [],
                                'review_checklist_coverage': {}, 'brief_scope_notes': []}
    problems: list[str] = findings['problems']

    module_c = (tgt / 'ps4rf_kread.c').read_text()
    module_h = (tgt / 'ps4rf_kread.h').read_text()
    module_c_code = _strip_c_comments(module_c)
    module_h_code = _strip_c_comments(module_h)
    agent_c = (tgt / 'ps4rf_agent.c').read_text()
    agent_h = (tgt / 'ps4rf_agent.h').read_text()
    host_c = (tgt / 'ps4rf_kread_host.c').read_text()
    findings['source_sha256'] = {
        'native/target/ps4rf_kread.c': sha256_file(tgt / 'ps4rf_kread.c'),
        'native/target/ps4rf_kread.h': sha256_file(tgt / 'ps4rf_kread.h'),
        'native/target/ps4rf_kread_host.c': sha256_file(tgt / 'ps4rf_kread_host.c'),
        'native/target/ps4rf_agent.c': sha256_file(tgt / 'ps4rf_agent.c'),
        'native/target/build_ps4.sh': sha256_file(tgt / 'build_ps4.sh'),
        'native/target/build_host.sh': sha256_file(tgt / 'build_host.sh'),
    }

    disassembly = run(['objdump', '-d', '--no-show-raw-insn', str(elf)])
    rows = _disasm_rows(disassembly)
    by_func: dict[str, list[tuple[int, str]]] = {}
    for func, addr, insn in rows:
        by_func.setdefault(func, []).append((addr, insn))
    defined_set: set[str] = set()
    undefined_set: set[str] = set()
    for line in run(['nm', '-P', str(elf)]).splitlines():
        parts = line.split()
        if len(parts) >= 2:
            (defined_set if parts[1] != 'U' else undefined_set).add(parts[0])

    # source constants the checks below are pinned to
    # the single normative source for the bound: the registry file the generator reads
    registry_h = (repo_root / 'tools/profiles/regions.py')
    registry_text = registry_h.read_text()
    registry_bound = re.search(r'^MAX_READ_LEN\s*=\s*(\d+)', registry_text, re.M)
    registry_bound = int(registry_bound.group(1)) if registry_bound else None
    regions_h_path = tgt / 'ps4rf_kread_regions.h'
    regions_h_text = regions_h_path.read_text() if regions_h_path.exists() else ''
    header_bound = re.search(r'#define\s+PS4RF_KREAD_MAX_LEN\s+(\d+)', regions_h_text)
    header_bound = int(header_bound.group(1)) if header_bound else None
    max_len_src = registry_bound          # every check below compares against the owner's value
    guard_define = re.search(r'#define\s+PS4RF_KREAD_GUARD\s+0x([0-9a-fA-F]+)', module_h_code)
    guard_value = int(guard_define.group(1), 16) if guard_define else None
    magic_out_define = re.search(r'#define\s+PS4RF_KREAD_MAGIC_OUT\s+0x([0-9a-fA-F]+)',
                                 module_h_code)
    magic_out_value = int(magic_out_define.group(1), 16) if magic_out_define else None
    xfast_define = re.search(r'#define\s+PS4RF_KREAD_XFAST_RVA\s+0x([0-9a-fA-F]+)', module_c_code)
    xfast_value = int(xfast_define.group(1), 16) if xfast_define else None

    # --- 1. exactly one kexec site, one syscall 11 (checklist 7/9/13: no arbitrary call) -----
    kexec_calls = [(func, addr, insn) for func, addr, insn in rows
                   if re.search(r'\bcallq?\s+[0-9a-f]+\s+<kexec>', insn)]
    payload_kexec = [site for site in kexec_calls if site[0].startswith('ps4rf_')]
    sdk_kexec = [site for site in kexec_calls if site[0] in KREAD_SDK_KEXEC_ALLOWANCE]
    kernel_kexec = [site for site in kexec_calls if site[0].startswith('ps4rf_kread_k')]
    findings['kexec'] = {
        'image_call_sites': [{'addr': hex(a), 'function': f} for f, a, _ in kexec_calls],
        'payload_call_sites': [{'addr': hex(a), 'function': f} for f, a, _ in payload_kexec],
        'sdk_allowances': [{'addr': hex(a), 'function': f,
                            'reason': 'libPS4 get_kernel_base() internal transition '
                                      '(the required cross-check drags it in; W11.2 allowance)'}
                           for f, a, _ in sdk_kexec],
    }
    drivers_here = [d for d in PRIVILEGED_DRIVERS if driver_present(defined_set, d)]
    sites_by_driver: dict[str, list] = {}
    for site in payload_kexec:
        sites_by_driver.setdefault(site[0], []).append(site)
    expected_runs = sorted(d['run'] for d in drivers_here)
    if sorted(sites_by_driver) != expected_runs:
        problems.append('W12 kexec: payload-owned call sites in '
                        + ','.join(sorted(sites_by_driver)) + ' (expected exactly one per '
                        'compiled-in driver: ' + ','.join(expected_runs) + ')')
    for run_fn, sites in sorted(sites_by_driver.items()):
        if len(sites) != 1:
            problems.append(f'W12 kexec: {len(sites)} payload-owned call site(s) in {run_fn} '
                            '(expected exactly one)')
    kernel_kexec = [site for site in kexec_calls
                    if any(kernel_section_symbol(site[0], d) for d in drivers_here)]
    findings['kexec']['drivers'] = [{'name': d['name'], 'run': d['run'],
                                     'callback': d['callback']} for d in drivers_here]
    if kernel_kexec:
        problems.append('W12 kexec: call site inside a kernel section: '
                        + ', '.join(f'{f}@{hex(a)}' for f, a, _ in kernel_kexec))
    outside = [site for site in kexec_calls if not site[0].startswith('ps4rf_')
               and site[0] not in KREAD_SDK_KEXEC_ALLOWANCE]
    if outside:
        problems.append('W12 kexec: call site outside the payload and the documented SDK '
                        'allowance: ' + ', '.join(f'{f}@{hex(a)}' for f, a, _ in outside))
    findings['brief_scope_notes'].append(
        f'kexec: whole image has {len(kexec_calls)} call site(s) = {len(payload_kexec)} '
        f'payload-owned + {len(sdk_kexec)} SDK allowance (get_kernel_base, named in W11.2)')
    findings['kexec']['callback_pointer_windows'] = {}
    findings['kexec']['jumps_before_the_call_in_run'] = {}
    for driver in drivers_here:
        run_fn = driver['run']
        sites = sites_by_driver.get(run_fn)
        if not sites:
            continue
        site_func, site_addr, _ = sites[0]
        site_rows = by_func.get(site_func, [])
        idx = next((i for i, (a, _t) in enumerate(site_rows) if a == site_addr), 0)
        window = ' ; '.join(t for _a, t in site_rows[max(0, idx - 6):idx])
        findings['kexec']['callback_pointer_windows'][run_fn] = window
        if 'lea' not in window or f"<{driver['callback']}>" not in window:
            problems.append('W12 kexec: the call site in ' + run_fn + ' does not pass &'
                            + driver['callback']
                            + ' (no lea of the callback in the 6 instructions before the call)')
        # no retry loop around the privileged transition. A backward jump alone is not a loop:
        # -Os merges the early refusals of the runner into one shared epilogue that sits before
        # the call in the listing (the W12 runner has none only because its body happens to be
        # laid out that way). The invariant is that no backward edge can flow back INTO the call:
        # for every jump that lands before it and starts after it, ask whether its target can
        # reach the call by forward control flow.
        def reaches_from(start_addr: int, goal: int) -> bool:
            order = [a for a, _i in site_rows]
            index = {a: i for i, a in enumerate(order)}
            if start_addr not in index:
                return False
            seen: set[int] = set()
            stack = [start_addr]
            while stack:
                a = stack.pop()
                if a == goal:
                    return True
                if a in seen:
                    continue
                seen.add(a)
                if a not in index:
                    continue
                i = index[a]
                insn_text = site_rows[i][1]
                mnemonic = insn_text.split()[0] if insn_text.split() else ''
                if mnemonic == 'ret':
                    continue
                target_m = re.search(r'\b(?:j\w+|jmpq?)\s+([0-9a-f]+)\s+<', insn_text)
                if mnemonic.startswith('j') and target_m:
                    tgt = int(target_m.group(1), 16)
                    if tgt in index:
                        stack.append(tgt)
                    if mnemonic.startswith('jmp'):
                        continue
                if i + 1 < len(order):
                    stack.append(order[i + 1])
            return False

        backward = []
        for addr, insn in site_rows:
            if not re.match(r'j', insn.split()[0]):
                continue
            target = re.search(r'([0-9a-f]+)\s+<', insn)
            if target and int(target.group(1), 16) < site_addr and addr > site_addr:
                if reaches_from(int(target.group(1), 16), site_addr):
                    backward.append((hex(addr), insn))
        findings['kexec']['jumps_before_the_call_in_run'][run_fn] = backward
        if backward:
            problems.append('W12 kexec: a jump targets an address before the kexec call in '
                            + run_fn + ' (a retry path): ' + '; '.join(t for _a, t in backward))
    syscall_rows = [(func, addr) for func, addr, insn in rows if re.match(r'syscall\b', insn)]
    sites11 = []
    for i, (_func, _addr, insn) in enumerate(rows):
        if re.search(r'mov\s+\$0xb,%r(?:ax|eax)\b', insn):
            nxt = rows[i + 1][2] if i + 1 < len(rows) else ''
            if 'syscall_macro' in nxt:
                sites11.append((_func, _addr))
    findings['kexec']['syscall_instructions'] = [{'addr': hex(a), 'function': f}
                                                 for f, a in syscall_rows]
    findings['kexec']['syscall11_sites'] = [{'addr': hex(a), 'function': f} for f, a in sites11]
    if len(sites11) != 1 or sites11[0][0] != 'kexec':
        problems.append(f'W12 kexec: syscall 11 sites {[(f, hex(a)) for f, a in sites11]} '
                        '(expected exactly one, the SDK kexec wrapper)')
    stray_syscalls = [f'{f}@{hex(a)}' for f, a in syscall_rows if f.startswith('ps4rf_')]
    if stray_syscalls:
        problems.append('W12: raw syscall instruction in payload code: ' + ', '.join(stray_syscalls))

    # --- 2. exactly one privileged callback symbol, no other payload entry, no other module --
    # W17F: the expected kernel section and callback set is the union over the compiled-in drivers
    drivers_all = [d for d in PRIVILEGED_DRIVERS if driver_present(defined_set, d)]
    expected_kernel_syms = sorted({sym for d in drivers_all for sym in d['kernel_symbols']})
    expected_callbacks = sorted({d['callback'] for d in drivers_all})
    kernel_syms = sorted(name for name in defined_set
                         if any(kernel_section_symbol(name, d) for d in drivers_all))
    kpayload_syms = sorted(name for name in defined_set if 'kpayload' in name)
    findings['symbols'] = {
        'kernel_section_defined': kernel_syms,
        'expected_kernel_section': expected_kernel_syms,
        'kpayload_named_defined': kpayload_syms,
        'callback_defined': KREAD_CALLBACK in defined_set,
        'other_wave_modules': sorted(name for name in defined_set
                                     if name.startswith(('ps4rf_attest', 'ps4rf_bootread',
                                                         'ps4rf_boot'))),
    }
    stray_kernel_syms = [name for name in kernel_syms if name not in expected_kernel_syms]
    if stray_kernel_syms or not set(expected_kernel_syms) <= set(kernel_syms):
        problems.append('W12 kernel section symbols: ' + ','.join(kernel_syms) + ' (expected '
                        + ','.join(expected_kernel_syms) + ')')
    missing_callbacks = [cb for cb in expected_callbacks if cb not in defined_set]
    if missing_callbacks:
        problems.append('W12 callback symbol missing: ' + ','.join(missing_callbacks))
    ps4rf_kpayloads = [name for name in kpayload_syms if name.startswith('ps4rf_')]
    if sorted(ps4rf_kpayloads) != expected_callbacks:
        problems.append('W12 callback symbols: ' + ','.join(ps4rf_kpayloads) + ' (expected '
                        'exactly ' + ','.join(expected_callbacks) + ')')
    stray_payloads = [name for name in kpayload_syms if not name.startswith('ps4rf_')
                      and name not in KREAD_SDK_KPAYLOAD_ALLOWANCE]
    if stray_payloads:
        problems.append('W12 kernel payload symbols outside the SDK allowance: '
                        + ','.join(stray_payloads))
    if findings['symbols']['other_wave_modules']:
        problems.append('W12 image carries another wave module: '
                        + ','.join(findings['symbols']['other_wave_modules']))
    if sdk is not None and (sdk / 'libPS4.a').exists():
        archive = run(['nm', str(sdk / 'libPS4.a')])
        findings['symbols']['sdk_archive_defines'] = {
            name: bool(re.search(r'\bT ' + re.escape(name) + r'\b', archive))
            for name in ('kexec', 'get_kernel_base', 'kpayload_kbase')}

    # --- 3. msr access: one payload rdmsr, zero wrmsr ---------------------------------------
    rdmsr_sites = [(func, addr) for func, addr, insn in rows if re.search(r'\brdmsr\b', insn)]
    wrmsr_sites = [(func, addr) for func, addr, insn in rows if re.search(r'\bwrmsr\b', insn)]
    rdmsr_by_func: dict[str, int] = {}
    for func, _a in rdmsr_sites:
        rdmsr_by_func[func] = rdmsr_by_func.get(func, 0) + 1
    payload_rdmsr = [(f, a) for f, a in rdmsr_sites if f.startswith('ps4rf_')]
    findings['msr'] = {
        'rdmsr_total_image': len(rdmsr_sites),
        'rdmsr_by_function': rdmsr_by_func,
        'rdmsr_payload_sites': [f'{f}@{hex(a)}' for f, a in payload_rdmsr],
        'rdmsr_sdk_allowance': sorted({f for f, _a in rdmsr_sites
                                       if f in KREAD_SDK_RDMSR_ALLOWANCE}),
        'wrmsr_total_image': len(wrmsr_sites),
        'wrmsr_sites': [f'{f}@{hex(a)}' for f, a in wrmsr_sites],
    }
    if wrmsr_sites:
        problems.append(f'W12 msr: {len(wrmsr_sites)} wrmsr instruction(s) in the image: '
                        + ', '.join(f'{f}@{hex(a)}' for f, a in wrmsr_sites))
    if [f for f, _a in payload_rdmsr] != ['ps4rf_kread_k_readmsr']:
        problems.append('W12 msr: payload rdmsr sites '
                        + ', '.join(f'{f}@{hex(a)}' for f, a in payload_rdmsr)
                        + ' (expected exactly one, in ps4rf_kread_k_readmsr)')
    if rdmsr_by_func.get('ps4rf_kread_k_readmsr', 0) != 1:
        problems.append('W12 msr: ps4rf_kread_k_readmsr holds '
                        + str(rdmsr_by_func.get('ps4rf_kread_k_readmsr', 0))
                        + ' rdmsr instruction(s) (expected 1)')
    non_allowed = [(f, a) for f, a in rdmsr_sites
                   if f != 'ps4rf_kread_k_readmsr' and f not in KREAD_SDK_RDMSR_ALLOWANCE]
    if non_allowed:
        problems.append('W12 msr: rdmsr outside the payload leaf and the SDK allowance: '
                        + ', '.join(f'{f}@{hex(a)}' for f, a in non_allowed))

    # --- 4. the callback: bounded leaves only, no indirect call, no allocator or lock -------
    cb_rows = by_func.get(KREAD_CALLBACK, [])
    if not cb_rows:
        problems.append('W12 callback: no disassembly for ' + KREAD_CALLBACK)
    allowed_calls = set(KREAD_CALLBACK_ALLOWED_CALLS)
    call_targets: dict[str, list[str]] = {}
    indirect: list[str] = []
    for addr, insn in cb_rows:
        if re.search(r'\b(callq?|jmpq?)\s+\*', insn):
            indirect.append(f'{hex(addr)} {insn}')
        m = re.search(r'\bcallq?\s+[0-9a-f]+\s+<([^>]+)>', insn)
        if m:
            call_targets.setdefault(m.group(1).split('+')[0], []).append(hex(addr))
    findings['callback_calls'] = {
        'targets': {t: sites for t, sites in sorted(call_targets.items())},
        'allowed_targets': sorted(allowed_calls),
        'indirect_calls': indirect,
        'read8_call_sites': [hex(a) for a, t in cb_rows if '<ps4rf_kread_k_read8>' in t],
        'readmsr_call_sites': [hex(a) for a, t in cb_rows if '<ps4rf_kread_k_readmsr>' in t],
    }
    bad_targets = [t for t in sorted(call_targets) if t not in allowed_calls]
    missing_calls = [t for t in KREAD_WEAK_LEAVES if t not in call_targets]
    if bad_targets:
        problems.append('W12 callback: call target(s) outside the allowed module leaves '
                        '(no allocator, no locking, no memcpy/memset, no external helper): '
                        + ', '.join(bad_targets))
    if missing_calls:
        problems.append('W12 callback: missing expected call to ' + ', '.join(missing_calls))
    if indirect:
        problems.append('W12 callback: indirect call/jump: ' + '; '.join(indirect))
    if len(findings['callback_calls']['read8_call_sites']) != 1:
        problems.append('W12 callback: ' + str(len(findings['callback_calls']['read8_call_sites']))
                        + ' ps4rf_kread_k_read8 call site(s) (expected exactly one bounded copy '
                        'loop body)')
    stray_stdlib = [name for name in sorted(defined_set | undefined_set)
                    if name.startswith(('memcpy', 'memset', 'memmove', 'strcpy', 'bzero',
                                        'malloc', 'free', 'pthread', 'mutex'))]
    payload_owned_stdlib = [name for name in stray_stdlib if name.startswith('ps4rf_')]
    findings['callback_calls']['image_string_or_allocator_symbols'] = stray_stdlib
    findings['callback_calls']['payload_owned_string_or_allocator_symbols'] = payload_owned_stdlib
    findings['callback_calls']['image_symbol_note'] = (
        'the image symbol table carries libPS4 libc names (strlen/memcpy/snprintf pointers and '
        'the SDK init helpers); the binding rule is that no ps4rf_kread* function CALLS one of '
        'the forbidden helpers (checked per call site above)')
    if payload_owned_stdlib:
        problems.append('W12: payload-owned allocator/string helper symbol: '
                        + ','.join(payload_owned_stdlib))
    kernel_indirect = [f'{f}@{hex(a)}' for f, a, insn in rows
                       if f.startswith('ps4rf_kread_k')
                       and re.search(r'\b(callq?|jmpq?)\s+\*', insn)]
    user_indirect = [{'site': f'{f}@{hex(a)}', 'insn': insn}
                     for f, a, insn in rows
                     if re.match(r'ps4rf_kread_(run|validate|event|event_status|probe_request|'
                                 r'cb_status_name|run_status_name|bye_reason)$', f)
                     and re.search(r'\b(callq?|jmpq?)\s+\*', insn)]
    findings['callback_calls']['kernel_section_indirect_call_or_jump'] = kernel_indirect
    findings['callback_calls']['user_section_indirect_calls'] = user_indirect
    findings['callback_calls']['user_section_indirect_note'] = (
        'the user section reaches the libPS4 libc pointer table the same way every other target '
        'module does (ps4rf_agent_run calls strlen/memcpy through it); the privileged callback '
        'has no indirect call or jump at all')
    if kernel_indirect:
        problems.append('W12: indirect call/jump in the kernel section: ' + ','.join(kernel_indirect))
    forbidden_calls = [f'{f}@{hex(a)}'
                       for f, a, insn in rows if f.startswith('ps4rf_kread')
                       for tgt in re.findall(r'<([^>]+)>', insn)
                       if any(tgt.lower().startswith(bad) for bad in KREAD_FORBIDDEN_CALL_TARGETS)]
    findings['callback_calls']['forbidden_call_targets'] = forbidden_calls
    if forbidden_calls:
        problems.append('W12: module calls a forbidden helper (allocator/lock/persist/IO): '
                        + ','.join(forbidden_calls))

    # --- 5. the argument-block ABI is CHECKED, not assumed (checklist 8, review item 1) ------
    args_block = re.search(r'struct\s+ps4rf_kread_args\s*\{(.*?)\}\s*;', module_h, re.S)
    args_members: list[tuple[str, str]] = []
    if args_block:
        for line in args_block.group(1).splitlines():
            code = line.split(';')[0].strip()
            if not code or code.startswith('/*') or code.startswith('*'):
                continue
            m = re.match(r'^(.*\*)\s*(\w+)$', code)
            if m:
                args_members.append((' '.join(m.group(1).split()), m.group(2)))
    info_load = [(a, t) for a, t in cb_rows if re.search(r'mov\s+0x8\(%rsi\),%\w+', t)]
    info_reg_match = re.search(r'mov\s+0x8\(%rsi\),%(\w+)', info_load[0][1]) if info_load else None
    info_reg = info_reg_match.group(1) if info_reg_match else None
    args_reads = [(hex(a), t) for a, t in cb_rows
                  if re.search(r'(?<![\w)])\(%rsi\)|0x0\(%rsi\)', t)]
    findings['dispatch_abi'] = {
        'args_fields': [{'type': t, 'name': n} for t, n in args_members],
        'expected_args_fields': [{'type': t, 'name': n}
                                 for t, n in KREAD_EXPECTED_ARGS_FIELDS],
        'first_field_is_syscall_handler': bool(args_members)
        and args_members[0][1] == 'syscall_handler',
        'callback_reads_syscall_handler_field': [t for _a, t in args_reads],
        'callback_info_load': [{'addr': hex(a), 'insn': t} for a, t in info_load],
        'callback_info_pointer_register': info_reg,
        'host_ABI_assumption_in_module': [t for _a, t in cb_rows if re.search(r'0x0\(%rsi\)', t)],
    }
    if [n for _t, n in args_members] != [n for _t, n in KREAD_EXPECTED_ARGS_FIELDS]:
        problems.append(
            'W12 args ABI: struct ps4rf_kread_args members '
            + str([n for _t, n in args_members]) + ' do not match the kernel kexec ABI '
            + str([n for _t, n in KREAD_EXPECTED_ARGS_FIELDS]) + ' (the kernel builds the args '
            'struct {syscall_handler, <pointer passed to kexec>} and hands the payload a pointer '
            'to it: libPS4 source/payload_utils.c kpayload_kbase(struct thread *, struct '
            'kpayload_kbase_args *) with payload_utils.h { void *syscall_handler; ... }; the '
            'W9 harness tests/harness/attest_offline.c and the W11.2 module document the same '
            'ABI). Without syscall_handler first the callback reads kernel code as its block and '
            'a failure report would write cb_status into kernel memory -- a forbidden write; the '
            'harness case J proves the runtime behaviour with a field-0 decoy that carries a '
            'valid caller marker')
    if [t for t, _n in args_members] != [t for t, _n in KREAD_EXPECTED_ARGS_FIELDS]:
        problems.append('W12 args ABI: field types ' + str([t for t, _n in args_members])
                        + ' (expected ' + str([t for t, _n in KREAD_EXPECTED_ARGS_FIELDS]) + ')')
    if 'args->syscall_handler' in module_c_code:
        problems.append('W12 args ABI: the module reads args->syscall_handler (the kernel field '
                        'is never read)')
    if not info_load:
        problems.append('W12 args ABI: the callback has no `mov 0x8(%rsi),%reg` load of the '
                        'caller block from the wrapper SECOND field')
    if args_reads:
        problems.append('W12 args ABI: the callback reads the wrapper FIRST field (%rsi offset 0): '
                        + '; '.join(t for _a, t in args_reads))
    if sdk is not None and (sdk / 'include' / 'payload_utils.h').exists():
        sdk_payload_h = (sdk / 'include' / 'payload_utils.h').read_text()
        findings['dispatch_abi']['sdk_abi_evidence'] = {
            'file': str(sdk / 'include' / 'payload_utils.h'),
            'args_structs_with_syscall_handler_first': len(re.findall(
                r'struct\s+kpayload_\w+_args\s*\{\s*void\s*\*\s*syscall_handler\s*;',
                sdk_payload_h))}
    harness = repo_root / 'tests' / 'harness' / 'kread_offline.c'
    harness_cases = sorted(set(re.findall(r'^\s*\{"([A-Z0-9]+)",', harness.read_text(),
                                          re.M))) if harness.exists() else []
    findings['dispatch_abi']['harness'] = {
        'file': str(harness.relative_to(repo_root)),
        'sha256': sha256_file(harness) if harness.exists() else None,
        'cases': harness_cases,
        'required_cases_missing': [c for c in KREAD_HARNESS_CASES if c not in harness_cases],
        'runtime_proof': 'tests/test_kread_offline.py compiles the production callback with '
                         'replaced leaf reads plus replaced kexec/get_kernel_base and runs the '
                         'case matrix, including case J (wrapper field 0 = decoy with a valid '
                         'caller marker: byte-identical afterwards) and the counter-proof build '
                         '-DPS4RF_KREAD_HARNESS_MUTANT_HOST_ABI which must fail',
    }
    if not harness.exists():
        problems.append('W12: tests/harness/kread_offline.c is missing (the runtime ABI proof)')
    elif findings['dispatch_abi']['harness']['required_cases_missing']:
        problems.append('W12 harness: cases missing from the offline matrix: '
                        + ','.join(findings['dispatch_abi']['harness']['required_cases_missing']))

    # --- 6. the request side carries no address; the runtime VA is written, never read ------
    info_block = re.search(r'typedef\s+struct\s*\{(.*?)\}\s*ps4rf_kread_info\s*;', module_h, re.S)
    observed_fields: list[tuple[str, str]] = []
    request_fields: list[str] = []
    bytes_len = sha_len = None
    if info_block:
        for line in info_block.group(1).splitlines():
            m = re.match(r'\s*(u?int(?:8|16|32|64)_t)\s+(\w+)\s*(\[[^\]]*\])?\s*;', line)
            if m:
                observed_fields.append((m.group(2), m.group(1)))
                if m.group(3) == '[PS4RF_KREAD_MAX_LEN]':
                    bytes_len = header_bound
                if m.group(3) == '[32]':
                    sha_len = 32
                if '/* in ' in line:
                    request_fields.append(m.group(2))
    findings['request_side'] = {
        'info_fields': [{'name': n, 'type': t} for n, t in observed_fields],
        'request_fields': request_fields,
        'expected_request_fields': list(KREAD_REQUEST_FIELDS),
        'bytes_field_length': bytes_len,
        'sha256_field_length': sha_len,
    }
    if [(n, t) for n, t in observed_fields] != [(n, t) for n, t in KREAD_EXPECTED_INFO_FIELDS]:
        problems.append('W12 info layout: observed fields ' + str([(n, t) for n, t in observed_fields])
                        + ' (expected ' + str(list(KREAD_EXPECTED_INFO_FIELDS)) + ')')
    if request_fields != list(KREAD_REQUEST_FIELDS):
        problems.append('W12 request side: the block fields marked as inputs are '
                        + str(request_fields) + ' (expected exactly '
                        + str(list(KREAD_REQUEST_FIELDS)) + ': region index, offset and length, '
                        'the caller marker and the payload-filled SDK base -- no address)')
    addressish_requests = [n for n in request_fields if KREAD_ADDRESS_KEY_PATTERN.search(n)]
    if addressish_requests:
        problems.append('W12 request side: address-like input field(s): '
                        + ','.join(addressish_requests))
    # the callback writes the resolved runtime VA; no read of it may feed the copy
    cb_source = module_c_code.split('int ps4rf_kread_kpayload', 1)[1].split('\nint ', 1)[0] \
        if 'int ps4rf_kread_kpayload' in module_c_code else ''
    rva_lines = [ln.strip() for ln in cb_source.splitlines() if 'resolved_runtime_va' in ln]
    rva_writes = [ln for ln in rva_lines if re.match(r'info->resolved_runtime_va\s*=', ln)]
    offset_hex = None
    if info_block:
        sizes = {'uint32_t': 4, 'int32_t': 4, 'uint64_t': 8, 'int64_t': 8, 'uint8_t': 1,
                 'int8_t': 1}
        field_rows = []
        for name, typ in KREAD_EXPECTED_INFO_FIELDS:
            size = bytes_len if name == 'bytes' else (sha_len if name == 'sha256' else sizes[typ])
            align = 8 if size == 8 else (4 if size == 4 else 1)
            field_rows.append((name, size, align))
        layout = _sysv_layout(field_rows)
        offset_hex = hex(layout['offsets']['resolved_runtime_va'])
    rva_stores = [(hex(a), t) for a, t in cb_rows
                  if offset_hex and re.search(r'mov\w*\s+[^,]+,0x' + offset_hex[2:] + r'\(', t)]
    rva_loads = [(hex(a), t) for a, t in cb_rows
                 if offset_hex and re.search(r'mov\w*\s+0x' + offset_hex[2:] + r'\(%\w+\),', t)
                 and re.search(r'0x' + offset_hex[2:] + r'\(%' + (info_reg or 'ZZZ') + r'\)', t)]
    findings['request_side'].update({
        'callback_runtime_va_offset': offset_hex,
        'callback_source_lines': rva_lines,
        'callback_source_writes': len(rva_writes),
        'callback_binary_stores_to_runtime_va': rva_stores,
        'callback_binary_loads_of_runtime_va': rva_loads,
    })
    if not rva_lines or len(rva_writes) != len(rva_lines):
        problems.append('W12 request side: resolved_runtime_va is not write-only in the callback: '
                        + str(rva_lines))
    if not rva_stores:
        problems.append('W12 request side: no store to the resolved_runtime_va field (' + str(offset_hex)
                        + ') in the callback')
    if rva_loads:
        problems.append('W12 request side: the callback LOADS the runtime VA: '
                        + ', '.join(t for _a, t in rva_loads))
    if 'jval_get' in module_c_code:
        problems.append('W12 request side: ps4rf_kread.c reads a jval (no host input may reach '
                        'the module)')
    if 'kbase_sdk = get_kernel_base();' not in module_c_code:
        problems.append('W12 request side: kbase_sdk is not filled from get_kernel_base()')
    # W14 (stage A): the W13-C2 trigger block is DELETED by design -- the read lives behind the
    # single wired provider route, and the session loop carries no read path at all. The slice
    # below therefore stays empty; it exists so that the W13-C1/C2 shape checks still fire if the
    # block ever reappears (the live variant of "no read path in the session loop" is
    # gate_agent_source(), which needs no console artefact).
    agent_start = agent_c.find('/* W13-C2 request contract')
    hook_start = agent_c.find('if (!kread_done')
    agent_end = agent_c.find('#endif', hook_start) if hook_start >= 0 else -1
    agent_block = agent_c[agent_start:agent_end] if agent_start >= 0 else ''
    # --- W13-C1: the request the agent parses is exactly (region index, offset, length) ------
    parsed_keys = re.findall(r'jval_get\(kread_args,\s*"([^"]+)"', agent_block)
    parsed_value_uses = {name: len(re.findall(r'\b' + name + r'\b', agent_block))
                         for name in ('kread_index', 'kread_offset', 'kread_length')}
    normalized_block = ' '.join(agent_block.split())
    agent_checks = {
        'trigger_is_kernel_read': 'ps4rf_op_is(request_op, "kernel.read")' in agent_block,
        'one_shot_set_before_run': 0 <= agent_block.find('kread_done = 1;')
        < agent_block.find('ps4rf_kread_run('),
        # W13-C2: the three integers live under body.arguments; the same keys directly under the
        # body are not a request (the live W13-C1 attempt 2 read a flat body and saw nothing)
        'arguments_are_read_from_body_arguments': 'jval_get(op_body, "arguments")'
        in normalized_block,
        'no_flat_body_read': not re.search(
            r'jval_get\(op_body,\s*"(region_index|offset|length)"', agent_block),
        'request_fields_are_the_three_bounded_parameters': parsed_keys
        == ['region_index', 'offset', 'length'],
        'no_address_field_parsed': not any(KREAD_ADDRESS_KEY_PATTERN.search(key)
                                           for key in parsed_keys),
        'fields_are_integers': agent_block.count('== JVAL_INT') == 3,
        # the request is accepted only when all three fields were readable; a request that is not
        # is refused explicitly, never repaired and never defaulted
        'all_three_readable_before_accept': 'kread_args_ok = 1;' in agent_block
        and len(re.findall(r'\bkread_args_ok\b', agent_block)) == 3,
        'explicit_refusal_for_unparsable_request': 'ps4rf_kread_refuse_arguments(&g_kread_info)'
        in normalized_block,
        'no_sentinel_substitutes': all(
            token not in agent_block and token not in module_c
            for token in ('PS4RF_KREAD_INDEX_NONE', 'PS4RF_KREAD_OFFSET_NONE',
                          'PS4RF_KREAD_LENGTH_NONE')),
        'run_call_shape': ('kread_args_ok ? ps4rf_kread_run(&g_kread_info, kread_index, '
                           'kread_offset, kread_length) : ps4rf_kread_refuse_arguments('
                           '&g_kread_info);' in normalized_block),
        # each parsed value exists exactly three times: the declaration, the strict integer
        # assignment and the call -- any fourth use is a value on its way somewhere else
        'parsed_values_only_reach_the_call': parsed_value_uses == {'kread_index': 3,
                                                                   'kread_offset': 3,
                                                                   'kread_length': 3},
        'no_probe_left': 'ps4rf_kread_probe_request' not in agent_block,
        'no_address_arithmetic_on_request_values': not re.search(
            r'kread_(index|offset|length)\s*[-+*/]', agent_block),
    }
    module_checks = {
        'index_bounds_check': 'if (index >= PS4RF_KREAD_REGION_COUNT) {' in module_c_code
        and 'if (region_index >= PS4RF_KREAD_REGION_COUNT) {' in module_c_code,
        'row_identity_check': ('PS4RF_KREAD_REGIONS[region_index].identity_status != '
                               'PS4RF_KREAD_IDENTITY_STRICT_FINGERPRINT' in module_c_code),
        'length_bound_check': module_c_code.count('|| length > PS4RF_KREAD_MAX_LEN)') == 2,
        'containment_check': module_c_code.count('sum > region->length') == 1
        and 'sum > PS4RF_KREAD_REGIONS[region_index].length' in module_c_code,
        'checked_add': module_c_code.count('sum < offset') == 2,
        # W16 option B + Track A: the module has TWO fixed window steps beside the request path's
        # own lookup -- the binding-window step and the observation-window step, both addressing
        # their rows through the generated neutral indices only. Every lookup is pinned by name AND
        # the total number of table lookups is pinned, so a new lookup of any name fails this check
        # and a renamed one fails it too.
        'compile_time_table_lookup': module_c_code.count('&PS4RF_KREAD_REGIONS[index]') == 1
        and module_c_code.count('&PS4RF_KREAD_REGIONS[row_index]') == 2
        and module_c_code.count('&PS4RF_KREAD_REGIONS[') == 4,
        'rva_composed_from_the_table_row': ('uint64_t rva64 = (uint64_t)region->rva + '
                                            '(uint64_t)offset;' in module_c_code),
        'runtime_va_is_base_plus_resolved_rva': ('uint64_t address = kbase + rva64;'
                                                 in module_c_code
                                                 and 'info->resolved_runtime_va = address;'
                                                 in module_c_code),
        'no_probe_left': 'ps4rf_kread_probe_request' not in module_c_code,
        'no_host_input_key_in_module': not re.search(r'"(region_index|offset|length|address|rva)"',
                                                     module_c_code),
    }
    # --- W13-C2 / WIRE-CATALOG R2: the operation's argument contract --------------------------
    # kernel.read takes the bounded region triplet and nothing else; the retired addr/size pair is
    # not a valid production contract anywhere, and the operation, its capability, its route and the
    # wire framing are untouched.
    optable_h = (tgt / 'ps4rf_optable_data.h').read_text()
    kread_arg_rows = re.findall(r'\{"([^"]+)", (PS4RF_T_\w+), (\d)\},  /\* kernel\.read \*/',
                                optable_h)
    schema_text = (repo_root / 'tools' / 'primitive_iface' / 'schema.py').read_text()
    schema_op = re.search(r"Op\('kernel\.read'.*?defer_reason=[^)]*\)", schema_text, re.S)
    schema_block = schema_op.group(0) if schema_op else ''
    schema_args = re.findall(r"f\('([^']+)', 'int', (True|False)", schema_block)
    kread_arg_names = [row[0] for row in kread_arg_rows]
    wire_checks = {
        'arg_rows_are_the_bounded_triplet': kread_arg_rows
        == [('region_index', 'PS4RF_T_INT', '1'), ('offset', 'PS4RF_T_INT', '1'),
            ('length', 'PS4RF_T_INT', '1')],
        'no_legacy_argument_name_in_the_slice': not any(
            name in kread_arg_names for name in ('addr', 'address', 'va', 'kernel_va', 'ptr',
                                                 'source', 'size')),
        'schema_declares_the_same_triplet': schema_args == [('region_index', 'True'),
                                                           ('offset', 'True'),
                                                           ('length', 'True')],
        'generated_validator_rejects_unknown_keys': 'if (!found) return 0;' in optable_h,
        'operation_and_capability_unchanged': '{"kernel.read", "kernel", "kernel.read"'
        in optable_h,
        'route_stays_deferred_privilege': 'PS4RF_ROUTE_DEFERRED_PRIVILEGE, PS4RF_TARGET_DEFERRED'
        in optable_h,
        'no_second_operation_added': 'kernel.read.bounded' not in optable_h,
        'revision_is_documented': 'WIRE-CATALOG R2' in schema_block
        or 'WIRE-CATALOG R2' in (repo_root / 'docs' / 'P4-W13C2-WIRE-CATALOG-R2.md').read_text(),
    }
    findings['wire_catalog'] = {
        'source': 'native/target/ps4rf_optable_data.h + tools/primitive_iface/schema.py',
        'kernel_read_arg_rows': kread_arg_rows,
        'schema_kernel_read_args': schema_args,
        'checks': wire_checks,
    }
    findings['request_side']['agent_block_found'] = bool(agent_block)
    findings['request_side']['agent_block_checks'] = agent_checks
    findings['request_side']['agent_block_note'] = (
        'W14: the W13-C2 trigger block is deleted by design -- these checks are recorded history '
        'and only fire if the block reappears; the live property is proven by gate_agent_source()')
    findings['request_side']['parsed_request_keys'] = parsed_keys
    findings['request_side']['parsed_value_uses'] = parsed_value_uses
    findings['request_side']['module_checks'] = module_checks
    if agent_block:
        problems.append('W14 agent: a kread trigger block is present in ps4rf_agent.c (the read '
                        'must stay behind the wired provider route)')
        for name, ok in agent_checks.items():
            if not ok:
                problems.append('W12 agent: kread block check failed: ' + name)
    for name, ok in module_checks.items():
        if not ok:
            problems.append('W13C1 module: request shape check failed: ' + name)
    for name, ok in wire_checks.items():
        if not ok:
            problems.append('W13C2 wire catalog: kernel.read argument contract check failed: '
                            + name)
    if 'ps4rf_kread' in agent_h or 'KREAD_FAILED' not in agent_h:
        problems.append('W12 agent header: PS4RF_AGENT_KREAD_FAILED missing')
    wire_mentions = [name for name in ('ps4rf_protocol.c', 'ps4rf_protocol.h')
                     if 'kread' in (repo_root / 'native' / 'src' / name).read_text().lower()]
    findings['request_side']['frozen_wire_kread_mentions'] = wire_mentions
    if wire_mentions:
        problems.append('W12 wire protocol: frozen wire sources mention kread: '
                        + ','.join(wire_mentions))
    event_keys = re.findall(r'jval_obj_set\(event,\s*"([^"]+)"', module_c)
    addressish_keys = sorted(k for k in set(event_keys)
                             if KREAD_ADDRESS_KEY_PATTERN.search(k)
                             and k not in KREAD_EVIDENCE_ONLY_ADDRESS_KEYS)
    findings['request_side'].update({
        'event_key_count': len(event_keys),
        'event_keys': sorted(event_keys),
        'event_keys_missing': sorted(KREAD_EXPECTED_EVENT_KEYS - set(event_keys)),
        'event_keys_added': sorted(set(event_keys) - KREAD_EXPECTED_EVENT_KEYS),
        'event_address_keys_outside_evidence_only': addressish_keys,
    })
    if findings['request_side']['event_keys_added'] or \
            findings['request_side']['event_keys_missing']:
        problems.append('W12 event schema: keys changed (added: '
                        + ','.join(findings['request_side']['event_keys_added']) + '; missing: '
                        + ','.join(findings['request_side']['event_keys_missing']) + ')')
    if addressish_keys:
        problems.append('W12 event schema: address-shaped key(s) outside the evidence-only set: '
                        + ','.join(addressish_keys))
    for required in ('requested_region', 'requested_offset', 'requested_length', 'resolved_rva',
                     'resolved_runtime_va'):
        if required not in event_keys:
            problems.append('W12 evidence: the event does not carry the checklist item 10 field '
                            + required)

    # --- 7. bounds: 4096, checked add, containment, canonical VA ----------------------------
    bound_forms = []
    if isinstance(max_len_src, int):
        bound_forms = [hex(max_len_src), hex(max_len_src - 1)] if max_len_src > 0 else []
    max_len_sites = [(hex(a), t) for a, t in cb_rows
                     if any(re.search(r'(cmp|lea)\w*\s+.*\$' + form + r'\b', t)
                            for form in bound_forms)]
    findings['single_normative_source'] = {
        'bound_owner': KREAD_BOUND_OWNER,
        'bounds_rules_owner': KREAD_BOUNDS_RULE_OWNER,
        'region_policy_owner': KREAD_REGION_POLICY_OWNER,
        'request_model_owner': KREAD_REQUEST_MODEL_OWNER,
        'registry_file': str(registry_h.relative_to(repo_root)),
        'registry_sha256': sha256_file(registry_h) if registry_h.exists() else None,
        'registry_MAX_READ_LEN': registry_bound,
        'generated_header': str(regions_h_path.relative_to(repo_root)),
        'generated_header_MAX_READ_LEN': header_bound,
        'parity': 'MATCH' if (registry_bound is not None and registry_bound == header_bound)
                  else 'DRIFT',
        'compiled_bound_forms_looked_for': bound_forms,
        'compiled_bound_sites_in_callback': [{'addr': a, 'insn': t} for a, t in max_len_sites],
    }
    if registry_bound is None or header_bound is None or registry_bound != header_bound:
        problems.append('W12 single-source parity: ' + KREAD_BOUND_OWNER + ' says '
                        + str(registry_bound) + ' while the generated header ('
                        + str(regions_h_path.relative_to(repo_root)) + ') defines '
                        + str(header_bound) + ' -- regenerating the table from the registry is the '
                        'only fix (the payload must compile the registry value)')
    add_wrap = [(hex(a), t) for i, (a, t) in enumerate(cb_rows)
                if re.match(r'add\b', t) and i + 1 < len(cb_rows)
                and re.match(r'jb\b', cb_rows[i + 1][1])]
    containment = [(hex(a), t) for i, (a, t) in enumerate(cb_rows)
                   if re.search(r'cmp\w*\s+.*0x20\(%r\w+', t) and i + 1 < len(cb_rows)
                   and re.match(r'j(a|b)', cb_rows[i + 1][1])]
    canonical = [{'addr': hex(a), 'insn': t} for a, t in cb_rows
                 if f'${hex(KREAD_KERNEL_MIN - 1)}' in t]
    read8_index = next((i for i, (_a, t) in enumerate(cb_rows)
                        if '<ps4rf_kread_k_read8>' in t), None)
    read8_window = [t for _a, t in cb_rows[max(0, (read8_index or 0) - 4):(read8_index or 0) + 1]]
    findings['bounds'] = {
        'max_read_len_owner': KREAD_BOUND_OWNER,
        'registry_max_read_len': max_len_src,
        'generated_header_max_read_len': header_bound,
        'parity': findings['single_normative_source']['parity'],
        'callback_max_len_bound_sites': [{'addr': a, 'insn': t} for a, t in max_len_sites],
        'callback_checked_add_sites': [{'addr': a, 'insn': t} for a, t in add_wrap],
        'callback_containment_sites': [{'addr': a, 'insn': t} for a, t in containment],
        'callback_canonical_compare': canonical,
        'callback_read8_window': read8_window,
        'counters_single_pass': True,
    }
    if not max_len_sites:
        problems.append('W12 bounds: no bound immediate (cmp/lea $'
                        + (bound_forms[0] if bound_forms else '?') + ' or $'
                        + (bound_forms[1] if len(bound_forms) > 1 else '?') + ') in '
                        + KREAD_CALLBACK + ' -- the compiled copy loop does not carry '
                        + KREAD_BOUND_OWNER + ' = ' + str(max_len_src))
    if xfast_value != KREAD_LSTAR_PAGE_OFFSET:
        problems.append(f'W12 bounds: PS4RF_KREAD_XFAST_RVA == {xfast_value!r} (expected '
                        f'{hex(KREAD_LSTAR_PAGE_OFFSET)}: kbase = LSTAR - 0x1C0)')
    if 'uint64_t kbase = lstar - (uint64_t)PS4RF_KREAD_XFAST_RVA;' not in module_c_code:
        problems.append('W12 bounds: the kbase relation (LSTAR - XFAST_RVA) is not present')
    if not add_wrap:
        problems.append('W12 bounds: no checked add with a carry/wrap branch in ' + KREAD_CALLBACK)
    if not containment:
        problems.append('W12 bounds: no region containment compare (region->length, table row '
                        '+0x20) in ' + KREAD_CALLBACK)
    if not canonical:
        problems.append('W12 bounds: no canonical-address compare (KERNEL_MIN - 1) in '
                        + KREAD_CALLBACK)
    if 'if (sum < offset) {' not in module_c_code:
        problems.append('W12 bounds: the 32 bit wraparound check `if (sum < offset)` is missing '
                        'from the module source')
    if 'if (sum > region->length) {' not in module_c_code:
        problems.append('W12 bounds: the region containment check `if (sum > region->length)` is '
                        'missing from the module source')
    if 'if (address < kbase || address < PS4RF_KREAD_KERNEL_MIN) {' not in module_c_code:
        problems.append('W12 bounds: the canonical runtime VA check is missing from the module '
                        'source')
    if 'if (length == 0u || length > PS4RF_KREAD_MAX_LEN) {' not in module_c_code:
        problems.append('W12 bounds: the length bound check against PS4RF_KREAD_MAX_LEN is missing '
                        'from the module source')
    if 'if (index >= PS4RF_KREAD_REGION_COUNT) {' not in module_c_code:
        problems.append('W12 bounds: the region index check is missing from the module source')
    host_checks = {
        'includes_module_header': '#include "ps4rf_kread.h"' in host_c,
        'kexec_fails': re.search(r'int kexec\(void \*func, void \*user_arg\)\s*\{[^}]*return -1;',
                                 host_c, re.S) is not None,
        'no_kernel_base': re.search(r'uint64_t get_kernel_base\(void\)\s*\{\s*return 0ull;',
                                    host_c) is not None,
        'no_real_rdmsr': 'rdmsr' not in _strip_c_comments(host_c),
        'no_inline_asm': '__asm' not in host_c,
    }
    findings['host_stand_in'] = host_checks
    if not all(host_checks.values()):
        problems.append('W12 host stand-in: ps4rf_kread_host.c is not the honest stand-in '
                        '(kexec -1, kernel base 0, no real MSR read): ' + str(host_checks))

    # --- 8. the store census: every store target is the payload's own block or its frame -----
    cb_stores = _kread_stores(cb_rows)
    run_stores = _kread_stores(by_func.get('ps4rf_kread_run', []))
    def classify(stores, info_reg_name):
        bad = []
        for store in stores:
            if info_reg_name and store['base'] == info_reg_name:
                store['kind'] = 'own-result-block'
            elif store['base'] in ('rsp', 'rbp'):
                store['kind'] = 'own-frame'
            elif store['base'] == 'rip' and 'g_ps4rf_kread_called' in store['insn']:
                store['kind'] = 'one-shot-guard-symbol'
            else:
                store['kind'] = 'UNEXPECTED'
                bad.append(store)
        return bad
    bad_cb = classify(cb_stores, info_reg)
    bad_run = classify(run_stores, info_reg)
    findings['stores'] = {
        'callback_info_register': info_reg,
        'callback_store_count': len(cb_stores),
        'callback_stores': cb_stores,
        'callback_stores_outside_the_result_block': bad_cb,
        'run_store_count': len(run_stores),
        'run_stores': run_stores,
        'run_stores_outside_the_result_block_and_the_guard': bad_run,
        'note': 'a store through a kbase-derived register would be a kernel write; every store in '
                'the callback is a store into the payload-owned result block',
    }
    if bad_cb:
        problems.append('W12 stores: ' + str(len(bad_cb)) + ' store(s) in ' + KREAD_CALLBACK
                        + ' outside the payload result block: '
                        + '; '.join(s['insn'] for s in bad_cb))
    if bad_run:
        problems.append('W12 stores: store(s) in ps4rf_kread_run outside the result block and the '
                        'guard: ' + '; '.join(s['insn'] for s in bad_run))
    if not cb_stores:
        problems.append('W12 stores: no store found in ' + KREAD_CALLBACK + ' (the census is '
                        'vacuous)')
    if not info_reg:
        problems.append('W12 stores: the payload block register could not be derived, the census '
                        'cannot attribute any store')

    # --- 9. one-shot guard before the single kexec, no retry --------------------------------
    assignments = re.findall(r'g_ps4rf_kread_called\s*=\s*(\d+)', module_c_code)
    guard_set_pos = module_c_code.find('g_ps4rf_kread_called = 1;')
    kexec_call_pos = module_c_code.find('= kexec(')
    source_call_sites = len(re.findall(r'=\s*kexec\s*\(', module_c_code))
    guard_refs = [(func, addr, insn) for func, addr, insn in rows
                  if '<g_ps4rf_kread_called>' in insn]
    guard_writes = [r for r in guard_refs if re.search(r'\bmov\w*\s+\$0x1,', r[2])]
    findings['one_shot'] = {
        'source_assignments': assignments,
        'source_kexec_call_sites': source_call_sites,
        'guard_set_before_kexec_in_source': 0 <= guard_set_pos < kexec_call_pos,
        'goto_in_module': bool(re.search(r'\bgoto\b', module_c_code)),
        'binary_guard_references': [{'function': f, 'addr': hex(a), 'insn': t}
                                    for f, a, t in guard_refs],
        'binary_guard_writes': len(guard_writes),
        'first_result_block_store_in_run': next((s['addr'] for s in run_stores
                                                 if s.get('kind') == 'own-result-block'), None),
    }
    # W14 (stage A): the one shot is per SESSION -- the session entry re-arms it once. The demand
    # is unchanged in substance: exactly one declaration, exactly one re-arm inside the
    # session-entry helper, exactly one guard set before kexec, and no reset anywhere else (a reset
    # in the run path would allow a retry).
    session_begin_start = module_c_code.find('ps4rf_kread_session_begin(')
    session_begin_end = module_c_code.find('\n}', session_begin_start) \
        if session_begin_start >= 0 else -1
    session_block = module_c_code[session_begin_start:session_begin_end] \
        if session_begin_start >= 0 else ''
    session_rearms = len(re.findall(r'g_ps4rf_kread_called\s*=\s*0;', session_block))
    run_path_rearms = len(re.findall(r'g_ps4rf_kread_called\s*=\s*0;',
                                     module_c_code[session_begin_end:]
                                     if session_begin_end > 0 else ''))
    findings['one_shot']['session_entry_rearms'] = session_rearms
    findings['one_shot']['guard_resets_outside_the_session_entry'] = run_path_rearms
    if assignments != ['0', '0', '1']:
        problems.append('W14 one-shot: g_ps4rf_kread_called assignments ' + str(assignments)
                        + ' (expected exactly the declaration 0, the one session-entry re-arm 0 '
                        'and the one guard set 1; any further assignment is a retry path)')
    if session_rearms != 1:
        problems.append('W14 one-shot: the session entry does not re-arm the guard exactly once ('
                        + str(session_rearms) + ')')
    if run_path_rearms != 0:
        problems.append('W14 one-shot: ' + str(run_path_rearms)
                        + ' guard reset(s) outside the session entry (a retry path)')
    if not findings['one_shot']['guard_set_before_kexec_in_source']:
        problems.append('W12 one-shot: the guard is not set before kexec in the source')
    if source_call_sites != 1:
        problems.append('W12 one-shot: ' + str(source_call_sites)
                        + ' kexec call site(s) in the module source (expected exactly 1)')
    if findings['one_shot']['goto_in_module']:
        problems.append('W12 one-shot: goto in the module (a retry path)')
    if len(guard_writes) != 1:
        problems.append('W12 one-shot: ' + str(len(guard_writes))
                        + ' store(s) to the guard symbol in the image (expected 1)')
    if payload_kexec and guard_writes:
        call_func, call_addr, _ = payload_kexec[0]
        guard_func, guard_addr, _t = guard_writes[0]
        if not (guard_func == call_func and guard_addr < call_addr):
            problems.append('W12 one-shot: the guard store does not sit before the kexec call '
                            '(guard ' + guard_func + '@' + hex(guard_addr) + ', kexec ' + call_func
                            + '@' + hex(call_addr) + ')')
    if run_stores:
        first_block_store = next((s for s in run_stores if s.get('kind') == 'own-result-block'),
                                 None)
        if guard_writes and first_block_store:
            if int(first_block_store['addr'], 16) < guard_writes[0][1]:
                problems.append('W12 one-shot: the caller block is written at '
                                + first_block_store['addr'] + ', before the guard store at '
                                + hex(guard_writes[0][1]))

    # --- 10. the generated region table: no drift, no UNRESOLVED, compiled == generated -----
    gen = subprocess.run([sys.executable, str(tgt / 'gen_kread_regions.py'), '--check'],
                         capture_output=True, text=True)
    header_path = regions_h_path
    header_text = regions_h_text
    table_rows = re.findall(
        r'\{\s*(\d+)u,\s*"([^"]+)",\s*0x([0-9A-Fa-f]+)u,\s*(\d+)u,\s*(PS4RF_KREAD_IDENTITY_\w+)\s*\}',
        header_text)
    count_define = re.search(r'#define\s+PS4RF_KREAD_REGION_COUNT\s+(\d+)u', header_text)
    refused_define = re.search(r'#define\s+PS4RF_KREAD_REGION_REFUSED_UNRESOLVED\s+(\d+)u',
                               header_text)
    identity_counts: dict[str, int] = {}
    for _i, _n, _r, _l, identity in table_rows:
        identity_counts[identity] = identity_counts.get(identity, 0) + 1
    structural = [n for _i, n, _r, _l, identity in table_rows
                  if identity == 'PS4RF_KREAD_IDENTITY_STRUCTURAL_ONLY']
    blob = elf.read_bytes()
    ident_bits = {'PS4RF_KREAD_IDENTITY_STRICT_FINGERPRINT': 0,
                  'PS4RF_KREAD_IDENTITY_STRUCTURAL_ONLY': 1}
    compiled_in_image = {}
    for _i, name, rva, length, identity in table_rows:
        pattern = (name.encode() + b'\0' * (24 - len(name))
                   + struct.pack('<III', int(rva, 16), int(length), ident_bits[identity]))
        compiled_in_image[name] = pattern in blob
    findings['region_table'] = {
        'generator': KREAD_GENERATOR,
        'generator_sha256': sha256_file(tgt / 'gen_kread_regions.py'),
        'header': KREAD_REGIONS_HEADER,
        'header_sha256': sha256_file(header_path),
        'drift_check_exit': gen.returncode,
        'drift_check_stdout': gen.stdout.strip(),
        'drift_check_stderr': gen.stderr.strip(),
        'provisional': 'PROVISIONAL' in header_text,
        'registry_line': next((ln.strip(' *') for ln in header_text.splitlines()
                               if ln.strip().startswith('* registry:')), None),
        'region_count_define': int(count_define.group(1)) if count_define else None,
        'rows_parsed': len(table_rows),
        'identity_counts': identity_counts,
        'structural_only_regions': structural,
        'refused_unresolved': int(refused_define.group(1)) if refused_define else None,
        'rows_literal_in_the_image': compiled_in_image,
        'region_policy_owner': KREAD_REGION_POLICY_OWNER,
        'review_item_2_window_policy': 'the W12 table keeps the W9/W10 window policy: every '
                                       'STRICT_FINGERPRINT window byte-identical to the pinned '
                                       'image, aperture_global STRUCTURAL_ONLY and never a '
                                       'trusted identity source (tools/profiles/w10_gate.py '
                                       'enforces that; W12 does not restate it)',
    }
    if gen.returncode != 0:
        problems.append('W12 region table: the checked-in header does not match a fresh generation '
                        'from the canonical registry (drift): ' + (gen.stderr.strip() or gen.stdout.strip()))
    if findings['region_table']['provisional']:
        problems.append('W12 region table: the header is PROVISIONAL (generated from the bootstrap, '
                        'not from tools/profiles/regions.py)')
    if not count_define or int(count_define.group(1)) != len(table_rows):
        problems.append('W12 region table: PS4RF_KREAD_REGION_COUNT '
                        + str(findings['region_table']['region_count_define']) + ' != '
                        + str(len(table_rows)) + ' table row(s)')
    if not table_rows:
        problems.append('W12 region table: no region row parsed from the generated header')
    strict_names = [n for _i, n, _r, _l, identity in table_rows
                    if identity == 'PS4RF_KREAD_IDENTITY_STRICT_FINGERPRINT']
    w9_w10_windows = ('image_elf', 'amd_iommu', 'gbase_vtophys', 'code_anchor', 'xfast_entry',
                      'copyout_prologue', 'prison0_static')
    # W16: the CCP/keymgr binding windows the revision candidate binds. Recorded history stays:
    # the W9/W10 seven-window policy, boottime (W11.2) and the nine-window W12 table are all
    # still asserted below -- W16 only *adds* five TEXT windows and one STRUCTURAL_ONLY pool
    # window, so an absent W16 window is a regression and so is a vanished W12 one.
    w16_strict_windows = ('ccp_submit_entry', 'ccp_device_gate', 'keymgr_claim_entry',
                          'keymgr_bind_entry', 'keymgr_release_entry')
    w16_structural_windows = ('keymgr_pool',)
    # Track A (owner decision of 2026-10-07): the read-only observation windows of the CCP/KeyMgr
    # live step (docs/P4-A-OBSERVATION-WINDOWS.md). STRUCTURAL_ONLY by rule -- runtime state, never
    # an identity source -- appended after the W16 rows so every earlier compiled index is stable.
    a_obs_windows = ('keymgr_ctx_lock', 'keymgr_sm_gate', 'ccp_stage_msg', 'ccp_stage_ptr',
                     'ccp_client_a_buf')
    findings['region_table']['strict_names'] = strict_names
    findings['region_table']['w9_w10_windows_present'] = [n for n in w9_w10_windows
                                                          if n in strict_names]
    findings['region_table']['w16_windows_present'] = [n for n in w16_strict_windows
                                                       if n in strict_names]
    findings['region_table']['policy_reference'] = (
        'the seven-window STRICT set plus the single STRUCTURAL_ONLY window is the frozen W9/W10 '
        'window policy; W11.2 added boottime as one more proven 16 byte read and W12 compiled '
        'the same nine windows; W16 adds the five CCP/keymgr binding fingerprints and the '
        'keymgr slot pool (STRUCTURAL_ONLY) that the revision candidate '
        'profiles/fw1352/profile-13.52-ccp1.json binds and whose live byte-match is its '
        'promotion precondition -- the policy itself stays in tools/profiles/promotion.py, '
        'tools/profiles/regions.py and '
        'tests/test_profile_promotion.py::test_window_policy_matrix_is_seven_plus_one; Track A '
        '(owner decision 2026-10-07) adds the five read-only observation windows of '
        'docs/P4-A-OBSERVATION-WINDOWS.md -- STRUCTURAL_ONLY runtime state, never identity '
        'sources, read by the payload\'s own fixed step')
    if identity_counts.get('PS4RF_KREAD_IDENTITY_STRICT_FINGERPRINT') != 13 or \
            identity_counts.get('PS4RF_KREAD_IDENTITY_STRUCTURAL_ONLY') != 7 or \
            len(table_rows) != 20:
        problems.append('W12/W16/A region table: policy counts ' + str(identity_counts) + ' over '
                        + str(len(table_rows)) + ' row(s) (expected 13 STRICT_FINGERPRINT = the '
                        'seven W9/W10 windows + boottime (W11.2) + the five CCP/keymgr binding '
                        'windows (W16), and 7 STRUCTURAL_ONLY = aperture_global + keymgr_pool '
                        '(W16) + the five Track A observation windows '
                        '(docs/P4-A-OBSERVATION-WINDOWS.md); the W12 table had 8 STRICT + 1 '
                        'STRUCTURAL over 9 rows)')
    if [n for n in w9_w10_windows if n not in strict_names]:
        problems.append('W12 region table: W9/W10 window(s) missing from the STRICT set: '
                        + ','.join([n for n in w9_w10_windows if n not in strict_names]))
    if [n for n in w16_strict_windows if n not in strict_names]:
        problems.append('W16 region table: CCP/keymgr binding window(s) missing from the STRICT '
                        'set: ' + ','.join([n for n in w16_strict_windows
                                            if n not in strict_names]))
    if [n for n in w16_structural_windows if n not in structural]:
        problems.append('W16 region table: structural window(s) missing from the compiled '
                        'table: ' + ','.join([n for n in w16_structural_windows
                                              if n not in structural]))
    if [n for n in a_obs_windows if n not in structural]:
        problems.append('Track A region table: observation window(s) missing from the compiled '
                        'table: ' + ','.join([n for n in a_obs_windows if n not in structural]))
    if structural != ['aperture_global', 'keymgr_pool'] + list(a_obs_windows):
        problems.append('W12/W16/A region table: STRUCTURAL_ONLY regions changed: '
                        + str(structural) + ' (expected aperture_global (W9), keymgr_pool (W16) '
                        'and the five Track A observation windows '
                        '(docs/P4-A-OBSERVATION-WINDOWS.md), in table order)')
    unresolved_rows = [n for _i, n, _r, _l, identity in table_rows
                       if identity == 'PS4RF_KREAD_IDENTITY_UNRESOLVED']
    findings['region_table']['unresolved_rows'] = unresolved_rows
    if unresolved_rows or not refused_define:
        problems.append('W12 region table: UNRESOLVED entry/entries in the compiled table ('
                        + ','.join(unresolved_rows) + ') or missing refusal count ('
                        + str(findings['region_table']['refused_unresolved']) + ')')
    not_in_image = [n for n, ok in compiled_in_image.items() if not ok]
    if not_in_image:
        problems.append('W12 region table: row(s) not found literally in the image (the compiled '
                        'table differs from the generated one): ' + ','.join(not_in_image))
    registry_probe = re.search(r'#define\s+PS4RF_KREAD_REGION_IDX_XFAST_ENTRY\s+(\d+)u', header_text)
    findings['region_table']['xfast_region_index'] = int(registry_probe.group(1)) \
        if registry_probe else None
    kernel_immediates: list[dict[str, str]] = []
    unexpected_imm: list[str] = []
    for func, addr, insn in rows:
        if not func.startswith('ps4rf_kread_k'):
            continue
        for value in _hex_immediates(insn):
            if value >= 0x100000:
                kernel_immediates.append({'addr': hex(addr), 'function': func, 'value': hex(value)})
                if value not in KREAD_KERNEL_IMMEDIATE_ALLOWLIST:
                    unexpected_imm.append(f'{hex(value)} in {func}@{hex(addr)}')
    findings['region_table']['kernel_section_immediates_ge_1mib'] = kernel_immediates
    findings['region_table']['kernel_section_immediate_allowlist'] = {
        hex(v): why for v, why in KREAD_KERNEL_IMMEDIATE_ALLOWLIST.items()}
    if unexpected_imm:
        problems.append('W12 region table: unexpected kernel-section immediate(s) >= 1 MiB '
                        '(possible second read source): ' + '; '.join(unexpected_imm))
    findings['region_table']['region_rows'] = [
        {'index': int(i), 'name': n, 'rva': f'0x{int(r, 16):x}', 'length': int(l),
         'identity': identity.rsplit('_', 1)[1]} for i, n, r, l, identity in table_rows]

    # --- 11. forbidden subsystems, persistence, host-ABI leftovers --------------------------
    all_syms = sorted(defined_set | undefined_set)
    subsystem_hits = [name for name in all_syms
                      if any(re.search(r'(^|[^a-z0-9])' + bad + r'([^a-z0-9]|$)', name.lower())
                             for bad in KREAD_FORBIDDEN_SUBSYSTEMS)]
    source_subsystem_hits = [bad for bad in KREAD_FORBIDDEN_SUBSYSTEMS
                             if re.search(bad, module_c_code, re.I)]
    findings['forbidden'] = {
        'subsystem_symbols': subsystem_hits,
        'subsystem_source_mentions': source_subsystem_hits,
        'wrmsr': len(wrmsr_sites),
        'sysent_or_syscall_table_symbols': [n for n in all_syms
                                            if 'sysent' in n.lower()
                                            or 'syscall_table' in n.lower()],
        'persistence_symbols': [n for n in all_syms
                                if any(re.search(r'(^|[^a-z0-9])' + bad + r'([^a-z0-9]|$)',
                                                 n.lower())
                                       for bad in KREAD_FORBIDDEN_SUBSYSTEMS)],
        'resolved_runtime_va_not_an_input': 'proved in request_side and stores above',
    }
    if subsystem_hits:
        problems.append('W12 forbidden: MRSAMU/GPUVM/KeyMgr/CCP/persistence symbol(s) referenced: '
                        + ','.join(subsystem_hits))
    if source_subsystem_hits:
        problems.append('W12 forbidden: the module source mentions forbidden subsystem(s): '
                        + ','.join(source_subsystem_hits))
    if findings['forbidden']['sysent_or_syscall_table_symbols']:
        problems.append('W12 forbidden: syscall-table symbol(s): '
                        + ','.join(findings['forbidden']['sysent_or_syscall_table_symbols']))

    # --- 12. parity: provider matrix, W4/W5/W7 decisions, health regression -----------------
    optable = (tgt / 'ps4rf_optable_data.h')
    optable_text = optable.read_text()
    row = next((ln.strip() for ln in optable_text.splitlines()
                if ln.strip().startswith('{"kernel.read"')), None)
    parity_refs = {}
    for rel in KREAD_PARITY_FILES:
        path = repo_root / rel
        parity_refs[rel] = {'sha256': sha256_file(path)} if path.exists() else {'missing': True}
    matrix_text = (repo_root / 'tools/dispatch/matrix.py').read_text()
    kread_text = (repo_root / 'tools/profiles/regions.py').read_text()
    cli_text = (repo_root / 'tools/hostctl/cli.py').read_text()
    health_test_text = (repo_root / 'tests/test_live_health.py').read_text()
    registry_text = (repo_root / 'tools/profiles/regions.py').read_text()
    findings['parity'] = {
        'provider_matrix_row_kernel_read': row,
        'provider_matrix_reference': 'native/target/ps4rf_optable_data.h (frozen, generated) + '
                                     'tools/dispatch/matrix.py (route semantics)',
        'matrix_route_constant': next((ln.strip() for ln in matrix_text.splitlines()
                                       if 'ROUTE_DEFERRED_PRIVILEGE =' in ln), None),
        'matrix_deferred_row_counts': [ln.strip() for ln in matrix_text.splitlines()
                                       if 'ROUTE_DEFERRED_PRIVILEGE) !=' in ln
                                       or 'ROUTE_DEFERRED_HOST_CHAIN) !=' in ln],
        'registry_max_read_len_constant': next((ln.strip() for ln in kread_text.splitlines()
                                                if re.match(r'MAX_READ_LEN\s*=', ln.strip())), None),
        'generated_header_max_read_len_constant': next(
            (ln.strip() for ln in regions_h_text.splitlines()
             if re.match(r'#define\s+PS4RF_KREAD_MAX_LEN\s', ln.strip())), None),
        'registry_identity_counts': {ident: len(re.findall(r'identity_status=' + ident,
                                                           registry_text))
                                     for ident in ('IDENTITY_STRICT', 'IDENTITY_STRUCTURAL_ONLY',
                                                   'IDENTITY_UNRESOLVED')},
        'health_probe_check': 'port-3232-connect' in cli_text,
        'health_log_activity_outside_the_verdict': (
            'log_activity_observed' in cli_text and 'log_activity_observed' in health_test_text),
        'health_reference': 'tools/hostctl/cli.py::live_health + tests/test_live_health.py '
                            '(the probe id and the verdict/log split stay where they are; W12 '
                            'does not restate the semantics)',
        'w4_w5_w7_references': parity_refs,
        'suite': 'W2->W12 regression is run by pytest (tests/), not by the manifest gate',
    }
    # W14 / WIRE-CATALOG R3: the TARGET catalog row for kernel.read is the one wired privileged
    # provider (target-side route override only). The HOST route is a different question and is
    # checked separately below -- the frozen host matrix keeps exactly its four routes, so the host
    # still defers this operation to the target side.
    overrides_block = re.search(r'TARGET_ROUTE_OVERRIDES = \{(.*?)\}', matrix_text, re.S)
    override_pairs = re.findall(r"'([\w.]+)':\s*ROUTE_(\w+),", overrides_block.group(1)) \
        if overrides_block else []
    host_routes_line = next((ln.strip() for ln in matrix_text.splitlines()
                             if re.match(r'ROUTES\s*=', ln.strip())), None)
    # W17F: exact SET parity for the wired privileged providers. The named set is the authority --
    # no magic count, and no blanket allowance for arbitrary future overrides.
    expected_override_pairs = {('kernel.read', 'PRIVILEGED_PROVIDER'),
                               ('kernel.snapshot.recipe', 'PRIVILEGED_PROVIDER'),
                               ('ioctl.invoke', 'PRIVILEGED_PROVIDER')}
    findings['parity'].update({
        'target_route_override_pairs': override_pairs,
        'expected_target_route_override_pairs': sorted(expected_override_pairs),
        'host_route_table': host_routes_line,
        'host_route_untouched': set(override_pairs) == expected_override_pairs
        and len(override_pairs) == len(expected_override_pairs)
        and host_routes_line is not None and 'ROUTE_PRIVILEGED_PROVIDER' not in host_routes_line,
    })
    if row is None:
        problems.append('W12 parity: no kernel.read row in the frozen provider matrix')
    elif not ('PS4RF_ROUTE_PRIVILEGED_PROVIDER' in row and 'PS4RF_TARGET_WIRED' in row
              and 'PS4RF_TARGET_DEFERRED' not in row):
        problems.append('W12 parity: the TARGET matrix row for kernel.read is not the WIRE-CATALOG '
                        'R3 row (route PS4RF_ROUTE_PRIVILEGED_PROVIDER, target wired): ' + row)
    if not findings['parity']['host_route_untouched']:
        problems.append('W14 parity: the HOST route matrix changed (expected exactly the named '
                        'target-side overrides and an unchanged four-route host table): got '
                        + str(override_pairs) + ' want ' + str(sorted(expected_override_pairs))
                        + ' / ' + str(host_routes_line))
    if not findings['parity']['health_probe_check']:
        problems.append('W12 parity: the health probe check port-3232-connect is missing from '
                        'tools/hostctl/cli.py')
    if not findings['parity']['health_log_activity_outside_the_verdict']:
        problems.append('W12 parity: log_activity_observed is not wired as a separate observation '
                        'in tools/hostctl/cli.py / tests/test_live_health.py')
    if findings['parity']['registry_max_read_len_constant'] is None or \
            str(registry_bound) not in findings['parity']['registry_max_read_len_constant']:
        problems.append('W12 parity: ' + KREAD_BOUND_OWNER + ' is not readable as a constant '
                        'declaration (' + str(findings['parity']
                                              ['registry_max_read_len_constant']) + ')')

    # --- 13. reproducibility -----------------------------------------------------------------
    repro: dict[str, Any] = {
        'checked': False,
        'note': "build_ps4.sh builds twice and cmp's ELF+BIN (a REPRO FAIL stops the build before "
                'the manifest); pass --repro-elf <second ELF> to record the comparison here',
    }
    if repro_elf is not None:
        same = sha256_file(elf) == sha256_file(repro_elf) and elf.read_bytes() == repro_elf.read_bytes()
        repro = {'checked': True, 'identical': same, 'elf_sha256': sha256_file(elf),
                 'repro_elf': str(repro_elf), 'repro_elf_sha256': sha256_file(repro_elf)}
        if not same:
            problems.append('W12 reproducibility: ' + str(repro_elf) + ' is not byte-identical to '
                            + str(elf))
    findings['reproducibility'] = repro

    findings['review_checklist_coverage'] = {
        '1 request schema/no raw address': 'request_side.request_fields + '
                                           'event_address_keys_outside_evidence_only',
        '2 region registry/STRUCTURAL_ONLY': 'region_table.identity_counts + structural_only_regions',
        '3 bounds': 'bounds (max length, checked add, containment, canonical VA)',
        '4/5/6 host-side (profile, boot binding, capability, verification)': 'tools/ modules, '
                                                                            'referenced in parity',
        '7 callback': 'callback_calls + stores',
        '8 syscall_handler ABI': 'dispatch_abi (source + binary) + harness cases A and J',
        '9 guard': 'one_shot (source + binary, before the kexec call)',
        '10 evidence': 'request_side event keys + runtime VA write-only proof',
        '11 mutants': 'reported separately (the wave report), not by this gate',
        '12 positive verification': 'tools/hostctl/kreadverify.py + tests/test_kread_verify.py',
        '13 manifest gates': 'this gate: max read, no kernel write, no raw address, no arbitrary '
                             'call, no GPUVM/KeyMgr/CCP/SAMU, no persistence, reproducibility, '
                             'provider-matrix parity, W4/W5/W7 references, health anchor',
        '14 stop/report': 'build id + hashes in the manifest; the wave report carries the rest',
    }
    findings['ok'] = not problems
    return findings


def parse_attest_table(path: pathlib.Path) -> list[tuple[str, int, bytes]]:
    """Read the generated attestation table: (id, rva, expected window bytes)."""
    text = path.read_text()
    rows = []
    for match in re.finditer(r'\{\s*\{\s*(\'[^\']*\'(?:,\s*\'[^\']*\')*)\s*\},\s*'
                             r'0x([0-9A-F]+)u,\s*(\d+)u,\s*PS4RF_ATTEST_KIND_(\w+),\s*'
                             r'PS4RF_ATTEST_POLICY_(\w+),\s*\{\s*([^}]*)\}\s*\}', text):
        chars, rva, length, kind, policy, raw = match.groups()
        name = ''.join(c for c in re.findall(r"'([^']*)'", chars) if c != '\\0')
        values = [int(v, 16) for v in re.findall(r'0x([0-9a-f]{2})', raw)]
        rows.append((name, int(rva, 16), bytes(values[:int(length)]), kind.lower(),
                     policy.lower().replace('structural_only', 'STRUCTURAL_ONLY')
                     .replace('strict_fingerprint', 'STRICT_FINGERPRINT')))
    return rows


# W17: the user/kernel split is by symbol name. Beside the attestation's own kernel prefix, every
# compiled privileged driver names its kernel section with its own `ps4rf_<driver>_k` prefix, so a
# combined artefact classifies those leaves and callbacks as kernel code as well -- otherwise the
# attestation gate would read a driver's rdmsr leaf as user code (and fail the combined build for
# something the driver's own gate already allows).
KERNEL_NAME_PREFIXES = ('ps4rf_attest_k',)
# the driver *provider* modules whose user section is allowed to know the canonical kernel window
# (the same constant gate_kread allows for the read driver): their provider-side helpers are
# reported, not failed. The attestation artefact's own user code, and the shared agent/stub code,
# stays under the rule -- so the W9 verdict is unchanged.
KERNEL_WINDOW_MODULES = ('ps4rf_kread_', 'ps4rf_recipe_')


def classify_function(name: str) -> str:
    if name.startswith(KERNEL_NAME_PREFIXES) or \
            any(name == d['callback'] or kernel_section_symbol(name, d)
                for d in PRIVILEGED_DRIVERS):
        return 'kernel'
    if name.startswith(('ps4rf_', '_main', 'crt0')):
        return 'owned_user'
    if name.startswith(('initKernel', 'initLibc', 'initNetwork', 'kexec', 'get_kernel_base',
                        'get_memory_dump', 'build_kpayload', 'syscall', '__readmsr')):
        return 'sdk'
    return 'other'


def gate_attestation(elf: pathlib.Path, profile: str, table_path: pathlib.Path) -> dict[str, Any]:
    """Section-aware gates for the W9 artefact (kernel/user split by symbol name).

    Kernel section  = ps4rf_attest_k*  : rdmsr allowed (exactly the fixed measurement set),
                                   no syscall, no indirect call, no control-register write.
    Owned user code              : no privileged instruction at all, no kernel-address
                                   immediate, no kernel RVA constant.
    Whole artefact               : exactly one syscall 11 site, and it belongs to the SDK's
                                   kexec wrapper; every table window is compiled in.
    """
    findings: dict[str, Any] = {
        'profile': profile, 'classes': {}, 'kernel': {}, 'owned_user': {},
        'indirect_calls': {'kernel': [], 'owned_user': [], 'sdk': []},
        'privileged': {'rdmsr': [], 'wrmsr': [], 'syscall': [], 'cr_access': []},
        'syscall11_sites': [], 'owned_user_kernel_immediates': [],
        'driver_user_kernel_immediates': [],
        'table_windows_present': {}, 'problems': [],
    }
    disassembly = run(['objdump', '-d', '--no-show-raw-insn', str(elf)])
    current = 'other'
    current_name = ''
    counts: dict[str, dict[str, int]] = {}
    instruction_counts: dict[str, int] = {}
    for line in disassembly.splitlines():
        header_match = re.match(r'^[0-9a-f]+ <([^>]+)>:', line)
        if header_match:
            current_name = header_match.group(1).split('+')[0]
            current = classify_function(current_name)
            counts.setdefault(current, {'rdmsr': 0, 'wrmsr': 0, 'syscall': 0, 'cr': 0,
                                        'indirect': 0, 'insns': 0})
            continue
        insn = re.match(r'^\s+([0-9a-f]+):\s+(.*)$', line)
        if not insn or current not in counts:
            continue
        address, text = insn.groups()
        bucket = counts[current]
        bucket['insns'] += 1
        if re.search(r'\brdmsr\b', text):
            bucket['rdmsr'] += 1
            findings['privileged']['rdmsr'].append(f'{address} {text.strip()} [{current}]')
        if re.search(r'\bwrmsr\b', text):
            bucket['wrmsr'] += 1
            findings['privileged']['wrmsr'].append(f'{address} {text.strip()} [{current}]')
        if re.search(r'\bsyscall\b', text):
            bucket['syscall'] += 1
            findings['privileged']['syscall'].append(f'{address} {text.strip()} [{current}]')
        if re.search(r'%cr[0-9]', text):
            bucket['cr'] += 1
            findings['privileged']['cr_access'].append(f'{address} {text.strip()} [{current}]')
        if re.search(r'\b(call|jmp)\s+\*', text):
            bucket['indirect'] += 1
            findings['indirect_calls'].setdefault(current, []).append(f'{address} {text.strip()}')
        # A kernel-space literal is a *large negative* 64 bit value in the canonical upper
        # half (0xffff800000000000 .. 0xffffffffffffffff, i.e. below -0x100000 when read as
        # signed). Sign-extended small constants such as -1, -4 or a -128 stack adjustment
        # then do not count as kernel addresses.
        literal = re.search(r'0x(ffff[0-9a-f]{4,})', text)
        if current == 'owned_user' and literal:
            digits = literal.group(1)
            value = int(digits, 16)
            if len(digits) <= 8 and value >> 31:         # sign-extended 32 bit immediate
                value |= 0xFFFFFFFF00000000
            signed = value - (1 << 64) if value >= (1 << 63) else value
            if signed <= -0x100000:                      # >= 1 MiB below zero: kernel literal
                where = f'{address} {text.strip()}'
                if current_name.startswith(KERNEL_WINDOW_MODULES):
                    # a driver provider's own canonical-window constant: reported, not failed
                    findings['driver_user_kernel_immediates'].append(f'{where} [{current_name}]')
                else:
                    findings['owned_user_kernel_immediates'].append(where)

    findings['classes'] = counts
    kernel = counts.get('kernel', {})
    user = counts.get('owned_user', {})
    findings['kernel'] = kernel
    findings['owned_user'] = user
    problems: list[str] = findings['problems']

    if not kernel or kernel.get('insns', 0) == 0:
        problems.append('no kernel-section instructions found (ps4rf_attest_k*)')
    if kernel.get('rdmsr', 0) < 1:
        problems.append('kernel section performs no rdmsr (LSTAR must be measured there)')
    if kernel.get('wrmsr', 0) != 0:
        problems.append('kernel section contains wrmsr (write primitive)')
    if kernel.get('syscall', 0) != 0:
        problems.append('kernel section contains syscall')
    if kernel.get('cr', 0) != 0:
        problems.append('kernel section touches a control register')
    if counts.get('kernel', {}).get('indirect', 0) != 0:
        problems.append('kernel section contains an indirect call/jump')
    if user.get('rdmsr', 0) or user.get('wrmsr', 0) or user.get('cr', 0):
        problems.append('owned user code contains a privileged instruction')
    if findings['owned_user_kernel_immediates']:
        problems.append('owned user code carries a kernel-address immediate')

    # Exactly one *syscall 11* site in the whole artefact, and it must be the SDK's kexec
    # wrapper. libPS4 also carries generic syscall wrappers (read/write/open/close, none of
    # them number 11) which the W8 artefact already contained; they are counted and reported
    # as an allowance instead of being mixed into the rule.
    lines = disassembly.splitlines()
    current = 'other'
    for index, line in enumerate(lines):
        header_match = re.match(r'^[0-9a-f]+ <([^>]+)>:', line)
        if header_match:
            current = classify_function(header_match.group(1).split('+')[0])
            continue
        # The syscall *number* is set in the wrapper (mov $0xb,%rax) and the instruction lives
        # in the shared syscall_macro, so the wrapper plus its target is the site to look for.
        if re.search(r'mov\s+\$0xb,%r(?:ax|eax)', line):
            following = lines[index + 1] if index + 1 < len(lines) else ''
            if 'syscall_macro' in following:
                findings['syscall11_sites'].append(f'{line.strip()} [{current}]')
    if profile == 'w9':
        sites = findings['syscall11_sites']
        if len(sites) != 1:
            problems.append(f'syscall 11 sites: {len(sites)} (expected exactly one, in kexec)')
        elif not sites[0].endswith('[sdk]'):
            problems.append(f'syscall 11 site outside the SDK wrapper: {sites[0]}')
    findings['syscall_sites_total'] = sum(bucket.get('syscall', 0) for bucket in counts.values())
    findings['syscall_allowance'] = ('libPS4 generic syscall wrappers (read/write/open/close, '
                                     'syscall numbers 3/4/5/6) are linked by the SDK and are '
                                     'not syscall 11')

    table = parse_attest_table(table_path)
    if not table:
        problems.append(f'no attestation table entries parsed from {table_path}')
    blob = elf.read_bytes()
    policies = {'STRICT_FINGERPRINT': 0, 'STRUCTURAL_ONLY': 0}
    findings['windows'] = []
    for name, rva, expected, kind, policy in table:
        present = expected in blob
        findings['table_windows_present'][name] = present
        policies[policy] = policies.get(policy, 0) + 1
        findings['windows'].append({
            'id': name, 'rva': f'0x{rva:x}', 'len': len(expected), 'kind': kind,
            'policy': policy,
            'counts_towards_strict_score': policy == 'STRICT_FINGERPRINT',
            'observed_required_to_equal_expected': policy == 'STRICT_FINGERPRINT',
            'expected_sha256': hashlib.sha256(expected).hexdigest(),
            'expected_source': 'kernel.bin (pinned FW13.52 image, sha256 in '
                               'native/target/ps4rf_attest_data.h)',
            'compiled_in': present,
        })
        if not present:
            problems.append(f'attestation window {name} (rva 0x{rva:x}) not compiled in')
    findings['policy_counts'] = policies
    if policies['STRUCTURAL_ONLY'] != 1 or policies['STRICT_FINGERPRINT'] != 7:
        problems.append(f'window policy counts: {policies} (expected 7 STRICT_FINGERPRINT, '
                        f'1 STRUCTURAL_ONLY)')
    # the structural window is the documented one; a silent policy change must not pass
    structural = [w['id'] for w in findings['windows'] if w['policy'] == 'STRUCTURAL_ONLY']
    if structural != ['aperture_global']:
        problems.append(f'STRUCTURAL_ONLY windows changed: {structural}')
    return findings


def gate_agent_source(root: pathlib.Path) -> dict[str, Any]:
    """W14 §5.1/§2/§3 as *source* gates (no console artefact required).

    "The session loop holds no ``kernel.read`` state and no ``kernel.read`` call site" is a
    property of ``native/target/ps4rf_agent.c`` itself: it must hold for every build profile and
    must be provable in the offline suite. ``gate_kread`` proves the same property on a *linked*
    console artefact; this gate proves it from the sources before that artefact exists, so a
    stage-A regression cannot hide behind a build that needs the console SDK. Comments are
    stripped first -- a property that only holds in prose is not a property.

    The resident daemon (W14 §2/§3/§12/§13) is checked the same way: it drives the frozen session
    entry point, serves no socket of its own, reaches no privileged primitive, has exactly one
    place where a session can start, and the callback seam carries no request.
    """
    tgt = root / 'native' / 'target'
    agent = _strip_c_comments((tgt / 'ps4rf_agent.c').read_text())
    agent_h = _strip_c_comments((tgt / 'ps4rf_agent.h').read_text())
    daemon = _strip_c_comments((tgt / 'ps4rf_daemon.c').read_text())
    daemon_h = _strip_c_comments((tgt / 'ps4rf_daemon.h').read_text())

    session_loop = {
        'no_read_operation_name': 'kernel.read' not in agent,
        'no_read_module_symbols': not re.search(r'ps4rf_kread|KREAD_|\bkread', agent),
        'no_read_request_state': not re.search(
            r'kread_(index|offset|length|done|args|info)', agent),
        'no_read_request_fields': not re.search(r'"(region_index|offset|length)"', agent),
        'single_agent_entry_point': agent.count('ps4rf_agent_run(') >= 1,
        'session_entry_rearms_through_the_router': 'ps4rf_stub_session_begin();' in agent,
        'no_privileged_primitive': not re.search(r'\bkexec\s*\(|get_kernel_base\s*\(', agent),
        'checkpoint_is_signal_only': 'g_checkpoint(g_checkpoint_ctx)' in agent
        and 'typedef int (*ps4rf_agent_checkpoint_fn)(void *ctx);' in agent_h,
    }
    resident_daemon = {
        'drives_the_frozen_session': daemon.count('ps4rf_agent_run(') == 1,
        'dispatches_no_operation': not re.search(
            r'ps4rf_router_handle|ps4rf_provider_enter|ps4rf_stub_invoke|kernel\.read', daemon),
        'serves_no_socket_of_its_own': not re.search(r'\b(listen|accept|bind|select)\s*\(', daemon)
        and 'net_connect' in daemon,
        'no_privileged_primitive': not re.search(r'\bkexec\s*\(|get_kernel_base\s*\(', daemon),
        'lifecycle_is_the_frozen_one': all(
            state in daemon_h for state in ('BOOTSTRAP', 'RESIDENT_IDLE', 'SESSION_ACTIVE',
                                            'SESSION_CLEANUP', 'EXITED')),
        'four_exit_reasons_declared': sum(
            reason in daemon_h for reason in ('EXIT_PROTOCOL', 'EXIT_RECOVERY', 'EXIT_INTEGRITY',
                                              'EXIT_ADMIN')) == 4,
        'one_session_at_a_time': 'PS4RF_DAEMON_SESSION_BUSY' in daemon
        and 'refuse_while_busy' in daemon,
        'cleanup_demand_is_checked': 'ps4rf_res_live' in daemon
        and 'PS4RF_CLEANUP_COMPLETE' in daemon,
    }
    # §14/§2/§5/§6 (W14B review): the properties the reviewer asked to be *tested* are also
    # properties of the sources, so a regression in the daemon module cannot hide behind a build
    # that needs the console SDK.
    session_isolation = {
        'hello_carries_the_identity_block': all(
            f'"{field}"' in agent for field in ('agent_version', 'build_id', 'platform', 'profile_id',
                                                'boot_id', 'boot_sec', 'boot_usec', 'boot_status',
                                                'session_state', 'nonce')),
        'identity_is_a_typed_contract': 'ps4rf_agent_identity' in agent_h
        and 'ps4rf_agent_identity_init' in agent and 'ps4rf_agent_platform' in agent,
        'no_unwiped_exit_after_the_keys_exist': not re.search(
            r'return\s+PS4RF_AGENT_\w+;', agent[agent.index('hello = build_hello('):]),
        'session_teardown_is_the_only_release_path': agent.count('ps4rf_res_teardown(') == 1
        and not re.search(r'\b(ps4rf_res_free|free)\s*\(\s*\&?\w*res', agent),
        'boot_state_is_seeded_into_every_session': 'identity->recovery_required' in agent,
    }
    recovery_semantics = {
        'one_mapping_from_session_to_boot_state': daemon.count(
            'ps4rf_daemon_session_recovery_required') >= 2,
        'a_lost_transport_is_not_in_the_mapping': 'd_eq(bye, "RECOVERY_REQUIRED")' not in daemon,
        'the_flag_is_never_lowered': not re.search(r'recovery_required\s*=\s*0', daemon),
        'dial_misses_touch_no_state': 'dial_backoff_us' in daemon
        and 'PS4RF_DAEMON_BACKOFF_MIN_US' in daemon_h,
    }
    # §9/§15: the four exit reasons have producers, and the one that ends a healthy lifetime is
    # scoped: authenticated, authorised, requesting the end instead of performing it, and reaching
    # nothing but the agent's own lifetime.
    stub = _strip_c_comments((tgt / 'ps4rf_stub.c').read_text())
    shutdown = stub[stub.index('static const char *op_session_shutdown('):]
    shutdown = shutdown[:shutdown.index('\n}\n')]
    table = (tgt / 'ps4rf_optable_data.h').read_text()
    admin_shutdown = {
        'the_handler_exists_and_is_dispatched': 'op_session_shutdown(' in stub
        and 'strcmp(name, "session.shutdown") == 0' in stub,
        'the_row_is_capability_free_and_wired':
            '"session.shutdown", "session", "", "", PS4RF_ROUTE_STUB, PS4RF_TARGET_WIRED' in table,
        'the_wire_contract_pins_the_admitted_value':
            'PS4RF_SESSION_SHUTDOWN_CAPABILITY "session.admin"' in stub
            and 'PS4RF_SESSION_SHUTDOWN_CAPABILITY' in shutdown
            and 'CAPABILITY_REQUIRED' in shutdown,
        'served_only_in_the_resident_mode': 'ps4rf_agent_is_resident()' in shutdown
        and 'OPERATION_DEFERRED' in shutdown,
        'requests_the_end_instead_of_performing_it': 'rt->admin_shutdown = 1;' in shutdown
        and not re.search(r'\b(exit|_exit|abort|raise)\s*\(', shutdown),
        'changes_no_kernel_state': not re.search(
            r'kexec|sceKernel|reboot|binloader|bin_loader|persist|mount|firmware|payload',
            shutdown, re.I),
        'the_lifetime_ends_through_the_daemon_only':
            'ADMIN_SHUTDOWN' in agent and 'ADMIN_SHUTDOWN' in daemon
            and daemon.count('d_eq(bye, "ADMIN_SHUTDOWN")') == 1,
    }
    checks = {'session_loop': session_loop, 'resident_daemon': resident_daemon,
              'session_isolation': session_isolation, 'recovery_semantics': recovery_semantics,
              'admin_shutdown': admin_shutdown}
    problems = [f'W14 {block}: {name}' for block, block_checks in checks.items()
                for name, ok in block_checks.items() if not ok]
    return {'source': 'native/target/ps4rf_agent.c + ps4rf_daemon.{c,h}',
            'checks': checks, 'problems': problems}


def sources_manifest(root: pathlib.Path) -> dict:
    files = {}
    for path in sorted(list((root / 'native/target').glob('*.c')) +
                       list((root / 'native/target').glob('*.h')) +
                       list((root / 'native/src').glob('*.c')) +
                       list((root / 'native/src').glob('*.h'))):
        if path.name == 'parity_harness.c':
            continue
        files[str(path.relative_to(root))] = sha256_file(path)
    return files


def agent_version_gate(source_root) -> dict:
    """The build's version-string gate: (problems, the constant it insists on)."""
    root = pathlib.Path(source_root)
    agent_h = (root / 'native/target/ps4rf_agent.h').read_text()
    agent_c = (root / 'native/target/ps4rf_agent.c').read_text()
    problems: list[str] = []
    checks = (
        ('the agent version is a single constant in the header',
         re.search(r'#define\s+PS4RF_AGENT_VERSION\s+"[a-z0-9-]+"', agent_h) is not None),
        ('HELLO reports that constant, not a literal',
         'jval_new_string(PS4RF_AGENT_VERSION)' in agent_c),
    )
    for title, ok in checks:
        if not ok:
            problems.append(f'agent_version: {title}')
    stale = sorted({match for match in re.findall(r'ps4rfd-target-w\d+', agent_c)})
    if stale:
        problems.append('agent_version: a wave literal is hardcoded in the agent: '
                        + ', '.join(stale))
    return {'problems': problems, 'constant': 'PS4RF_AGENT_VERSION'}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--elf', required=True)
    ap.add_argument('--bin', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--manifest-out', default=None)
    ap.add_argument('--source-root', required=True)
    ap.add_argument('--sdk', required=True)
    ap.add_argument('--expect-host', required=True)
    ap.add_argument('--expect-port', type=int, required=True)
    ap.add_argument('--label', default='')
    ap.add_argument('--build-id', default='')
    ap.add_argument('--allow-symbols', default='initKernel,initLibc,initNetwork')
    ap.add_argument('--profile', default='w8',
                    choices=('w8', 'w9', 'w11', BOOTREAD_PROFILE, KREAD_PROFILE))
    ap.add_argument('--resident', action='store_true',
                    help='the artefact is a W14 resident build (ps4rfd_daemon drives the sessions)')
    ap.add_argument('--providers', default='',
                    help='the privileged providers this build compiles, comma separated '
                         '(kread, recipe, ioctl): each one is gated on the linked dispatch path')
    ap.add_argument('--repro-elf', default=None,
                    help='second build of the same sources (w11.2): recorded in the manifest as '
                         'the byte-identical reproducibility proof (build_ps4.sh cmp equivalent)')
    ap.add_argument('--attest-table', default=None,
                    help='generated ps4rf_attest_data.h (w9 only)')
    args = ap.parse_args()

    elf = pathlib.Path(args.elf)
    binary = pathlib.Path(args.bin)
    header = gate_elf(elf)
    # section scans read the ELF (section file offsets) -- the BIN is the delivery form
    findings = gate_code_and_data(elf, header, expect_host=args.expect_host,
                                  expect_port=args.expect_port, profile=args.profile)
    attest: dict[str, Any] = {}
    if args.profile == 'w9':
        table_path = pathlib.Path(args.attest_table) if args.attest_table else \
            pathlib.Path(args.source_root) / 'native/target/ps4rf_attest_data.h'
        attest = gate_attestation(elf, args.profile, table_path)
    bootid: dict[str, Any] = {}
    if args.profile == 'w11':
        bootid = gate_bootid(elf, args.profile)
    bootread: dict[str, Any] = {}
    if args.profile == BOOTREAD_PROFILE:
        bootread = gate_bootread(elf, args.profile, sdk=pathlib.Path(args.sdk),
                                 repro_elf=pathlib.Path(args.repro_elf)
                                 if args.repro_elf else None)
    kread: dict[str, Any] = {}
    providers = frozenset(p.strip() for p in args.providers.split(',') if p.strip())
    if args.profile == KREAD_PROFILE or 'kread' in providers:
        kread = gate_kread(elf, args.profile, sdk=pathlib.Path(args.sdk),
                           repro_elf=pathlib.Path(args.repro_elf)
                           if args.repro_elf else None)
    # W17F: the two generic research primitives (bounded recipe snapshot, allowlisted ioctl).
    # The gate self-detects whether the wave is compiled in, so it also runs on the kread profile.
    w17: dict[str, Any] = gate_w17(elf, args.profile, sdk=pathlib.Path(args.sdk),
                                   repro_elf=pathlib.Path(args.repro_elf)
                                   if args.repro_elf else None, providers=providers)
    # source-level W14 gates: they need no ELF, so they run for every profile (a stage-A
    # regression in the session loop must fail here even when no console artefact was built)
    agent_source = gate_agent_source(pathlib.Path(args.source_root))

    problems = []
    if header['relocations']:
        problems.append(f"{len(header['relocations'])} relocation(s) present")
    if findings['forbidden_symbols']:
        problems.append('forbidden symbols: ' + ','.join(findings['forbidden_symbols']))
    if findings['forbidden_code']:
        problems.append('forbidden code: ' + ','.join(findings['forbidden_code']))
    if findings['loader_port']:
        problems.append('loader port constant in ' + ','.join(findings['loader_port']))
    if not findings['host_target']['ok']:
        problems.append('host/port constant not found in .rodata/.data')
    if attest:
        problems.extend(attest['problems'])
    if bootid:
        problems.extend(bootid['problems'])
    if bootread:
        problems.extend(bootread['problems'])
    if kread:
        problems.extend(kread['problems'])
    if w17:
        problems.extend(w17['problems'])
    problems.extend(agent_source['problems'])

    sdk = pathlib.Path(args.sdk)
    # W14: a resident artefact must actually enter the daemon -- a build that silently kept the
    # single-session entry point would produce three "sessions" only in the operator's head, so the
    # gate reads the entry point and the linked object, not the flag.
    # W14-D1 / W15 §10: the build identity string must come from the constant and must not be a
    # stale wave literal -- a hardcoded version kept reporting "w8" through two waves because only
    # the build id, label and context were asserted.
    version = agent_version_gate(args.source_root)
    problems.extend(version['problems'])

    resident = None
    if args.resident:
        target_text = (pathlib.Path(args.source_root) / 'native/target/ps4rfd_target.c').read_text()
        resident = {'problems': [], 'problems_extra': [],
                    'entry_point': 'ps4rfd_target.c::_main -> ps4rf_daemon_run',
                    'source_guard': 'PS4RF_TARGET_RESIDENT'}
        elf_bytes = elf.read_bytes()
        checks = (
            ('the console entry point runs the daemon under the resident guard',
             '#ifdef PS4RF_TARGET_RESIDENT' in target_text and 'ps4rf_daemon_run' in target_text),
            ('the single-session path is kept for the other profiles',
             'ps4rf_agent_run(fd, psk, PS4RF_TARGET_LABEL' in target_text),
            ('the linked artefact contains the daemon',
             'ps4rf_daemon_run' in header['defined_symbols']
             or b'ps4rf_daemon_run' in elf_bytes),
            ('the resident console build takes its run bounds from the generated config',
             all(name in target_text for name in ('PS4RF_TARGET_MAX_SESSIONS',
                                                  'PS4RF_TARGET_IDLE_ROUNDS',
                                                  'PS4RF_TARGET_IDLE_PAUSE_MS',
                                                  'PS4RF_TARGET_BACKOFF_MAX_MS'))),
            ('the daemon still dials out only (no listener, no loader port in the target sources)',
             'net_listen' not in (pathlib.Path(args.source_root) / 'native/target/ps4rf_daemon.c')
             .read_text()),
        )
        for title, ok in checks:
            if not ok:
                resident['problems'].append(f'resident: {title}')
                problems.append(f'resident: {title}')

    manifest = {
        'schema': f'ps4rf-{args.profile}-target-build/1',
        'label': args.label,
        'build_id': args.build_id,
        'elf': {'path': str(elf), 'sha256': header['sha256'], 'size': header['size'],
                'type': header['info']['type'], 'machine': header['info']['machine'],
                'entry': header['info']['entry'], 'load_segments': header['load_segments']},
        'bin': {'path': str(binary), 'sha256': sha256_file(binary), 'size': binary.stat().st_size},
        'toolchain': {
            'cc': run(['gcc', '--version']).splitlines()[0],
            'ld': run(['ld', '--version']).splitlines()[0],
            'objcopy': run(['objcopy', '--version']).splitlines()[0],
            'sdk_path': str(sdk),
            'sdk_lib_sha256': sha256_file(sdk / 'libPS4.a') if (sdk / 'libPS4.a').exists() else None,
            'sdk_crt0_sha256': sha256_file(sdk / 'crt0.s') if (sdk / 'crt0.s').exists() else None,
            'sdk_linker_x_sha256': sha256_file(sdk / 'linker.x') if (sdk / 'linker.x').exists() else None,
        },
        'sections': header['sections'],
        'relocations': [],
        'defined_symbols': header['defined_symbols'],
        'undefined_symbols': header['undefined_symbols'],
        'runtime_dependencies': {
            'libc': "libPS4 libc pointer table filled by initLibc()",
            'net': "libPS4 network pointers filled by initNetwork(); libSceNet.sprx is loaded by the SDK",
            'kernel_pointers': "initKernel() resolves module loader + sysctl/getpid/sceKernelUsleep",
            'no_dynamic_linking': not any(line.startswith('NEEDED')
                                          for line in run(['readelf', '-dW', str(elf)]).splitlines()),
        },
        'gates': {'relocations_zero': not header['relocations'], **findings,
                  'agent_source': agent_source,
                  'agent_version': version,
                  **({'resident': resident} if resident else {}),
                  **({'attestation': attest} if attest else {}),
                  **({'boot_identity': bootid} if bootid else {}),
                  **({'bootread': bootread} if bootread else {}),
                  **({'kread': kread} if kread else {}),
                  **({'w17': w17} if w17 else {})},
        'sources': sources_manifest(pathlib.Path(args.source_root)),
        'problems': problems,
        'verdict': 'PASS' if not problems else 'FAIL',
    }
    pathlib.Path(args.out).write_text(json.dumps(manifest, indent=1, sort_keys=True) + '\n')
    if args.manifest_out:
        pathlib.Path(args.manifest_out).write_text(
            json.dumps({'elf_sha256': manifest['elf']['sha256'],
                        'bin_sha256': manifest['bin']['sha256'],
                        'verdict': manifest['verdict']}, indent=1))
    for problem in problems:
        print('GATE FAIL:', problem, file=sys.stderr)
    print(json.dumps({'verdict': manifest['verdict'], 'elf_sha256': manifest['elf']['sha256'],
                      'bin_sha256': manifest['bin']['sha256'],
                      'relocations': len(header['relocations']),
                      'sections': len(header['sections']),
                      'undefined_symbols': len(header['undefined_symbols']),
                      'problems': problems}, indent=1))
    return 0 if not problems else 1


if __name__ == '__main__':
    raise SystemExit(main())
