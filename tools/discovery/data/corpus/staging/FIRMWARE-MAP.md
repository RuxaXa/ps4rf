# FIRMWARE-MAP — PS4/PS5 firmware → FreeBSD lineage → mitigations

Reference table for the offline kernel image analyser. Every row carries exactly one
provenance mark. Written 2026-11-05, public sources only, no firmware bytes, no Sony
binaries, no console contact.

Purpose: when the analyser is handed an unknown PlayStation kernel image, this file must
say **which FreeBSD code lineage that image plausibly belongs to** and **which mitigations
were already present in that firmware era** — without letting a guessed version mapping
become a measurement.

---

## 0. Provenance discipline

| Mark | Meaning |
|---|---|
| SOURCED | A source that was actually fetched states this claim (quote in the evidence column / source table). |
| INFERRED | This document deduced the claim. The row states *from what*, and the inference rule is written out so it can be attacked. |
| UNKNOWN | No public basis found. Recorded so that the gap is visible, never filled by plausibility. |

Rules applied here:

1. A platform-level statement ("the PS4 kernel runs a modified FreeBSD 9.0") is **not**
   a per-firmware statement. Applying it to a specific firmware band is marked INFERRED,
   and the inference rule is always the same: *platform-level source + no documented
   rebase + no contrary version string*. The falsifier is named in each section.
2. "Based on FreeBSD X" and "is FreeBSD X" are different claims. Sony modifies core,
   drivers and the syscall layer heavily. Nothing in this file claims an unmodified tree.
3. Absence of a mitigation is a claim and needs a source. Where the only source is a
   dated talk, the covered firmware range is bounded by that talk's date (stated).
4. A version number that could not be checked against a fetched document is not written
   down as fact. Uncorroborated claims are parked in §6 ("considered and rejected").

---

## 1. Kernel lineage

### 1.1 PS4 (Orbis OS) — one lineage, no documented rebase

Platform-level claim, **SOURCED**:

> "Where we were - PS4 Attack Surface" (slide bullets, quoted in order):
> "Runs a modified FreeBSD 9.0" · "Core & networking are mostly untouched" · "Some
> drivers were modified/added" · "~ 150 custom syscalls added" · "No legacy syscalls."
> — Specter, *Next-Gen Exploitation: Exploring the PS5 Security
> Landscape*, hardwear.io USA 2023 (S1).

Corroborating statements (all platform-level, none per-version):

* Wikipedia, *PlayStation 4 system software*: "The operating system is **Orbis OS**,
  based on FreeBSD 9." (S2)
* Phoronix, 2013-06-23: "The operating system at the heart of Sony's PlayStation 4 is
  FreeBSD 9.0 … a Sony spin of FreeBSD 9.0", sourced to a VGLeaks report on a
  second-generation devkit (S3). This is pre-launch, devkit-derived reporting.
* psdevwiki, *PS4/Syscalls*: "The PS4 kernel is based on **FreeBSD 9**, hence why PS4 has
  many syscalls in common with standard FreeBSD. However, some syscalls from FreeBSD are
  missing or disabled, and some custom syscalls have been added." (S4)
* CTurt, *Hacking the PS4, part 3* (2015, FW 1.76 era): references FreeBSD 9.0-RELEASE
  man pages and the `FREEBSD90` source cross-reference when explaining PS4 kernel
  behaviour (S5). Weak as a lineage statement, strong as a practitioner signal.

What Sony itself says: the PS4 OSS portal has a page titled **"FreeBSD Kernel"**, but its
body is licence text (Mach/CMU, RSA, Beerware, Cronyx, …) and **names no FreeBSD
version** (S6). A FreeBSD reviewer makes the same observation in D34374: the page "starts
with 'Mach Operating System' and searching for FreeBSD in it, I see bits and pieces by
individual contributors" (S7). So Sony's own disclosure confirms *FreeBSD kernel code is
present*; it does **not** confirm 9.0.

| Firmware band | Kernel lineage claim | Source | Mark |
|---|---|---|---|
| 1.00 – 1.76 | Sony-modified FreeBSD 9.0 | S1 (platform), S5 (1.76-era behaviour) | INFERRED |
| 2.00 – 2.57 | Sony-modified FreeBSD 9.0 | S1, S2, S3, S4 | INFERRED |
| 3.00 – 3.55 | Sony-modified FreeBSD 9.0 | S1, S4 | INFERRED |
| 4.00 – 4.74 | Sony-modified FreeBSD 9.0 | S1, S4, S8 (4.05 exploitation) | INFERRED |
| 5.00 – 5.56 | Sony-modified FreeBSD 9.0 | S1, S4, S9 (5.05 exploitation) | INFERRED |
| 6.00 – 6.72 | Sony-modified FreeBSD 9.0 | S1, S4 | INFERRED |
| 7.00 – 7.55 | Sony-modified FreeBSD 9.0 | S1, S4 | INFERRED |
| 8.00 – 8.53 | Sony-modified FreeBSD 9.0 | S1, S4 | INFERRED |
| 9.00 – 9.60 | Sony-modified FreeBSD 9.0 | S1, S4, S10 (9.00 no SMEP) | INFERRED |
| 10.00 – 10.71 | Sony-modified FreeBSD 9.0 | S1, S4 | INFERRED |
| 11.00 – 11.52 | Sony-modified FreeBSD 9.0 | S1, S4 | INFERRED |
| 12.00 – 12.52 | Sony-modified FreeBSD 9.0 | S1, S4 | INFERRED |
| 13.00 – 13.52 | Sony-modified FreeBSD 9.0 | S1, S4 | INFERRED |
| 14.00 | Sony-modified FreeBSD 9.0 | S1, S4 | INFERRED |
| *(all PS4)* | "PS4 runs a modified FreeBSD 9.0" — stated as a platform property | S1, S2, S3, S4 | SOURCED |

**Inference rule for the band rows:** the only public statements are platform-level and
say 9.0; no public source reports a rebase of the PS4 kernel to another FreeBSD base; no
public PS4 kernel version string has been published that contradicts 9.0. Therefore each
band inherits 9.0. **Falsifier:** any PS4 kernel image whose `version` string or
`__FreeBSD_version` is not a 9.0-branch value. Note carefully that *individual subsystems
were clearly updated over the console's life* (see §3 and §5) — a modern PS4 image will
not diff cleanly against stock 9.0-RELEASE everywhere. "Base 9.0" ≠ "frozen at 9.0".

### 1.2 PS5 — FreeBSD 11.0, and the value is checkable

Platform-level claim, **SOURCED**:

> "Where we are - PS5 Attack Surface: **Based off FreeBSD 11.0**. Inherits sandboxing
> improvements made over time to PS4, as well as improvements made by FreeBSD to kernel
> core." — Specter, hardwear.io USA 2023 (S1).

> "The kernel is based on **FreeBSD 11.0** (value of `__FreeBSD_version` is **1100122**)."
> — psdevwiki, *PS5/Kernel* (S11).

> "Uses **FreeBSD 11**." — ChendoChap, *PS5 Webkit Execution* (2022) (S12).

Independent check of the number (this document, SOURCED): in FreeBSD's
`releng/11.0/sys/sys/param.h`, `#define __FreeBSD_version 1100122`
("Master, propagated to newvers") (S13), and `releng/11.0/sys/conf/newvers.sh` has
`REVISION="11.0"` / `BRANCH="RELEASE-p16"` (S14). 1100122 is therefore the
**11.0-RELEASE branch value** (any `-pN` patch level), not a 11.x-STABLE value and not
`1100500`.

| Firmware band | Kernel lineage claim | Source | Mark |
|---|---|---|---|
| 1.00 – 1.14 | FreeBSD 11.0 (`__FreeBSD_version` 1100122) | S1, S11, S12, S13 | INFERRED |
| 2.00 – 2.70 | FreeBSD 11.0 | S1, S11, S13 | INFERRED |
| 3.00 – 3.21 | FreeBSD 11.0 | S1, S11, S13 | INFERRED |
| 4.00 – 4.51 | FreeBSD 11.0 | S1, S11, S13 | INFERRED |
| 5.00 – 5.50 | FreeBSD 11.0 | S1, S11, S13 | INFERRED |
| 6.00 – 6.50 | FreeBSD 11.0 | S1, S11, S13 | INFERRED |
| 7.00 – 7.61 | FreeBSD 11.0 | S1, S11, S13 | INFERRED |
| 8.00 – 8.60 | FreeBSD 11.0 | S1, S11, S13 | INFERRED |
| 9.00 – 9.60 | FreeBSD 11.0 | S1, S11, S13 | INFERRED |
| 10.00 – 10.60 | FreeBSD 11.0 | S1, S11, S13 | INFERRED |
| 11.00 – 11.60 | FreeBSD 11.0 | S1, S11, S13 | INFERRED |
| 12.00 – 12.70+ | FreeBSD 11.0 | S1, S11, S13 | INFERRED |
| *(all PS5)* | "PS5 kernel is FreeBSD 11.0, `__FreeBSD_version` 1100122" | S11 + S13 | SOURCED |

**Inference rule for the band rows:** the claim is a build constant, not a per-version
feature; no public source reports a PS5 rebase. **Falsifier:** a PS5 image whose
`__FreeBSD_version` is not 1100122 (e.g. 1200xxx or 1300xxx) would prove a rebase that no
public source currently documents.

### 1.3 The 9-vs-11 confusion, and why it is not a real conflict

One FreeBSD Phabricator comment (S7) asserts: "PS4 and PS5 system softwares are only based
on FreeBSD 11, and it can be proved by `__FreeBSD_version`". That is a **review comment by
a contributor**, not a measured result, and it contradicts every PS4-specific source
(S1, S4) and the PS5-specific `1100122` value. The same thread contains a reviewer
pushing back that Sony's PS4 OSS page does not even mention a version. Treat the comment
as a rejected claim (§6), not as evidence of a shared 11.0 base.

### 1.4 Local corpus cross-check (not a public source)

The repository already holds two PS4 images whose `sysent` layout was resolved
(`tools/discovery/data/fw/fw900.json`, `fw1352.json`): stride **48 bytes**, `sy_narg` at
+0, `sy_call` at +8, `sy_thrcnt` at +44. FreeBSD's own headers give the same shape for
**9, 10 and 11** (verified: `stable/9`, `stable/10`, `stable/11` `sys/sys/sysent.h` are
identical here, size 48) and a completely different shape for **13/14** (`sy_call` at +0,
`sy_narg` at +16, size 40) (S15, S16). So the local images are *consistent with* a
9/10/11-generation sysent and *inconsistent with* 13/14 — which is a consistency check,
**not** a lineage proof (it cannot separate 9 from 11). Recorded here because it is the
one measurement the consuming repo already has.

---

## 2. Userland (WebKit) lineage

Sony publishes one WebKit source drop **per system-software band** on its OSS portal.
That is a strong, official, per-firmware statement about userland lineage — but it gives
the *drop identity*, not the upstream WebKit revision, except where the file name carries
a branch number.

### 2.1 PS4 — Sony OSS WebKit drops (SOURCED, S17)

| PS4 firmware | WebKit drop |
|---|---|
| ≤ 1.76 | `webkit-176.zip` |
| 2.00 – 2.04 | `webkit-200.zip` |
| 2.50 – 2.57 | `webkit-250.zip` |
| 3.00 – 3.15 | `webkit-300.zip` |
| 3.50 | `webkit-350.zip` |
| 3.55 | `webkit_355.zip` |
| 4.00 – 4.07 | `webkit-400.zip` |
| 4.50 – 4.74 | `webkit-450.zip` |
| 5.00 | `webkit-500.zip` |
| 5.03 | `webkit-503.zip` |
| 5.05 | `webkit-505.zip` |
| 5.50 | `webkit-550.zip` |
| 5.53 / 5.53-01 | `webkit-553.zip` / `webkit-553-01.zip` |
| 5.55 – 5.56 | `webkit-555.zip` |
| 6.00 – 6.20 | `webkit-600.zip` |
| 6.50 – 6.72 | `webkit-650.zip` |
| 7.00 – 7.02 | `webkit-700.zip` |
| 7.50 – 7.55 | `webkit-750.zip` |
| 8.00 – 8.03 | `webkit-800.zip` |
| 8.50 – 8.53 | `webkit-850.zip` |
| 9.00 – 9.04 | `webkit-900.zip` |
| 9.50 – 9.60 | `webkit-950.zip` |
| 10.00 – 10.01 | `webkit-1000.zip` |
| 10.50 – 10.71 | `webkit-1050.zip` |
| 11.00 – 11.50 | `webkit-1100.zip` |
| 11.50 – 11.52 | `webkit-1150-1.zip`, `webkit-1150-2.zip` |
| 12.00 | `webkit-1200-1.zip`, `webkit-1200-2.zip` |
| 12.50 – 12.52 | `WebKit-601-1250.zip` (A), `WebKit-616-1250.zip` (B) |
| 13.00 – 13.52+ | `WebKit-601-1300.zip` (A), `WebKit-616-1300.zip` (B) |

Reading of the last two rows (INFERRED): from 12.50 the PS4 ships **two** WebKit
codebases whose file names carry upstream branch numbers **601** and **616**. Two engines
is consistent with a system browser engine plus a second embedded/web-app engine; this
document does not establish which is which. Earlier drops carry only the firmware number
in the filename, so **the upstream WebKit revision for PS4 ≤ 12.00 is not established**
from public pages — it would require opening the published archives and reading their
version headers (an offline step, not performed here).

Qualitative userland note (SOURCED, S18): the PS4 Internet Browser had **JIT disabled
since system software 2.00**, and no WebGL/SVG/WebAssembly. Specter states the same from
the attacker side: "JIT memory was accessible to browser due to logic bug until 2.xx FW"
(S1). Both dated statements agree on the 2.00 boundary.

### 2.2 PS5 — Sony OSS WebKit drops (SOURCED, S19)

| PS5 firmware | WebKit drop |
|---|---|
| 1.00 – 1.14 | `WebKit-100.zip` |
| 2.00 | `WebKit-200.zip` |
| 2.20 – 2.26 | `WebKit-220.zip` |
| 2.30 – 2.70 | `WebKit-230.zip` |
| 3.00 – 3.21 | `WebKit-300.zip` |
| 4.00 – 4.51 | `WebKit-400.zip` |
| 5.00 – 5.50 | `WebKit-500.zip` |
| 6.00 – 6.50 | `WebKit-600.zip` |
| 7.00 – 7.61 | `WebKit-700.zip` |
| 8.00 – 8.60 | `WebKit-800.zip` |
| 9.00 – 9.60 | `WebKit_900.zip` |
| 10.00 – 10.60 | `WebKit-1000.zip` |
| 11.00 – 11.60 | `WebKit-1100.zip` |
| 12.00 – 14.00 | `WebKit-1200.zip` |
| 14.00 – | `WebKit_1400.zip` |

The PS5 drop names carry no WebKit branch number at all, so **the upstream WebKit version
per PS5 firmware is not established** from public pages. What *is* established is that the
userland engine is versioned per firmware band and that the PS5 browser inherits PS4
sandboxing improvements (S1).

---

## 3. Mitigations by firmware era

Two tables. "First seen" is the earliest firmware for which a fetched source *states* the
mitigation is present. Where the source gives a range ("2.xx", "5.0x", "6.xx") the exact
version inside that range is **not established** and is not guessed.

### 3.1 PS4

| Feature | First seen | Evidence | Mark |
|---|---|---|---|
| **No kernel ASLR** (baseline, 1.76) | 1.00 – 1.76 | CTurt: "Just in case you needed any more confirmation that there is **no kernel ASLR**, these function addresses are always the same across reboots" — kernel text around `0xffffffff824…` (S5). Specter: "No ASLR at launch" (S1). | SOURCED |
| **kASLR introduced** | "2.xx" (exact version unknown; absent at 1.76) | Specter: "No Address Space Layout Randomization (ASLR) at launch" · "Enabled in 2.xx" (S1). qwertyoruiopz: "kernel ASLR (kASLR) is now **enabled past 1.76**" (S8). | SOURCED |
| **No SMAP** | 1.00 – 9.00+ | qwertyoruiopz (4.05): "…as the PS4 does **not** have Supervisor-Mode-Access-Prevention (SMAP)" (S8). Specter: "No SMAP/SMEP for its lifespan" (S1). | SOURCED |
| **No SMEP** | 1.00 – 9.00+ | TheFloW, HackerOne #1379975 (tested on 9.00): "Kernel exploitation becomes trivial as there is **no SMEP** and one can simply jump to user with a corrupted function pointer" (S10). | SOURCED |
| **Kernel .text write protection (CR0.WP)** | ≤ 4.05 | 4.05 writeup: "We have to disable the write protection on the kernel .text before we can make any patches … the WP bit at bit 16" (S8). 5.05 writeup does the same (S9). | SOURCED |
| **Userland RWX blocked; JIT via paired syscalls only** | ≤ 1.76 (design), tightened 2.00 | CTurt: no way to map a RWX page; `sys_jitshm_create` + `sys_jitshm_alias` give RW and RX aliases of the same physical memory; syscall from JIT memory faults (S5). 4.05: `sys_mmap` with PROT_EXEC succeeds but executing it faults (S8). | SOURCED |
| **Browser JIT withdrawn** | 2.00 | psdevwiki: "JIT: not supported since PS4 System Software 2.00" (S18); Specter: logic bug gave browser JIT access "until 2.xx FW" (S1). | SOURCED |
| **Scheduler stack-pointer check ("poor man's SMAP")** | "5.0x" | Cryptogenic: "At some point in **5.0x**, it seems Sony added some mitigation into the scheduler to check the stack pointer against userland addresses when running in kernel context, similar to … SMAP. This turned an otherwise fairly trivial exploit into … kernel memory manipulation to run a kernel ROP (kROP) chain" (S9). | SOURCED |
| **Attack-surface reduction (driver removal, syscall permission tightening)** | "6.xx" | Specter: "Steadily been improving on both PS4 and by extension PS5" · "**6.xx firmwares made huge leaps**" · "Various drivers like USB were removed and syscall permission checking was tightened up" (S1). | SOURCED |
| **Custom syscall block, no legacy syscalls** | 1.00 (baseline) | Specter: "~150 custom syscalls added. No legacy syscalls" (S1). qwertyoruiopz: 85 custom syscalls on 1.76, 120 on 4.05; syscall 0 removed by 4.05 (S8). | SOURCED |
| **SMEP / SMAP added later** | — | No public source reports SMEP or SMAP ever being enabled on PS4. Specter's "for its lifespan" is dated July 2023 (PS4 fw ≈ 10.5x at the time), so 11.00–14.00 is inference-free UNKNOWN, not "absent". | UNKNOWN |

Era summary (all from the rows above):

* **1.00 – 1.76** — weakest: no kASLR, no SMEP, no SMAP, no legacy syscalls; JIT reachable
  from the browser; "didn't even have to ROP < 2.xx" (S1).
* **2.00 – 4.74** — kASLR on; browser JIT gone; kernel text write-protected; still no
  SMEP/SMAP.
* **5.00 – 5.56** — plus the scheduler stack-pointer check.
* **6.00 – 6.72** — plus driver removal / syscall permission tightening.
* **7.00 – 10.71** — no *new* kernel mitigation is documented; 9.00 is explicitly still
  SMEP-less (S10).
* **11.00 – 14.00** — **UNKNOWN**. No fetched source describes this era's mitigation set.

### 3.2 PS5

| Feature | First seen | Evidence | Mark |
|---|---|---|---|
| **kASLR** | 1.00 (launch) | Specter: "ASLR and SMAP/SMEP have been **enforced since launch**" (S1). | SOURCED |
| **SMAP + SMEP** | 1.00 (launch) | Same slide (S1); ChendoChap mitigation table lists SMEP and SMAP as kernel mitigations (S12); psdevwiki PS5 kernel feature list: "nx bit, smap, smep, umip, nda/xotext" (S11). | SOURCED |
| **NX** | 1.00 | psdevwiki feature list ("nx bit") (S11); Specter's PS4-vs-PS5 mitigation matrix has an NX column (S1). | SOURCED |
| **Clang CFI (forward-edge, kernel + user)** | 1.00 | Specter: "Kernel also has software Control Flow Integrity (CFI) … Bypassable post-R/W on earlier kernels — CFI enforce variable was in data segment and writable — This was **fixed sometime in 3.xx kernels**" (S1). ChendoChap: "clang-based CFI" broke the PS4 vtable-smash strategy on PS5 (S12). | SOURCED |
| **XOM / XOTEXT (R^X) in userland and kernel** | 1.00 | Specter: "eXecute-Only Memory (XOM) / 'xotext' mitigate ROP ability … **XOM is enforced both in userspace and kernel**" (S1). Byepervisor: "System contains hardware-enforced eXecute-Only Memory (XOM), aka XOTEXT … used in userland (games, apps, libraries) and kernel. These mitigations are enforced by the hypervisor" (S20). | SOURCED |
| **Hypervisor (AMD SVM), VBS-style** | 1.00 (embedded in kernel), isolated from 3.00 | Byepervisor timeline (slide lines): "1.00 FW / In-kernel hypervisor, first iteration" · "3.00 FW / Isolated hypervisor, v2" · "5.00 FW / Lots of newer stuff, no known exploits" (S20). Specter: guest x86 FreeBSD kernel; "Embedded as part of the kernel on lower firmwares. On higher firmwares it's loaded separately but is still similar in function"; CR0/CR4 writes filtered, EFER NDA/xotext masked, GMET prevents executing user pages in kernel context even if SMEP is bypassed (S1). | SOURCED |
| **UMIP** (blocks SGDT/SIDT/SLDT/SMSW/STR in user mode) | 1.00 (listed at launch-era kernel) | psdevwiki PS5 kernel feature list (S11). Single source only; no per-version statement, so confidence is medium. | SOURCED |
| **Kernel .data write protection (hypervisor-enforced)** | 6.00 | psdevwiki: "Since PS5 System Software version **6.00**, attempting to write to kernel .data section results in a kernel panic, as a consequence of Hypervisor protection. However, there exists a workaround as the GPU can write to kernel .data via DMA. … this vulnerability does not enable an attacker to write to the kernel .text segment because of the XOM protection" (S21). | SOURCED |
| **BD-J sandbox escape requires a kernel exploit** | 6.00 | psdevwiki: "On PS5 System Software 6.00 and above, in order to escape the BD-J sandbox, a kernel exploit is required" (S21). | SOURCED |
| **Syscall / libkernel access blocked from main usermode apps** | 8.00 | psdevwiki: "Since PS5 System Software version 8.00 … Sony blocked syscall and libkernel access from the main contenders such as BD-J, WebKit, PS2emu …" — the same section carries an unverified-response caveat from another editor (S21). | SOURCED |
| **CR0.WP / XOM bypass mitigated** | "Maybe since PS5 FW 5.00" | psdevwiki: technique "proposed … in a PS4 kernel exploit since System Software version 6.51", adapted to PS5 by Specter; "**Maybe** since PS5 FW 5.00" patched (S21). | SOURCED |

Era summary:

* **1.00 – 2.70** — full launch mitigation set; hypervisor embedded in the kernel.
* **3.00 – 4.51** — isolated hypervisor v2; kCFI enforcement variable fixed "sometime in 3.xx".
* **5.00 – 5.50** — "lots of newer stuff" (S20); CR0.WP/XOM bypass possibly closed.
* **6.00 – 6.50** — kernel .data writes trapped by the hypervisor; BD-J needs a kernel bug.
* **7.00 – 7.61** — no new mitigation documented.
* **8.00 – 14.00** — usermode syscall/libkernel blocking from 8.00; nothing else documented.

### 3.3 IDT / GDT protections — what is actually documented

* **PS4:** no public source describes an IDT- or GDT-specific *enforced* protection. The
  only related CPU feature that would matter (UMIP) is **not** in any PS4 source found.
  → **UNKNOWN**, and must not be described as "protected".
* **PS5:** UMIP is listed in the PS5 kernel feature set (S11), which is the closest thing
  to a GDT/IDT protection (it blocks user-mode `SGDT`/`SIDT`/`SLDT`/`SMSW`/`STR`, i.e.
  userland descriptor-table leaks). **However, IDT hijacking still works on PS5** as a
  post-R/W technique: sleirsgoevy's method "Set up IDT handlers and point the Interrupt
  Stack (IST) to a ROP chain … Write custom page fault handler to run code you want",
  used to run PS4 homebrew on PS5 (S20). So the IDT itself is **not** protected by XOM or
  by the hypervisor; it is a data structure an attacker with kernel R/W can rewrite.
  Do not model "IDT protected" as a PS5 mitigation.

| Feature | Platform | Documented state | Mark |
|---|---|---|---|
| UMIP (user-mode SGDT/SIDT/SLDT/SMSW/STR blocked) | PS4 | never mentioned in any PS4 source; no descriptor-table protection documented | UNKNOWN |
| UMIP | PS5 | listed in the PS5 kernel feature set (S11); single source | SOURCED |
| IDT write protection | PS5 | none: IDT hijack remains a working post-R/W technique (S20) | SOURCED |

### 3.4 dmap (direct map) protections — what is actually documented

* **PS4:** the direct map exists and is used by every public exploit chain as the
  kernel-R/W substrate. No source describes a dmap-specific protection. → **UNKNOWN**.
* **PS5:** the direct map still exists and is still reachable (`PADDR_TO_DMAP`,
  `kernel_pmap`, "physical memory readable by kernel" / Meme Dumper) (S21). Kernel text
  is protected by **second-level address translation** (nested paging / SLAT), not by
  removing the dmap: "Kernel XOTEXT is harder to break … Flipping XOTEXT bit on kernel's
  own PTEs has no effect. Permissions are enforced through Second Level Address
  Translation (SLAT)" (S20). So the correct model is: *dmap unchanged; text permissions
  moved to NPT*. A dmap-specific mitigation is **not established** on either platform.

| Feature | Platform | Documented state | Mark |
|---|---|---|---|
| dmap-specific protection | PS4 | no source; the direct map is the substrate every public chain uses for kernel R/W | UNKNOWN |
| dmap-specific protection | PS5 | no source; dmap still reachable (`PADDR_TO_DMAP`, `kernel_pmap`, Meme Dumper, S21); text permissions enforced in NPT/SLAT, not by removing the dmap (S20) | SOURCED |

### 3.5 W^X

| Platform | Userland | Kernel | Mark |
|---|---|---|---|
| PS4 | No direct RWX mapping; RW/RX aliases via `sys_jitshm_create`/`sys_jitshm_alias`, and browser JIT withdrawn at 2.00 (S5, S18, S1) | .text write-protected via CR0.WP by 4.05/5.05 (S8, S9); no SMEP, so userland pages remain **executable** from ring 0 ("Userland memory access from ring0 is allowed", S1) → W^X holds for kernel text, not for the kernel's execution provenance | INFERRED |
| PS5 | XOTEXT enforced in userland (games/apps/libs) (S20, S1) | XOTEXT + not writable; write protection via CRs, HV protects CRs/MSRs; text permissions enforced in NPT/SLAT (S20) | SOURCED |

---

## 4. Explicit "not established" list

No public evidence was found for any of the following. They are **not** gaps to be filled
by inference; they are open measurements.

1. **Any per-firmware change of the PS4 kernel's FreeBSD base version.** No source maps a
   PS4 firmware number to anything other than "modified FreeBSD 9.0". All band rows in
   §1.1 are the same claim, not 14 independent findings.
2. **The PS4 kernel's `__FreeBSD_version` value.** No fetched source publishes it. (The
   expected value for a stock 9.0 base would be **900044**, verified in
   `releng/9.0/sys/sys/param.h` (S22) and in the FreeBSD Porter's Handbook, which lists
   `900044 … 9.0-RELEASE` (S23) — but *expected* is not *observed*.)
3. **The PS4 kernel `version` / `uname -v` string.** No fetched source quotes one.
4. **The exact PS4 firmware in which kASLR was enabled** ("2.xx" only).
5. **The exact PS4 firmware in which the scheduler stack-pointer check appeared** ("5.0x").
6. **The exact PS4 firmware in which the 6.xx driver/syscall hardening landed** ("6.xx").
7. **PS4 11.00 – 14.00 mitigation set.** No source after mid-2023 describes it. Whether
   SMEP/SMAP were ever added there is unknown.
8. **Any PS5 kernel base-version change.** No source; `__FreeBSD_version` 1100122 is the
   only published value.
9. **The exact PS5 firmware in which the kCFI enforcement variable was made read-only**
   ("sometime in 3.xx").
10. **UMIP on PS4.** Never mentioned; absence of a mention is not evidence of absence.
11. **IDT/GDT protection on PS4**, and **dmap-specific protection on either platform**
    (§3.3, §3.4).
12. **Upstream WebKit revision per firmware band** for all PS4 bands ≤ 12.00 and all PS5
    bands (only drop names are public; the 12.50+ PS4 drops expose branch numbers 601/616).
13. **Which of the two PS4 WebKit drops (601 vs 616) backs which application** from 12.50.
14. **Whether the PS5 "PS4 SELF" sysvec is a full FreeBSD-9-compat ABI** or only a
    partial shim. psdevwiki states the kernel contains three `sysvec` structs ("PS4 SELF",
    "FreeBSD ELF64", "Native SELF") and that the first is for PS4 backwards compatibility
    (S11), but not how complete the compat ABI is.

---

## 5. What an offline static analyser can use to guess lineage — hypotheses, not facts

Nothing in this section has been tested against a real image in this pass. Each item says
what to measure, what signal to expect, and how it can mislead. Ordered by expected
signal-to-noise.

### H1 — Version string in `.rodata` (highest value, cheapest test)

FreeBSD kernels embed a `version` string built by `sys/conf/newvers.sh`
(`FreeBSD <REVISION>-<BRANCH> #<build> …`). Sony may strip or rewrite it, but if any
`FreeBSD …` / `…BSD …` string survives, it is direct evidence.
**Test:** scan printable strings for `^FreeBSD `, `-RELEASE`, `#\d+`, `r\d{6}`; then
cross-check the revision number against FreeBSD's svn history for the branch.
**Trap:** a stray string from a vendored driver (e.g. a `$FreeBSD$` CVS keyword or a
third-party `#include` comment) is not the kernel's own version. Require the string to
sit next to `newvers`-shaped fields and to be referenced from code.
**Note:** an uncorroborated third-party repo claims a 13.52 ident "HeerBSD r228995" (§6);
that number is *consistent* with a Jan-2012 9.0-branch build but was **not** verified.

### H2 — `__FreeBSD_version` immediate in code

`__FreeBSD_version` is a compile-time integer; code that reports or gates on it can leave
the constant in an immediate or a comparison. Target values: **900044** (9.0-RELEASE),
**1100122** (11.0-RELEASE) (S13, S22, S23).
**Test:** search for the 32-bit immediates; require proximity to a version-reporting
function (e.g. a sysctl/`uname`-like path), not a bare match.
**Trap:** 900044 / 1100122 could occur as data. A bare immediate match is a lead, not a
finding.

### H3 — `struct sysent` shape (discriminates 9/10/11 from 13/14; **not** 9 from 11)

Verified layouts (S15, S16):

| Base | `sy_narg` | `sy_call` | `sy_thrcnt` | stride |
|---|---|---|---|---|
| FreeBSD 9 / 10 / 11 | +0 (int32) | +8 | +44 | 48 |
| FreeBSD 13 / 14 | +16 (uint8) | +0 | +32 | 40 |

**Test:** locate the table (dense array of 8-byte code pointers with a per-entry refcount
near the end), measure stride and the offset of the pointer field.
**Trap:** this cannot separate 9, 10 and 11 — they are byte-identical here. A "stride 48"
result supports "9/10/11-generation" and *refutes* 13/14, nothing more. Do not report it
as "FreeBSD 9 confirmed".

### H4 — `struct vm_map_entry` field order (separates 9 from 11)

Verified (S24): both have `prev,next,left,right,start,end` at +0x00…+0x28. Then
* FreeBSD 9: `avail_ssize` at +0x30, `adj_free` at +0x38, `next_read` (vm_pindex_t) last;
* FreeBSD 11: `pad0` at +0x30, `next_read` (vm_offset_t) at +0x38, `adj_free` at +0x40.

**Test:** find a `vm_map` and walk entries; read the 3rd qword after `end`.
**Signal:** non-zero at +0x30 → 9-style (`avail_ssize`, non-zero only for the stack
entry); zero at +0x30 with a plausible kernel VA at +0x38 → 11-style.
**Trap:** `avail_ssize` is zero for every non-stack entry, so "zero at +0x30" on one entry
proves nothing; check a stack entry or the trailing `next_read` position instead.

### H5 — Syscall table population and numbering

FreeBSD's own maximum syscall number is **545** in `stable/9` and **551** in `stable/11`
(verified, S25) — only 6 apart, so the number alone does not separate them. What *does*
separate a PlayStation kernel from stock FreeBSD is the **custom block**:
Specter reports "~150 custom syscalls" and "no legacy syscalls" (S1); qwertyoruiopz
counted 85 custom syscalls on 1.76 and 120 on 4.05, with syscall 0 removed (S8); the
local PS4 images resolve entries at index 661 (fw900.json comment) in a 700-entry table.
**Test:** count populated slots and locate the first index above 545/551 that is occupied.
**Signal:** PS4 signature = a large block above the stock maximum plus gaps where legacy
syscalls were removed. Refined: **PS5** additionally has three `sysvec` structs ("PS4
SELF", "FreeBSD ELF64", "Native SELF") (S11) — a structural feature no PS4 source
describes.
**Trap:** a PS5 "PS4 SELF" sysvec may make a PS5 image *look* PS4-like from the table
alone; pair with H6/H7.

### H6 — Kernel text/driver symbol sets and string families

PS4 uses drivers Sony added/modified and PS5 removed some of them (Specter: "Various
drivers like USB were removed" at PS4 6.xx) (S1). Symbol names, panic strings, sysctl
names and `devfs` node names are cheap lineage-era fingerprints.
**Test:** extract function-name-like strings and panic format strings; compare against a
stock FreeBSD 9 vs 11 build of the same subsystem.
**Trap:** Sony strips symbols in retail images; absence of names is not evidence.

### H7 — Byte-level function fingerprinting against stock FreeBSD builds

Specter's "core & networking are mostly untouched" (S1) is the premise: if a core
function is unmodified, its machine code should match a stock build of the same FreeBSD
version. Build 9.0-RELEASE and 11.0-RELEASE with a comparable config, hash function
bodies, and match.
**Signal:** a run of exact matches to one tree and mismatches to the other.
**Trap:** compiler version, config options and inlining all change the bytes. Match at the
level of *basic-block sequences* with a tolerance, and require many independent functions
before asserting lineage.

### H8 — Mitigation-state probes as era fingerprints

Presence/absence of a mitigation narrows the era more reliably than any struct:
* kernel text writable at ring 0 without clearing CR0.WP → pre-4.05-like or non-PS4;
* userland pages executable from ring 0 (no SMEP) → PS4, any era ≤ 10.7x (S1, S10);
* `sidt`/`sgdt` permitted in user mode → no UMIP → PS4-like (S11 lists UMIP only for PS5);
* PTEs with an xotext/XOM bit set (bit 58-class, HV-only) → PS5 (S1, S20).
**Trap:** these are *behavioural* properties; a static image shows the PTEs and the CR0.WP
setup code, not the runtime state. Treat as "the code that would enforce X exists/does not
exist", not as "X was enabled at runtime".

### H9 — Section/symbol table shape (PS4 vs PS5 kernel module format)

The local corpus already keys on `sysent`, `cdevsw`, `prison0` offsets and a
`jmp qword ptr [rsi]` gadget (`ff 26`) at a firmware-specific RVA (fw900.json,
fw1352.json). Those RVAs move every firmware, so they identify *a* firmware only with a
per-firmware profile — they do **not** identify a lineage. Use them to confirm a candidate
match, never to establish the base version.

### H10 — Hypervisor presence (PS5-only, all eras)

An embedded or separately loaded AMD-SVM hypervisor with NPT and XOM bits is a PS5
signature (S1, S20). On PS4 there is no hypervisor ("No hypervisor" — qwertyoruiopz's
02r0 deck, cited in the local corpus inventory). **Test:** look for `vmrun`/`vmmcall`/
`VMCB`-shaped structures and a second-level page table. **Trap:** firmware 1.00–2.70 PS5
embeds the HV in the kernel, so "HV present as a separate image" is a 3.00+ signal only.

**Ranking for a first pass:** H1 → H3 → H5 → H4 → H7. H1 is decisive when it fires; H3
cheaply falsifies 13/14; H5 separates PlayStation from stock; H4 separates 9 from 11;
H7 is the expensive confirmation.

---

## 6. Claims considered and rejected

| Claim | Where it comes from | Why it is not used |
|---|---|---|
| "PS4 and PS5 system softwares are only based on FreeBSD 11" | FreeBSD Phabricator D34374, comment by `mchoo` (S7) | Contributor comment, no measurement shown; contradicted by PS4-specific sources (S1, S4) and by the PS5-only `1100122` value. The same thread's reviewer disputes even the PS4 OSS page's FreeBSD content. |
| "PS4 FW 13.52 kernel base: FreeBSD 9" **and** "Syscall ABI is FreeBSD 13.0 (correcting the 'FreeBSD 9' claim)" | Two repositories by the same author (`BillZaiD/ps4-kernel-uaf-research-fw1352`, `BillZaiD/ps4-fw1352-kernel-research-paper`) | The two documents contradict each other; neither shows a version string or a header comparison. The "FreeBSD 13.0" claim is *inconsistent* with the 48-byte `sysent` layout those same offsets imply, since FreeBSD 13/14 use a 40-byte layout with `sy_call` at +0 (S15, S16). Not citable. |
| "HeerBSD r228995" as the 13.52 kernel ident | `BillZaiD/ps4-fw1352-kernel-research-paper` title | Single uncorroborated source. The revision number is *plausible* for a Jan-2012 9.0-branch build, which is exactly why it must not be adopted without a second, independent observation. |
| "PS4 7.00 added SMEP/SMAP" (various forum posts) | Forum/social posts surfaced in search | No primary source; contradicted by Specter ("no SMAP/SMEP for its lifespan", 2023) and TheFloW (9.00, no SMEP). Not used. |

---

## 7. Source fetch status

Every source cited above, with the result of the fetch performed on 2026-11-05.
"OK" = page fetched and the quoted text was read in the response. "OK (Wayback)" = the
live page was Cloudflare-blocked or truncated, the Internet Archive snapshot was fetched
instead. "BLOCKED" = could not be read; such a source is never used to carry a claim.

| ID | Source | Supports | Fetch status |
|---|---|---|---|
| S1 | Specter, *Next-Gen Exploitation: Exploring the PS5 Security Landscape*, hardwear.io USA 2023 — https://hardwear.io/wp-content/uploads/2026/04/next-gen-exploitation-exploring-the-PS5-security-landscape.pdf | PS4 = modified FreeBSD 9.0; PS5 = FreeBSD 11.0; PS4 no ASLR at launch / 2.xx; no SMAP/SMEP "for its lifespan"; 6.xx hardening; PS5 ASLR+SMAP/SMEP since launch; kCFI; XOM; hypervisor details | **OK** (PDF text extracted, 15,922 chars) |
| S2 | Wikipedia, *PlayStation 4 system software* — https://en.wikipedia.org/wiki/PlayStation_4_system_software | "Orbis OS, based on FreeBSD 9" | **OK** |
| S3 | Phoronix, 2013-06-23, *Sony's PlayStation 4 Is Running Modified FreeBSD 9* — https://www.phoronix.com/news/MTM5NDI | FreeBSD 9.0, devkit-derived, pre-launch | **OK** |
| S4 | psdevwiki, *PS4/Syscalls* — https://www.psdevwiki.com/ps4/Syscalls | "PS4 kernel is based on FreeBSD 9"; missing/disabled + custom syscalls | **OK** |
| S5 | CTurt, *Hacking the PS4, part 3 — Kernel exploitation* (2015) — https://cturt.github.io/ps4-3.html | "no kernel ASLR … same across reboots"; JIT/RWX design; FreeBSD 9.0-RELEASE references | **OK** |
| S6 | Sony, PS4 OSS — *FreeBSD Kernel* — https://www.playstation.com/en-us/oss/ps4/freebsd-kernel/ | FreeBSD kernel code is in PS4; **no version named** | **OK** (licence text only) |
| S7 | FreeBSD Phabricator D34374, *FreeBSD on PlayStation 3, PlayStation 4, and PlayStation 5* — https://reviews.freebsd.org/D34374 | The "FreeBSD 11 for PS4 too" comment; reviewer's note that the Sony page names no version | **OK** (page fetched; the tail of one comment is cut by the page's own "show more") |
| S8 | qwertyoruiopz, *PS4 4.05 'NamedObj' Kernel Exploit Writeup* — https://www.exploit-db.com/exploits/44232 | kASLR "enabled past 1.76"; "PS4 does not have SMAP"; CR0.WP text protection; RWX/mmap behaviour; 85→120 custom syscalls | **OK** |
| S9 | Specter (Cryptogenic), *PS4 5.05 BPF Double Free Kernel Exploit Writeup* — https://raw.githubusercontent.com/Cryptogenic/Exploit-Writeups/master/FreeBSD/PS4%205.05%20BPF%20Double%20Free%20Kernel%20Exploit%20Writeup.md | "poor man's SMAP" scheduler stack check in 5.0x; CR0.WP patch step; FreeBSD 9 (FREEBSD90) cross-reference | **OK** |
| S10 | TheFloW, HackerOne report #1379975, *bd-j exploit chain* (tested on 9.00) — https://hackerone.com/reports/1379975 | "no SMEP" on PS4 9.00 | **OK** |
| S11 | psdevwiki, *PS5/Kernel* — https://www.psdevwiki.com/ps5/Kernel | FreeBSD 11.0; `__FreeBSD_version` 1100122; nx/smap/smep/umip/nda-xotext; 3 sysvecs | **OK** (live) + **OK (Wayback 2026-01-31)** |
| S12 | ChendoChap, *PS5 Webkit Execution* (2022) — https://github.com/ChendoChap/PS5-Webkit-Execution | "Uses FreeBSD 11"; SMEP/SMAP/XOM/CFI mitigation table; clang CFI | **OK** |
| S13 | FreeBSD `releng/11.0/sys/sys/param.h` — https://cgit.freebsd.org/src/plain/sys/sys/param.h?h=releng/11.0 | `#define __FreeBSD_version 1100122` | **OK** (raw file) |
| S14 | FreeBSD `releng/11.0/sys/conf/newvers.sh` — https://cgit.freebsd.org/src/plain/sys/conf/newvers.sh?h=releng/11.0 | `REVISION="11.0"`, `BRANCH="RELEASE-p16"` | **OK** (raw file) |
| S15 | FreeBSD `sys/sys/sysent.h` `stable/9`, `stable/10`, `stable/11` — https://cgit.freebsd.org/src/plain/sys/sys/sysent.h?h=stable/9 (etc.) | identical 48-byte sysent: narg@0, call@8, thrcnt@44 | **OK** (raw files) |
| S16 | FreeBSD `sys/sys/sysent.h` `stable/13`, `stable/14` — https://cgit.freebsd.org/src/plain/sys/sys/sysent.h?h=stable/13 (etc.) | 13/14 layout: call@0, narg@16, thrcnt@32, size 40 | **OK** (raw files) |
| S17 | Sony, PS4 OSS — *WebKit* — https://www.playstation.com/en-us/oss/ps4/webkit/ | per-firmware WebKit source drops, 1.76 → 13.00; 601/616 branch labels from 12.50 | **OK** |
| S18 | psdevwiki, *PS4/Internet_Browser* — https://psdevwiki.com/ps4/Internet_Browser | "JIT: not supported since PS4 System Software 2.00"; no WebGL/SVG/WASM | **OK** |
| S19 | Sony, PS5 OSS — *WebKit* — https://www.playstation.com/en-us/oss/ps5/webkit/ | per-firmware WebKit drops, 1.00 → 14.00 | **OK** |
| S20 | Specter, *Byepervisor: How we broke the PS5 Hypervisor*, hardwear.io 2026 — https://hardwear.io/wp-content/uploads/2026/03/Byepervisor__Breaking_PS5_Hypervisor_Security.pdf | XOM/XOTEXT user+kernel, HV-enforced; kernel text not writable, CRs/MSRs protected; SLAT/nested paging; HV timeline 1.00 embedded / 3.00 isolated / 5.00; IDT hijack as workaround | **OK** (PDF text extracted, 17,965 chars) |
| S21 | psdevwiki, *PS5/Vulnerabilities* (Kernel + Usermode securities sections) — https://www.psdevwiki.com/ps5/Vulnerabilities (live page Cloudflare/truncated) | 6.00 kernel .data write → panic; GPU DMA workaround; XOM blocks .text; 6.00 BD-J needs kexploit; 8.00 syscall/libkernel blocking; CR0.WP/XOM bypass "maybe 5.00" | **OK (Wayback 2026-01-02, full text read from cache)** |
| S22 | FreeBSD `releng/9.0/sys/sys/param.h` — https://cgit.freebsd.org/src/plain/sys/sys/param.h?h=releng/9.0 | `#define __FreeBSD_version 900044` | **OK** (raw file) |
| S23 | FreeBSD Porter's Handbook, *FreeBSD 9 Versions* and *FreeBSD 11 Versions* — https://docs.freebsd.org/en_US.ISO8859-1/books/porters-handbook/versions-9.html (and `-11`) | 900044 = 9.0-RELEASE; 1100121 → 1100500 transition; 1100122 not listed in the table | **OK** |
| S24 | FreeBSD `sys/vm/vm_map.h` `stable/9`, `stable/11` — https://cgit.freebsd.org/src/plain/sys/vm/vm_map.h?h=stable/9 (etc.) | 9: `avail_ssize` @+0x30; 11: `pad0` @+0x30, `next_read` @+0x38 | **OK** (raw files) |
| S25 | FreeBSD `sys/sys/syscall.h` `stable/9`, `stable/11` — https://cgit.freebsd.org/src/plain/sys/sys/syscall.h?h=stable/9 (etc.) | `SYS_MAXSYSCALL` 545 (9) vs 551 (11) | **OK** (raw files) |
| — | psdevwiki, *PS4/Kernel* — https://www.psdevwiki.com/ps4/Kernel | — | **OK but empty** (page has no content, live and Wayback 2024/2025); therefore PS4 has no psdevwiki kernel feature list to cite |
| — | Sony, PS4/PS5 OSS index — https://doc.dl.playstation.net/doc/ps4-oss/index.html (and `ps5-oss`) | — | **BLOCKED** (extractor: "page is behind a login or paywall"); not used for any claim |
| — | playstationdev.wiki, *PS5 Kernel* (linked from S7) — https://playstationdev.wiki/ps5devwiki/index.php?title=Kernel | — | **BLOCKED** (empty response, 60 chars); the D34374 comment's link could not be verified, so the comment is not used |
| — | fail0verflow, *The First PS4 Kernel Exploit: Adieu* — https://fail0verflow.com/blog/2017/ps4-namedobj-exploit/ | — | **OK but no mitigation statements** (no ASLR/SMEP/SMAP text found); not cited for mitigations |
| — | ChendoChap, *pOOBs4* — https://github.com/ChendoChap/pOOBs4 | — | **OK but no keyword hits** for SMEP/SMAP/ASLR; not cited |

---

## 8. One-paragraph answer to the original question

Public evidence supports exactly two kernel-lineage claims, both platform-level and both
stable across the console's life: **PS4 runs a Sony-modified FreeBSD 9.0** (Specter 2023;
Wikipedia/Phoronix 2013; psdevwiki) and **PS5 runs a Sony-modified FreeBSD 11.0**
(`__FreeBSD_version` 1100122 = `releng/11.0`, i.e. 11.0-RELEASE). No public source maps an
individual firmware version to a different base version, so every per-band row in this
document is an INFERRED application of those two platform statements and is falsifiable by
a single contradicting version string. The mitigation timeline is comparatively
well-sourced for the eras people exploited: PS4 launched with **no kASLR and no SMEP/SMAP**
and only gained kASLR in 2.xx, a scheduler stack check in 5.0x and driver/syscall
hardening in 6.xx, while never (through the 2023 sources) gaining SMEP/SMAP; PS5 launched
with **kASLR, SMAP/SMEP, kCFI, XOM and a hypervisor** and added hypervisor-enforced
kernel `.data` write protection at 6.00 and usermode syscall blocking at 8.00. Everything
about PS4 11.00–14.00, PS4's `__FreeBSD_version`, per-band WebKit revisions, and
IDT/GDT- or dmap-specific protections is **not established** and is listed as such in §4.
