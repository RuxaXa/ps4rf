# Corpus staging — source fetch log (PS4/PS5 kernel UAF / ownership bugs, 2023+)

Scope of this pass: `afterglow` (kqueue knote vs. `/dev/apm` clone, fd teardown) and
further publicly documented PlayStation kernel use-after-free / reference-count
families from 2023 onward that were not already staged.

Five entries were written by this pass:

| Entry file | Family | Platform | First fixed |
|---|---|---|---|
| `afterglow.json` | kqueue knote held past a `/dev/apm` clone free | PS4 13.52, 14.00 | none public |
| `kqueueex-ucred-refcount.json` | `sys_kqueueex` ucred refcount leak → 32-bit wrap → UAF | PS5 ≤ 12.70 | PS5 13.00 |
| `netcontrol-double-fdrop.json` | `sys_netcontrol` netevent double `fdrop` | PS4 ≤ 13.00, PS5 ≤ 12.00 | PS4 13.02 / PS5 12.02 |
| `umtx-shm-registry-refcount.json` | `umtx_shm_unref_reg_locked` double registry drop (CVE-2024-43102) | PS5 ≤ 7.61 | PS5 8.00 (upstream 2024-09-04) |
| `fsc2h-ctrl-stack-free.json` | `sys_fsc2h_ctrl` free() of a kernel stack pointer | PS5 ≤ 10.40 | PS5 11.00 |

**Not duplicated in this pass.** Other staging passes were writing into the same
directory concurrently — an fs/AIO pass (`SOURCES-fs.md`, `lapse-aio-multi-delete.json`,
`relapse-aio-multi-wait.json`, `pfs-readdir-filename-overflow.json`,
`poobs4-exfat-upcasetable.json`) and a network/PPP pass (`SOURCES-network.md`,
`pppwn-sppp-lcp-rcr.json`, `sppp-pap-input-underflow.json`, `ipv6-pktopts-uaf.json`);
further WebKit/BD-J entries appeared from other passes while this file was written.
Lapse and Relapse fall inside this brief's 2023+ window, but those entries already
exist and were left untouched rather than overwritten; this pass's lapse/relapse
sources are listed under "Fetched but not cited" so the work is not silently lost.
The IPv6 `ip6_pktopts` entry belongs to the network pass (that bug predates 2023).
Only the five files in the table above were created by this pass. If a later network
pass also stages `sys_netcontrol`, deduplicate on the HackerOne report URL rather
than on the file name.

All entries use `role: "training"`. Per the corpus README, describing a root cause
here already means the family cannot later serve as a blind test; none of these
entries is a negative sample.

## Fetched and cited

| # | URL | Tool | Result | Used for |
|---|-----|------|--------|----------|
| 1 | https://raw.githubusercontent.com/well0nez/afterglow-web/main/afterglow.js | terminal `curl -sL` | OK — 88,197 bytes, 2,115 lines; key blocks read at lines 1–60, 195–265, 380–580, 1275–1460, 1595–1665 | Trigger sequence (`/dev/apm`, `kqueue`/`kevent` EVFILT_READ filter `0xFFFF`, second open of `/dev/apm<unit>` + close as the free, `setsockopt(level 17, optname 128)` spray of `TUNE.object = 104`, re-arm); "our notes hang on clones freed long ago"; "closing a queue walks its notes and detaches each one from a device that is gone"; `destroy_dev_sched`; `knote_fdclose()`; `kqueue_close()` note-array length in the high half of `kq+0xa0`; per-CPU-bucket free/refill requirement; `0x38`/`0x58` fake-object fields |
| 2 | https://raw.githubusercontent.com/well0nez/afterglow-web/main/README.md | terminal `curl -sL` | OK — 5,227 bytes, 117 lines | Firmware 13.52 + 14.00; Lua original also exists; `fo_close` → `apmclose` on process exit when handles are left armed; "the reclaimed object supplies the stack pointer … before a single instruction of ours runs" |
| 3 | https://raw.githubusercontent.com/well0nez/afterglow-web/main/TECHNICAL.md | web_extract + terminal `curl` | OK — 5,549 bytes | "The kernel bug, the reclaim, the ring 0 bootstrap and the handle teardown are the same as in the Lua version"; one 57-site patch set per firmware because fixed kernel addresses moved |
| 4 | https://www.psdevwiki.com/ps4/Vulnerabilities | web_extract | OK — 407,046 clean characters; page oldid 297469; kernel sections read at lines 2690–3060 | afterglow: "Undocumented kernel vulnerability (codename afterglow)", FW ≤ ?14.00?, "To be documented", "Opens the device `/dev/apm` many times", unpatched as of 14.00, "maybe" PS5 ≤ 13.60. Also netcontrol (`<= 13.00`, fixed 13.02, slidybat/TheFloW credits) and umtx context |
| 5 | https://raw.githubusercontent.com/BillZaiD/ps4-kernel-uaf-research-fw1352/main/README.md | web_extract + terminal `curl` | OK — 22,076 bytes (21,985 clean chars) | Independent 13.52 claim of a kqueue knote UAF via pipe close and EVFILT_USER reclaim; claims exploitation blocked by the sandbox and by kernel-pointer stripping. Cited only as a corroborating signal, with its conflict against afterglow recorded in `gaps` |
| 6 | https://gist.github.com/Gezine/89581201a9c1da80317ffff1de519294 | web_extract | OK — full gist text (PoC header + C) | `sys_kqueueex`: `crhold()` with no `crfree()` on the `copyinstr()` error path; 2^32-call wrap; falloc `crhold`s; `setuid()` freeing the ucred; `cr_ref=1` spray; repeated `crfree`; "Bug was patched at PS5 13.00"; "PS4 kqueue does not hold ucred" |
| 7 | https://www.psdevwiki.com/ps5/Vulnerabilities | web_extract | OK — 232,938 clean characters; page oldid 4821; sections read at lines 1079–1148, 1265–1420, 1500–1560 | kqueueex: affected ≤ 12.70, fixed 13.00, ~50 min trigger, PS4 unaffected, port list. Relapse/PS5 context (PS4 lacks multi-mode `set_waiter`); umtx: ≤ 7.61, fixed 8.00, "decrements the refcount only if … `USHMF_REG_LINKED`"; fsc2h: ≤ 10.40, maybe 10.60, fixed 11.00 |
| 8 | https://hackerone.com/reports/3320669 | web_extract | OK — disclosed report body incl. pre-fix C code, reproduction and timeline | netcontrol: `getsock_cap()` reference owned by netevent, two `fdrop()` calls in `kern_netevent_clear_queue()`, fd-number comparison, 5-step reproduction, PS4 `fcntl(F_SETFL)` re-free vs PS5 `fget()` hang, weakness "Double Free", disclosed 2026-05-01, $10,000 |
| 9 | https://gist.github.com/TheOfficialFloW/7174351201b5260d7780780f4059bebf | web_extract | OK — 29,107 clean chars (Java BD-J implementation) | netcontrol implementation: `__sys_netcontrol` cmds `0x20000003`/`0x20000007`, `dup()`, pipebuf corruption to arbitrary R/W |
| 10 | https://www.freebsd.org/security/advisories/FreeBSD-SA-24:14.umtx.asc | web_extract | OK — full PGP-signed advisory text | umtx: concurrent `UMTX_SHM_DESTROY` drops the refcount too many times; panic or UAF including code execution; CVE-2024-43102; corrected 2024-09-04 |
| 11 | https://github.com/freebsd/freebsd-src/commit/62f40433ab47ad4a9694a22a0313d57661502ca1 | terminal `curl` of `.patch` | OK — 4,539 bytes; commit message + `kern_umtx.c` diff | umtx mechanism and fix: unconditional registry-reference drop tied to `USHMF_LINKED`, lock dropped between `umtx_shm_find_reg()` and `umtx_shm_unref_reg(true)`, `force` → `linked_ref` |
| 12 | https://hackerone.com/reports/2900606 | web_extract | OK — disclosed report body | fsc2h: four-thread WAIT/RESOLVE/COMPLETE sequence, "path 2 is … a pointer to kernel stack", "Privilege escalation" |

## Fetched but not cited

| URL | Result | Why not cited |
|-----|--------|---------------|
| https://github.com/well0nez/afterglow-web | web_extract OK — repo page, 49,354 clean chars | Same README/TECHNICAL content as rows 2–3; used only to locate the raw files |
| https://zecoxao.github.io/afterglow/ | web_extract OK — landing page: "PS4 kernel exploit · firmware 13.52 and 14.00", by well0nez/m0zz | Host page only; no technical claim |
| https://raw.githubusercontent.com/kmeps4/PSFree/main/lapse.mjs | web_extract OK — 50,072 clean chars | Lapse already staged by the concurrent fs/AIO pass (`lapse-aio-multi-delete.json`); no duplicate entry written |
| https://pastebin.com/hrRgDXLL | web_extract OK — 39 numbered lines | Relapse already staged (`relapse-aio-multi-wait.json`); no duplicate entry written |
| https://raw.githubusercontent.com/ntfargo/Relapse-Exploit/main/README.md | web_extract OK | Same reason (Relapse already staged) |
| https://gist.github.com/zecoxao/80dff057233c1f203352ff8bf317294d | terminal `curl`, 283,242-byte HTML; header read | "prolapse" WIP PoC for PS5 14.10, asserts a `*state != saved_generation_id` recheck in 14.20 for an `aio_multi_delete` re-lookup double free. Unverified and outside this pass's entries; recorded here as a lead only |
| https://github.com/jordyidk/slopkit (and the pinned `bagagwa.js`) | not fetched | Cited indirectly by the dev wiki for the info leak; the write-up (row: pastebin) already covers it |

## Search hits deliberately not fetched and not cited

Reddit threads (including one claiming a `CVE-2026-49412` IPV6_MSFILTER race on
PS5 13.40), gbatemp/psxhax threads, YouTube videos, onejailbreak articles and the
Wikipedia "Softmod" article appeared in search results. None is cited: snippets
were used only to decide what to fetch, and no claim in the entries rests on a
snippet. The `CVE-2026-49412` claim in particular was left out — it exists only in
a forum post and could not be corroborated by any fetchable primary source.

## Conflicts and limits recorded in the entries

1. **afterglow has no public root-cause document.** The exploit's comments and the
   dev wiki ("To be documented", "Opens the device `/dev/apm` many times") are the
   whole public record. Which 128-byte object is actually reclaimed — knote, clone
   or note slot — is not stated anywhere fetched, and the two fake-object fields
   (`+0x38`, `+0x58`) do not obviously match the FreeBSD-9 knote layout quoted by
   the secondary 13.52 paper. Hence `confidence: medium`.
2. **The 13.52 knote/pipe paper conflicts with afterglow.** It reports a knote UAF
   in the same subsystem through pipe close, says exploitation is blocked, and
   gives a different trigger from afterglow's working 13.52 exploit. The entry
   records the paper only as a corroborating signal and keeps the conflict in
   `gaps`; no claim depends on it.
3. **kqueueex has one substantive source.** The dev wiki's bug description restates
   the PoC header almost verbatim, so the mechanism and the 13.00 fix are not
   independently corroborated.
4. **netcontrol's fix is not public.** The pre-fix handler is quoted in full, but
   the post-fix code is not; only the first fixed versions (PS5 12.02 / PS4 13.02)
   are public.
5. **umtx's patch evidence is FreeBSD's, not Sony's.** SA-24:14 and commit
   `62f40433ab47` are authoritative for the shared code, but they are not the PS5
   binary; the PS5 backport is not public.
6. **fsc2h's fix is a version cutoff only.** The report describes the trigger, not
   the change; 10.60 is explicitly "maybe" and 11.00 is stated without mechanism.

## Verification

Each file was loaded back with `json.load()` after writing. Files written by this
pass: `afterglow.json`, `kqueueex-ucred-refcount.json`,
`netcontrol-double-fdrop.json`, `umtx-shm-registry-refcount.json`,
`fsc2h-ctrl-stack-free.json` — all parse. The four pre-existing staging entries
and `SOURCES-fs.md` were not modified.

No firmware image, Sony binary, key, console address or exploit payload is stored
here. Offsets quoted in the entries are only those the cited sources state as
text.
