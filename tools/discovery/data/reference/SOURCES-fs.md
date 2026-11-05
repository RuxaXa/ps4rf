# Corpus staging — source fetch log (PS4 FreeBSD-9-era fs/aio kernel bugs)

Scope: pOOBs4 (exFAT up-case table), Lapse (aio_multi_delete), plus the two closest
siblings that the public record documents — Relapse (aio_multi_wait) and the
pfs_readdir filename overflow.

Every source below was actually retrieved during this pass. "Result" describes what the
tool returned, not what the page claims. Nothing was taken from a search-result snippet
alone; snippets were used only to decide what to fetch.

## Fetched and used

| # | URL | Tool | Result | Used for |
|---|-----|------|--------|----------|
| 1 | https://github.com/ChendoChap/pOOBs4 | web_extract | OK — full repo README rendered (9 commits, last 2022-01-17) | pOOBs4 mechanics: modified exFAT image, 9.00-vs-9.03 kernel diff, fixed in 9.03, bug predates 1.00, PS5 status, trigger sequence |
| 2 | https://hackerone.com/reports/1340942 | web_extract | OK — disclosed report body incl. C code and full timeline | CVE-2022-3349 root cause: `dataLength`/`size` 64-bit vs `sceFatfsCreateHeapVl(int size)`, 512-byte-multiple overflow example, spray target, reporter/disclosure dates |
| 3 | https://www.psdevwiki.com/ps4/Vulnerabilities | web_extract | OK — 407,046 clean chars; full text cached, sections read at lines 2717–3060 and 3228–3279 | PS4 exFAT section (credits, pre/post-9.03 pseudo-code, affected/fixed), Lapse section (affected 5.00–12.02, fixed 12.50/10.20, code comment, PoC), pfs_readdir section |
| 4 | https://nvd.nist.gov/vuln/detail/CVE-2022-3349 | web_extract | OK — full NVD record | CVE description naming `UVFAT_readupcasetable`/`dataLength`, CWE-787, publication 2022-09-28, CPE coverage of PS4 and PS5 |
| 5 | https://github.com/Al-Azif/psfree-lapse | web_extract | OK — README rendered | Lapse is the kernel exploit of the chain; scope table PS4 1.01–12.02, PS5 1.00–10.01 |
| 6 | https://raw.githubusercontent.com/Al-Azif/psfree-lapse/main/src/lapse.mjs | terminal `curl -sSL` | OK — 60,047 bytes, 1,985 lines | Verbatim `aio_multi_delete` bug summary, race widening via `soclose()`/`thr_suspend_ucontext`, 0x80-zone double-free comment |
| 7 | https://blog.gistre.epita.fr/posts/marco.chan-witzel-2026-07-13-lapse-the-aio-kernel-exploit-behind-the-ps5-jailbreak/ | web_extract | OK — 31,528 clean chars | Two-thread interleaving table, read-lock vs missing-write-lock explanation, PS5 10.20 fix statement (secondary/educational source) |
| 8 | https://pastebin.com/hrRgDXLL | web_extract | OK — 39 numbered lines | aio_multi_wait mode-0 mechanism (cached base, same node linked N times, owner overwritten, cleanup unlinks last, array freed, waker write/lock/decrements); claim that PS4 13.52 takes 3 args and has no mode |
| 9 | https://www.psdevwiki.com/ps5/Vulnerabilities | web_extract | OK — 232,938 clean chars; sections read at lines 1079–1148 and 1240–1269 | Relapse section: affected ≤13.60, "maybe" fixed 14.00, wrapper rejects mode 0 with EINVAL, contradictory PS4 statements |
| 10 | https://pastebin.com/aPZ28Afu | web_extract | OK — 93 lines | Standalone aio_multi_delete trigger PoC text (MULTI flag required, wait-then-race, ESRCH equality check) |
| 11 | https://twitter.com/notnotzecoxao/status/1972775526877233470 | web_extract | OK — post text and replies | pfs_readdir buffer-overflow patch disclosure, 2025-09-29 |

## Fetched but NOT used as evidence

| URL | Result | Why not used |
|-----|--------|--------------|
| https://pastebin.com/Qv7DdXnB | OK — 168 lines | Titled "Bug Patched on 12.50 PS4" but it is a reconstructed pseudo-code listing with "PATCHED" annotations that contradict the structure documented elsewhere (stack cookie, `lookupCookie`, `alloca` buffers) and that are not visible in any other source. Treated as unverifiable; no claim in the entries rests on it. |

## Search hits deliberately not fetched / not used

Reddit threads, psxhax forum pages, YouTube videos, onejailbreak and other aggregator
posts appeared in search results but were not fetched and are not cited. `sentinelone`,
`endorlabs`, `invicti` and similar hits were unrelated CVEs (Linux exFAT, PHP) and were
discarded on title alone.

## Conflicts in the public record (recorded in the entries)

1. **Who found the exFAT bug.** The PS4 dev wiki credits TheFloW (report 2021-09-15) and
   separately credits zecoxao's 9.00/9.03 diff advice and ChendoChap's implementation.
   The pOOBs4 README says the bug was found while diffing 9.00 and 9.03. The entry keeps
   both claims and does not resolve them.
2. **Relapse on PS4.** Jordy's write-up says the PS4 13.52 `aio_multi_wait` reads three
   arguments and has no `mode`, and the PS5 wiki says the bug does not affect PS4. The PS4
   wiki lists a PS4 13.02–13.52 "relapse" implementation by raw13g and elsewhere says the
   vulnerability also affects PS4. The entry is therefore scoped to PS5 and the conflict is
   in `gaps`.
3. **Lapse lower bound.** Al-Azif's table starts at PS4 1.01; the PS4 wiki says the SceAIO
   syscalls are unimplemented before 5.00. The entry uses 5.00 as the lower bound and notes
   the discrepancy.
4. **Lapse fix mechanism.** Only "fixed in 12.50 / 10.20" is public. The missing write lock
   is documented; the actual 12.50 change is not. Marked as inference in `firmware.differences`.

## Limits

* No firmware, kernel dump, Sony binary, key or console was touched.
* Offsets quoted in the write-ups as kernel virtual addresses are deliberately not copied
  into the entries.
* Wiki text is a secondary transcription of someone else's decompilation; where an entry
  depends on it the source is labelled `writeup`, not `advisory`.
