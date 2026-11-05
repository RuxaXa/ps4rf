# Corpus staging - entry-chain source fetch log

Scope: how public PS4/PS5 exploits get from a user-reachable component (Blu-ray/BD-J
JAR, WebKit browser, YouTube app) to kernel code. Seven entries were written:

| Entry file | Entry family | Terminal kernel stage |
|---|---|---|
| `bd-jb-bluray-entry.json` | BD-J Xlet / bdjstack sandbox escape (TheFloW) | none in the entry itself; chained to Lapse or another kernel bug |
| `bd-jb2-bdjo-traversal.json` | BDJO `baseDirectory` path traversal (BD-JB2) | chained to AIO / umtx on PS5, Lapse on PS4 |
| `bd-jb-1342-checkpackageaccess.json` | PS5 `checkPackageAccess` escape (BD-JB-13.42) | chained to a netcontrol/Poops payload |
| `y2jb-youtube-lapse.json` | PS5 YouTube app cache injection (Y2JB) | `aio_multi_delete` double free (Lapse) |
| `ps4-webkit-namedobj.json` | PS4 WebKit browser | `namedobj` type confusion -> UAF |
| `ps4-webkit-poobs4.json` | PS4 WebKit browser (bad_hoist) | exFAT up-case table heap overflow (pOOBs4) |
| `ps5-webkit-ipv6-uaf.json` | PS5 modal browser (User Manual) | IPv6 `ip6_pktopts` UAF (CVE-2020-7457) |

The kernel-bug side of Lapse, pOOBs4, Relapse and pfs_readdir is already covered by
sibling staging files (`lapse-aio-multi-delete.json`, `poobs4-exfat-upcasetable.json`,
`relapse-aio-multi-wait.json`, `pfs-readdir-filename-overflow.json`); these entry-chain
entries describe only enough of the terminal bug to anchor the chain.

Every source below was actually retrieved during this pass. "Result" describes what the
tool returned, not what the page claims. Nothing is cited from a search-result snippet
alone; snippets were used only to choose what to fetch.

## Fetched and used

| # | URL | Tool | Result | Used for |
|---|-----|------|--------|----------|
| 1 | https://hackerone.com/reports/1379975 | web_extract | OK - full disclosed report body, code blocks and timeline; resolved 2022-04-04, disclosed 2022-06-10, $20k | BD-JB five-vulnerability chain: `userprefs` `readObject`, `IxcProxy`, `com.oracle.security.Service`, `CompilerAgentRequest` memcpy at +0x38, UDF `inf_len`/`sector_size` overflow; tested on 9.00 |
| 2 | https://raw.githubusercontent.com/TheOfficialFloW/Presentations/master/2022-hardwear-io-bd-jb.pdf | web_extract | OK - PDF text extracted (full slide deck) | JVM `-Xbootclasspath` includes `bdjstack.jar`; vuln #1 path `/OS/HDD/download0/mnt_ada/userprefs`; vuln #2 `IxcProxy`; PS4 separate JIT compiler process vs "PS5: JVM JIT not supported"; support PS4 <9.50 / PS5 <5.00; privileged `URLClassLoader` traversal example |
| 3 | https://www.psdevwiki.com/ps4/Vulnerabilities | web_extract | OK - 407,046 clean chars; full text cached; sections read at lines 752-831, 1237-1270, 3228-3279 | BD-JB <=9.00, BD-JB2 <=12.52 and its `BdjPolicyImpl` prefix bug, BD-JB-EX <=13.52, BD-JB-14.00, PS4/PS5 `system_ex` paths, exFAT before/after 9.03 |
| 4 | https://www.psdevwiki.com/ps5/Vulnerabilities | web_extract | OK - 232,938 clean chars; full text cached; sections read at lines 353-420, 449-510, 556-645, 1358-1412 | PS5 BD-JB <=4.51, BD-JB2 <=7.61 fixed 8.00, BD-JB-13.42 <=13.42 fixed 13.60, BD-JB-EX <=13.60, YouTube app 2.00-13.60, V8/SpiderMonkey split, aio_multi_delete <=10.01 fixed 10.20, IPv6 UAF 3.00-4.51 |
| 5 | https://www.psdevwiki.com/ps5/Exploit_Chains | web_extract | OK - full chain table | WebKit (CSSFontFaceSet / loadInSameDocument) + IPv6 UAF combinations for 1.00-5.50 and 3.00-4.51; BD-JB/BD-JB2 + AIO/umtx combinations |
| 6 | https://github.com/TheOfficialFloW/bd-jb | web_extract | OK - README rendered (minimal), repository created 2021-10-22 | Public "first bd-j hack" implementation; BD-JB2 is based on it |
| 7 | https://consolemods.org/wiki/PS4:BD-JB | web_extract | OK - full page | BD-JB disc workflow; `Lapse.iso` 9.00-12.02; Henloader 9.00-12.52; 13.00+ workaround copying `00000.jar` into `bdjstack/lib/ext`; 14.00 `hen.iso` |
| 8 | https://consolemods.org/wiki/PS4:Exploit_Chart | web_extract | OK - full chart | 1.76 JSArray WebKit overflow; NamedOBJ <=4.07; later WebKit kernel pairings |
| 9 | https://github.com/Gezine/BD-JB5 | web_extract | OK - README and file listing | PS5 BD-JB5 supported up to 13.42; 13.60+ needs `bdj_unpatch.elf` from an already-jailbroken PS5; it backs up/replaces `bdjstack.jar`; `payloads` tree includes Poops |
| 10 | https://gist.github.com/TheOfficialFloW/7174351201b5260d7780780f4059bebf | web_extract | OK - 29,107 clean chars; Java source | `com.bdjb.exploit.kernel.ExploitNetControlImpl`: a BD-J payload that dlsyms libkernel symbols and drives `__sys_netcontrol` |
| 11 | https://blog.gistre.epita.fr/posts/marco.chan-witzel-2026-07-13-lapse-the-aio-kernel-exploit-behind-the-ps5-jailbreak/ | web_extract | OK - 31,528 clean chars; head+tail inline, omitted middle read from the cached file | YouTube app entry, unchecked `splash.html` cache, V8 TheHole CVE-2021-38003/CVE-2022-4174, quoted `aio_multi_delete` body, two-thread race, 5-stage Lapse chain, PS5 10.20 fix |
| 12 | https://github.com/Gezine/Y2JB | web_extract | OK - full README | Y2JB = userland code execution via the PS5 YouTube app; minimum 4.03; `PPSA01650` app versions; `/user/download/PPSA01650` `download0.dat`; Lapse payload capped at 10.01 |
| 13 | https://fail0verflow.com/blog/2017/ps4-namedobj-exploit/ | web_extract | OK - 16,803 clean chars; head+tail inline, omitted middle read from the cached file | Browser-process entry; id_table/IDT_TYPE design; `namedobj_create` kind control; `namedobj_create_ex` cast; `namedobj_delete` UAF; `kern.file` leak; kqueue/kevent ROP; fixed in 4.06 and the 4.07 check |
| 14 | https://github.com/Cryptogenic/PS4-4.05-Kernel-Exploit | web_extract | OK - full README | Full namedobj implementation for 4.05; WebKit delivery ("WebKit very rarely crashes"); kernel patch set including syscall 11 |
| 15 | https://hackerone.com/reports/1340942 | web_extract | OK - full disclosed report body with C code and timeline; resolved 2021-12-07, disclosed 2022-09-21, $10k | exFAT 64-bit `dataLength`/`size` truncated by 32-bit `sceFatfsCreateHeapVl`; `0x100000200 -> 0x200` example; sector-multiple overflow; USB trigger; kernel code execution impact |
| 16 | https://github.com/ChendoChap/pOOBs4 | web_extract | OK - full README and file listing | 9.00 exploit; bug found by diffing 9.00 and 9.03; modified exFAT USB image; credits sleirsgoevy's 9.00 WebKit exploit; fixed in 9.03; bug predates 1.00 |
| 17 | https://github.com/sleirsgoevy/bad_hoist | web_extract | OK - full README | PS4 WebKit bad_hoist implementation, loaded from the PS4 web browser; tested 6.51-6.72 |
| 18 | https://github.com/ChendoChap/PS5-Webkit-Execution | web_extract | OK - full README | PS5 4.03 browser vulnerable; clang CFI blocks PS4 vtable smash; Web Worker stack leak and pivot; says the Project Zero report was actually CVE-2021-30889; PoC modified to 9.00 for pOOBs4 |
| 19 | https://github.com/Cryptogenic/PS5-IPV6-Kernel-Exploit | web_extract | OK - full README | PS5 3.00-4.51 IPv6 UAF; five stages (pktopts UAF, rthdr spray, kqueue leak, IPV6_RTHDR R/W, cleanup); XOM/HV prevent kernel code execution; DNS-redirect User Manual entry |
| 20 | https://security.freebsd.org/advisories/FreeBSD-SA-20:20.ipv6.asc | web_extract | OK - full PGP-signed advisory | CVE-2020-7457: `IPV6_2292PKTOPTIONS` set handler missing synchronization, racing accesses modify freed memory, memory corruption/privilege escalation; corrected revisions |

## Fetched but not used as evidence

| URL | Result | Why not used |
|-----|--------|--------------|
| https://www.psdevwiki.com/ps4/Exploit_Chains | OK - page is a stub with one PPPwn row | No BD-J/WebKit chain data |
| https://github.com/TheOfficialFloW/Presentations/blob/master/2022-hardwear-io-bd-jb.pdf | OK but returned the GitHub UI shell, not the PDF text | Superseded by the raw URL (#2) |
| https://github.com/Gezine/BD-JB-1250 | OK - full README | Supports PS4 BD-JB 9.00-12.52 and Lapse 9.00-12.02, but the same facts are covered by ConsoleMods (#7); not cited to keep the source set small |

## Search hits deliberately not fetched / not used

`psxhax` forum pages, Reddit threads, YouTube videos, Instagram posts, `vicianalab.com`
and the `elhacker.info` mirror of the bd-jb slides appeared in search results but were not
fetched and are not cited. The `elhacker.info` PDF mirror was not used because the
author's raw GitHub PDF (#2) was fetched successfully.

## Conflicts in the public record (recorded in the entries, not resolved)

1. **9.00 WebKit CVE naming.** ConsoleMods says pOOBs4 used CVE-2021-30858; ChendoChap's
   PS5 writeup says the Project Zero report was actually CVE-2021-30889, and pOOBs4 credits
   sleirsgoevy's `bad_hoist`. The entry keeps both readings and does not pick one.
2. **namedobj fixed version.** fail0verflow says fixed in 4.06 and shows the 4.07 check;
   the ConsoleMods chart lists NamedOBJ for <=4.07. The entry uses 4.06 and records the
   one-release discrepancy.
3. **BD-JB support ceiling.** The slides say PS4 <9.50 and PS5 <5.00; the PS4 wiki pins the
   five-vulnerability chain at <=9.00; HackerOne says only "tested on latest 9.00". The
   entry records the range and flags the lack of a per-gadget patch map.
4. **YouTube app version boundary.** The PS5 wiki mentions 12.60+ and app versions
   `01.000.025?`/`01.000.030`; the Y2JB README says 4.03-12.40 use `01.000.003` and 12.60+
   use `01.000.030`. The entry treats the 12.60 boundary as approximate.
5. **BD-JB2 "fixed in 13.00".** The PS4 wiki also lists BD-JB-13.00 (CVE-2025-64390) for
   13.00-13.02, a different path-injection variant. The entry notes that "fixed in 13.00"
   applies to BD-JB2 specifically, not to every BD-J path trick.

## Limits

* No firmware, kernel dump, Sony binary, key or console was touched.
* Wiki text is a secondary transcription of someone else's decompilation; where an entry
  depends on it the source is labelled `writeup`, not `advisory`.
* Repository READMEs are self-report by the exploit authors. They are cited for what they
  claim, not as independent verification.
* The slides are the author's own presentation material and use a decompiler transcription;
  they are cited as `writeup`.
* Firmware ranges are the ranges the sources state. They are not re-measured against an
  image in this pass, and no offsets from the writeups are copied into the entries.
