# Network-stack families — source fetch log

Scope: PPPwn / `sppp(4)` and the IPv6 socket-option family. Every claim in the three
staging entries names a source below. No firmware, no Sony binary, no console contact.

Fetch methods used: `web_extract` (hosted extractor), `curl` in the sandbox,
`r.jina.ai` text proxy, and one `browser_navigate`. Status is what the tool actually
returned, not what the URL should contain.

## Fetched successfully

| URL | Status | Tool | Supports (as used in the entries) | Entry |
|---|---|---|---|---|
| https://hackerone.com/reports/2177925 | 200, full report body | web_extract | Unchecked LCP/IPCP option length used as copy size and loop stride; heap overwrite **and** overread in `sppp_lcp_RCR` / `sppp_ipcp_RCR`; malloc size influenced via the LCP header; second bug: `sppp_pap_input` negative `len - 6` bypass → OOB `memcmp` + ACK/NAK oracle; impact statement "PS4/PS5 … kernel context" | pppwn-sppp-lcp-rcr, sppp-pap-input-underflow |
| https://hackerone.com/reports/2177925.json | 200, metadata only | curl | Submitted 2023-09-22, disclosed 2024-04-25, severity high | pppwn-sppp-lcp-rcr |
| https://github.com/TheOfficialFloW/PPPwn | 200, README rendered | web_extract | "kernel RCE for PS4 up to FW 11.00", PoC for CVE-2006-4304, full supported-firmware list, stage 0–4 log | pppwn-sppp-lcp-rcr |
| https://raw.githubusercontent.com/TheOfficialFloW/PPPwn/master/README.md | 200, full text | web_extract | Same claims as above, untruncated (firmware list, run log, "prints PPPwned") | pppwn-sppp-lcp-rcr |
| https://raw.githubusercontent.com/TheOfficialFloW/PPPwn/master/pppwn.py | 200, 879 lines | curl | Weaponisation detail: `TARGET_SIZE=0x100`, `len=TARGET_SIZE+4`, fake `in6_llentry` with `le_next = pppoe_softc+0x40`, ICMPv6 heap grooming, leak of `pppoe_softc_list`, `kaslr_offset`, per-firmware offset classes | pppwn-sppp-lcp-rcr |
| https://raw.githubusercontent.com/TheOfficialFloW/PPPwn/master/stage1/stage1.c | 200, full text | web_extract | Repair of the corrupted `in6_llentry` links and of the `nd6_ns_output` side effects — confirms which object the overflow hits | pppwn-sppp-lcp-rcr |
| https://www.freebsd.org/security/advisories/FreeBSD-SA-06:18.ppp.asc | 200, full advisory | web_extract | 2006 advisory: `sppp(4)` fails to validate LCP option lengths, read/written beyond the kernel buffer; CVE-2006-4304; announced 2006-08-23 | pppwn-sppp-lcp-rcr |
| https://security.freebsd.org/patches/SA-06:18/ppp.patch | 200, 3755 bytes, 24 hunks | curl | Exact upstream guard `len >= 2 && p[1] >= 2 && len >= p[1]` in twelve loops; **no** hunk touches `sppp_pap_input` | pppwn-sppp-lcp-rcr, sppp-pap-input-underflow |
| https://www.freebsd.org/security/advisories/ | 200 via curl (extractor 429) | curl | Advisory index confirms `FreeBSD-SA-06:18.ppp` exists (the `.asc` header prints 06:08 — internal inconsistency noted in gaps) | pppwn-sppp-lcp-rcr |
| https://x.com/theflow0/status/1783620012994945437 | 200, post text | web_extract | "The PS4 (up to FW 11.00) and PS5 (up to FW 8.20) were vulnerable to CVE-2006-4304" | pppwn-sppp-lcp-rcr |
| https://consolemods.org/wiki/PS4:Exploit_Chart | 200, table | web_extract | Firmware matrix: PPPwn 7.00–11.00, "11.00 firmware is the last version that supports the PPPwn exploit"; "IPV6 UaF" 5.50–6.51; "IPV6 Double Free" 7.00–7.55 | pppwn-sppp-lcp-rcr, ipv6-pktopts-uaf |
| https://ironpeak.be/blog/pppwned/ | 200, ~14k chars read | web_extract | Secondary narrative: the unchecked loop, the 2006 guard, "six near-identical routines". Used for context only — it adds no version facts | pppwn-sppp-lcp-rcr |
| https://hackerone.com/reports/826026 | 200, full report + comments | web_extract | Missing locks in `IPV6_2292PKTOPTIONS`; race frees `ip6_pktopts` while `ip6_setpktopt` handles it; `ip6po_pktinfo` hijack → arbitrary R/W; reachable from WebKit sandbox; unpatched at 7.02; PlayStation: "patched via PS4 system software version 7.50"; reporter: "verified that it was properly fixed" | ipv6-pktopts-uaf |
| https://security.freebsd.org/advisories/FreeBSD-SA-20:20.ipv6.asc | 200, full advisory | web_extract | Same CVE-2020-7457 upstream: "The IPV6_2292PKTOPTIONS set handler was missing synchronization, so racing accesses could modify freed memory"; credits syzkaller and Andy Nguyen; corrected 2020-04-02 (r359565); references report 826026 | ipv6-pktopts-uaf |
| https://hackerone.com/reports/1441103 | 200 via `r.jina.ai` only | r.jina.ai | PS5 vulnerable to report 826026; used with the BD-J chain; resolved 2022-03-31 | ipv6-pktopts-uaf |
| https://hackerone.com/reports/1441103.json | 200, metadata | curl | Title "Use-after-free in setsockopt IPV6_2292PKTOPTIONS (CVE-2020-7457)", submitted 2022-01-04, resolved | ipv6-pktopts-uaf |
| https://raw.githubusercontent.com/Cryptogenic/PS5-IPV6-Kernel-Exploit/master/README.md | 200 via curl (extractor 429) | curl | PS5 port based on TheFlow's IPv6 UAF (report 1441103); supported 3.00–4.51; stage 1 "trigger the initial UAF on `ip6_pktopts`"; XOM blocks code execution | ipv6-pktopts-uaf |
| https://raw.githubusercontent.com/sleirsgoevy/ps4jb/master/README.md | 200 | web_extract | PS4 6.72 chain credits TheFlow's kernel exploit as HackerOne report 826026 | ipv6-pktopts-uaf |

## Fetched but not used as evidence

| URL | Status | Why not used |
|---|---|---|
| https://consolemods.org/wiki/PS4:PPPwn | 200 | End-user setup guide (PPPoE LAN, firmware selection, retry knobs). Corroborates the entry conditions only; no exploit internals, so nothing cites it. |
| https://en.wikipedia.org/wiki/PlayStation_4_system_software | 200 | Looked for an 11.02/11.50 date to pin the fix boundary; the page lists 11.00 → 11.50 with no 11.02 detail and gives no driver-level information. Left out rather than used loosely. |
| https://api.github.com/repos/TheOfficialFloW/PPPwn/contents/stage1 and `/stage2` | 200 | File inventory only (`stage1.c`, `offsets.h`, `start.S`, …); confirms no PS5 payload tree exists in the repo. |

## Failures (recorded, then worked around)

| URL | Failure | Recovery |
|---|---|---|
| https://hackerone.com/reports/1441103 | `web_extract` twice: Keenable backend read timeout (30 s) | `r.jina.ai` proxy returned the report text; `.json` endpoint gave metadata |
| https://hackerone.com/reports/1441103 | `browser_navigate` returned an empty page (JS app, no snapshot) | same as above |
| https://raw.githubusercontent.com/Cryptogenic/PS5-IPV6-Kernel-Exploit/master/README.md | `web_extract`: Firecrawl 429 | `curl` returned the raw file |
| https://www.freebsd.org/security/advisories/ | `web_extract`: Firecrawl 429 | `curl` returned the index |

## Notes on source quality

- **Primary**: the two HackerOne reports (vendor + reporter comments), the two FreeBSD
  advisories and the 2006 patch, and the PPPwn source tree. Everything version-specific
  in the entries comes from these.
- **Secondary**: ConsoleMods exploit chart (community matrix, useful for firmware spans
  but not a vendor statement) and the ironpeak blog (2026 narrative; its advisory
  numbering follows the `.asc` header typo, so it is not cited for version claims).
- **Not established by any fetched source**: which PS4 firmware first ships a fixed
  `sppp(4)`; whether the PAP path was ever fixed; the PS5 fix version for the IPv6 UAF.
  These are in the entries as gaps, not as claims.
