# External Tool Integrations

Status legend: **ADAPTER v0.1** = source + tests exist and run offline against a
mock; **PLANNED** = decided, nothing built yet; **CONCEPT** = idea only.
No adapter is marked implemented unless source and tests exist.

## Recon & privilege-escalation knowledge (added 2026-10-05)

| Tool | Purpose | Status |
|---|---|---|
| PEASS-ng / linPEAS | Linux host / auxiliary target enumeration (filesystem, permissions, SUID/SGID, capabilities, services, cron, sockets, credentials-presence, mounts, kernel/OS, interesting binaries) with **target-OS detection** | ADAPTER v0.1 (offline vs. `tools/recon/peass/mock/`; PS4/OrbisOS explicitly NOT scanned generically; `tools/recon/peass/`) |
| GTFOBins | Local **knowledge base** (no executable primitive): sudo, SUID, capabilities, shell escape, file read/write, upload/download, command execution, library loading, restricted-shell bypass → escalation *candidates* | ADAPTER v0.1 (knowledge-only, `tools/knowledge/gtfobins/`; index + matcher, corpus is external input, never vendored) |
| unix-privesc (compat layer) | Platform-independent local enumeration schema/classifier from which Linux **and** FreeBSD/OrbisOS checks are derived later | ADAPTER v0.1 (`tools/recon/unix_privesc/`; Linux vs. FreeBSD/OrbisOS classified separately, PS4-specific checks stay native) |
| pspy | Process/cron observation on live Linux targets | PLANNED |
| Linux Smart Enumeration (LSE) | Alternative Linux enumeration surface | PLANNED |
| unix-privesc-check | Cross-Unix local enumeration corroboration | PLANNED |
| Nuclei | Template scanning of reachable web/network services only | PLANNED |
| ffuf / feroxbuster | Web surface discovery | PLANNED |
| nmap / masscan | Network discovery | PLANNED |
| SecLists | Wordlist/corpus provider | PLANNED |

## Analysis & exploitation backends (existing)

| Tool | Purpose | Handoff status |
|---|---|---|
| OrbisProbe | Discovery, ranking, proof planning | ADAPTER v0.1 (offline, mock-tested; `tools/orbisprobe/`, see `ORBISPROBE-PS4RF-MAPPING.md`) |
| Metasploit | Exploit/aux/session backend via RPC | ADAPTER v0.1 (offline vs. msfrpcd mock; `tools/metasploit/`, DoD §12.7 matrix in its README) |
| Ghidra | Headless RE, xrefs, decompile, diffing | ADAPTER v0.1 (offline vs. headless-CLI mock; `tools/ghidra/`, real postscript pending) |
| Rizin | Fast CLI analysis, CFG/xrefs | ADAPTER v0.1 (offline vs. command-surface mock; `tools/rizin/`, xrefs/CFG/boundaries) |
| angr | CFG, dataflow, symbolic constraints | ADAPTER v0.1 (offline vs. runner mock; `tools/angr/`, runner placeholder hash-pinned) |
| AFL++ | Parser/fuzz corpus and crash workflow | ADAPTER v0.1 (offline vs. tool-surface mock; `tools/aflplusplus/`, corpus/crash/reproducer via evidence) |
| Unicorn | Offline function emulation | PLANNED |
| syzkaller concepts | Stateful sequence mutation/minimization | CONCEPT |
| Scapy | Network crafting | PLANNED |
| Wireshark/TShark | PCAP analysis | PLANNED |
| mitmproxy | HTTP/TLS traffic workflow | PLANNED |
| boofuzz | Protocol fuzzing | PLANNED |

## Canonical integration order

OrbisProbe → GTFOBins knowledge adapter → PEASS/linPEAS adapter → unix-privesc
recon layer → Metasploit → Ghidra → Rizin → angr → AFL++. (The analysis backends
were built first in this repository's history; the order above is the canonical
one going forward. Native `ps4rfd` follows only after the host core and adapters
are stable and the W0 review has passed — **W0 passed on 2026-10-05**, see
`docs/P4-W0-DECISIONS.md`.)

## Wire layer (normative, not an external tool)

| Artifact | Status |
|---|---|
| Frame type byte mapping v1 | **DEFINED in-repo** (W0/D12) — single-sourced in `core/rpc/wire.py`: `0x01` REQUEST, `0x02` RESPONSE, `0x03` EVENT (reserved), `0x04` BYE, `0x05` READY (reserved); any other byte = protocol error, fail-close |
| Wire specification | `docs/P4-WIRE-SPEC-v1.md` (header layout, direction rule, sequence ceiling, fail-close matrix, verification) |
| W0 decision record | `docs/P4-W0-DECISIONS.md` (D1–D19, binding) |
| §70 text (native primitive gate) | `docs/spec-history/70-capability-gated-native-primitive-additions.md` (normative) |
| Freeze drift log | `FREEZE-DRIFT.md` + `tests/test_freeze_drift.py` (read by the gate) |

## Security rule for recon output (binding)

Nothing produced by a recon or knowledge adapter is an exploit finding by itself:

    Recon → Observation → Candidate → Verification → Primitive → Exploit candidate

* Every adapter record carries `classification = OBSERVATION` (knowledge matches:
  `CANDIDATE` with `source = external_knowledge`) and `requires_verification = True`;
  PS4RF decides reachability, attacker control, preconditions, target
  compatibility and the verification experiment.
* No privilege-escalation technique is ever executed because of a linPEAS or
  GTFOBins match — the knowledge adapter stores no recipes and executes nothing.
* PS4/OrbisOS is FreeBSD-based: linPEAS is **not** a generic PS4 scanner. The
  PEASS adapter marks compatibility for supported targets only and reports
  FreeBSD/OrbisOS/unknown explicitly; PS4-specific checks are implemented
  natively later through PS4RF surface/experiment modules.
* These adapters are external tools and never the PS4RF source of truth.
