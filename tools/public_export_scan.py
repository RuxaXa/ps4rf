#!/usr/bin/env python3
"""Fail-closed scan of the fresh PS4RF public-export tree.

The two allowed strings are explicit synthetic credentials used to verify redaction tests;
anything else matching the same pattern fails the scan.
"""
from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
problems: list[str] = []
files = [path for path in ROOT.rglob("*") if path.is_file() and ".git" not in path.parts]
forbidden_files = {
    "kernel.bin", "fw900-kernel-48m.bin", "fw900-kernel-rx.bin",
    "ps4-fw900-cross-processor-handoff-20260907.zip",
    "ps4_fw1352_ccp_harness.zip", "samurf-0.1.0.zip",
}
patterns = {
    "private key": rb"-----BEGIN (?:RSA |OPENSSH |EC |PGP )?PRIVATE KEY-----",
    "GitHub token": rb"\bgh[pousr]_[A-Za-z0-9]{20,}\b",
    "AWS access key": rb"\bAKIA[0-9A-Z]{16}\b",
    "OpenAI-style key": rb"\bsk-[A-Za-z0-9_-]{20,}\b",
    "credential URL": rb"https?://[^/\s:@]+:[^/\s@]+@",
    "hardcoded password": rb"(?i)\b(?:password|passwd|api[_-]?key|secret|token)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
}
for path in files:
    rel = path.relative_to(ROOT).as_posix()
    if path.name in forbidden_files or rel.startswith("references/"):
        problems.append(f"forbidden file: {rel}")
    data = path.read_bytes()
    if data[:2] == b"PK":
        problems.append(f"nested ZIP/archive: {rel}")
    for label, pattern in patterns.items():
        if re.search(pattern, data):
            scrubbed = data.replace(b"test-token-0123456789abcdef", b"") \
                           .replace(b"Sup3rS3cret!", b"")
            if re.search(pattern, scrubbed):
                problems.append(f"{label}: {rel}")
    if len(data) > 1_000_000 and data[:4] in (b"\x7fELF", b"MZ\x90\x00"):
        problems.append(f"large executable blob: {rel} ({len(data)} bytes)")

print(f"files={len(files)} bytes={sum(p.stat().st_size for p in files)}")
print(f"max_file={max((p.stat().st_size, p.relative_to(ROOT).as_posix()) for p in files)}")
if problems:
    print("REFUSED")
    for problem in problems:
        print(" -", problem)
    raise SystemExit(1)
print("PASS: no forbidden blobs, nested archives, private keys or token patterns")
