"""N4 / T-MSF regression tests for tools/metasploit/redact.py (spec v0.4 §10.4).

T-MSF-01: a secret in module options must appear in evidence neither in clear
          text nor as any derived digest.
T-MSF-02: ``options_sha256`` is computed over the redacted object only, so two
          runs that differ solely in secret values hash identically -- there is
          no secret fingerprint.
"""

from __future__ import annotations

import hashlib

from tools.metasploit.redact import REDACTED, options_sha256, redact_options

SECRET = "Sup3rS3cret!"


def test_t_msf_01_no_secret_nor_digest_in_evidence():
    opts = {"LHOST": "10.0.0.1", "RPORT": 4444, "PASSWORD": SECRET, "TOKEN": SECRET}
    clean, redacted = redact_options(opts)
    assert redacted == ["PASSWORD", "TOKEN"]
    assert clean["PASSWORD"] == REDACTED and clean["TOKEN"] == REDACTED
    blob = repr(clean) + options_sha256(opts)
    assert SECRET not in blob
    assert hashlib.sha256(SECRET.encode()).hexdigest() not in blob


def test_t_msf_02_options_hash_is_secret_independent():
    a = {"RPORT": 4444, "PASSWORD": "secret-one"}
    b = {"RPORT": 4444, "PASSWORD": "secret-two"}
    assert options_sha256(a) == options_sha256(b)     # kein Secret-Fingerprint


def test_t_msf_03_non_secret_values_survive_redaction():
    """Redaction removes secrets only -- other values stay inspectable."""
    opts = {"RHOST": "192.0.2.10", "RPORT": 4444, "PASSWORD": SECRET}
    clean, redacted = redact_options(opts)
    assert clean["RHOST"] == "192.0.2.10" and clean["RPORT"] == 4444
    assert redacted == ["PASSWORD"]
