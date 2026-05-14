"""Unit tests for _parse_cert_file and analyze_certificate_issues.

_parse_cert_file  — parses PEM/DER X.509 files, returns structured dicts.
analyze_certificate_issues — walks a rootfs, flags expired, self-signed,
                             and weak-key (RSA ≤ 1024-bit) certificates.

All test certificates are generated in-process with the cryptography library
so there are no checked-in binary blobs or external fixtures.
"""

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from firmware_analysis.analysis.analyzers.system import (
    _parse_cert_file,
    analyze_certificate_issues,
)
from firmware_analysis.analysis.analyzers.context import AnalysisContext


# ── Cert generation helpers ───────────────────────────────────────────────────

_NOW = datetime.now(timezone.utc)


def _ec_key():
    return ec.generate_private_key(ec.SECP256R1())


def _rsa_key(bits=2048):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _build_cert(key, subject_cn: str, issuer_cn: str, not_before, not_after) -> bytes:
    """Return PEM-encoded certificate bytes signed with key."""
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(subject_cn))
        .issuer_name(_name(issuer_cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def _valid_self_signed_pem(cn="device.local", bits=2048) -> bytes:
    key = _rsa_key(bits)
    return _build_cert(
        key, cn, cn,
        not_before=_NOW - timedelta(days=30),
        not_after=_NOW + timedelta(days=365),
    )


def _expired_pem(cn="old.device") -> bytes:
    key = _ec_key()
    return _build_cert(
        key, cn, cn,
        not_before=_NOW - timedelta(days=730),
        not_after=_NOW - timedelta(days=1),
    )


def _weak_rsa_pem(cn="weak.device") -> bytes:
    key = _rsa_key(1024)
    return _build_cert(
        key, cn, cn,
        not_before=_NOW - timedelta(days=30),
        not_after=_NOW + timedelta(days=365),
    )


def _ca_signed_pem(subject_cn="leaf", issuer_cn="Root CA") -> bytes:
    """Cert where subject != issuer (simulates CA-issued; signed with same key for simplicity)."""
    key = _ec_key()
    return _build_cert(
        key, subject_cn, issuer_cn,
        not_before=_NOW - timedelta(days=30),
        not_after=_NOW + timedelta(days=365),
    )


def _der_bytes(pem: bytes) -> bytes:
    cert = x509.load_pem_x509_certificate(pem)
    return cert.public_bytes(serialization.Encoding.DER)


def _make_ctx(tmp_path) -> AnalysisContext:
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    out = tmp_path / "out"
    out.mkdir()
    return AnalysisContext(rootfs=rootfs, out_dir=out, configs=[], elf_cache={})


# ── _parse_cert_file: PEM parsing ─────────────────────────────────────────────

class TestParseCertFilePem:
    def test_valid_pem_returns_one_entry(self, tmp_path):
        p = tmp_path / "cert.pem"
        p.write_bytes(_valid_self_signed_pem())
        result = _parse_cert_file(p)
        assert len(result) == 1

    def test_expired_pem_detected(self, tmp_path):
        p = tmp_path / "old.pem"
        p.write_bytes(_expired_pem())
        info = _parse_cert_file(p)[0]
        assert info["expired"] is True

    def test_not_expired_pem_not_flagged(self, tmp_path):
        p = tmp_path / "valid.pem"
        p.write_bytes(_valid_self_signed_pem())
        info = _parse_cert_file(p)[0]
        assert info["expired"] is False

    def test_self_signed_detected(self, tmp_path):
        p = tmp_path / "self.pem"
        p.write_bytes(_valid_self_signed_pem(cn="router"))
        info = _parse_cert_file(p)[0]
        assert info["self_signed"] is True

    def test_ca_signed_not_flagged_as_self_signed(self, tmp_path):
        p = tmp_path / "leaf.pem"
        p.write_bytes(_ca_signed_pem())
        info = _parse_cert_file(p)[0]
        assert info["self_signed"] is False

    def test_weak_rsa_1024_detected(self, tmp_path):
        p = tmp_path / "weak.pem"
        p.write_bytes(_weak_rsa_pem())
        info = _parse_cert_file(p)[0]
        assert info["weak_key"] is True
        assert info["key_bits"] == 1024
        assert info["key_type"] == "RSA"

    def test_rsa_2048_not_flagged_as_weak(self, tmp_path):
        p = tmp_path / "strong.pem"
        p.write_bytes(_valid_self_signed_pem(bits=2048))
        info = _parse_cert_file(p)[0]
        assert info["weak_key"] is False

    def test_ec_key_not_flagged_as_weak(self, tmp_path):
        p = tmp_path / "ec.pem"
        p.write_bytes(_ca_signed_pem())
        info = _parse_cert_file(p)[0]
        assert info["key_type"] == "EC"
        assert info["weak_key"] is False

    def test_multi_cert_pem_returns_all(self, tmp_path):
        p = tmp_path / "chain.pem"
        pem1 = _valid_self_signed_pem(cn="a")
        pem2 = _expired_pem(cn="b")
        p.write_bytes(pem1 + pem2)
        result = _parse_cert_file(p)
        assert len(result) == 2

    def test_returned_dict_has_expected_keys(self, tmp_path):
        p = tmp_path / "cert.pem"
        p.write_bytes(_valid_self_signed_pem())
        info = _parse_cert_file(p)[0]
        for key in ("subject", "issuer", "not_before", "not_after",
                    "key_type", "key_bits", "expired", "self_signed", "weak_key"):
            assert key in info

    def test_subject_and_issuer_are_strings(self, tmp_path):
        p = tmp_path / "cert.pem"
        p.write_bytes(_valid_self_signed_pem(cn="mydevice"))
        info = _parse_cert_file(p)[0]
        assert isinstance(info["subject"], str)
        assert isinstance(info["issuer"], str)
        assert "mydevice" in info["subject"]


# ── _parse_cert_file: DER parsing ─────────────────────────────────────────────

class TestParseCertFileDer:
    def test_valid_der_returns_one_entry(self, tmp_path):
        p = tmp_path / "cert.der"
        p.write_bytes(_der_bytes(_valid_self_signed_pem()))
        assert len(_parse_cert_file(p)) == 1

    def test_expired_der_detected(self, tmp_path):
        p = tmp_path / "old.der"
        p.write_bytes(_der_bytes(_expired_pem()))
        assert _parse_cert_file(p)[0]["expired"] is True

    def test_der_self_signed_detected(self, tmp_path):
        p = tmp_path / "self.der"
        p.write_bytes(_der_bytes(_valid_self_signed_pem()))
        assert _parse_cert_file(p)[0]["self_signed"] is True


# ── _parse_cert_file: non-cert files ─────────────────────────────────────────

class TestParseCertFileNonCert:
    def test_private_key_pem_returns_empty(self, tmp_path):
        key = _ec_key()
        p = tmp_path / "key.pem"
        p.write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
        assert _parse_cert_file(p) == []

    def test_random_bytes_returns_empty(self, tmp_path):
        p = tmp_path / "garbage.crt"
        p.write_bytes(b"\x00\x01\x02\x03" * 64)
        assert _parse_cert_file(p) == []

    def test_empty_file_returns_empty(self, tmp_path):
        p = tmp_path / "empty.pem"
        p.write_bytes(b"")
        assert _parse_cert_file(p) == []

    def test_nonexistent_file_returns_empty(self, tmp_path):
        p = tmp_path / "missing.pem"
        assert _parse_cert_file(p) == []

    def test_text_file_returns_empty(self, tmp_path):
        p = tmp_path / "config.crt"
        p.write_text("not a certificate")
        assert _parse_cert_file(p) == []


# ── analyze_certificate_issues: output files ──────────────────────────────────

class TestAnalyzeCertificateIssuesOutput:
    def test_writes_txt_file(self, tmp_path):
        ctx = _make_ctx(tmp_path)
        analyze_certificate_issues(ctx)
        assert (tmp_path / "out" / "certificate_issues.txt").exists()

    def test_writes_json_file(self, tmp_path):
        ctx = _make_ctx(tmp_path)
        analyze_certificate_issues(ctx)
        assert (tmp_path / "out" / "certificate_issues.json").exists()

    def test_empty_rootfs_empty_json(self, tmp_path):
        ctx = _make_ctx(tmp_path)
        analyze_certificate_issues(ctx)
        data = json.loads((tmp_path / "out" / "certificate_issues.json").read_text())
        assert data == []

    def test_empty_rootfs_txt_says_none(self, tmp_path):
        ctx = _make_ctx(tmp_path)
        analyze_certificate_issues(ctx)
        txt = (tmp_path / "out" / "certificate_issues.txt").read_text()
        assert "(none)" in txt


# ── analyze_certificate_issues: detection ─────────────────────────────────────

class TestAnalyzeCertificateIssuesDetection:
    def _run(self, tmp_path, cert_files: dict) -> list:
        ctx = _make_ctx(tmp_path)
        for name, data in cert_files.items():
            p = ctx.rootfs / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
        analyze_certificate_issues(ctx)
        return json.loads((tmp_path / "out" / "certificate_issues.json").read_text())

    def test_clean_cert_produces_no_findings(self, tmp_path):
        # CA-signed, not expired, 2048-bit RSA
        data = _ca_signed_pem()
        findings = self._run(tmp_path, {"etc/ssl/leaf.pem": data})
        assert findings == []

    def test_expired_cert_flagged(self, tmp_path):
        findings = self._run(tmp_path, {"etc/ssl/old.pem": _expired_pem()})
        assert len(findings) == 1
        assert "expired" in findings[0]["flags"]

    def test_self_signed_cert_flagged(self, tmp_path):
        findings = self._run(tmp_path, {"etc/ssl/self.crt": _valid_self_signed_pem()})
        assert len(findings) == 1
        assert "self-signed" in findings[0]["flags"]

    def test_weak_rsa_cert_flagged(self, tmp_path):
        findings = self._run(tmp_path, {"etc/ssl/weak.pem": _weak_rsa_pem()})
        assert len(findings) == 1
        assert any("weak-key" in f for f in findings[0]["flags"])

    def test_multiple_issues_on_one_cert(self, tmp_path):
        # Expired + self-signed
        findings = self._run(tmp_path, {"etc/ssl/bad.pem": _expired_pem()})
        flags = findings[0]["flags"]
        assert "expired" in flags
        assert "self-signed" in flags

    def test_multiple_cert_files_all_scanned(self, tmp_path):
        findings = self._run(tmp_path, {
            "etc/ssl/a.pem": _expired_pem(cn="a"),
            "etc/ssl/b.crt": _expired_pem(cn="b"),
        })
        assert len(findings) == 2

    def test_non_cert_file_not_included_in_findings(self, tmp_path):
        key = _ec_key()
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        # Private key has .pem extension but is not a cert — should not appear
        findings = self._run(tmp_path, {"etc/ssl/key.pem": key_pem})
        assert findings == []

    def test_der_file_is_scanned(self, tmp_path):
        findings = self._run(tmp_path, {"etc/ssl/cert.der": _der_bytes(_expired_pem())})
        assert len(findings) == 1
        assert "expired" in findings[0]["flags"]


# ── analyze_certificate_issues: JSON structure ────────────────────────────────

class TestAnalyzeCertificateIssuesJsonStructure:
    def _finding(self, tmp_path, pem: bytes) -> dict:
        ctx = _make_ctx(tmp_path)
        p = ctx.rootfs / "etc" / "ssl" / "cert.pem"
        p.parent.mkdir(parents=True)
        p.write_bytes(pem)
        analyze_certificate_issues(ctx)
        data = json.loads((tmp_path / "out" / "certificate_issues.json").read_text())
        return data[0]

    def test_finding_has_required_keys(self, tmp_path):
        f = self._finding(tmp_path, _expired_pem())
        for key in ("file", "flags", "subject", "issuer", "not_after", "key_type", "key_bits"):
            assert key in f

    def test_file_path_is_relative_to_rootfs(self, tmp_path):
        f = self._finding(tmp_path, _expired_pem())
        assert f["file"] == "etc/ssl/cert.pem"
        assert not f["file"].startswith("/")

    def test_flags_is_a_list(self, tmp_path):
        f = self._finding(tmp_path, _expired_pem())
        assert isinstance(f["flags"], list)
        assert len(f["flags"]) >= 1

    def test_key_bits_is_integer_or_none(self, tmp_path):
        f = self._finding(tmp_path, _expired_pem())
        assert f["key_bits"] is None or isinstance(f["key_bits"], int)
