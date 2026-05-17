"""Unit tests for sensitive file permission checks.

Function under test: analyze_sensitive_permissions (system.py)

Three categories of findings:

  1. Authentication database files (/etc/shadow, /etc/gshadow)
       world_readable_auth_file  (critical) — world-read bit set
       group_readable_auth_file  (high)     — group-read bit set, world-read clear
       world_writable_auth_file  (critical) — world-write bit set (independent check)

  2. SSH / dropbear host private keys
       ssh_host_key_permissions  (critical) — world-readable
                                 (high)     — group-readable
                                 (medium)   — other bits beyond 0600 set

  3. World-readable private-key and credential-named files
       world_readable_credential_file (high)

All three categories are checked against the real filesystem permissions of files
created with explicit chmod calls. Files already reported by an earlier category
are not double-reported in a later one.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from firmware_analysis.analysis.analyzers.system import analyze_sensitive_permissions
from firmware_analysis.analysis.analyzers.context import AnalysisContext


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_ctx(tmp_path, files: dict) -> AnalysisContext:
    """Build an AnalysisContext with files at given relative paths and permissions.

    files: {rel: content}              → default filesystem permissions
           {rel: (content, mode_int)}  → explicit chmod applied after write
    """
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    out = tmp_path / "out"
    out.mkdir()
    for rel, spec in files.items():
        content, mode = (spec if isinstance(spec, tuple) else (spec, None))
        path = rootfs / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        if mode is not None:
            path.chmod(mode)
    return AnalysisContext(rootfs=rootfs, out_dir=out, configs=[])


def _perms_json(tmp_path) -> dict:
    return json.loads((tmp_path / "out" / "sensitive_permissions.json").read_text())


def _findings_for(data: dict, check: str) -> list[dict]:
    return [f for f in data["findings"] if f["check"] == check]


# ── /etc/shadow and /etc/gshadow permissions ─────────────────────────────────

class TestShadowPermissions:
    def test_world_readable_shadow_is_critical(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/shadow": ("root:$6$hash:...", 0o644)})
        analyze_sensitive_permissions(ctx)
        data = _perms_json(tmp_path)
        f = next((x for x in data["findings"]
                  if x["file"] == "etc/shadow" and x["check"] == "world_readable_auth_file"), None)
        assert f is not None
        assert f["severity"] == "critical"

    def test_world_readable_shadow_check_name(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/shadow": ("root:$6$hash:...", 0o644)})
        analyze_sensitive_permissions(ctx)
        data = _perms_json(tmp_path)
        checks = {x["check"] for x in data["findings"] if x["file"] == "etc/shadow"}
        assert "world_readable_auth_file" in checks

    def test_shadow_600_produces_no_finding(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/shadow": ("root:$6$hash:...", 0o600)})
        analyze_sensitive_permissions(ctx)
        data = _perms_json(tmp_path)
        assert not any(f["file"] == "etc/shadow" for f in data["findings"])

    def test_shadow_000_produces_no_finding(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/shadow": ("root:$6$hash:...", 0o000)})
        analyze_sensitive_permissions(ctx)
        data = _perms_json(tmp_path)
        assert not any(f["file"] == "etc/shadow" for f in data["findings"])

    def test_shadow_640_group_readable_is_high(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/shadow": ("root:$6$hash:...", 0o640)})
        analyze_sensitive_permissions(ctx)
        data = _perms_json(tmp_path)
        f = next((x for x in data["findings"]
                  if x["file"] == "etc/shadow" and x["check"] == "group_readable_auth_file"), None)
        assert f is not None
        assert f["severity"] == "high"

    def test_shadow_group_readable_check_name(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/shadow": ("root:$6$hash:...", 0o640)})
        analyze_sensitive_permissions(ctx)
        data = _perms_json(tmp_path)
        checks = {x["check"] for x in data["findings"] if x["file"] == "etc/shadow"}
        assert "group_readable_auth_file" in checks

    def test_shadow_world_writable_is_critical(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/shadow": ("root:$6$hash:...", 0o602)})
        analyze_sensitive_permissions(ctx)
        data = _perms_json(tmp_path)
        f = next((x for x in data["findings"]
                  if x["file"] == "etc/shadow" and x["check"] == "world_writable_auth_file"), None)
        assert f is not None
        assert f["severity"] == "critical"

    def test_shadow_777_produces_both_world_readable_and_world_writable(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/shadow": ("root:$6$hash:...", 0o777)})
        analyze_sensitive_permissions(ctx)
        data = _perms_json(tmp_path)
        checks = {x["check"] for x in data["findings"] if x["file"] == "etc/shadow"}
        assert "world_readable_auth_file" in checks
        assert "world_writable_auth_file" in checks

    def test_gshadow_world_readable_is_critical(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/gshadow": ("root:::", 0o644)})
        analyze_sensitive_permissions(ctx)
        data = _perms_json(tmp_path)
        f = next((x for x in data["findings"]
                  if x["file"] == "etc/gshadow" and x["check"] == "world_readable_auth_file"), None)
        assert f is not None
        assert f["severity"] == "critical"

    def test_shadow_absent_no_finding(self, tmp_path):
        ctx = _make_ctx(tmp_path, {})
        analyze_sensitive_permissions(ctx)
        data = _perms_json(tmp_path)
        assert not any(f["file"] == "etc/shadow" for f in data["findings"])

    def test_shadow_finding_records_mode(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/shadow": ("root:$6$hash:...", 0o644)})
        analyze_sensitive_permissions(ctx)
        data = _perms_json(tmp_path)
        f = next(x for x in data["findings"] if x["file"] == "etc/shadow")
        assert f["mode"] == "0644"


# ── SSH / dropbear host private key permissions ───────────────────────────────

class TestSshHostKeyPermissions:
    def test_ssh_key_600_no_finding(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/ssh/ssh_host_rsa_key": ("PRIVATE", 0o600)})
        analyze_sensitive_permissions(ctx)
        data = _perms_json(tmp_path)
        assert not _findings_for(data, "ssh_host_key_permissions")

    def test_ssh_key_644_is_critical(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/ssh/ssh_host_rsa_key": ("PRIVATE", 0o644)})
        analyze_sensitive_permissions(ctx)
        data = _perms_json(tmp_path)
        findings = _findings_for(data, "ssh_host_key_permissions")
        assert len(findings) == 1
        assert findings[0]["severity"] == "critical"

    def test_ssh_key_640_is_high(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/ssh/ssh_host_rsa_key": ("PRIVATE", 0o640)})
        analyze_sensitive_permissions(ctx)
        data = _perms_json(tmp_path)
        findings = _findings_for(data, "ssh_host_key_permissions")
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"

    def test_ssh_key_660_is_high(self, tmp_path):
        # 0o660 = owner+group rw — group-readable
        ctx = _make_ctx(tmp_path, {"etc/ssh/ssh_host_rsa_key": ("PRIVATE", 0o660)})
        analyze_sensitive_permissions(ctx)
        data = _perms_json(tmp_path)
        findings = _findings_for(data, "ssh_host_key_permissions")
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"

    def test_ssh_key_620_is_medium(self, tmp_path):
        # 0o620 = owner rw, group write only — not readable by group/world but still wider than 600
        ctx = _make_ctx(tmp_path, {"etc/ssh/ssh_host_rsa_key": ("PRIVATE", 0o620)})
        analyze_sensitive_permissions(ctx)
        data = _perms_json(tmp_path)
        findings = _findings_for(data, "ssh_host_key_permissions")
        assert len(findings) == 1
        assert findings[0]["severity"] == "medium"

    def test_ssh_public_key_not_flagged(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/ssh/ssh_host_rsa_key.pub": ("ssh-rsa AAAA...", 0o644)})
        analyze_sensitive_permissions(ctx)
        data = _perms_json(tmp_path)
        assert not _findings_for(data, "ssh_host_key_permissions")

    def test_ssh_ecdsa_key_644_is_critical(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/ssh/ssh_host_ecdsa_key": ("PRIVATE", 0o644)})
        analyze_sensitive_permissions(ctx)
        data = _perms_json(tmp_path)
        findings = _findings_for(data, "ssh_host_key_permissions")
        assert findings[0]["severity"] == "critical"

    def test_ssh_ed25519_key_644_is_critical(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/ssh/ssh_host_ed25519_key": ("PRIVATE", 0o644)})
        analyze_sensitive_permissions(ctx)
        data = _perms_json(tmp_path)
        findings = _findings_for(data, "ssh_host_key_permissions")
        assert findings[0]["severity"] == "critical"

    def test_dropbear_host_key_644_is_critical(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/dropbear/dropbear_rsa_host_key": ("PRIVATE", 0o644)})
        analyze_sensitive_permissions(ctx)
        data = _perms_json(tmp_path)
        findings = _findings_for(data, "ssh_host_key_permissions")
        assert len(findings) == 1
        assert findings[0]["severity"] == "critical"

    def test_ssh_key_in_nonstandard_location_found_via_rglob(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "usr/share/keys/ssh_host_rsa_key": ("PRIVATE", 0o644),
        })
        analyze_sensitive_permissions(ctx)
        data = _perms_json(tmp_path)
        findings = _findings_for(data, "ssh_host_key_permissions")
        assert len(findings) == 1

    def test_multiple_ssh_keys_all_reported(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "etc/ssh/ssh_host_rsa_key":     ("PRIVATE", 0o644),
            "etc/ssh/ssh_host_ecdsa_key":   ("PRIVATE", 0o640),
        })
        analyze_sensitive_permissions(ctx)
        data = _perms_json(tmp_path)
        findings = _findings_for(data, "ssh_host_key_permissions")
        assert len(findings) == 2

    def test_ssh_key_finding_mode_recorded(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/ssh/ssh_host_rsa_key": ("PRIVATE", 0o644)})
        analyze_sensitive_permissions(ctx)
        data = _perms_json(tmp_path)
        f = _findings_for(data, "ssh_host_key_permissions")[0]
        assert f["mode"] == "0644"

    def test_ssh_key_finding_file_is_relative_to_rootfs(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/ssh/ssh_host_rsa_key": ("PRIVATE", 0o644)})
        analyze_sensitive_permissions(ctx)
        data = _perms_json(tmp_path)
        f = _findings_for(data, "ssh_host_key_permissions")[0]
        assert f["file"] == "etc/ssh/ssh_host_rsa_key"


# ── World-readable credential and private key files ───────────────────────────

class TestWorldReadableCredentials:
    def test_world_readable_pem_is_high(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/ssl/server.pem": ("-----BEGIN PRIVATE KEY-----", 0o644)})
        analyze_sensitive_permissions(ctx)
        data = _perms_json(tmp_path)
        findings = _findings_for(data, "world_readable_credential_file")
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"

    def test_world_readable_key_file_is_high(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/ssl/server.key": ("-----BEGIN RSA PRIVATE KEY-----", 0o644)})
        analyze_sensitive_permissions(ctx)
        data = _perms_json(tmp_path)
        findings = _findings_for(data, "world_readable_credential_file")
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"

    def test_world_readable_p12_is_high(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/ssl/bundle.p12": ("binary", 0o644)})
        analyze_sensitive_permissions(ctx)
        data = _perms_json(tmp_path)
        findings = _findings_for(data, "world_readable_credential_file")
        assert len(findings) == 1

    def test_world_readable_pfx_is_high(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/ssl/bundle.pfx": ("binary", 0o644)})
        analyze_sensitive_permissions(ctx)
        data = _perms_json(tmp_path)
        findings = _findings_for(data, "world_readable_credential_file")
        assert len(findings) == 1

    def test_pem_with_600_not_flagged(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/ssl/server.pem": ("-----BEGIN PRIVATE KEY-----", 0o600)})
        analyze_sensitive_permissions(ctx)
        data = _perms_json(tmp_path)
        assert not _findings_for(data, "world_readable_credential_file")

    def test_pub_file_644_not_flagged(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/ssl/server.pub": ("ssh-rsa AAAA...", 0o644)})
        analyze_sensitive_permissions(ctx)
        data = _perms_json(tmp_path)
        assert not _findings_for(data, "world_readable_credential_file")

    def test_password_named_file_world_readable_is_high(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/password.conf": ("admin=secret", 0o644)})
        analyze_sensitive_permissions(ctx)
        data = _perms_json(tmp_path)
        findings = _findings_for(data, "world_readable_credential_file")
        assert len(findings) == 1

    def test_passwd_named_file_world_readable_is_high(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/wpa_passwd": ("password=wpa2secret", 0o644)})
        analyze_sensitive_permissions(ctx)
        data = _perms_json(tmp_path)
        findings = _findings_for(data, "world_readable_credential_file")
        assert len(findings) == 1

    def test_secret_named_file_world_readable_is_high(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/secret.conf": ("api_key=abc123", 0o644)})
        analyze_sensitive_permissions(ctx)
        data = _perms_json(tmp_path)
        findings = _findings_for(data, "world_readable_credential_file")
        assert len(findings) == 1

    def test_private_named_file_world_readable_is_high(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/private.conf": ("token=secret", 0o644)})
        analyze_sensitive_permissions(ctx)
        data = _perms_json(tmp_path)
        findings = _findings_for(data, "world_readable_credential_file")
        assert len(findings) == 1

    def test_credential_named_file_world_readable_is_high(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/credentials.json": ('{"user":"admin"}', 0o644)})
        analyze_sensitive_permissions(ctx)
        data = _perms_json(tmp_path)
        findings = _findings_for(data, "world_readable_credential_file")
        assert len(findings) == 1

    def test_credential_file_check_name(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/ssl/server.pem": ("-----BEGIN PRIVATE KEY-----", 0o644)})
        analyze_sensitive_permissions(ctx)
        data = _perms_json(tmp_path)
        f = _findings_for(data, "world_readable_credential_file")[0]
        assert f["check"] == "world_readable_credential_file"

    def test_credential_file_finding_records_mode(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/ssl/server.pem": ("-----BEGIN PRIVATE KEY-----", 0o644)})
        analyze_sensitive_permissions(ctx)
        data = _perms_json(tmp_path)
        f = _findings_for(data, "world_readable_credential_file")[0]
        assert f["mode"] == "0644"

    def test_ssh_host_key_world_readable_not_double_reported(self, tmp_path):
        # A file matching both SSH key pattern AND the name word "private"
        # should appear only once (check 2 takes priority).
        ctx = _make_ctx(tmp_path, {
            "etc/ssh/ssh_host_rsa_key": ("PRIVATE KEY MATERIAL", 0o644),
        })
        analyze_sensitive_permissions(ctx)
        data = _perms_json(tmp_path)
        ssh_findings  = _findings_for(data, "ssh_host_key_permissions")
        cred_findings = [f for f in _findings_for(data, "world_readable_credential_file")
                         if f["file"] == "etc/ssh/ssh_host_rsa_key"]
        assert len(ssh_findings) == 1
        assert len(cred_findings) == 0


# ── Output files and JSON structure ───────────────────────────────────────────

class TestJsonOutput:
    def test_output_files_always_written(self, tmp_path):
        ctx = _make_ctx(tmp_path, {})
        analyze_sensitive_permissions(ctx)
        assert (tmp_path / "out" / "sensitive_permissions.txt").exists()
        assert (tmp_path / "out" / "sensitive_permissions.json").exists()

    def test_empty_rootfs_no_findings(self, tmp_path):
        ctx = _make_ctx(tmp_path, {})
        analyze_sensitive_permissions(ctx)
        data = _perms_json(tmp_path)
        assert data["findings"] == []

    def test_json_has_required_top_level_keys(self, tmp_path):
        ctx = _make_ctx(tmp_path, {})
        analyze_sensitive_permissions(ctx)
        data = _perms_json(tmp_path)
        assert set(data.keys()) == {"findings", "summary"}

    def test_summary_has_four_severity_keys(self, tmp_path):
        ctx = _make_ctx(tmp_path, {})
        analyze_sensitive_permissions(ctx)
        data = _perms_json(tmp_path)
        assert set(data["summary"].keys()) == {"critical", "high", "medium", "low"}

    def test_empty_rootfs_summary_all_zero(self, tmp_path):
        ctx = _make_ctx(tmp_path, {})
        analyze_sensitive_permissions(ctx)
        data = _perms_json(tmp_path)
        assert data["summary"] == {"critical": 0, "high": 0, "medium": 0, "low": 0}

    def test_finding_has_required_fields(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/shadow": ("root:$6$hash:...", 0o644)})
        analyze_sensitive_permissions(ctx)
        data = _perms_json(tmp_path)
        f = data["findings"][0]
        assert "file"     in f
        assert "check"    in f
        assert "mode"     in f
        assert "severity" in f
        assert "note"     in f

    def test_summary_counts_match_findings(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "etc/shadow":                ("root:$6$hash:...", 0o644),  # critical
            "etc/ssh/ssh_host_rsa_key":  ("PRIVATE",         0o640),  # high
        })
        analyze_sensitive_permissions(ctx)
        data = _perms_json(tmp_path)
        assert data["summary"]["critical"] == 1
        assert data["summary"]["high"] == 1
        assert data["summary"]["medium"] == 0

    def test_mode_string_format_is_zero_prefixed_octal(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/shadow": ("root:$6$hash:...", 0o644)})
        analyze_sensitive_permissions(ctx)
        data = _perms_json(tmp_path)
        f = next(x for x in data["findings"] if x["file"] == "etc/shadow")
        assert f["mode"].startswith("0")
        assert len(f["mode"]) == 4
