"""Unit tests for _TLS_ISSUES patterns and analyze_tls_config.

_TLS_ISSUES patterns — compiled regexes that detect weak SSL/TLS directives.
analyze_tls_config  — walks web server config files under rootfs, emits
                      tls_config_issues.txt and tls_config_issues.json.

Tests cover: each pattern's positive/negative cases, comment-line skipping,
inline comment stripping, Apache disable-flag (-SSLv2/-SSLv3) exclusion,
TLSv1.2/1.3 safe-protocol exclusion, JSON structure, and path relativity.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from firmware_analysis.analysis.analyzers.web import (
    _TLS_ISSUES,
    analyze_tls_config,
)
from firmware_analysis.analysis.analyzers.context import AnalysisContext


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_ctx(tmp_path) -> AnalysisContext:
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    out = tmp_path / "out"
    out.mkdir()
    return AnalysisContext(rootfs=rootfs, out_dir=out, configs=[], elf_cache={})


def _write_config(ctx: AnalysisContext, name: str, content: str) -> Path:
    p = ctx.rootfs / "etc" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return p


def _run(tmp_path, config_name: str, content: str) -> list:
    ctx = _make_ctx(tmp_path)
    _write_config(ctx, config_name, content)
    analyze_tls_config(ctx)
    return json.loads((tmp_path / "out" / "tls_config_issues.json").read_text())


def _issues(findings: list) -> set:
    return {f["issue"] for f in findings}


def _pat(label: str) -> object:
    """Return the compiled pattern for a given issue label."""
    for lbl, pat, _ in _TLS_ISSUES:
        if lbl == label:
            return pat
    raise KeyError(label)


# ── Pattern unit tests: SSLv2 ─────────────────────────────────────────────────

class TestPatternSSLv2:
    def test_bare_sslv2_matches(self):
        assert _pat("SSLv2 enabled").search("SSLv2")

    def test_plus_sslv2_matches(self):
        assert _pat("SSLv2 enabled").search("+SSLv2")

    def test_nginx_ssl_protocols_sslv2_matches(self):
        assert _pat("SSLv2 enabled").search("ssl_protocols SSLv2 SSLv3 TLSv1;")

    def test_apache_disable_flag_not_matched(self):
        assert not _pat("SSLv2 enabled").search("SSLProtocol all -SSLv2 -SSLv3")

    def test_case_insensitive(self):
        assert _pat("SSLv2 enabled").search("sslv2")


# ── Pattern unit tests: SSLv3 ─────────────────────────────────────────────────

class TestPatternSSLv3:
    def test_bare_sslv3_matches(self):
        assert _pat("SSLv3 enabled").search("SSLv3")

    def test_apache_disable_flag_not_matched(self):
        assert not _pat("SSLv3 enabled").search("SSLProtocol all -SSLv2 -SSLv3")

    def test_lighttpd_enable_matches(self):
        assert _pat("SSLv3 enabled").search('ssl.use-sslv3 = "enable"')


# ── Pattern unit tests: TLSv1 ─────────────────────────────────────────────────

class TestPatternTLSv1:
    @pytest.mark.parametrize("text", [
        "ssl_protocols TLSv1;",
        "SSLProtocol TLSv1",
        "TLSv1.0",
        "TLSv1.1",
        "ssl_protocols TLSv1 TLSv1.1;",
    ])
    def test_weak_tls_versions_match(self, text):
        assert _pat("TLS 1.0/1.1 configured").search(text)

    @pytest.mark.parametrize("text", [
        "ssl_protocols TLSv1.2 TLSv1.3;",
        "TLSv1.2",
        "TLSv1.3",
        "SSLProtocol TLSv1.2",
    ])
    def test_safe_tls_versions_not_matched(self, text):
        assert not _pat("TLS 1.0/1.1 configured").search(text)

    def test_mixed_line_only_flags_weak_part(self):
        # Line with both weak and strong — pattern should find the weak one
        line = "ssl_protocols TLSv1 TLSv1.2 TLSv1.3;"
        assert _pat("TLS 1.0/1.1 configured").search(line)


# ── Pattern unit tests: RC4 ──────────────────────────────────────────────────

class TestPatternRC4:
    def test_rc4_cipher_suite_matches(self):
        assert _pat("RC4 cipher").search("SSLCipherSuite RC4-MD5:RC4-SHA")

    def test_rc4_in_nginx_ciphers_matches(self):
        assert _pat("RC4 cipher").search("ssl_ciphers RC4:HIGH:!aNULL:!MD5;")

    def test_word_boundary_not_matching_partial(self):
        # RC4 is only matched as a full word
        assert not _pat("RC4 cipher").search("NORC4ALLOWED")

    def test_case_insensitive(self):
        assert _pat("RC4 cipher").search("rc4-sha")


# ── Pattern unit tests: NULL cipher ──────────────────────────────────────────

class TestPatternNull:
    @pytest.mark.parametrize("text", [
        "SSLCipherSuite eNULL",
        "SSLCipherSuite aNULL",
        "ssl_ciphers NULL-SHA:NULL-MD5",
        "ssl_ciphers NULL-SHA256",
    ])
    def test_null_cipher_variants_match(self, text):
        assert _pat("NULL cipher").search(text)

    def test_non_null_cipher_not_matched(self):
        assert not _pat("NULL cipher").search("SSLCipherSuite HIGH:!aNULL")


# ── Pattern unit tests: EXPORT cipher ────────────────────────────────────────

class TestPatternExport:
    def test_export_keyword_matches(self):
        assert _pat("EXPORT cipher").search("SSLCipherSuite EXPORT")

    def test_export_in_nginx_matches(self):
        assert _pat("EXPORT cipher").search("ssl_ciphers EXPORT:HIGH;")

    def test_case_insensitive(self):
        assert _pat("EXPORT cipher").search("export")


# ── Pattern unit tests: anonymous DH ─────────────────────────────────────────

class TestPatternAnonDH:
    @pytest.mark.parametrize("text", ["ssl_ciphers ADH:HIGH;", "SSLCipherSuite AECDH"])
    def test_anon_dh_matches(self, text):
        assert _pat("anonymous DH cipher").search(text)

    def test_word_boundary(self):
        assert not _pat("anonymous DH cipher").search("MADHATTER")


# ── analyze_tls_config: output files ─────────────────────────────────────────

class TestAnalyzeTlsConfigOutput:
    def test_writes_txt_file(self, tmp_path):
        ctx = _make_ctx(tmp_path)
        analyze_tls_config(ctx)
        assert (tmp_path / "out" / "tls_config_issues.txt").exists()

    def test_writes_json_file(self, tmp_path):
        ctx = _make_ctx(tmp_path)
        analyze_tls_config(ctx)
        assert (tmp_path / "out" / "tls_config_issues.json").exists()

    def test_empty_rootfs_empty_json(self, tmp_path):
        ctx = _make_ctx(tmp_path)
        analyze_tls_config(ctx)
        assert json.loads((tmp_path / "out" / "tls_config_issues.json").read_text()) == []

    def test_empty_rootfs_txt_says_none(self, tmp_path):
        ctx = _make_ctx(tmp_path)
        analyze_tls_config(ctx)
        txt = (tmp_path / "out" / "tls_config_issues.txt").read_text()
        assert "(none" in txt


# ── analyze_tls_config: detection ────────────────────────────────────────────

class TestAnalyzeTlsConfigDetection:
    def test_sslv2_in_nginx_conf_flagged(self, tmp_path):
        findings = _run(tmp_path, "nginx.conf", "ssl_protocols SSLv2 SSLv3 TLSv1;\n")
        assert any(f["issue"] == "SSLv2 enabled" for f in findings)

    def test_sslv3_in_nginx_conf_flagged(self, tmp_path):
        findings = _run(tmp_path, "nginx.conf", "ssl_protocols SSLv3 TLSv1.2;\n")
        assert any(f["issue"] == "SSLv3 enabled" for f in findings)

    def test_tlsv1_in_httpd_conf_flagged(self, tmp_path):
        findings = _run(tmp_path, "httpd.conf", "SSLProtocol TLSv1 TLSv1.1\n")
        assert any(f["issue"] == "TLS 1.0/1.1 configured" for f in findings)

    def test_rc4_in_lighttpd_conf_flagged(self, tmp_path):
        findings = _run(tmp_path, "lighttpd.conf", 'ssl.cipher-list = "RC4-MD5"\n')
        assert any(f["issue"] == "RC4 cipher" for f in findings)

    def test_export_cipher_flagged(self, tmp_path):
        findings = _run(tmp_path, "nginx.conf", "ssl_ciphers EXPORT:HIGH:!aNULL;\n")
        assert any(f["issue"] == "EXPORT cipher" for f in findings)

    def test_null_cipher_flagged(self, tmp_path):
        findings = _run(tmp_path, "nginx.conf", "ssl_ciphers eNULL:HIGH;\n")
        assert any(f["issue"] == "NULL cipher" for f in findings)

    def test_anon_dh_flagged(self, tmp_path):
        findings = _run(tmp_path, "nginx.conf", "ssl_ciphers ADH:HIGH;\n")
        assert any(f["issue"] == "anonymous DH cipher" for f in findings)

    def test_safe_config_produces_no_findings(self, tmp_path):
        safe = "ssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers HIGH:!aNULL:!RC4:!EXPORT;\n"
        assert _run(tmp_path, "nginx.conf", safe) == []

    def test_apache_disable_flags_not_flagged(self, tmp_path):
        # -SSLv2 -SSLv3 disables them — should produce no findings
        findings = _run(tmp_path, "httpd.conf", "SSLProtocol all -SSLv2 -SSLv3\n")
        assert not any(f["issue"] in ("SSLv2 enabled", "SSLv3 enabled") for f in findings)

    def test_multiple_issues_on_one_line_all_reported(self, tmp_path):
        findings = _run(tmp_path, "nginx.conf", "ssl_protocols SSLv2 SSLv3;\n")
        issues = _issues(findings)
        assert "SSLv2 enabled" in issues
        assert "SSLv3 enabled" in issues

    def test_multiple_config_files_all_scanned(self, tmp_path):
        ctx = _make_ctx(tmp_path)
        _write_config(ctx, "nginx.conf",   "ssl_protocols SSLv3;\n")
        _write_config(ctx, "httpd.conf",   "SSLCipherSuite RC4-MD5\n")
        analyze_tls_config(ctx)
        findings = json.loads((tmp_path / "out" / "tls_config_issues.json").read_text())
        files = {f["file"].split("/")[-1] for f in findings}
        assert "nginx.conf" in files
        assert "httpd.conf" in files


# ── analyze_tls_config: comment handling ─────────────────────────────────────

class TestAnalyzeTlsConfigComments:
    def test_full_line_hash_comment_skipped(self, tmp_path):
        findings = _run(tmp_path, "nginx.conf", "# ssl_protocols SSLv2 SSLv3;\n")
        assert findings == []

    def test_indented_hash_comment_skipped(self, tmp_path):
        findings = _run(tmp_path, "nginx.conf", "    # SSLCipherSuite RC4-MD5\n")
        assert findings == []

    def test_semicolon_comment_line_skipped(self, tmp_path):
        findings = _run(tmp_path, "openssl.cnf", "; SSLv2 is disabled\n")
        assert findings == []

    def test_inline_comment_does_not_cause_false_positive(self, tmp_path):
        # Directive is fine; SSLv2 only mentioned in comment suffix
        line = "ssl_protocols TLSv1.2 TLSv1.3; # SSLv2 SSLv3 TLSv1 are disabled\n"
        findings = _run(tmp_path, "nginx.conf", line)
        assert findings == []

    def test_active_directive_before_inline_comment_is_flagged(self, tmp_path):
        line = "ssl_protocols SSLv3 TLSv1.2; # modern clients only\n"
        findings = _run(tmp_path, "nginx.conf", line)
        assert any(f["issue"] == "SSLv3 enabled" for f in findings)


# ── analyze_tls_config: JSON structure ───────────────────────────────────────

class TestAnalyzeTlsConfigJsonStructure:
    def _finding(self, tmp_path) -> dict:
        findings = _run(tmp_path, "nginx.conf", "ssl_protocols SSLv3;\n")
        return findings[0]

    def test_finding_has_required_keys(self, tmp_path):
        f = self._finding(tmp_path)
        for key in ("file", "line", "text", "issue", "cve_note"):
            assert key in f

    def test_file_path_is_relative_to_rootfs(self, tmp_path):
        f = self._finding(tmp_path)
        assert not f["file"].startswith("/")
        assert f["file"].endswith("nginx.conf")

    def test_line_number_is_positive_integer(self, tmp_path):
        f = self._finding(tmp_path)
        assert isinstance(f["line"], int)
        assert f["line"] >= 1

    def test_text_contains_original_line(self, tmp_path):
        f = self._finding(tmp_path)
        assert "SSLv3" in f["text"]

    def test_cve_note_is_nonempty_string(self, tmp_path):
        f = self._finding(tmp_path)
        assert isinstance(f["cve_note"], str)
        assert len(f["cve_note"]) > 0

    def test_line_number_correct(self, tmp_path):
        content = "# comment\nssl_protocols SSLv3;\n"
        findings = _run(tmp_path, "nginx.conf", content)
        assert findings[0]["line"] == 2
