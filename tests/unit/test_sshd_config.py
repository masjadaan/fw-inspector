"""Unit tests for SSH server configuration analysis.

Two functions under test:

  _parse_sshd_directives (system.py)
    Pure function: sshd_config text → {directive_lower: (value_lower, lineno)}.
    First-occurrence-wins, comment lines skipped, inline comments stripped,
    lines without a value skipped.

  analyze_sshd_config (system.py)
    Finds all sshd_config files under rootfs, applies _SSHD_CHECKS against
    each, and writes sshd_config.txt + sshd_config.json with per-finding
    metadata and a severity summary.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from firmware_analysis.analysis.analyzers.system import (
    _parse_sshd_directives,
    analyze_sshd_config,
)
from firmware_analysis.analysis.analyzers.context import AnalysisContext


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_ctx(tmp_path, sshd_files: dict) -> AnalysisContext:
    """Build an AnalysisContext with sshd_config files written at given relative paths.

    sshd_files: {relative_path_str: file_content_str}
    """
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    out = tmp_path / "out"
    out.mkdir()
    for rel, content in sshd_files.items():
        path = rootfs / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return AnalysisContext(rootfs=rootfs, out_dir=out, configs=[])


def _sshd_json(tmp_path) -> dict:
    return json.loads((tmp_path / "out" / "sshd_config.json").read_text())


# ── _parse_sshd_directives: basic parsing ────────────────────────────────────

class TestParseSshdDirectivesBasic:
    def test_empty_text_returns_empty(self):
        assert _parse_sshd_directives("") == {}

    def test_blank_lines_skipped(self):
        assert _parse_sshd_directives("\n\n\n") == {}

    def test_comment_lines_skipped(self):
        assert _parse_sshd_directives("# PermitRootLogin yes\n") == {}

    def test_keyword_without_value_skipped(self):
        assert _parse_sshd_directives("PermitRootLogin\n") == {}

    def test_basic_directive_parsed(self):
        result = _parse_sshd_directives("PermitRootLogin yes\n")
        assert "permitrootlogin" in result
        assert result["permitrootlogin"][0] == "yes"

    def test_multiple_directives_all_parsed(self):
        text = "PermitRootLogin no\nPasswordAuthentication yes\n"
        result = _parse_sshd_directives(text)
        assert "permitrootlogin" in result
        assert "passwordauthentication" in result


# ── _parse_sshd_directives: case handling ────────────────────────────────────

class TestParseSshdDirectivesCasing:
    def test_directive_key_lowercased(self):
        result = _parse_sshd_directives("PERMITROOTLOGIN yes\n")
        assert "permitrootlogin" in result

    def test_value_lowercased(self):
        result = _parse_sshd_directives("PermitRootLogin YES\n")
        assert result["permitrootlogin"][0] == "yes"

    def test_mixed_case_directive_and_value(self):
        result = _parse_sshd_directives("PermitEmptyPasswords Yes\n")
        assert result["permitemptypasswords"][0] == "yes"


# ── _parse_sshd_directives: first-occurrence semantics ───────────────────────

class TestParseSshdDirectivesFirstOccurrence:
    def test_first_occurrence_wins_when_dangerous_first(self):
        text = "PermitRootLogin yes\nPermitRootLogin no\n"
        result = _parse_sshd_directives(text)
        assert result["permitrootlogin"][0] == "yes"

    def test_first_occurrence_wins_when_safe_first(self):
        text = "PermitRootLogin no\nPermitRootLogin yes\n"
        result = _parse_sshd_directives(text)
        assert result["permitrootlogin"][0] == "no"


# ── _parse_sshd_directives: comment handling ─────────────────────────────────

class TestParseSshdDirectivesComments:
    def test_inline_comment_stripped_from_value(self):
        result = _parse_sshd_directives("PermitRootLogin yes  # dangerous\n")
        assert result["permitrootlogin"][0] == "yes"

    def test_hash_only_line_skipped(self):
        result = _parse_sshd_directives("# just a comment\n")
        assert result == {}

    def test_commented_out_dangerous_setting_not_parsed(self):
        result = _parse_sshd_directives("# PermitRootLogin yes\nPermitRootLogin no\n")
        assert result["permitrootlogin"][0] == "no"


# ── _parse_sshd_directives: line number tracking ─────────────────────────────

class TestParseSshdDirectivesLineNumbers:
    def test_line_number_is_one_based(self):
        result = _parse_sshd_directives("PermitRootLogin yes\n")
        assert result["permitrootlogin"][1] == 1

    def test_line_number_skips_blank_and_comment_lines(self):
        text = "\n# comment\nPermitRootLogin yes\n"
        result = _parse_sshd_directives(text)
        assert result["permitrootlogin"][1] == 3

    def test_two_directives_have_correct_independent_line_numbers(self):
        text = "PermitRootLogin no\nPasswordAuthentication yes\n"
        result = _parse_sshd_directives(text)
        assert result["permitrootlogin"][1] == 1
        assert result["passwordauthentication"][1] == 2


# ── analyze_sshd_config: no config file ──────────────────────────────────────

class TestAnalyzeSshdConfigNoFile:
    def test_no_sshd_config_writes_empty_findings(self, tmp_path):
        ctx = _make_ctx(tmp_path, {})
        analyze_sshd_config(ctx)
        data = _sshd_json(tmp_path)
        assert data["config_files"] == []
        assert data["findings"] == []

    def test_output_files_always_written(self, tmp_path):
        ctx = _make_ctx(tmp_path, {})
        analyze_sshd_config(ctx)
        assert (tmp_path / "out" / "sshd_config.json").exists()
        assert (tmp_path / "out" / "sshd_config.txt").exists()

    def test_summary_all_zeros_when_no_file(self, tmp_path):
        ctx = _make_ctx(tmp_path, {})
        analyze_sshd_config(ctx)
        s = _sshd_json(tmp_path)["summary"]
        assert s == {"critical": 0, "high": 0, "medium": 0, "low": 0}


# ── analyze_sshd_config: safe settings ───────────────────────────────────────

class TestAnalyzeSshdConfigSafe:
    def test_hardened_config_produces_no_findings(self, tmp_path):
        safe = (
            "PermitRootLogin no\n"
            "PasswordAuthentication no\n"
            "PermitEmptyPasswords no\n"
            "Protocol 2\n"
            "StrictModes yes\n"
            "X11Forwarding no\n"
            "GatewayPorts no\n"
        )
        ctx = _make_ctx(tmp_path, {"etc/ssh/sshd_config": safe})
        analyze_sshd_config(ctx)
        assert _sshd_json(tmp_path)["findings"] == []

    def test_config_file_listed_even_with_no_findings(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/ssh/sshd_config": "PermitRootLogin no\n"})
        analyze_sshd_config(ctx)
        assert "etc/ssh/sshd_config" in _sshd_json(tmp_path)["config_files"]

    def test_protocol_2_not_flagged(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/ssh/sshd_config": "Protocol 2\n"})
        analyze_sshd_config(ctx)
        assert _sshd_json(tmp_path)["findings"] == []

    def test_x11forwarding_no_not_flagged(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/ssh/sshd_config": "X11Forwarding no\n"})
        analyze_sshd_config(ctx)
        assert _sshd_json(tmp_path)["findings"] == []

    def test_permit_root_login_prohibit_password_not_flagged(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/ssh/sshd_config": "PermitRootLogin prohibit-password\n"})
        analyze_sshd_config(ctx)
        assert _sshd_json(tmp_path)["findings"] == []


# ── analyze_sshd_config: critical findings ───────────────────────────────────

class TestAnalyzeSshdConfigCritical:
    def test_permit_root_login_yes_is_critical(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/ssh/sshd_config": "PermitRootLogin yes\n"})
        analyze_sshd_config(ctx)
        findings = _sshd_json(tmp_path)["findings"]
        assert len(findings) == 1
        assert findings[0]["directive"] == "PermitRootLogin"
        assert findings[0]["severity"] == "critical"
        assert findings[0]["value"] == "yes"

    def test_permit_empty_passwords_yes_is_critical(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/ssh/sshd_config": "PermitEmptyPasswords yes\n"})
        analyze_sshd_config(ctx)
        findings = _sshd_json(tmp_path)["findings"]
        assert any(f["directive"] == "PermitEmptyPasswords" and f["severity"] == "critical"
                   for f in findings)

    def test_two_critical_settings_both_counted(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "etc/ssh/sshd_config": "PermitRootLogin yes\nPermitEmptyPasswords yes\n"
        })
        analyze_sshd_config(ctx)
        assert _sshd_json(tmp_path)["summary"]["critical"] == 2


# ── analyze_sshd_config: high findings ───────────────────────────────────────

class TestAnalyzeSshdConfigHigh:
    def test_protocol_1_is_high(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/ssh/sshd_config": "Protocol 1\n"})
        analyze_sshd_config(ctx)
        findings = _sshd_json(tmp_path)["findings"]
        assert any(f["directive"] == "Protocol" and f["severity"] == "high" for f in findings)


# ── analyze_sshd_config: medium findings ─────────────────────────────────────

class TestAnalyzeSshdConfigMedium:
    def test_password_authentication_yes_is_medium(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/ssh/sshd_config": "PasswordAuthentication yes\n"})
        analyze_sshd_config(ctx)
        findings = _sshd_json(tmp_path)["findings"]
        assert any(f["directive"] == "PasswordAuthentication" and f["severity"] == "medium"
                   for f in findings)

    def test_gateway_ports_yes_is_medium(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/ssh/sshd_config": "GatewayPorts yes\n"})
        analyze_sshd_config(ctx)
        findings = _sshd_json(tmp_path)["findings"]
        assert any(f["directive"] == "GatewayPorts" and f["severity"] == "medium"
                   for f in findings)

    def test_strict_modes_no_is_medium(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/ssh/sshd_config": "StrictModes no\n"})
        analyze_sshd_config(ctx)
        findings = _sshd_json(tmp_path)["findings"]
        assert any(f["directive"] == "StrictModes" and f["severity"] == "medium"
                   for f in findings)

    def test_permit_user_environment_yes_is_medium(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/ssh/sshd_config": "PermitUserEnvironment yes\n"})
        analyze_sshd_config(ctx)
        findings = _sshd_json(tmp_path)["findings"]
        assert any(f["directive"] == "PermitUserEnvironment" for f in findings)

    def test_ignore_rhosts_no_is_medium(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/ssh/sshd_config": "IgnoreRhosts no\n"})
        analyze_sshd_config(ctx)
        findings = _sshd_json(tmp_path)["findings"]
        assert any(f["directive"] == "IgnoreRhosts" and f["severity"] == "medium"
                   for f in findings)


# ── analyze_sshd_config: low findings ────────────────────────────────────────

class TestAnalyzeSshdConfigLow:
    def test_x11_forwarding_yes_is_low(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/ssh/sshd_config": "X11Forwarding yes\n"})
        analyze_sshd_config(ctx)
        findings = _sshd_json(tmp_path)["findings"]
        assert any(f["directive"] == "X11Forwarding" and f["severity"] == "low"
                   for f in findings)


# ── analyze_sshd_config: parser robustness ───────────────────────────────────

class TestAnalyzeSshdConfigParsing:
    def test_commented_directive_not_flagged(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/ssh/sshd_config": "# PermitRootLogin yes\n"})
        analyze_sshd_config(ctx)
        assert _sshd_json(tmp_path)["findings"] == []

    def test_case_insensitive_directive_matched(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/ssh/sshd_config": "permitrootlogin yes\n"})
        analyze_sshd_config(ctx)
        assert len(_sshd_json(tmp_path)["findings"]) == 1

    def test_case_insensitive_value_matched(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/ssh/sshd_config": "PermitRootLogin YES\n"})
        analyze_sshd_config(ctx)
        assert len(_sshd_json(tmp_path)["findings"]) == 1

    def test_inline_comment_does_not_affect_detection(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "etc/ssh/sshd_config": "PermitRootLogin yes  # bad\n"
        })
        analyze_sshd_config(ctx)
        assert len(_sshd_json(tmp_path)["findings"]) == 1

    def test_first_occurrence_wins_dangerous_then_safe(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "etc/ssh/sshd_config": "PermitRootLogin yes\nPermitRootLogin no\n"
        })
        analyze_sshd_config(ctx)
        assert len(_sshd_json(tmp_path)["findings"]) == 1

    def test_first_occurrence_wins_safe_then_dangerous(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "etc/ssh/sshd_config": "PermitRootLogin no\nPermitRootLogin yes\n"
        })
        analyze_sshd_config(ctx)
        assert _sshd_json(tmp_path)["findings"] == []

    def test_line_number_recorded_correctly(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "etc/ssh/sshd_config": "\n# comment\nPermitRootLogin yes\n"
        })
        analyze_sshd_config(ctx)
        assert _sshd_json(tmp_path)["findings"][0]["line"] == 3

    def test_file_path_relative_to_rootfs(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/ssh/sshd_config": "PermitRootLogin yes\n"})
        analyze_sshd_config(ctx)
        f = _sshd_json(tmp_path)["findings"][0]
        assert f["file"] == "etc/ssh/sshd_config"
        assert not f["file"].startswith("/")


# ── analyze_sshd_config: multiple config files ───────────────────────────────

class TestAnalyzeSshdConfigMultipleFiles:
    def test_findings_collected_from_all_files(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "etc/ssh/sshd_config":     "PermitRootLogin yes\n",
            "usr/etc/sshd_config":     "PermitEmptyPasswords yes\n",
        })
        analyze_sshd_config(ctx)
        data = _sshd_json(tmp_path)
        assert len(data["config_files"]) == 2
        assert data["summary"]["critical"] == 2

    def test_all_config_files_listed(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "etc/ssh/sshd_config": "PermitRootLogin no\n",
            "etc/sshd_config":     "Protocol 2\n",
        })
        analyze_sshd_config(ctx)
        assert len(_sshd_json(tmp_path)["config_files"]) == 2

    def test_safe_file_and_unsafe_file_correct_counts(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "etc/ssh/sshd_config": "PermitRootLogin no\n",
            "etc/sshd_config":     "PermitRootLogin yes\n",
        })
        analyze_sshd_config(ctx)
        data = _sshd_json(tmp_path)
        assert data["summary"]["critical"] == 1
        assert len(data["findings"]) == 1


# ── analyze_sshd_config: JSON structure ──────────────────────────────────────

class TestAnalyzeSshdConfigJsonStructure:
    def test_finding_has_all_required_keys(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/ssh/sshd_config": "PermitRootLogin yes\n"})
        analyze_sshd_config(ctx)
        f = _sshd_json(tmp_path)["findings"][0]
        for key in ("file", "line", "directive", "value", "severity", "note"):
            assert key in f

    def test_summary_has_all_severity_keys(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/ssh/sshd_config": ""})
        analyze_sshd_config(ctx)
        s = _sshd_json(tmp_path)["summary"]
        for key in ("critical", "high", "medium", "low"):
            assert key in s

    def test_note_field_is_non_empty_string(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/ssh/sshd_config": "PermitRootLogin yes\n"})
        analyze_sshd_config(ctx)
        f = _sshd_json(tmp_path)["findings"][0]
        assert isinstance(f["note"], str) and len(f["note"]) > 0
