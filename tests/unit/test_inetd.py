"""Unit tests for inetd / xinetd service detection.

Three functions under test:

  _parse_inetd_conf (system.py)
    Pure function: (text, source) → list[dict].
    Parses /etc/inetd.conf lines into service dicts.  Skips comments and
    malformed lines (< 6 fields).  Strips /protocol suffixes from service names.

  _parse_xinetd_blocks (system.py)
    Pure function: (text, source) → list[dict].
    Extracts "service <name> { ... }" blocks from xinetd config text.
    "disable = yes" sets disabled=True; missing or "no" leaves it False.

  analyze_inetd (system.py)
    Scans rootfs for inetd.conf, etc/inetd.d/, xinetd.conf, and etc/xinetd.d/,
    parses them, flags enabled dangerous services, and writes inetd.txt +
    inetd.json with {config_files, services, findings, summary}.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from firmware_analysis.analysis.analyzers.system import (
    _parse_inetd_conf,
    _parse_xinetd_blocks,
    analyze_inetd,
)
from firmware_analysis.analysis.analyzers.context import AnalysisContext


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_ctx(tmp_path, files: dict) -> AnalysisContext:
    """Build an AnalysisContext with the given files written at relative paths.

    files: {relative_path_str: file_content_str}
    """
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    out = tmp_path / "out"
    out.mkdir()
    for rel, content in files.items():
        path = rootfs / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return AnalysisContext(rootfs=rootfs, out_dir=out, configs=[])


def _inetd_json(tmp_path) -> dict:
    return json.loads((tmp_path / "out" / "inetd.json").read_text())


# ── _parse_inetd_conf: basic parsing ─────────────────────────────────────────

class TestParseInetdConfBasic:
    def test_empty_text_returns_empty_list(self):
        assert _parse_inetd_conf("", "etc/inetd.conf") == []

    def test_blank_lines_skipped(self):
        assert _parse_inetd_conf("\n\n\n", "etc/inetd.conf") == []

    def test_comment_lines_skipped(self):
        assert _parse_inetd_conf("# telnet stream tcp nowait root /usr/sbin/telnetd\n",
                                 "etc/inetd.conf") == []

    def test_short_line_fewer_than_six_fields_skipped(self):
        assert _parse_inetd_conf("telnet stream tcp nowait root\n", "etc/inetd.conf") == []

    def test_basic_service_parsed(self):
        line = "telnet  stream  tcp  nowait  root  /usr/sbin/telnetd  telnetd\n"
        result = _parse_inetd_conf(line, "etc/inetd.conf")
        assert len(result) == 1
        svc = result[0]
        assert svc["name"] == "telnet"
        assert svc["socket_type"] == "stream"
        assert svc["protocol"] == "tcp"
        assert svc["user"] == "root"
        assert svc["server"] == "/usr/sbin/telnetd"

    def test_source_recorded_correctly(self):
        line = "ftp  stream  tcp  nowait  root  /usr/sbin/ftpd  ftpd\n"
        result = _parse_inetd_conf(line, "etc/inetd.conf")
        assert result[0]["source"] == "etc/inetd.conf"

    def test_format_is_inetd(self):
        line = "ftp  stream  tcp  nowait  root  /usr/sbin/ftpd  ftpd\n"
        result = _parse_inetd_conf(line, "etc/inetd.conf")
        assert result[0]["format"] == "inetd"

    def test_inetd_services_are_never_disabled(self):
        line = "telnet  stream  tcp  nowait  root  /usr/sbin/telnetd  telnetd\n"
        result = _parse_inetd_conf(line, "etc/inetd.conf")
        assert result[0]["disabled"] is False

    def test_multiple_services_all_parsed(self):
        text = (
            "telnet  stream  tcp  nowait  root  /usr/sbin/telnetd  telnetd\n"
            "ftp     stream  tcp  nowait  root  /usr/sbin/ftpd     ftpd\n"
        )
        result = _parse_inetd_conf(text, "etc/inetd.conf")
        assert len(result) == 2
        names = {r["name"] for r in result}
        assert names == {"telnet", "ftp"}


# ── _parse_inetd_conf: service name normalisation ────────────────────────────

class TestParseInetdConfNameNorm:
    def test_protocol_suffix_stripped(self):
        line = "ftp/tcp  stream  tcp  nowait  root  /usr/sbin/ftpd  ftpd\n"
        result = _parse_inetd_conf(line, "etc/inetd.conf")
        assert result[0]["name"] == "ftp"

    def test_name_is_lowercased(self):
        line = "TELNET  stream  tcp  nowait  root  /usr/sbin/telnetd  telnetd\n"
        result = _parse_inetd_conf(line, "etc/inetd.conf")
        assert result[0]["name"] == "telnet"

    def test_mixed_case_with_suffix(self):
        line = "FTP/TCP  stream  tcp  nowait  root  /usr/sbin/ftpd  ftpd\n"
        result = _parse_inetd_conf(line, "etc/inetd.conf")
        assert result[0]["name"] == "ftp"

    def test_optional_args_captured(self):
        line = "ftp  stream  tcp  nowait  root  /usr/sbin/ftpd  ftpd -l -a\n"
        result = _parse_inetd_conf(line, "etc/inetd.conf")
        assert result[0]["args"] == ["ftpd", "-l", "-a"]

    def test_no_args_gives_empty_list(self):
        line = "telnet  stream  tcp  nowait  root  /usr/sbin/telnetd\n"
        result = _parse_inetd_conf(line, "etc/inetd.conf")
        assert result[0]["args"] == []


# ── _parse_xinetd_blocks: basic parsing ──────────────────────────────────────

class TestParseXinetdBlocksBasic:
    def test_empty_text_returns_empty_list(self):
        assert _parse_xinetd_blocks("", "etc/xinetd.conf") == []

    def test_text_with_no_service_blocks_returns_empty(self):
        assert _parse_xinetd_blocks("includedir /etc/xinetd.d\n", "etc/xinetd.conf") == []

    def test_basic_block_parsed(self):
        text = (
            "service telnet\n"
            "{\n"
            "    socket_type = stream\n"
            "    user        = root\n"
            "    server      = /usr/sbin/in.telnetd\n"
            "    disable     = no\n"
            "}\n"
        )
        result = _parse_xinetd_blocks(text, "etc/xinetd.d/telnet")
        assert len(result) == 1
        svc = result[0]
        assert svc["name"] == "telnet"
        assert svc["server"] == "/usr/sbin/in.telnetd"
        assert svc["user"] == "root"
        assert svc["disabled"] is False

    def test_source_recorded(self):
        text = "service ftp\n{\n    server = /usr/sbin/ftpd\n    disable = no\n}\n"
        result = _parse_xinetd_blocks(text, "etc/xinetd.d/ftp")
        assert result[0]["source"] == "etc/xinetd.d/ftp"

    def test_format_is_xinetd(self):
        text = "service ftp\n{\n    server = /usr/sbin/ftpd\n    disable = no\n}\n"
        result = _parse_xinetd_blocks(text, "etc/xinetd.d/ftp")
        assert result[0]["format"] == "xinetd"

    def test_name_is_lowercased(self):
        text = "service TELNET\n{\n    server = /usr/sbin/in.telnetd\n    disable = no\n}\n"
        result = _parse_xinetd_blocks(text, "etc/xinetd.d/telnet")
        assert result[0]["name"] == "telnet"

    def test_multiple_blocks_in_single_file(self):
        text = (
            "service telnet\n{\n    server = /usr/sbin/in.telnetd\n    disable = no\n}\n"
            "service ftp\n{\n    server = /usr/sbin/ftpd\n    disable = no\n}\n"
        )
        result = _parse_xinetd_blocks(text, "etc/xinetd.conf")
        assert len(result) == 2
        names = {r["name"] for r in result}
        assert names == {"telnet", "ftp"}


# ── _parse_xinetd_blocks: disable handling ───────────────────────────────────

class TestParseXinetdBlocksDisabled:
    def test_disable_yes_sets_disabled_true(self):
        text = "service telnet\n{\n    server = /usr/sbin/in.telnetd\n    disable = yes\n}\n"
        result = _parse_xinetd_blocks(text, "etc/xinetd.d/telnet")
        assert result[0]["disabled"] is True

    def test_disable_no_sets_disabled_false(self):
        text = "service telnet\n{\n    server = /usr/sbin/in.telnetd\n    disable = no\n}\n"
        result = _parse_xinetd_blocks(text, "etc/xinetd.d/telnet")
        assert result[0]["disabled"] is False

    def test_missing_disable_defaults_to_false(self):
        text = "service ftp\n{\n    server = /usr/sbin/ftpd\n}\n"
        result = _parse_xinetd_blocks(text, "etc/xinetd.d/ftp")
        assert result[0]["disabled"] is False

    def test_disable_case_insensitive(self):
        text = "service telnet\n{\n    server = /usr/sbin/in.telnetd\n    disable = YES\n}\n"
        result = _parse_xinetd_blocks(text, "etc/xinetd.d/telnet")
        assert result[0]["disabled"] is True

    def test_disable_inline_comment_stripped(self):
        text = "service telnet\n{\n    server = /usr/sbin/in.telnetd\n    disable = yes # legacy\n}\n"
        result = _parse_xinetd_blocks(text, "etc/xinetd.d/telnet")
        assert result[0]["disabled"] is True

    def test_plus_equals_operator_does_not_pollute_disable(self):
        text = (
            "service telnet\n"
            "{\n"
            "    server          = /usr/sbin/in.telnetd\n"
            "    disable         = no\n"
            "    log_on_failure += USERID\n"
            "}\n"
        )
        result = _parse_xinetd_blocks(text, "etc/xinetd.d/telnet")
        assert result[0]["disabled"] is False


# ── analyze_inetd: no config found ───────────────────────────────────────────

class TestAnalyzeInetdEmpty:
    def test_no_config_writes_empty_findings(self, tmp_path):
        ctx = _make_ctx(tmp_path, {})
        analyze_inetd(ctx)
        data = _inetd_json(tmp_path)
        assert data["config_files"] == []
        assert data["services"] == []
        assert data["findings"] == []

    def test_no_config_summary_all_zero(self, tmp_path):
        ctx = _make_ctx(tmp_path, {})
        analyze_inetd(ctx)
        data = _inetd_json(tmp_path)
        assert data["summary"] == {"critical": 0, "high": 0, "medium": 0, "low": 0}

    def test_output_files_always_written(self, tmp_path):
        ctx = _make_ctx(tmp_path, {})
        analyze_inetd(ctx)
        assert (tmp_path / "out" / "inetd.txt").exists()
        assert (tmp_path / "out" / "inetd.json").exists()


# ── analyze_inetd: inetd.conf ─────────────────────────────────────────────────

class TestAnalyzeInetdInetdConf:
    def test_dangerous_service_produces_finding(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "etc/inetd.conf": "telnet  stream  tcp  nowait  root  /usr/sbin/telnetd  telnetd\n",
        })
        analyze_inetd(ctx)
        data = _inetd_json(tmp_path)
        assert len(data["findings"]) == 1
        assert data["findings"][0]["service"] == "telnet"

    def test_finding_severity_is_critical_for_telnet(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "etc/inetd.conf": "telnet  stream  tcp  nowait  root  /usr/sbin/telnetd  telnetd\n",
        })
        analyze_inetd(ctx)
        data = _inetd_json(tmp_path)
        assert data["findings"][0]["severity"] == "critical"
        assert data["summary"]["critical"] == 1

    def test_safe_service_produces_no_finding(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "etc/inetd.conf": "smtp  stream  tcp  nowait  root  /usr/sbin/smtpd  smtpd\n",
        })
        analyze_inetd(ctx)
        data = _inetd_json(tmp_path)
        assert data["findings"] == []

    def test_service_still_recorded_in_services_list(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "etc/inetd.conf": "telnet  stream  tcp  nowait  root  /usr/sbin/telnetd  telnetd\n",
        })
        analyze_inetd(ctx)
        data = _inetd_json(tmp_path)
        assert len(data["services"]) == 1
        assert data["services"][0]["name"] == "telnet"

    def test_config_file_recorded(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "etc/inetd.conf": "telnet  stream  tcp  nowait  root  /usr/sbin/telnetd  telnetd\n",
        })
        analyze_inetd(ctx)
        data = _inetd_json(tmp_path)
        assert "etc/inetd.conf" in data["config_files"]

    def test_finding_records_server_and_user(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "etc/inetd.conf": "ftp  stream  tcp  nowait  daemon  /usr/sbin/ftpd  ftpd\n",
        })
        analyze_inetd(ctx)
        data = _inetd_json(tmp_path)
        f = data["findings"][0]
        assert f["server"] == "/usr/sbin/ftpd"
        assert f["user"] == "daemon"

    def test_ftp_severity_is_high(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "etc/inetd.conf": "ftp  stream  tcp  nowait  root  /usr/sbin/ftpd  ftpd\n",
        })
        analyze_inetd(ctx)
        data = _inetd_json(tmp_path)
        assert data["findings"][0]["severity"] == "high"

    def test_multiple_dangerous_services_all_found(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "etc/inetd.conf": (
                "telnet  stream  tcp  nowait  root  /usr/sbin/telnetd  telnetd\n"
                "ftp     stream  tcp  nowait  root  /usr/sbin/ftpd     ftpd\n"
                "tftp    dgram   udp  wait    root  /usr/sbin/tftpd    tftpd\n"
            ),
        })
        analyze_inetd(ctx)
        data = _inetd_json(tmp_path)
        assert len(data["findings"]) == 3
        names = {f["service"] for f in data["findings"]}
        assert names == {"telnet", "ftp", "tftp"}


# ── analyze_inetd: xinetd ─────────────────────────────────────────────────────

class TestAnalyzeInetdXinetd:
    def test_enabled_dangerous_service_produces_finding(self, tmp_path):
        text = (
            "service telnet\n"
            "{\n"
            "    socket_type = stream\n"
            "    user        = root\n"
            "    server      = /usr/sbin/in.telnetd\n"
            "    disable     = no\n"
            "}\n"
        )
        ctx = _make_ctx(tmp_path, {"etc/xinetd.d/telnet": text})
        analyze_inetd(ctx)
        data = _inetd_json(tmp_path)
        assert len(data["findings"]) == 1
        assert data["findings"][0]["service"] == "telnet"

    def test_disabled_dangerous_service_not_in_findings(self, tmp_path):
        text = (
            "service telnet\n"
            "{\n"
            "    server  = /usr/sbin/in.telnetd\n"
            "    disable = yes\n"
            "}\n"
        )
        ctx = _make_ctx(tmp_path, {"etc/xinetd.d/telnet": text})
        analyze_inetd(ctx)
        data = _inetd_json(tmp_path)
        assert data["findings"] == []

    def test_disabled_service_still_in_services_list(self, tmp_path):
        text = (
            "service telnet\n"
            "{\n"
            "    server  = /usr/sbin/in.telnetd\n"
            "    disable = yes\n"
            "}\n"
        )
        ctx = _make_ctx(tmp_path, {"etc/xinetd.d/telnet": text})
        analyze_inetd(ctx)
        data = _inetd_json(tmp_path)
        assert len(data["services"]) == 1
        assert data["services"][0]["disabled"] is True

    def test_xinetd_conf_file_is_scanned(self, tmp_path):
        text = (
            "service ftp\n"
            "{\n"
            "    server  = /usr/sbin/ftpd\n"
            "    disable = no\n"
            "}\n"
        )
        ctx = _make_ctx(tmp_path, {"etc/xinetd.conf": text})
        analyze_inetd(ctx)
        data = _inetd_json(tmp_path)
        assert "etc/xinetd.conf" in data["config_files"]
        assert data["findings"][0]["service"] == "ftp"

    def test_rsh_alias_shell_flagged_as_critical(self, tmp_path):
        text = (
            "service shell\n"
            "{\n"
            "    server  = /usr/sbin/in.rshd\n"
            "    disable = no\n"
            "}\n"
        )
        ctx = _make_ctx(tmp_path, {"etc/xinetd.d/rsh": text})
        analyze_inetd(ctx)
        data = _inetd_json(tmp_path)
        assert data["findings"][0]["severity"] == "critical"

    def test_finger_severity_is_medium(self, tmp_path):
        text = (
            "service finger\n"
            "{\n"
            "    server  = /usr/sbin/in.fingerd\n"
            "    disable = no\n"
            "}\n"
        )
        ctx = _make_ctx(tmp_path, {"etc/xinetd.d/finger": text})
        analyze_inetd(ctx)
        data = _inetd_json(tmp_path)
        assert data["findings"][0]["severity"] == "medium"

    def test_talk_severity_is_low(self, tmp_path):
        text = (
            "service talk\n"
            "{\n"
            "    server  = /usr/sbin/in.talkd\n"
            "    disable = no\n"
            "}\n"
        )
        ctx = _make_ctx(tmp_path, {"etc/xinetd.d/talk": text})
        analyze_inetd(ctx)
        data = _inetd_json(tmp_path)
        assert data["findings"][0]["severity"] == "low"


# ── analyze_inetd: mixed sources ─────────────────────────────────────────────

class TestAnalyzeInetdMultiple:
    def test_inetd_conf_and_xinetd_d_both_scanned(self, tmp_path):
        xinetd_text = (
            "service ftp\n"
            "{\n"
            "    server  = /usr/sbin/ftpd\n"
            "    disable = no\n"
            "}\n"
        )
        ctx = _make_ctx(tmp_path, {
            "etc/inetd.conf": "telnet  stream  tcp  nowait  root  /usr/sbin/telnetd  telnetd\n",
            "etc/xinetd.d/ftp": xinetd_text,
        })
        analyze_inetd(ctx)
        data = _inetd_json(tmp_path)
        assert len(data["config_files"]) == 2
        names = {f["service"] for f in data["findings"]}
        assert names == {"telnet", "ftp"}

    def test_summary_counts_across_all_sources(self, tmp_path):
        xinetd_text = (
            "service finger\n"
            "{\n"
            "    server  = /usr/sbin/in.fingerd\n"
            "    disable = no\n"
            "}\n"
        )
        ctx = _make_ctx(tmp_path, {
            "etc/inetd.conf": "telnet  stream  tcp  nowait  root  /usr/sbin/telnetd  telnetd\n",
            "etc/xinetd.d/finger": xinetd_text,
        })
        analyze_inetd(ctx)
        data = _inetd_json(tmp_path)
        assert data["summary"]["critical"] == 1
        assert data["summary"]["medium"] == 1

    def test_inetd_d_directory_files_scanned(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "etc/inetd.d/telnet": "telnet  stream  tcp  nowait  root  /usr/sbin/telnetd  telnetd\n",
        })
        analyze_inetd(ctx)
        data = _inetd_json(tmp_path)
        assert len(data["findings"]) == 1
        assert data["findings"][0]["service"] == "telnet"

    def test_json_structure_has_required_keys(self, tmp_path):
        ctx = _make_ctx(tmp_path, {})
        analyze_inetd(ctx)
        data = _inetd_json(tmp_path)
        assert set(data.keys()) == {"config_files", "services", "findings", "summary"}

    def test_summary_has_four_severity_keys(self, tmp_path):
        ctx = _make_ctx(tmp_path, {})
        analyze_inetd(ctx)
        data = _inetd_json(tmp_path)
        assert set(data["summary"].keys()) == {"critical", "high", "medium", "low"}
