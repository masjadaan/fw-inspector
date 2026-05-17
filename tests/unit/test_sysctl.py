"""Unit tests for kernel sysctl hardening parameter analysis.

Two functions under test:

  _parse_sysctl_conf (system.py)
    Pure function: sysctl.conf text → {param: (value, lineno)}.
    Supports 'key = value' and 'key=value'. Comments (#, ;) skipped.
    Inline comments stripped. First-occurrence-wins per file.

  analyze_sysctl (system.py)
    Scans rootfs for sysctl.conf and sysctl.d/*.conf, flags parameters
    set to insecure values ("explicit" findings) and required parameters
    that are absent from all config files ("absent" findings).
    Absent-param checks always run — even with no config files found —
    because embedded kernels often ship with unsafe kernel defaults.
    Writes sysctl.txt + sysctl.json with {config_files, findings, summary}.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from firmware_analysis.analysis.analyzers.system import (
    _parse_sysctl_conf,
    analyze_sysctl,
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


def _sysctl_json(tmp_path) -> dict:
    return json.loads((tmp_path / "out" / "sysctl.json").read_text())


# ── _parse_sysctl_conf: basic parsing ────────────────────────────────────────

class TestParseSysctlConfBasic:
    def test_empty_text_returns_empty(self):
        assert _parse_sysctl_conf("") == {}

    def test_blank_lines_skipped(self):
        assert _parse_sysctl_conf("\n\n\n") == {}

    def test_hash_comment_lines_skipped(self):
        assert _parse_sysctl_conf("# kernel.randomize_va_space = 0\n") == {}

    def test_semicolon_comment_lines_skipped(self):
        assert _parse_sysctl_conf("; kernel.randomize_va_space = 0\n") == {}

    def test_line_without_equals_skipped(self):
        assert _parse_sysctl_conf("kernel.randomize_va_space\n") == {}

    def test_basic_param_parsed(self):
        result = _parse_sysctl_conf("kernel.randomize_va_space = 2\n")
        assert "kernel.randomize_va_space" in result
        assert result["kernel.randomize_va_space"][0] == "2"

    def test_multiple_params_all_parsed(self):
        text = "kernel.randomize_va_space = 2\nnet.ipv4.tcp_syncookies = 1\n"
        result = _parse_sysctl_conf(text)
        assert "kernel.randomize_va_space" in result
        assert "net.ipv4.tcp_syncookies" in result


# ── _parse_sysctl_conf: format variations ────────────────────────────────────

class TestParseSysctlConfFormat:
    def test_key_equals_value_no_spaces(self):
        result = _parse_sysctl_conf("kernel.randomize_va_space=2\n")
        assert result["kernel.randomize_va_space"][0] == "2"

    def test_key_equals_value_with_spaces(self):
        result = _parse_sysctl_conf("kernel.randomize_va_space = 2\n")
        assert result["kernel.randomize_va_space"][0] == "2"

    def test_key_is_lowercased(self):
        result = _parse_sysctl_conf("Kernel.Randomize_VA_Space = 2\n")
        assert "kernel.randomize_va_space" in result

    def test_value_preserved_as_is(self):
        result = _parse_sysctl_conf("kernel.randomize_va_space = 0\n")
        assert result["kernel.randomize_va_space"][0] == "0"

    def test_inline_hash_comment_stripped(self):
        result = _parse_sysctl_conf("kernel.randomize_va_space = 2 # enable ASLR\n")
        assert result["kernel.randomize_va_space"][0] == "2"

    def test_inline_semicolon_comment_stripped(self):
        result = _parse_sysctl_conf("kernel.randomize_va_space = 2 ; enable ASLR\n")
        assert result["kernel.randomize_va_space"][0] == "2"

    def test_first_occurrence_wins_for_duplicate_key(self):
        text = "kernel.randomize_va_space = 2\nkernel.randomize_va_space = 0\n"
        result = _parse_sysctl_conf(text)
        assert result["kernel.randomize_va_space"][0] == "2"

    def test_line_number_recorded_correctly(self):
        text = "\n\nkernel.randomize_va_space = 2\n"
        result = _parse_sysctl_conf(text)
        assert result["kernel.randomize_va_space"][1] == 3

    def test_first_line_has_lineno_one(self):
        result = _parse_sysctl_conf("kernel.randomize_va_space = 2\n")
        assert result["kernel.randomize_va_space"][1] == 1


# ── analyze_sysctl: no sysctl config present ─────────────────────────────────

class TestAnalyzeSysctlNoConfig:
    def test_no_config_files_empty(self, tmp_path):
        ctx = _make_ctx(tmp_path, {})
        analyze_sysctl(ctx)
        data = _sysctl_json(tmp_path)
        assert data["config_files"] == []

    def test_no_config_output_files_written(self, tmp_path):
        ctx = _make_ctx(tmp_path, {})
        analyze_sysctl(ctx)
        assert (tmp_path / "out" / "sysctl.txt").exists()
        assert (tmp_path / "out" / "sysctl.json").exists()

    def test_no_config_absent_aslr_finding_generated(self, tmp_path):
        ctx = _make_ctx(tmp_path, {})
        analyze_sysctl(ctx)
        data = _sysctl_json(tmp_path)
        absent_params = {f["parameter"] for f in data["findings"] if f["type"] == "absent"}
        assert "kernel.randomize_va_space" in absent_params

    def test_no_config_absent_syncookies_finding_generated(self, tmp_path):
        ctx = _make_ctx(tmp_path, {})
        analyze_sysctl(ctx)
        data = _sysctl_json(tmp_path)
        absent_params = {f["parameter"] for f in data["findings"] if f["type"] == "absent"}
        assert "net.ipv4.tcp_syncookies" in absent_params

    def test_no_config_no_explicit_findings(self, tmp_path):
        ctx = _make_ctx(tmp_path, {})
        analyze_sysctl(ctx)
        data = _sysctl_json(tmp_path)
        explicit = [f for f in data["findings"] if f["type"] == "explicit"]
        assert explicit == []

    def test_no_config_summary_reflects_absent_findings(self, tmp_path):
        ctx = _make_ctx(tmp_path, {})
        analyze_sysctl(ctx)
        data = _sysctl_json(tmp_path)
        # ASLR → critical, syncookies → high
        assert data["summary"]["critical"] >= 1
        assert data["summary"]["high"] >= 1


# ── analyze_sysctl: explicit insecure values ──────────────────────────────────

class TestAnalyzeSysctlExplicit:
    def test_aslr_zero_is_critical_finding(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "etc/sysctl.conf": "kernel.randomize_va_space = 0\nnet.ipv4.tcp_syncookies = 1\n",
        })
        analyze_sysctl(ctx)
        data = _sysctl_json(tmp_path)
        explicit = [f for f in data["findings"]
                    if f["type"] == "explicit" and f["parameter"] == "kernel.randomize_va_space"]
        assert len(explicit) == 1
        assert explicit[0]["severity"] == "critical"

    def test_explicit_finding_has_type_field(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "etc/sysctl.conf": "kernel.randomize_va_space = 0\nnet.ipv4.tcp_syncookies = 1\n",
        })
        analyze_sysctl(ctx)
        data = _sysctl_json(tmp_path)
        explicit = [f for f in data["findings"] if f["type"] == "explicit"]
        assert all(f["type"] == "explicit" for f in explicit)

    def test_explicit_finding_has_file_and_line(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "etc/sysctl.conf": "kernel.randomize_va_space = 0\nnet.ipv4.tcp_syncookies = 1\n",
        })
        analyze_sysctl(ctx)
        data = _sysctl_json(tmp_path)
        f = next(x for x in data["findings"]
                 if x["type"] == "explicit" and x["parameter"] == "kernel.randomize_va_space")
        assert "file" in f
        assert "line" in f
        assert f["line"] == 1

    def test_syncookies_zero_is_high_finding(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "etc/sysctl.conf": "kernel.randomize_va_space = 2\nnet.ipv4.tcp_syncookies = 0\n",
        })
        analyze_sysctl(ctx)
        data = _sysctl_json(tmp_path)
        explicit = [f for f in data["findings"]
                    if f["type"] == "explicit" and f["parameter"] == "net.ipv4.tcp_syncookies"]
        assert len(explicit) == 1
        assert explicit[0]["severity"] == "high"

    def test_accept_redirects_one_is_high_finding(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "etc/sysctl.conf": (
                "kernel.randomize_va_space = 2\n"
                "net.ipv4.tcp_syncookies = 1\n"
                "net.ipv4.conf.all.accept_redirects = 1\n"
            ),
        })
        analyze_sysctl(ctx)
        data = _sysctl_json(tmp_path)
        explicit = [f for f in data["findings"]
                    if f["type"] == "explicit"
                    and f["parameter"] == "net.ipv4.conf.all.accept_redirects"]
        assert len(explicit) == 1
        assert explicit[0]["severity"] == "high"

    def test_rp_filter_zero_is_medium_finding(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "etc/sysctl.conf": (
                "kernel.randomize_va_space = 2\n"
                "net.ipv4.tcp_syncookies = 1\n"
                "net.ipv4.conf.all.rp_filter = 0\n"
            ),
        })
        analyze_sysctl(ctx)
        data = _sysctl_json(tmp_path)
        explicit = [f for f in data["findings"]
                    if f["type"] == "explicit"
                    and f["parameter"] == "net.ipv4.conf.all.rp_filter"]
        assert len(explicit) == 1
        assert explicit[0]["severity"] == "medium"

    def test_dmesg_restrict_zero_is_medium_finding(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "etc/sysctl.conf": (
                "kernel.randomize_va_space = 2\n"
                "net.ipv4.tcp_syncookies = 1\n"
                "kernel.dmesg_restrict = 0\n"
            ),
        })
        analyze_sysctl(ctx)
        data = _sysctl_json(tmp_path)
        explicit = [f for f in data["findings"]
                    if f["type"] == "explicit" and f["parameter"] == "kernel.dmesg_restrict"]
        assert len(explicit) == 1
        assert explicit[0]["severity"] == "medium"

    def test_sysrq_one_is_low_finding(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "etc/sysctl.conf": (
                "kernel.randomize_va_space = 2\n"
                "net.ipv4.tcp_syncookies = 1\n"
                "kernel.sysrq = 1\n"
            ),
        })
        analyze_sysctl(ctx)
        data = _sysctl_json(tmp_path)
        explicit = [f for f in data["findings"]
                    if f["type"] == "explicit" and f["parameter"] == "kernel.sysrq"]
        assert len(explicit) == 1
        assert explicit[0]["severity"] == "low"

    def test_explicit_finding_value_recorded(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "etc/sysctl.conf": "kernel.randomize_va_space = 0\nnet.ipv4.tcp_syncookies = 1\n",
        })
        analyze_sysctl(ctx)
        data = _sysctl_json(tmp_path)
        f = next(x for x in data["findings"]
                 if x["type"] == "explicit" and x["parameter"] == "kernel.randomize_va_space")
        assert f["value"] == "0"


# ── analyze_sysctl: absent required parameters ────────────────────────────────

class TestAnalyzeSysctlAbsent:
    def test_absent_finding_has_type_absent(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/sysctl.conf": "net.ipv4.tcp_syncookies = 1\n"})
        analyze_sysctl(ctx)
        data = _sysctl_json(tmp_path)
        absent = [f for f in data["findings"] if f["type"] == "absent"]
        assert all(f["type"] == "absent" for f in absent)

    def test_absent_finding_has_no_file_field(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/sysctl.conf": "net.ipv4.tcp_syncookies = 1\n"})
        analyze_sysctl(ctx)
        data = _sysctl_json(tmp_path)
        absent = [f for f in data["findings"] if f["type"] == "absent"]
        assert len(absent) > 0
        assert all("file" not in f for f in absent)

    def test_absent_finding_has_no_line_field(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/sysctl.conf": "net.ipv4.tcp_syncookies = 1\n"})
        analyze_sysctl(ctx)
        data = _sysctl_json(tmp_path)
        absent = [f for f in data["findings"] if f["type"] == "absent"]
        assert all("line" not in f for f in absent)

    def test_present_safe_value_suppresses_absent_finding(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "etc/sysctl.conf": "kernel.randomize_va_space = 2\nnet.ipv4.tcp_syncookies = 1\n",
        })
        analyze_sysctl(ctx)
        data = _sysctl_json(tmp_path)
        absent_params = {f["parameter"] for f in data["findings"] if f["type"] == "absent"}
        assert "kernel.randomize_va_space" not in absent_params
        assert "net.ipv4.tcp_syncookies" not in absent_params

    def test_present_insecure_value_does_not_also_trigger_absent(self, tmp_path):
        # ASLR is present (value=0) → explicit finding; must NOT also generate absent finding.
        ctx = _make_ctx(tmp_path, {
            "etc/sysctl.conf": "kernel.randomize_va_space = 0\nnet.ipv4.tcp_syncookies = 1\n",
        })
        analyze_sysctl(ctx)
        data = _sysctl_json(tmp_path)
        absent_params = {f["parameter"] for f in data["findings"] if f["type"] == "absent"}
        assert "kernel.randomize_va_space" not in absent_params

    def test_aslr_absent_is_critical(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/sysctl.conf": "net.ipv4.tcp_syncookies = 1\n"})
        analyze_sysctl(ctx)
        data = _sysctl_json(tmp_path)
        aslr_absent = next(
            (f for f in data["findings"]
             if f["type"] == "absent" and f["parameter"] == "kernel.randomize_va_space"),
            None,
        )
        assert aslr_absent is not None
        assert aslr_absent["severity"] == "critical"

    def test_syncookies_absent_is_high(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"etc/sysctl.conf": "kernel.randomize_va_space = 2\n"})
        analyze_sysctl(ctx)
        data = _sysctl_json(tmp_path)
        sc_absent = next(
            (f for f in data["findings"]
             if f["type"] == "absent" and f["parameter"] == "net.ipv4.tcp_syncookies"),
            None,
        )
        assert sc_absent is not None
        assert sc_absent["severity"] == "high"


# ── analyze_sysctl: safe configuration ────────────────────────────────────────

class TestAnalyzeSysctlSafe:
    def test_all_safe_values_no_explicit_findings(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "etc/sysctl.conf": (
                "kernel.randomize_va_space = 2\n"
                "net.ipv4.tcp_syncookies = 1\n"
                "net.ipv4.conf.all.accept_redirects = 0\n"
                "net.ipv4.conf.all.rp_filter = 1\n"
                "kernel.dmesg_restrict = 1\n"
                "kernel.sysrq = 0\n"
            ),
        })
        analyze_sysctl(ctx)
        data = _sysctl_json(tmp_path)
        explicit = [f for f in data["findings"] if f["type"] == "explicit"]
        assert explicit == []

    def test_safe_aslr_and_syncookies_no_findings(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "etc/sysctl.conf": "kernel.randomize_va_space = 2\nnet.ipv4.tcp_syncookies = 1\n",
        })
        analyze_sysctl(ctx)
        data = _sysctl_json(tmp_path)
        assert data["findings"] == []

    def test_irrelevant_param_produces_no_finding(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "etc/sysctl.conf": (
                "kernel.randomize_va_space = 2\n"
                "net.ipv4.tcp_syncookies = 1\n"
                "some.unknown.parameter = 99\n"
            ),
        })
        analyze_sysctl(ctx)
        data = _sysctl_json(tmp_path)
        assert data["findings"] == []

    def test_aslr_value_1_not_critical(self, tmp_path):
        # value=1 is weak (randomise stack only) but not the insecure_val="0" → no explicit finding
        ctx = _make_ctx(tmp_path, {
            "etc/sysctl.conf": "kernel.randomize_va_space = 1\nnet.ipv4.tcp_syncookies = 1\n",
        })
        analyze_sysctl(ctx)
        data = _sysctl_json(tmp_path)
        explicit = [f for f in data["findings"]
                    if f["type"] == "explicit" and f["parameter"] == "kernel.randomize_va_space"]
        assert explicit == []


# ── analyze_sysctl: multiple config files ────────────────────────────────────

class TestAnalyzeSysctlMultiple:
    def test_sysctl_d_directory_scanned(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "etc/sysctl.d/10-hardening.conf": (
                "kernel.randomize_va_space = 0\nnet.ipv4.tcp_syncookies = 1\n"
            ),
        })
        analyze_sysctl(ctx)
        data = _sysctl_json(tmp_path)
        explicit = [f for f in data["findings"] if f["type"] == "explicit"]
        assert len(explicit) == 1
        assert explicit[0]["parameter"] == "kernel.randomize_va_space"

    def test_usr_lib_sysctl_d_scanned(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "usr/lib/sysctl.d/50-default.conf": (
                "kernel.randomize_va_space = 0\nnet.ipv4.tcp_syncookies = 1\n"
            ),
        })
        analyze_sysctl(ctx)
        data = _sysctl_json(tmp_path)
        explicit = [f for f in data["findings"] if f["type"] == "explicit"]
        assert len(explicit) == 1

    def test_config_file_recorded_in_json(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "etc/sysctl.conf": "kernel.randomize_va_space = 2\nnet.ipv4.tcp_syncookies = 1\n",
        })
        analyze_sysctl(ctx)
        data = _sysctl_json(tmp_path)
        assert "etc/sysctl.conf" in data["config_files"]

    def test_multiple_files_both_checked(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "etc/sysctl.conf": "kernel.randomize_va_space = 2\nnet.ipv4.tcp_syncookies = 1\n",
            "etc/sysctl.d/99-network.conf": "net.ipv4.conf.all.rp_filter = 0\n",
        })
        analyze_sysctl(ctx)
        data = _sysctl_json(tmp_path)
        assert len(data["config_files"]) == 2
        explicit = [f for f in data["findings"] if f["type"] == "explicit"]
        assert any(f["parameter"] == "net.ipv4.conf.all.rp_filter" for f in explicit)

    def test_summary_counts_correct_across_files(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "etc/sysctl.conf": "kernel.randomize_va_space = 0\nnet.ipv4.tcp_syncookies = 1\n",
            "etc/sysctl.d/99-net.conf": "net.ipv4.conf.all.rp_filter = 0\n",
        })
        analyze_sysctl(ctx)
        data = _sysctl_json(tmp_path)
        assert data["summary"]["critical"] == 1   # ASLR=0
        assert data["summary"]["medium"] >= 1     # rp_filter=0

    def test_json_structure_has_required_keys(self, tmp_path):
        ctx = _make_ctx(tmp_path, {})
        analyze_sysctl(ctx)
        data = _sysctl_json(tmp_path)
        assert set(data.keys()) == {"config_files", "findings", "summary"}

    def test_summary_has_four_severity_keys(self, tmp_path):
        ctx = _make_ctx(tmp_path, {})
        analyze_sysctl(ctx)
        data = _sysctl_json(tmp_path)
        assert set(data["summary"].keys()) == {"critical", "high", "medium", "low"}
