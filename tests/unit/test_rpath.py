"""Unit tests for RPATH/RUNPATH injection vector detection.

Two functions under test:

  _unsafe_rpath_components (binary.py)
    Pure function: list[str] → list[str].
    Returns only the path components that create a library hijacking opportunity:
    empty strings (CWD), relative paths, and known world-writable absolute dirs.
    $ORIGIN-relative paths are treated as safe.

  analyze_rpath (binary.py)
    Reads rec.rpath from the ELF cache, classifies each binary, and writes
    rpath.txt + rpath.json with separate "unsafe" and "all" sections.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from firmware_analysis.analysis.analyzers.binary import analyze_rpath, _unsafe_rpath_components
from firmware_analysis.analysis.analyzers.context import AnalysisContext
from firmware_analysis.analysis.analyzers.elf_cache import _ElfRecord


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_ctx(tmp_path, elf_entries: dict) -> AnalysisContext:
    """Build an AnalysisContext with a fake elf_cache.

    elf_entries: {relative_path_str: rpath_list}
    """
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    out = tmp_path / "out"
    out.mkdir()
    elf_cache = {}
    for rel, rpath in elf_entries.items():
        path = rootfs / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()
        rec = _ElfRecord()
        rec.rpath = rpath
        elf_cache[path] = rec
    return AnalysisContext(rootfs=rootfs, out_dir=out, configs=[], elf_cache=elf_cache)


def _rpath_json(tmp_path) -> dict:
    return json.loads((tmp_path / "out" / "rpath.json").read_text())


# ── _unsafe_rpath_components: safe paths ─────────────────────────────────────

class TestUnsafeRpathComponentsSafe:
    def test_absolute_lib_path_is_safe(self):
        assert _unsafe_rpath_components(["/lib"]) == []

    def test_absolute_usr_lib_path_is_safe(self):
        assert _unsafe_rpath_components(["/usr/lib"]) == []

    def test_multiple_absolute_paths_all_safe(self):
        assert _unsafe_rpath_components(["/lib", "/usr/lib", "/usr/local/lib"]) == []

    def test_origin_token_is_safe(self):
        assert _unsafe_rpath_components(["$ORIGIN/lib"]) == []

    def test_origin_braces_token_is_safe(self):
        assert _unsafe_rpath_components(["${ORIGIN}/lib"]) == []

    def test_origin_alone_is_safe(self):
        # $ORIGIN by itself resolves to the binary's own directory — acceptable
        assert _unsafe_rpath_components(["$ORIGIN"]) == []

    def test_empty_list_returns_empty(self):
        assert _unsafe_rpath_components([]) == []


# ── _unsafe_rpath_components: unsafe paths ────────────────────────────────────

class TestUnsafeRpathComponentsUnsafe:
    def test_empty_string_flagged_as_cwd(self):
        result = _unsafe_rpath_components([""])
        assert len(result) == 1
        assert "CWD" in result[0]

    def test_dot_is_relative_and_flagged(self):
        assert _unsafe_rpath_components(["."]) == ["."]

    def test_relative_lib_dir_is_flagged(self):
        assert _unsafe_rpath_components(["lib"]) == ["lib"]

    def test_dotdot_relative_path_is_flagged(self):
        assert _unsafe_rpath_components(["../lib"]) == ["../lib"]

    def test_tmp_dir_is_flagged(self):
        assert _unsafe_rpath_components(["/tmp"]) == ["/tmp"]

    def test_tmp_subdir_is_flagged(self):
        assert _unsafe_rpath_components(["/tmp/mylib"]) == ["/tmp/mylib"]

    def test_var_tmp_is_flagged(self):
        assert _unsafe_rpath_components(["/var/tmp"]) == ["/var/tmp"]

    def test_dev_shm_is_flagged(self):
        assert _unsafe_rpath_components(["/dev/shm"]) == ["/dev/shm"]

    def test_mixed_safe_and_unsafe_returns_only_unsafe(self):
        result = _unsafe_rpath_components(["/lib", ".", "/usr/lib", "/tmp"])
        assert set(result) == {".", "/tmp"}

    def test_all_unsafe_returns_all(self):
        result = _unsafe_rpath_components(["", ".", "/tmp"])
        assert len(result) == 3


# ── analyze_rpath: empty / no-rpath cases ────────────────────────────────────

class TestAnalyzeRpathEmpty:
    def test_empty_cache_writes_zero_counts(self, tmp_path):
        ctx = _make_ctx(tmp_path, {})
        analyze_rpath(ctx)
        data = _rpath_json(tmp_path)
        assert data["total_with_rpath"] == 0
        assert data["unsafe_count"] == 0
        assert data["unsafe"] == []
        assert data["all"] == []

    def test_binary_with_no_rpath_not_included(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"bin/tool": []})
        analyze_rpath(ctx)
        data = _rpath_json(tmp_path)
        assert data["total_with_rpath"] == 0

    def test_output_files_always_written(self, tmp_path):
        ctx = _make_ctx(tmp_path, {})
        analyze_rpath(ctx)
        assert (tmp_path / "out" / "rpath.json").exists()
        assert (tmp_path / "out" / "rpath.txt").exists()


# ── analyze_rpath: safe RPATH ─────────────────────────────────────────────────

class TestAnalyzeRpathSafe:
    def test_safe_absolute_rpath_in_all_not_unsafe(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"usr/bin/httpd": ["/lib", "/usr/lib"]})
        analyze_rpath(ctx)
        data = _rpath_json(tmp_path)
        assert data["total_with_rpath"] == 1
        assert data["unsafe_count"] == 0
        assert data["unsafe"] == []
        assert len(data["all"]) == 1

    def test_origin_rpath_in_all_not_unsafe(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"usr/bin/app": ["$ORIGIN/lib"]})
        analyze_rpath(ctx)
        data = _rpath_json(tmp_path)
        assert data["total_with_rpath"] == 1
        assert data["unsafe_count"] == 0

    def test_binary_path_is_relative_to_rootfs(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"usr/sbin/dropbear": ["/lib"]})
        analyze_rpath(ctx)
        data = _rpath_json(tmp_path)
        assert data["all"][0]["binary"] == "usr/sbin/dropbear"


# ── analyze_rpath: unsafe RPATH ───────────────────────────────────────────────

class TestAnalyzeRpathUnsafe:
    def test_relative_rpath_counted_as_unsafe(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"bin/vuln": ["."]})
        analyze_rpath(ctx)
        data = _rpath_json(tmp_path)
        assert data["unsafe_count"] == 1
        assert data["unsafe"][0]["binary"] == "bin/vuln"
        assert "." in data["unsafe"][0]["unsafe_paths"]

    def test_tmp_rpath_counted_as_unsafe(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"bin/vuln": ["/tmp"]})
        analyze_rpath(ctx)
        data = _rpath_json(tmp_path)
        assert data["unsafe_count"] == 1

    def test_empty_component_counted_as_unsafe(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"bin/vuln": [""]})
        analyze_rpath(ctx)
        data = _rpath_json(tmp_path)
        assert data["unsafe_count"] == 1

    def test_unsafe_binary_also_appears_in_all(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"bin/vuln": ["."]})
        analyze_rpath(ctx)
        data = _rpath_json(tmp_path)
        assert data["total_with_rpath"] == 1
        assert data["unsafe_count"] == 1

    def test_unsafe_paths_list_recorded_correctly(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"bin/vuln": ["/lib", ".", "/tmp"]})
        analyze_rpath(ctx)
        data = _rpath_json(tmp_path)
        unsafe_paths = data["unsafe"][0]["unsafe_paths"]
        assert "." in unsafe_paths
        assert "/tmp" in unsafe_paths
        assert "/lib" not in unsafe_paths

    def test_full_rpath_list_recorded_in_all(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"bin/vuln": ["/lib", "."]})
        analyze_rpath(ctx)
        data = _rpath_json(tmp_path)
        assert data["all"][0]["rpath"] == ["/lib", "."]


# ── analyze_rpath: multiple binaries ─────────────────────────────────────────

class TestAnalyzeRpathMultiple:
    def test_counts_are_independent(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "bin/safe":   ["/lib"],
            "bin/unsafe": ["."],
            "bin/norpath": [],
        })
        analyze_rpath(ctx)
        data = _rpath_json(tmp_path)
        assert data["total_with_rpath"] == 2
        assert data["unsafe_count"] == 1

    def test_two_unsafe_binaries_both_reported(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "bin/a": ["."],
            "bin/b": ["/tmp"],
        })
        analyze_rpath(ctx)
        data = _rpath_json(tmp_path)
        assert data["unsafe_count"] == 2
        unsafe_bins = {e["binary"] for e in data["unsafe"]}
        assert "bin/a" in unsafe_bins
        assert "bin/b" in unsafe_bins
