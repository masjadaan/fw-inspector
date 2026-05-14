"""Unit tests for analyze_dangerous_functions.

The analyzer reads rec.dangerous_imports from the ELF cache (populated by
_process_one_elf from readelf --dyn-syms UND symbols) and writes:
  - dangerous_functions.txt  (human-readable section)
  - dangerous_functions.json (list of {binary, functions} dicts)

Tests cover: empty cache, no-match binary, single hit, multiple binaries,
deduplication, JSON structure, and path relativity.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from firmware_analysis.analysis.analyzers.binary import analyze_dangerous_functions
from firmware_analysis.analysis.analyzers.context import AnalysisContext
from firmware_analysis.analysis.analyzers.elf_cache import _ElfRecord, _DANGEROUS_SYM_PAT


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_ctx(tmp_path, elf_entries: dict) -> AnalysisContext:
    """Build an AnalysisContext with a minimal fake elf_cache.

    elf_entries: {relative_path_str: [dangerous_import, ...]}
    """
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    out = tmp_path / "out"
    out.mkdir()
    elf_cache = {}
    for rel, imports in elf_entries.items():
        path = rootfs / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()
        rec = _ElfRecord()
        rec.dangerous_imports = imports
        elf_cache[path] = rec
    return AnalysisContext(rootfs=rootfs, out_dir=out, configs=[], elf_cache=elf_cache)


def _json(tmp_path) -> list:
    return json.loads((tmp_path / "out" / "dangerous_functions.json").read_text())


def _txt(tmp_path) -> str:
    return (tmp_path / "out" / "dangerous_functions.txt").read_text()


# ── Pattern smoke tests ───────────────────────────────────────────────────────

class TestDangerousSymPattern:
    @pytest.mark.parametrize("name", [
        "gets", "strcpy", "strcat", "sprintf", "vsprintf",
        "scanf", "fscanf", "sscanf", "mktemp", "tmpnam",
        "tempnam", "system", "popen", "rand", "srand",
    ])
    def test_known_dangerous_symbols_match(self, name):
        assert _DANGEROUS_SYM_PAT.match(name)

    @pytest.mark.parametrize("name", [
        "fgets", "strncpy", "snprintf", "printf", "memcpy",
        "strlen", "AES_encrypt", "gets_s", "rand_bytes",
        "system_call", "getenv",
    ])
    def test_safe_or_unrelated_symbols_do_not_match(self, name):
        assert not _DANGEROUS_SYM_PAT.match(name)

    def test_partial_prefix_does_not_match(self):
        # "gets" should not match "getservbyname"
        assert not _DANGEROUS_SYM_PAT.match("getservbyname")

    def test_pattern_is_case_sensitive(self):
        assert not _DANGEROUS_SYM_PAT.match("GETS")
        assert not _DANGEROUS_SYM_PAT.match("Strcpy")


# ── analyze_dangerous_functions: output files ─────────────────────────────────

class TestDangerousFunctionsOutput:
    def test_writes_txt_file(self, tmp_path):
        ctx = _make_ctx(tmp_path, {})
        analyze_dangerous_functions(ctx)
        assert (tmp_path / "out" / "dangerous_functions.txt").exists()

    def test_writes_json_file(self, tmp_path):
        ctx = _make_ctx(tmp_path, {})
        analyze_dangerous_functions(ctx)
        assert (tmp_path / "out" / "dangerous_functions.json").exists()

    def test_empty_cache_produces_empty_json(self, tmp_path):
        ctx = _make_ctx(tmp_path, {})
        analyze_dangerous_functions(ctx)
        assert _json(tmp_path) == []

    def test_empty_cache_txt_contains_none(self, tmp_path):
        ctx = _make_ctx(tmp_path, {})
        analyze_dangerous_functions(ctx)
        assert "(none)" in _txt(tmp_path)


# ── analyze_dangerous_functions: filtering ────────────────────────────────────

class TestDangerousFunctionsFiltering:
    def test_binary_with_no_dangerous_imports_excluded(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"usr/bin/safe": []})
        analyze_dangerous_functions(ctx)
        assert _json(tmp_path) == []

    def test_binary_with_dangerous_imports_included(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"usr/bin/vuln": ["gets", "strcpy"]})
        analyze_dangerous_functions(ctx)
        data = _json(tmp_path)
        assert len(data) == 1
        assert data[0]["binary"] == "usr/bin/vuln"

    def test_mixed_binaries_only_dangerous_ones_appear(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "usr/bin/safe":  [],
            "usr/bin/vuln":  ["sprintf"],
        })
        analyze_dangerous_functions(ctx)
        data = _json(tmp_path)
        assert len(data) == 1
        assert data[0]["binary"] == "usr/bin/vuln"


# ── analyze_dangerous_functions: JSON structure ───────────────────────────────

class TestDangerousFunctionsJsonStructure:
    def test_each_entry_has_binary_and_functions_keys(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"bin/a": ["gets"]})
        analyze_dangerous_functions(ctx)
        entry = _json(tmp_path)[0]
        assert "binary" in entry
        assert "functions" in entry

    def test_path_is_relative_to_rootfs(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"usr/sbin/httpd": ["system"]})
        analyze_dangerous_functions(ctx)
        assert _json(tmp_path)[0]["binary"] == "usr/sbin/httpd"

    def test_functions_list_matches_dangerous_imports(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"bin/a": ["gets", "sprintf", "system"]})
        analyze_dangerous_functions(ctx)
        assert set(_json(tmp_path)[0]["functions"]) == {"gets", "sprintf", "system"}

    def test_multiple_binaries_all_appear(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "bin/a": ["gets"],
            "bin/b": ["strcpy", "strcat"],
        })
        analyze_dangerous_functions(ctx)
        data = _json(tmp_path)
        assert len(data) == 2

    def test_functions_list_is_not_empty_for_matched_binary(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"bin/x": ["popen"]})
        analyze_dangerous_functions(ctx)
        assert len(_json(tmp_path)[0]["functions"]) >= 1


# ── analyze_dangerous_functions: txt content ──────────────────────────────────

class TestDangerousFunctionsTxtContent:
    def test_binary_path_appears_in_txt(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"usr/bin/vuln": ["gets"]})
        analyze_dangerous_functions(ctx)
        assert "usr/bin/vuln" in _txt(tmp_path)

    def test_function_name_appears_in_txt(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"bin/a": ["strcpy"]})
        analyze_dangerous_functions(ctx)
        assert "strcpy" in _txt(tmp_path)

    def test_section_header_present(self, tmp_path):
        ctx = _make_ctx(tmp_path, {})
        analyze_dangerous_functions(ctx)
        assert "Dangerous Functions" in _txt(tmp_path)
