"""Unit tests for the hardening analysis and CVE severity escalation chain.

Two functions under test:

  analyze_hardening (binary.py)
    Aggregates NX/PIE/RELRO/canary flags from the ELF cache into a summary
    dict and writes hardening.json.  Wrong counts here silently misprices
    every CVE that touches those binaries.

  _escalate (cve.py)
    Pure function: (base_severity, hardening_dict, reachable) → (severity, reasons).
    Applies +1 per absent mitigation, +2 for network reachability.
    Hardening values are *strings* ("False"/"no"/"none") because they come from
    CycloneDX SBOM properties, not from Python bools — a critical type contract
    that must be pinned.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from firmware_analysis.analysis.analyzers.binary import analyze_hardening
from firmware_analysis.analysis.analyzers.context import AnalysisContext
from firmware_analysis.analysis.analyzers.elf_cache import _ElfRecord
from firmware_analysis.cve.cve import _escalate


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_ctx(tmp_path, elf_entries: dict) -> AnalysisContext:
    """Build an AnalysisContext with a fake elf_cache for the given entries.

    elf_entries: {relative_path_str: hardening_dict}
    """
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    out = tmp_path / "out"
    out.mkdir()
    elf_cache = {}
    for rel, h in elf_entries.items():
        path = rootfs / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()
        rec = _ElfRecord()
        rec.hardening = h
        elf_cache[path] = rec
    return AnalysisContext(rootfs=rootfs, out_dir=out, configs=[], elf_cache=elf_cache)


def _hardening_json(tmp_path) -> dict:
    return json.loads((tmp_path / "out" / "hardening.json").read_text())


def _fully_unprotected():
    return {"nx": False, "pie": "no", "relro": "none", "canary": False}


def _fully_protected():
    return {"nx": True, "pie": "yes", "relro": "full", "canary": True}


# ── analyze_hardening: filtering ──────────────────────────────────────────────

class TestAnalyzeHardeningFiltering:
    def test_empty_cache_writes_zero_summary(self, tmp_path):
        ctx = _make_ctx(tmp_path, {})
        analyze_hardening(ctx)
        data = _hardening_json(tmp_path)
        assert data["summary"]["total"] == 0
        assert data["binaries"] == []

    def test_shared_library_pie_so_is_skipped(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "lib/libfoo.so": {"nx": True, "pie": "so", "relro": "partial", "canary": False},
        })
        analyze_hardening(ctx)
        assert _hardening_json(tmp_path)["summary"]["total"] == 0

    def test_empty_hardening_dict_is_skipped(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"usr/bin/tool": {}})
        analyze_hardening(ctx)
        assert _hardening_json(tmp_path)["summary"]["total"] == 0

    def test_executable_with_pie_yes_is_included(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "usr/bin/httpd": {"nx": True, "pie": "yes", "relro": "full", "canary": True},
        })
        analyze_hardening(ctx)
        assert _hardening_json(tmp_path)["summary"]["total"] == 1

    def test_executable_with_pie_no_is_included(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "usr/bin/httpd": _fully_unprotected(),
        })
        analyze_hardening(ctx)
        assert _hardening_json(tmp_path)["summary"]["total"] == 1

    def test_mixed_so_and_exe_counts_only_exe(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "lib/libssl.so": {"nx": True, "pie": "so", "relro": "partial", "canary": False},
            "usr/bin/openssl": _fully_unprotected(),
        })
        analyze_hardening(ctx)
        assert _hardening_json(tmp_path)["summary"]["total"] == 1


# ── analyze_hardening: NX counts ─────────────────────────────────────────────

class TestAnalyzeHardeningNx:
    def test_nx_enabled_counted(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"bin/a": {**_fully_protected()}})
        analyze_hardening(ctx)
        assert _hardening_json(tmp_path)["summary"]["nx_enabled"] == 1
        assert _hardening_json(tmp_path)["summary"]["nx_disabled"] == 0

    def test_nx_disabled_counted(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"bin/a": _fully_unprotected()})
        analyze_hardening(ctx)
        s = _hardening_json(tmp_path)["summary"]
        assert s["nx_disabled"] == 1
        assert s["nx_enabled"] == 0

    def test_nx_none_counted_as_unknown(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "bin/a": {"nx": None, "pie": "no", "relro": "none", "canary": False},
        })
        analyze_hardening(ctx)
        s = _hardening_json(tmp_path)["summary"]
        assert s["nx_unknown"] == 1
        assert s["nx_enabled"] == 0
        assert s["nx_disabled"] == 0

    def test_nx_counts_sum_to_total(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "bin/a": {**_fully_protected()},
            "bin/b": _fully_unprotected(),
            "bin/c": {"nx": None, "pie": "no", "relro": "none", "canary": False},
        })
        analyze_hardening(ctx)
        s = _hardening_json(tmp_path)["summary"]
        assert s["nx_enabled"] + s["nx_disabled"] + s["nx_unknown"] == s["total"]


# ── analyze_hardening: PIE counts ─────────────────────────────────────────────

class TestAnalyzeHardeningPie:
    def test_pie_yes_counted(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"bin/a": _fully_protected()})
        analyze_hardening(ctx)
        assert _hardening_json(tmp_path)["summary"]["pie_yes"] == 1

    def test_pie_no_counted(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"bin/a": _fully_unprotected()})
        analyze_hardening(ctx)
        assert _hardening_json(tmp_path)["summary"]["pie_no"] == 1

    def test_pie_missing_from_hardening_counted_as_unknown(self, tmp_path):
        # pie key absent → defaults to "unknown"
        ctx = _make_ctx(tmp_path, {"bin/a": {"nx": True, "relro": "full", "canary": True}})
        analyze_hardening(ctx)
        assert _hardening_json(tmp_path)["summary"]["pie_unknown"] == 1


# ── analyze_hardening: RELRO counts ──────────────────────────────────────────

class TestAnalyzeHardeningRelro:
    def test_relro_full_counted(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"bin/a": _fully_protected()})
        analyze_hardening(ctx)
        assert _hardening_json(tmp_path)["summary"]["relro_full"] == 1

    def test_relro_partial_counted(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "bin/a": {"nx": True, "pie": "yes", "relro": "partial", "canary": True},
        })
        analyze_hardening(ctx)
        assert _hardening_json(tmp_path)["summary"]["relro_partial"] == 1

    def test_relro_none_counted(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"bin/a": _fully_unprotected()})
        analyze_hardening(ctx)
        assert _hardening_json(tmp_path)["summary"]["relro_none"] == 1

    def test_relro_counts_sum_to_total(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "bin/a": _fully_protected(),
            "bin/b": {"nx": True, "pie": "yes", "relro": "partial", "canary": True},
            "bin/c": _fully_unprotected(),
        })
        analyze_hardening(ctx)
        s = _hardening_json(tmp_path)["summary"]
        assert s["relro_full"] + s["relro_partial"] + s["relro_none"] == s["total"]


# ── analyze_hardening: canary counts ─────────────────────────────────────────

class TestAnalyzeHardeningCanary:
    def test_canary_yes_counted(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"bin/a": _fully_protected()})
        analyze_hardening(ctx)
        assert _hardening_json(tmp_path)["summary"]["canary_yes"] == 1

    def test_canary_no_counted(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"bin/a": _fully_unprotected()})
        analyze_hardening(ctx)
        assert _hardening_json(tmp_path)["summary"]["canary_no"] == 1


# ── analyze_hardening: JSON output ───────────────────────────────────────────

class TestAnalyzeHardeningOutput:
    def test_writes_hardening_json(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"bin/a": _fully_unprotected()})
        analyze_hardening(ctx)
        assert (tmp_path / "out" / "hardening.json").exists()

    def test_binary_path_is_relative_to_rootfs(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"usr/sbin/httpd": _fully_protected()})
        analyze_hardening(ctx)
        data = _hardening_json(tmp_path)
        assert data["binaries"][0]["path"] == "usr/sbin/httpd"

    def test_binary_record_has_all_flag_keys(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"bin/a": _fully_unprotected()})
        analyze_hardening(ctx)
        b = _hardening_json(tmp_path)["binaries"][0]
        for key in ("path", "nx", "pie", "relro", "canary"):
            assert key in b

    def test_multiple_binaries_all_appear(self, tmp_path):
        ctx = _make_ctx(tmp_path, {
            "bin/a": _fully_protected(),
            "bin/b": _fully_unprotected(),
        })
        analyze_hardening(ctx)
        data = _hardening_json(tmp_path)
        assert data["summary"]["total"] == 2
        assert len(data["binaries"]) == 2


# ── _escalate: base severity ─────────────────────────────────────────────────

class TestEscalateBase:
    def test_no_flags_preserves_severity(self):
        sev, reasons = _escalate("medium", None, False)
        assert sev == "medium"
        assert reasons == []

    def test_all_known_base_severities_are_valid(self):
        for base in ("none", "info", "low", "medium", "high", "critical"):
            sev, _ = _escalate(base, None, False)
            assert sev == base

    def test_unknown_base_defaults_to_info_weight(self):
        # _WEIGHT.get(unknown, 1) → info(1), no flags → info
        sev, _ = _escalate("garbage", None, False)
        assert sev == "info"

    def test_base_is_case_insensitive(self):
        sev, _ = _escalate("MEDIUM", None, False)
        assert sev == "medium"


# ── _escalate: reachability ───────────────────────────────────────────────────

class TestEscalateReachability:
    def test_reachable_adds_two_levels(self):
        # low(2) + 2 = 4 = high
        sev, reasons = _escalate("low", None, True)
        assert sev == "high"
        assert "network-reachable entry point" in reasons

    def test_not_reachable_no_change(self):
        sev, reasons = _escalate("low", None, False)
        assert sev == "low"
        assert reasons == []


# ── _escalate: hardening flags ────────────────────────────────────────────────

class TestEscalateHardeningFlags:
    def test_nx_string_false_adds_one_level(self):
        # medium(3) + 1 = 4 = high
        sev, reasons = _escalate("medium", {"nx": "False"}, False)
        assert sev == "high"
        assert "NX disabled" in reasons

    def test_pie_no_adds_one_level(self):
        sev, reasons = _escalate("medium", {"pie": "no"}, False)
        assert sev == "high"
        assert "no PIE" in reasons

    def test_relro_none_adds_one_level(self):
        sev, reasons = _escalate("medium", {"relro": "none"}, False)
        assert sev == "high"
        assert "no RELRO" in reasons

    def test_canary_string_false_adds_one_level(self):
        sev, reasons = _escalate("medium", {"canary": "False"}, False)
        assert sev == "high"
        assert "no stack canary" in reasons

    def test_all_four_flags_add_four_levels(self):
        h = {"nx": "False", "pie": "no", "relro": "none", "canary": "False"}
        # low(2) + 4 = 6, capped at critical(5)
        sev, reasons = _escalate("low", h, False)
        assert sev == "critical"
        assert len(reasons) == 4

    def test_none_hardening_adds_nothing(self):
        sev, reasons = _escalate("high", None, False)
        assert sev == "high"
        assert reasons == []

    def test_empty_hardening_dict_adds_nothing(self):
        sev, reasons = _escalate("high", {}, False)
        assert sev == "high"
        assert reasons == []


# ── _escalate: type contract (string vs bool) ─────────────────────────────────

class TestEscalateTypeContract:
    def test_nx_bool_false_does_not_escalate(self):
        # hardening dict from hardening.json has Python bool False, not string "False"
        # _escalate only checks == "False" (string), so bool False must NOT trigger
        sev, reasons = _escalate("medium", {"nx": False}, False)
        assert sev == "medium"
        assert "NX disabled" not in reasons

    def test_canary_bool_false_does_not_escalate(self):
        sev, reasons = _escalate("medium", {"canary": False}, False)
        assert sev == "medium"
        assert "no stack canary" not in reasons

    def test_nx_bool_true_does_not_escalate(self):
        sev, reasons = _escalate("medium", {"nx": True}, False)
        assert sev == "medium"


# ── _escalate: ceiling ────────────────────────────────────────────────────────

class TestEscalateCeiling:
    def test_capped_at_critical(self):
        h = {"nx": "False", "pie": "no", "relro": "none", "canary": "False"}
        sev, _ = _escalate("high", h, True)  # 4+4+2 = 10 → critical
        assert sev == "critical"

    def test_critical_base_stays_critical_with_no_flags(self):
        sev, _ = _escalate("critical", None, False)
        assert sev == "critical"

    def test_reachable_plus_all_flags_from_none_base_reaches_critical(self):
        h = {"nx": "False", "pie": "no", "relro": "none", "canary": "False"}
        sev, _ = _escalate("none", h, True)  # 0+2+4 = 6 → critical
        assert sev == "critical"
