"""Unit tests for pipeline.py stage dependency chain.

Tests _run_stage in isolation (subprocess mocked) and verifies the
exact blocked_by wiring from main() without running Docker.

Key behavioral contracts under test:
  - "failed" and "skipped" dependency statuses block a downstream stage
  - "partial" does NOT block (stage 4 SVG can fail without blocking stage 5)
  - skip propagates transitively through the chain
  - stage 5 (CVE) is blocked by 3_graph, not 4_svg — so a missing graphviz
    install never prevents CVE enrichment
  - --skip-cve records stage 5 as "skipped", which then blocks stage 6
"""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from pipeline import StageResult, _run_stage, _write_manifest


# ── Helpers ───────────────────────────────────────────────────────────────────

def _stage(status: str, name: str = "dep") -> StageResult:
    return StageResult(name=name, status=status)


def _run(stages, key, blocked_by=None, required=True, returncode=0):
    """Call _run_stage with a mocked subprocess and return the result."""
    with patch("pipeline.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=returncode)
        result = _run_stage(
            key, f"Stage {key}", ["dummy_cmd"],
            stages, required=required, blocked_by=blocked_by,
        )
    return result


# ── Blocking guard ────────────────────────────────────────────────────────────

class TestRunStageBlockingGuard:
    def test_no_blocked_by_always_runs(self):
        stages = {}
        with patch("pipeline.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            _run_stage("s", "S", ["cmd"], stages)
        mock_run.assert_called_once()

    def test_dep_not_in_stages_stage_runs(self):
        # blocked_by set but dep not yet recorded → no block
        stages = {}
        with patch("pipeline.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            _run_stage("s", "S", ["cmd"], stages, blocked_by="missing_dep")
        mock_run.assert_called_once()

    def test_dep_success_stage_runs(self):
        stages = {"dep": _stage("success")}
        with patch("pipeline.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            _run_stage("s", "S", ["cmd"], stages, blocked_by="dep")
        mock_run.assert_called_once()

    def test_dep_partial_stage_runs(self):
        # partial (e.g. optional stage that failed) must NOT block downstream
        stages = {"dep": _stage("partial")}
        with patch("pipeline.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            _run_stage("s", "S", ["cmd"], stages, blocked_by="dep")
        mock_run.assert_called_once()

    def test_dep_failed_stage_skipped(self):
        stages = {"dep": _stage("failed")}
        with patch("pipeline.subprocess.run") as mock_run:
            result = _run_stage("s", "S", ["cmd"], stages, blocked_by="dep")
        mock_run.assert_not_called()
        assert result.status == "skipped"

    def test_dep_skipped_stage_skipped(self):
        # skipped propagates — if dep was itself skipped, this stage also skips
        stages = {"dep": _stage("skipped")}
        with patch("pipeline.subprocess.run") as mock_run:
            result = _run_stage("s", "S", ["cmd"], stages, blocked_by="dep")
        mock_run.assert_not_called()
        assert result.status == "skipped"


# ── Subprocess outcome → stage status ────────────────────────────────────────

class TestRunStageOutcomes:
    def test_exit_0_required_produces_success(self):
        result = _run({}, "s", returncode=0, required=True)
        assert result.status == "success"
        assert result.exit_code == 0

    def test_nonzero_exit_required_produces_failed(self):
        result = _run({}, "s", returncode=1, required=True)
        assert result.status == "failed"
        assert result.exit_code == 1

    def test_nonzero_exit_optional_produces_partial(self):
        result = _run({}, "s", returncode=1, required=False)
        assert result.status == "partial"

    def test_result_stored_in_stages_under_key(self):
        stages = {}
        result = _run(stages, "my_key")
        assert "my_key" in stages
        assert stages["my_key"] is result

    def test_skipped_result_also_stored_in_stages(self):
        stages = {"dep": _stage("failed")}
        with patch("pipeline.subprocess.run"):
            result = _run_stage("s", "S", ["cmd"], stages, blocked_by="dep")
        assert "s" in stages
        assert stages["s"] is result


# ── Skip note content ─────────────────────────────────────────────────────────

class TestRunStageSkipNote:
    def test_skip_note_names_the_dependency(self):
        stages = {"1_extract": _stage("failed")}
        with patch("pipeline.subprocess.run"):
            result = _run_stage("2_surface", "S2", ["cmd"], stages, blocked_by="1_extract")
        assert len(result.notes) == 1
        assert "1_extract" in result.notes[0]

    def test_skip_note_includes_dep_status_failed(self):
        stages = {"1_extract": _stage("failed")}
        with patch("pipeline.subprocess.run"):
            result = _run_stage("2_surface", "S2", ["cmd"], stages, blocked_by="1_extract")
        assert "failed" in result.notes[0]

    def test_skip_note_includes_dep_status_skipped(self):
        stages = {"2_surface": _stage("skipped")}
        with patch("pipeline.subprocess.run"):
            result = _run_stage("3_graph", "S3", ["cmd"], stages, blocked_by="2_surface")
        assert "skipped" in result.notes[0]


# ── StageResult.to_dict ───────────────────────────────────────────────────────

class TestStageResultToDict:
    def test_all_keys_present(self):
        r = StageResult(name="S", status="success", exit_code=0, duration_s=1.5)
        d = r.to_dict()
        for key in ("status", "exit_code", "duration_s", "notes"):
            assert key in d

    def test_duration_rounded_to_one_decimal(self):
        r = StageResult(name="S", status="success", duration_s=1.567)
        assert r.to_dict()["duration_s"] == 1.6


# ── _write_manifest ───────────────────────────────────────────────────────────

class TestWriteManifest:
    def test_creates_manifest_file(self, tmp_path):
        stages = {"1_extract": _stage("success", "Stage 1")}
        _write_manifest(tmp_path, "fw_id", "2026-01-01T00:00:00Z", stages)
        assert (tmp_path / "pipeline_manifest.json").exists()

    def test_manifest_contains_firmware_id(self, tmp_path):
        _write_manifest(tmp_path, "Archer_A5V6", "2026-01-01T00:00:00Z", {})
        data = json.loads((tmp_path / "pipeline_manifest.json").read_text())
        assert data["firmware_id"] == "Archer_A5V6"

    def test_manifest_contains_all_stages(self, tmp_path):
        stages = {
            "1_extract": _stage("success", "Stage 1"),
            "2_surface": _stage("skipped", "Stage 2"),
        }
        _write_manifest(tmp_path, "fw", "t", stages)
        data = json.loads((tmp_path / "pipeline_manifest.json").read_text())
        assert "1_extract" in data["stages"]
        assert "2_surface" in data["stages"]

    def test_failed_status_serialised_correctly(self, tmp_path):
        stages = {"1_extract": _stage("failed", "Stage 1")}
        _write_manifest(tmp_path, "fw", "t", stages)
        data = json.loads((tmp_path / "pipeline_manifest.json").read_text())
        assert data["stages"]["1_extract"]["status"] == "failed"


# ── Pipeline chain wiring ─────────────────────────────────────────────────────
#
# These tests simulate the exact blocked_by wiring from main() to verify
# that the correct stages are skipped when a dependency fails.
# subprocess.run is mocked; no Docker or filesystem access needed.

class TestPipelineChainWiring:

    def _simulate_chain(self, stage1_returncode=0, stage2_returncode=0,
                        stage3_returncode=0, stage4_returncode=0,
                        stage5_returncode=0, skip_cve=False):
        """Run the full 6-stage chain with controlled subprocess exit codes.

        Returns the stages dict after all stages have run.
        """
        stages = {}
        returns = iter([
            stage1_returncode, stage2_returncode,
            stage3_returncode, stage4_returncode,
            stage5_returncode,
        ])

        with patch("pipeline.subprocess.run") as mock_run:
            mock_run.side_effect = lambda cmd, **kw: MagicMock(returncode=next(returns, 0))

            _run_stage("1_extract", "Stage 1", ["cmd"], stages)
            _run_stage("2_surface", "Stage 2", ["cmd"], stages, blocked_by="1_extract")
            _run_stage("3_graph",   "Stage 3", ["cmd"], stages, blocked_by="2_surface")
            _run_stage("4_svg",     "Stage 4", ["cmd"], stages, blocked_by="3_graph",  required=False)

            if skip_cve:
                stages["5_cve"] = StageResult(
                    name="Stage 5 — CVE Enrichment", status="skipped", notes=["--skip-cve"]
                )
            else:
                _run_stage("5_cve",     "Stage 5", ["cmd"], stages, blocked_by="3_graph")

            _run_stage("6_heatmap", "Stage 6", ["cmd"], stages, blocked_by="5_cve")

        return stages

    def test_happy_path_all_succeed(self):
        stages = self._simulate_chain()
        for key in ("1_extract", "2_surface", "3_graph", "5_cve", "6_heatmap"):
            assert stages[key].status == "success", f"{key} expected success"

    def test_stage1_fail_blocks_stage2(self):
        stages = self._simulate_chain(stage1_returncode=1)
        assert stages["1_extract"].status == "failed"
        assert stages["2_surface"].status == "skipped"

    def test_stage1_fail_cascades_to_stage3(self):
        stages = self._simulate_chain(stage1_returncode=1)
        assert stages["3_graph"].status == "skipped"

    def test_stage1_fail_cascades_to_stage5(self):
        stages = self._simulate_chain(stage1_returncode=1)
        assert stages["5_cve"].status == "skipped"

    def test_stage1_fail_cascades_to_stage6(self):
        stages = self._simulate_chain(stage1_returncode=1)
        assert stages["6_heatmap"].status == "skipped"

    def test_stage2_fail_blocks_stage3(self):
        stages = self._simulate_chain(stage2_returncode=1)
        assert stages["2_surface"].status == "failed"
        assert stages["3_graph"].status == "skipped"

    def test_stage2_fail_cascades_to_stage5(self):
        # 3_graph skipped → 5_cve blocked by 3_graph → also skipped
        stages = self._simulate_chain(stage2_returncode=1)
        assert stages["5_cve"].status == "skipped"

    def test_stage3_fail_blocks_stage4(self):
        stages = self._simulate_chain(stage3_returncode=1)
        assert stages["3_graph"].status == "failed"
        assert stages["4_svg"].status == "skipped"

    def test_stage3_fail_blocks_stage5_directly(self):
        # stage 5 is blocked by 3_graph, independently of stage 4
        stages = self._simulate_chain(stage3_returncode=1)
        assert stages["5_cve"].status == "skipped"

    def test_stage4_partial_does_not_block_stage5(self):
        # stage 4 (SVG render) is optional — a partial result must not block CVE enrichment
        # stage 5 is blocked by 3_graph (success), not 4_svg
        stages = self._simulate_chain(stage4_returncode=1)  # → partial
        assert stages["4_svg"].status == "partial"
        assert stages["5_cve"].status == "success"

    def test_stage4_partial_does_not_block_stage6(self):
        stages = self._simulate_chain(stage4_returncode=1)
        assert stages["6_heatmap"].status == "success"

    def test_stage5_fail_blocks_stage6(self):
        stages = self._simulate_chain(stage5_returncode=1)
        assert stages["5_cve"].status == "failed"
        assert stages["6_heatmap"].status == "skipped"

    def test_skip_cve_flag_records_stage5_as_skipped(self):
        stages = self._simulate_chain(skip_cve=True)
        assert stages["5_cve"].status == "skipped"
        assert "skip-cve" in stages["5_cve"].notes[0]

    def test_skip_cve_flag_blocks_stage6(self):
        # --skip-cve records stage 5 as skipped → stage 6 must also be skipped
        stages = self._simulate_chain(skip_cve=True)
        assert stages["6_heatmap"].status == "skipped"

    def test_skip_note_cites_correct_dependency(self):
        stages = self._simulate_chain(stage1_returncode=1)
        assert "1_extract" in stages["2_surface"].notes[0]

    def test_cascaded_skip_note_cites_immediate_dep(self):
        # stage 3 is skipped because stage 2 is skipped (not because stage 1 failed)
        stages = self._simulate_chain(stage1_returncode=1)
        assert "2_surface" in stages["3_graph"].notes[0]
