"""Unit tests for analyze_protocols (network.py).

Strategy: real config files + real grep, no subprocess mocking.
This tests the actual regex patterns, not a stand-in for them.
The concern driving these tests is that off-by-one errors in a
grep pattern (e.g. matching too few or too many tokens) produce
a silently wrong present/absent boolean that feeds ap-snmp,
ap-upnp, and ap-tr069.

Coverage:
  - present/absent detection for each protocol
  - every keyword in each grep pattern triggers a match
  - case-insensitivity (grep -Ei)
  - one protocol matching does not affect others
  - evidence capped at _MAX_EVIDENCE (5)
  - off-by-one boundary: exactly 1 match → present:true
  - off-by-one boundary: exactly 5 matches → all 5 in evidence
  - off-by-one boundary: exactly 6 matches → truncated to 5
  - output JSON structure and file written
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from firmware_analysis.analysis.analyzers.context import AnalysisContext
from firmware_analysis.analysis.analyzers.network import analyze_protocols


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ctx(tmp_path, *config_texts: str) -> AnalysisContext:
    """Build an AnalysisContext with one config file per text argument."""
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    out = tmp_path / "out"
    out.mkdir()
    configs = []
    for i, text in enumerate(config_texts):
        cfg = tmp_path / f"config_{i}.cfg"
        cfg.write_text(text)
        configs.append(str(cfg))
    return AnalysisContext(rootfs=rootfs, out_dir=out, configs=configs)


def _result(tmp_path) -> dict:
    return json.loads((tmp_path / "out" / "protocols.json").read_text())


# ── Output structure ──────────────────────────────────────────────────────────

class TestAnalyzeProtocolsStructure:
    def test_writes_protocols_json(self, tmp_path):
        analyze_protocols(_ctx(tmp_path, "irrelevant=1"))
        assert (tmp_path / "out" / "protocols.json").exists()

    def test_output_has_all_four_protocol_keys(self, tmp_path):
        analyze_protocols(_ctx(tmp_path, "irrelevant=1"))
        result = _result(tmp_path)
        for proto in ("snmp", "upnp", "tr069", "mqtt"):
            assert proto in result

    def test_each_protocol_has_present_and_evidence(self, tmp_path):
        analyze_protocols(_ctx(tmp_path, "irrelevant=1"))
        result = _result(tmp_path)
        for proto in ("snmp", "upnp", "tr069", "mqtt"):
            assert "present" in result[proto]
            assert "evidence" in result[proto]

    def test_empty_config_all_protocols_absent(self, tmp_path):
        analyze_protocols(_ctx(tmp_path, ""))
        result = _result(tmp_path)
        for proto in ("snmp", "upnp", "tr069", "mqtt"):
            assert result[proto]["present"] is False
            assert result[proto]["evidence"] == []


# ── SNMP detection ────────────────────────────────────────────────────────────

class TestSnmpDetection:
    def test_community_keyword_triggers_snmp(self, tmp_path):
        analyze_protocols(_ctx(tmp_path, "community=public"))
        assert _result(tmp_path)["snmp"]["present"] is True

    def test_snmpd_keyword_triggers_snmp(self, tmp_path):
        analyze_protocols(_ctx(tmp_path, "snmpd_enabled=true"))
        assert _result(tmp_path)["snmp"]["present"] is True

    def test_public_keyword_triggers_snmp(self, tmp_path):
        analyze_protocols(_ctx(tmp_path, "read_community=public"))
        assert _result(tmp_path)["snmp"]["present"] is True

    def test_private_keyword_triggers_snmp(self, tmp_path):
        analyze_protocols(_ctx(tmp_path, "write_community=private"))
        assert _result(tmp_path)["snmp"]["present"] is True

    def test_snmp_case_insensitive(self, tmp_path):
        analyze_protocols(_ctx(tmp_path, "COMMUNITY=PUBLIC"))
        assert _result(tmp_path)["snmp"]["present"] is True

    def test_no_snmp_keywords_absent(self, tmp_path):
        analyze_protocols(_ctx(tmp_path, "mqtt_host=broker.local"))
        assert _result(tmp_path)["snmp"]["present"] is False

    def test_evidence_contains_matching_line(self, tmp_path):
        analyze_protocols(_ctx(tmp_path, "community=public\nunrelated=1"))
        ev = _result(tmp_path)["snmp"]["evidence"]
        assert any("community" in e for e in ev)


# ── UPnP detection ────────────────────────────────────────────────────────────

class TestUpnpDetection:
    def test_upnp_keyword_triggers(self, tmp_path):
        analyze_protocols(_ctx(tmp_path, "enable_upnp=1"))
        assert _result(tmp_path)["upnp"]["present"] is True

    def test_ssdp_keyword_triggers(self, tmp_path):
        analyze_protocols(_ctx(tmp_path, "ssdp_notify=enabled"))
        assert _result(tmp_path)["upnp"]["present"] is True

    def test_igd_keyword_triggers(self, tmp_path):
        analyze_protocols(_ctx(tmp_path, "igd_desc=/upnp/IGD.xml"))
        assert _result(tmp_path)["upnp"]["present"] is True

    def test_upnp_case_insensitive(self, tmp_path):
        analyze_protocols(_ctx(tmp_path, "ENABLE_UPNP=1"))
        assert _result(tmp_path)["upnp"]["present"] is True

    def test_no_upnp_keywords_absent(self, tmp_path):
        analyze_protocols(_ctx(tmp_path, "snmpd_enabled=true"))
        assert _result(tmp_path)["upnp"]["present"] is False


# ── TR-069 detection ──────────────────────────────────────────────────────────

class TestTr069Detection:
    def test_cwmp_keyword_triggers(self, tmp_path):
        analyze_protocols(_ctx(tmp_path, "cwmp_enabled=1"))
        assert _result(tmp_path)["tr069"]["present"] is True

    def test_tr069_keyword_triggers(self, tmp_path):
        analyze_protocols(_ctx(tmp_path, "tr069_acs=https://acs.isp.net"))
        assert _result(tmp_path)["tr069"]["present"] is True

    def test_acs_url_keyword_triggers(self, tmp_path):
        analyze_protocols(_ctx(tmp_path, "acs.url=https://acs.provider.net/"))
        assert _result(tmp_path)["tr069"]["present"] is True

    def test_inform_keyword_triggers(self, tmp_path):
        analyze_protocols(_ctx(tmp_path, "inform_interval=3600"))
        assert _result(tmp_path)["tr069"]["present"] is True

    def test_tr_069_underscore_variant_triggers(self, tmp_path):
        analyze_protocols(_ctx(tmp_path, "tr_069_enable=true"))
        assert _result(tmp_path)["tr069"]["present"] is True

    def test_tr069_case_insensitive(self, tmp_path):
        analyze_protocols(_ctx(tmp_path, "CWMP_ENABLED=1"))
        assert _result(tmp_path)["tr069"]["present"] is True

    def test_no_tr069_keywords_absent(self, tmp_path):
        analyze_protocols(_ctx(tmp_path, "upnp=enabled"))
        assert _result(tmp_path)["tr069"]["present"] is False


# ── MQTT detection ────────────────────────────────────────────────────────────

class TestMqttDetection:
    def test_mqtt_keyword_triggers(self, tmp_path):
        analyze_protocols(_ctx(tmp_path, "mqtt_host=broker.local"))
        assert _result(tmp_path)["mqtt"]["present"] is True

    def test_broker_keyword_triggers(self, tmp_path):
        analyze_protocols(_ctx(tmp_path, "broker_url=tcp://192.168.1.1:1883"))
        assert _result(tmp_path)["mqtt"]["present"] is True

    def test_mqtt_case_insensitive(self, tmp_path):
        analyze_protocols(_ctx(tmp_path, "MQTT_HOST=broker.local"))
        assert _result(tmp_path)["mqtt"]["present"] is True

    def test_no_mqtt_keywords_absent(self, tmp_path):
        analyze_protocols(_ctx(tmp_path, "cwmp_enabled=1"))
        assert _result(tmp_path)["mqtt"]["present"] is False


# ── Protocol independence ─────────────────────────────────────────────────────

class TestProtocolIndependence:
    def test_only_snmp_present_others_absent(self, tmp_path):
        analyze_protocols(_ctx(tmp_path, "snmpd_enabled=true"))
        result = _result(tmp_path)
        assert result["snmp"]["present"] is True
        assert result["upnp"]["present"] is False
        assert result["tr069"]["present"] is False
        assert result["mqtt"]["present"] is False

    def test_only_upnp_present_others_absent(self, tmp_path):
        analyze_protocols(_ctx(tmp_path, "enable_upnp=1"))
        result = _result(tmp_path)
        assert result["upnp"]["present"] is True
        assert result["snmp"]["present"] is False
        assert result["tr069"]["present"] is False
        assert result["mqtt"]["present"] is False

    def test_multiple_protocols_detected_independently(self, tmp_path):
        config = "snmpd_enabled=true\nenable_upnp=1\ncwmp_enabled=1\nmqtt_host=b"
        analyze_protocols(_ctx(tmp_path, config))
        result = _result(tmp_path)
        for proto in ("snmp", "upnp", "tr069", "mqtt"):
            assert result[proto]["present"] is True, f"{proto} should be present"


# ── Evidence cap and off-by-one ───────────────────────────────────────────────

class TestEvidenceCapAndBoundaries:
    def test_single_match_is_present_true(self, tmp_path):
        # off-by-one: exactly one line must be enough for present:true
        analyze_protocols(_ctx(tmp_path, "snmpd_enabled=true"))
        result = _result(tmp_path)
        assert result["snmp"]["present"] is True
        assert len(result["snmp"]["evidence"]) == 1

    def test_exactly_five_matches_all_in_evidence(self, tmp_path):
        # off-by-one: the 5th match must not be truncated
        lines = "\n".join(f"snmpd_host_{i}=10.0.0.{i}" for i in range(5))
        analyze_protocols(_ctx(tmp_path, lines))
        assert len(_result(tmp_path)["snmp"]["evidence"]) == 5

    def test_six_matches_truncated_to_five(self, tmp_path):
        lines = "\n".join(f"snmpd_host_{i}=10.0.0.{i}" for i in range(6))
        analyze_protocols(_ctx(tmp_path, lines))
        assert len(_result(tmp_path)["snmp"]["evidence"]) == 5

    def test_many_matches_truncated_to_five(self, tmp_path):
        lines = "\n".join(f"community_string_{i}=value" for i in range(20))
        analyze_protocols(_ctx(tmp_path, lines))
        assert len(_result(tmp_path)["snmp"]["evidence"]) == 5

    def test_evidence_is_empty_when_not_present(self, tmp_path):
        analyze_protocols(_ctx(tmp_path, "unrelated=value"))
        assert _result(tmp_path)["snmp"]["evidence"] == []

    def test_evidence_preserves_line_content(self, tmp_path):
        analyze_protocols(_ctx(tmp_path, "snmpd_community=secret123"))
        ev = _result(tmp_path)["snmp"]["evidence"]
        assert ev[0] == "snmpd_community=secret123"
