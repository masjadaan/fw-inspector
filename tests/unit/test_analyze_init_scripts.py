"""Unit tests for analyze_init_scripts (system.py).

Strategy: real init script files under rootfs/etc/init.d + real grep.
This exercises the actual regex patterns and the post-processing logic,
not mocked stand-ins.

Coverage:
  - early exit when no init.d / rc.d directories exist
  - service detection: every binary in _KNOWN_SERVICES
  - service detection reads from all three combined sections
  - service NOT in _KNOWN_SERVICES is excluded from detected_services
  - port extraction: regex -p <digits>, deduplication, int type
  - command injection: every pattern (eval, backtick, $(), IFS)
  - injection evidence capped at 5
  - hardcoded credentials: every keyword (password, passwd, secret, etc.)
  - vendor services: every keyword (tdpServer, tddp, cloud, omcid, onemesh, cwmp)
  - vendor services capped at 10
  - firewall rules: every keyword (iptables, ip6tables, nftables, INPUT, ACCEPT, DROP)
  - outbound connections: wget, curl, tftp
  - JSON structure: all keys present, valid types
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from firmware_analysis.analysis.analyzers.context import AnalysisContext
from firmware_analysis.analysis.analyzers.system import analyze_init_scripts


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ctx(tmp_path, init_script: str | None = None, rc_script: str | None = None) -> AnalysisContext:
    """Build a context with optional init.d and/or rc.d scripts."""
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    out = tmp_path / "out"
    out.mkdir()
    if init_script is not None:
        initd = rootfs / "etc" / "init.d"
        initd.mkdir(parents=True)
        (initd / "S01test").write_text(init_script)
    if rc_script is not None:
        rcd = rootfs / "etc" / "rc.d"
        rcd.mkdir(parents=True)
        (rcd / "S01test").write_text(rc_script)
    return AnalysisContext(rootfs=rootfs, out_dir=out, configs=[])


def _result(tmp_path) -> dict:
    return json.loads((tmp_path / "out" / "init_scripts.json").read_text())


# ── Early exit: no init directories ──────────────────────────────────────────

class TestNoInitDirs:
    def test_no_init_dirs_writes_empty_json(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path))
        result = _result(tmp_path)
        assert result["detected_services"] == []
        assert result["explicit_ports"] == []
        assert result["has_command_injection"] is False
        assert result["has_hardcoded_creds"] is False
        assert result["vendor_services"] == []

    def test_no_init_dirs_writes_all_keys(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path))
        result = _result(tmp_path)
        for key in ("detected_services", "explicit_ports", "has_command_injection",
                    "injection_evidence", "has_hardcoded_creds",
                    "vendor_services", "outbound_connections", "has_firewall_rules"):
            assert key in result

    def test_rc_d_used_when_init_d_absent(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, rc_script="dropbear -d /etc/dropbear\n"))
        assert "dropbear" in _result(tmp_path)["detected_services"]


# ── Service detection ─────────────────────────────────────────────────────────

class TestServiceDetection:
    def test_dropbear_detected(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "dropbear -d /etc/dropbear\n"))
        assert "dropbear" in _result(tmp_path)["detected_services"]

    def test_httpd_detected(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "httpd -p 80 -h /www\n"))
        assert "httpd" in _result(tmp_path)["detected_services"]

    def test_telnetd_detected(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "telnetd -l /bin/sh\n"))
        assert "telnetd" in _result(tmp_path)["detected_services"]

    def test_sshd_detected(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "sshd -D\n"))
        assert "sshd" in _result(tmp_path)["detected_services"]

    def test_ftpd_detected(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "ftpd -D\n"))
        assert "ftpd" in _result(tmp_path)["detected_services"]

    def test_tftpd_detected(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "tftpd -l -s /tftpboot\n"))
        assert "tftpd" in _result(tmp_path)["detected_services"]

    def test_snmpd_detected(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "snmpd -c /etc/snmpd.conf\n"))
        assert "snmpd" in _result(tmp_path)["detected_services"]

    def test_upnpd_detected(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "upnpd -D\n"))
        assert "upnpd" in _result(tmp_path)["detected_services"]

    def test_dhcpd_detected(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "dhcpd -cf /etc/dhcpd.conf\n"))
        assert "dhcpd" in _result(tmp_path)["detected_services"]

    def test_dnsd_detected(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "dnsd -c /etc/dns.conf\n"))
        assert "dnsd" in _result(tmp_path)["detected_services"]

    def test_unknown_service_not_in_detected(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "myvendord -D\n"))
        assert "myvendord" not in _result(tmp_path)["detected_services"]

    def test_multiple_services_all_detected(self, tmp_path):
        script = "dropbear -d /etc/dropbear\nhttpd -p 80\ntelnetd -l /bin/sh\n"
        analyze_init_scripts(_ctx(tmp_path, script))
        result = _result(tmp_path)["detected_services"]
        assert "dropbear" in result
        assert "httpd" in result
        assert "telnetd" in result

    def test_no_services_empty_list(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "echo hello\n"))
        assert _result(tmp_path)["detected_services"] == []

    def test_telnetd_detected_from_telnet_debug_section(self, tmp_path):
        # telnetd matches BOTH "Network-Exposed Services" and "Telnet and Debug Interfaces"
        # grep patterns; it must still appear exactly in detected_services (no duplicates)
        analyze_init_scripts(_ctx(tmp_path, "telnetd -l /bin/sh\n"))
        services = _result(tmp_path)["detected_services"]
        assert services.count("telnetd") == 1


# ── Port extraction ───────────────────────────────────────────────────────────

class TestExplicitPorts:
    def test_port_extracted_from_flag(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "httpd -p 80 -h /www\n"))
        assert 80 in _result(tmp_path)["explicit_ports"]

    def test_port_is_int_not_string(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "dropbear -p 22\n"))
        ports = _result(tmp_path)["explicit_ports"]
        assert all(isinstance(p, int) for p in ports)

    def test_multiple_ports_all_captured(self, tmp_path):
        script = "httpd -p 80\ndropbear -p 22\n"
        analyze_init_scripts(_ctx(tmp_path, script))
        ports = _result(tmp_path)["explicit_ports"]
        assert 80 in ports
        assert 22 in ports

    def test_duplicate_port_deduplicated(self, tmp_path):
        script = "httpd -p 8080\nhttpd -p 8080\n"
        analyze_init_scripts(_ctx(tmp_path, script))
        ports = _result(tmp_path)["explicit_ports"]
        assert ports.count(8080) == 1

    def test_no_port_bindings_empty_list(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "httpd -h /www\n"))
        assert _result(tmp_path)["explicit_ports"] == []

    def test_non_standard_port_captured(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "server -p 8443\n"))
        assert 8443 in _result(tmp_path)["explicit_ports"]


# ── Command injection detection ───────────────────────────────────────────────

class TestCommandInjection:
    def test_eval_triggers_injection(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "eval $CONFIG_CMD\n"))
        assert _result(tmp_path)["has_command_injection"] is True

    def test_backtick_triggers_injection(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "CMD=`cat /etc/config`\n"))
        assert _result(tmp_path)["has_command_injection"] is True

    def test_dollar_paren_triggers_injection(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "CMD=$(cat /etc/config)\n"))
        assert _result(tmp_path)["has_command_injection"] is True

    def test_ifs_assignment_triggers_injection(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "IFS=':'\nread a b c <<< $LINE\n"))
        assert _result(tmp_path)["has_command_injection"] is True

    def test_no_injection_patterns_is_false(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "dropbear -d /etc/dropbear\nhttpd -p 80\n"))
        assert _result(tmp_path)["has_command_injection"] is False

    def test_injection_evidence_contains_matching_lines(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "eval $DANGEROUS\n"))
        ev = _result(tmp_path)["injection_evidence"]
        assert len(ev) >= 1
        assert any("eval" in line for line in ev)

    def test_injection_evidence_capped_at_five(self, tmp_path):
        lines = "\n".join(f"eval $VAR_{i}" for i in range(10))
        analyze_init_scripts(_ctx(tmp_path, lines + "\n"))
        assert len(_result(tmp_path)["injection_evidence"]) <= 5


# ── Hardcoded credentials ─────────────────────────────────────────────────────

class TestHardcodedCredentials:
    def test_password_keyword_triggers(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "password=admin123\n"))
        assert _result(tmp_path)["has_hardcoded_creds"] is True

    def test_passwd_keyword_triggers(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "passwd=secret\n"))
        assert _result(tmp_path)["has_hardcoded_creds"] is True

    def test_secret_keyword_triggers(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "secret_key=abc123\n"))
        assert _result(tmp_path)["has_hardcoded_creds"] is True

    def test_token_keyword_triggers(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "api_token=xyzxyz\n"))
        assert _result(tmp_path)["has_hardcoded_creds"] is True

    def test_key_equals_triggers(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "key=supersecret\n"))
        assert _result(tmp_path)["has_hardcoded_creds"] is True

    def test_login_keyword_triggers(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "login=admin\n"))
        assert _result(tmp_path)["has_hardcoded_creds"] is True

    def test_credential_keyword_triggers(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "credential=root:pass\n"))
        assert _result(tmp_path)["has_hardcoded_creds"] is True

    def test_no_credential_keywords_is_false(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "dropbear -d /etc/dropbear\n"))
        assert _result(tmp_path)["has_hardcoded_creds"] is False


# ── Vendor services ───────────────────────────────────────────────────────────

class TestVendorServices:
    def test_tdpserver_detected(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "tdpServer -d\n"))
        assert len(_result(tmp_path)["vendor_services"]) > 0
        assert any("tdpServer" in v for v in _result(tmp_path)["vendor_services"])

    def test_tddp_detected(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "tddp &\n"))
        assert any("tddp" in v for v in _result(tmp_path)["vendor_services"])

    def test_cloud_detected(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "cloud_daemon -c /etc/cloud.cfg\n"))
        assert any("cloud" in v for v in _result(tmp_path)["vendor_services"])

    def test_omcid_detected(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "omcid &\n"))
        assert any("omcid" in v for v in _result(tmp_path)["vendor_services"])

    def test_onemesh_detected(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "onemesh_daemon -d\n"))
        assert any("onemesh" in v for v in _result(tmp_path)["vendor_services"])

    def test_cwmp_detected(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "cwmp -c /etc/cwmp.cfg\n"))
        assert any("cwmp" in v for v in _result(tmp_path)["vendor_services"])

    def test_no_vendor_keywords_empty_list(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "dropbear -d /etc/dropbear\n"))
        assert _result(tmp_path)["vendor_services"] == []

    def test_vendor_services_capped_at_ten(self, tmp_path):
        lines = "\n".join(f"tdpServer -instance {i}" for i in range(15))
        analyze_init_scripts(_ctx(tmp_path, lines + "\n"))
        assert len(_result(tmp_path)["vendor_services"]) <= 10


# ── Firewall rules ────────────────────────────────────────────────────────────

class TestFirewallRules:
    def test_iptables_triggers(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "iptables -A INPUT -j ACCEPT\n"))
        assert _result(tmp_path)["has_firewall_rules"] is True

    def test_ip6tables_triggers(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "ip6tables -P FORWARD DROP\n"))
        assert _result(tmp_path)["has_firewall_rules"] is True

    def test_nftables_triggers(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "nftables -f /etc/nftables.conf\n"))
        assert _result(tmp_path)["has_firewall_rules"] is True

    def test_input_chain_triggers(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "iptables -P INPUT DROP\n"))
        assert _result(tmp_path)["has_firewall_rules"] is True

    def test_no_firewall_keywords_is_false(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "dropbear -d /etc/dropbear\n"))
        assert _result(tmp_path)["has_firewall_rules"] is False


# ── Outbound connections ──────────────────────────────────────────────────────

class TestOutboundConnections:
    def test_wget_detected(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "wget http://update.example.com/fw.bin\n"))
        assert any("wget" in l for l in _result(tmp_path)["outbound_connections"])

    def test_curl_detected(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "curl -o /tmp/fw https://update.example.com/fw\n"))
        assert any("curl" in l for l in _result(tmp_path)["outbound_connections"])

    def test_tftp_detected(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "tftp -g -r firmware.bin 192.168.1.1\n"))
        assert any("tftp" in l for l in _result(tmp_path)["outbound_connections"])

    def test_no_outbound_keywords_empty_list(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "dropbear -d /etc/dropbear\n"))
        assert _result(tmp_path)["outbound_connections"] == []


# ── JSON output structure ─────────────────────────────────────────────────────

class TestOutputStructure:
    def test_all_required_keys_present(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "echo hello\n"))
        result = _result(tmp_path)
        for key in ("detected_services", "explicit_ports", "has_command_injection",
                    "injection_evidence", "has_hardcoded_creds",
                    "vendor_services", "outbound_connections", "has_firewall_rules"):
            assert key in result, f"missing key: {key}"

    def test_detected_services_is_list(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "dropbear -d\n"))
        assert isinstance(_result(tmp_path)["detected_services"], list)

    def test_explicit_ports_is_list(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "httpd -p 80\n"))
        assert isinstance(_result(tmp_path)["explicit_ports"], list)

    def test_has_command_injection_is_bool(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "echo hello\n"))
        assert isinstance(_result(tmp_path)["has_command_injection"], bool)

    def test_has_hardcoded_creds_is_bool(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "echo hello\n"))
        assert isinstance(_result(tmp_path)["has_hardcoded_creds"], bool)

    def test_has_firewall_rules_is_bool(self, tmp_path):
        analyze_init_scripts(_ctx(tmp_path, "echo hello\n"))
        assert isinstance(_result(tmp_path)["has_firewall_rules"], bool)
