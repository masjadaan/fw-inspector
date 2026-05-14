"""Unit tests for firmware_analysis/surface/parsers.py.

Each parser is tested in isolation using tmp_path (pytest's temporary
directory fixture) to write controlled input files.
"""

import json
import pytest
from pathlib import Path

from parsers import (
    _load,
    non_empty_lines,
    parse_architecture,
    parse_capabilities,
    parse_certificate_issues,
    parse_certs,
    parse_credentials,
    parse_dangerous_functions,
    parse_debug,
    parse_hardening,
    parse_init_services,
    parse_ipc,
    parse_nvram,
    parse_protocols,
    parse_setuid,
    parse_shellcheck,
    parse_tls_config_issues,
    parse_users,
    parse_weak_crypto,
    parse_web,
    parse_world_writable,
)


# ── _load ─────────────────────────────────────────────────────────────────────

class TestLoad:
    def test_missing_file_returns_default(self, tmp_path):
        assert _load(tmp_path / "missing.json", []) == []

    def test_missing_file_preserves_default_type(self, tmp_path):
        assert _load(tmp_path / "missing.json", {"k": 1}) == {"k": 1}

    def test_malformed_json_returns_default(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("{not valid json")
        assert _load(f, "fallback") == "fallback"

    def test_valid_json_returns_parsed(self, tmp_path):
        f = tmp_path / "data.json"
        f.write_text(json.dumps({"key": "value"}))
        assert _load(f, {}) == {"key": "value"}

    def test_valid_json_list(self, tmp_path):
        f = tmp_path / "data.json"
        f.write_text(json.dumps([1, 2, 3]))
        assert _load(f, []) == [1, 2, 3]


# ── non_empty_lines ───────────────────────────────────────────────────────────

class TestNonEmptyLines:
    def test_empty_string(self):
        assert non_empty_lines("") == []

    def test_only_blank_lines(self):
        assert non_empty_lines("\n\n\n") == []

    def test_strips_whitespace(self):
        assert non_empty_lines("  hello  \n  world  ") == ["hello", "world"]

    def test_blank_lines_between_content_are_dropped(self):
        assert non_empty_lines("a\n\nb") == ["a", "b"]

    def test_single_line_no_newline(self):
        assert non_empty_lines("only") == ["only"]


# ── parse_users ───────────────────────────────────────────────────────────────

class TestParseUsers:
    def test_missing_file_returns_empty(self, tmp_path):
        assert parse_users(tmp_path) == []

    def test_returns_users_list(self, tmp_path):
        data = {"users": [{"name": "root", "uid": 0}]}
        (tmp_path / "users_groups.json").write_text(json.dumps(data))
        result = parse_users(tmp_path)
        assert result == [{"name": "root", "uid": 0}]

    def test_missing_users_key_returns_empty(self, tmp_path):
        (tmp_path / "users_groups.json").write_text(json.dumps({"groups": []}))
        assert parse_users(tmp_path) == []


# ── parse_setuid ──────────────────────────────────────────────────────────────

class TestParseSetuid:
    def test_missing_file_returns_empty(self, tmp_path):
        assert parse_setuid(tmp_path) == []

    def test_returns_lines(self, tmp_path):
        (tmp_path / "setuid_binaries.txt").write_text("/usr/bin/passwd\n/bin/su\n")
        assert parse_setuid(tmp_path) == ["/usr/bin/passwd", "/bin/su"]

    def test_blank_lines_dropped(self, tmp_path):
        (tmp_path / "setuid_binaries.txt").write_text("/bin/ping\n\n/usr/bin/sudo\n")
        assert parse_setuid(tmp_path) == ["/bin/ping", "/usr/bin/sudo"]


# ── parse_capabilities ────────────────────────────────────────────────────────

class TestParseCapabilities:
    def test_missing_file_returns_empty(self, tmp_path):
        assert parse_capabilities(tmp_path) == []

    def test_parses_single_entry(self, tmp_path):
        (tmp_path / "capabilities.txt").write_text("/usr/bin/ping = cap_net_raw+ep\n")
        result = parse_capabilities(tmp_path)
        assert result == [{"path": "/usr/bin/ping", "capabilities": "cap_net_raw+ep"}]

    def test_parses_multiple_entries(self, tmp_path):
        content = "/bin/a = cap_net_admin+ep\n/bin/b = cap_sys_ptrace+ep\n"
        (tmp_path / "capabilities.txt").write_text(content)
        result = parse_capabilities(tmp_path)
        assert len(result) == 2
        assert result[0]["path"] == "/bin/a"
        assert result[1]["path"] == "/bin/b"

    def test_strips_whitespace_around_path_and_caps(self, tmp_path):
        (tmp_path / "capabilities.txt").write_text("  /bin/foo  =  cap_net_raw+ep  \n")
        result = parse_capabilities(tmp_path)
        assert result[0]["path"] == "/bin/foo"
        assert result[0]["capabilities"] == "cap_net_raw+ep"

    def test_malformed_lines_without_equals_are_skipped(self, tmp_path):
        content = "this line has no equals sign\n/bin/ping = cap_net_raw+ep\n"
        (tmp_path / "capabilities.txt").write_text(content)
        result = parse_capabilities(tmp_path)
        assert len(result) == 1
        assert result[0]["path"] == "/bin/ping"

    def test_empty_file_returns_empty(self, tmp_path):
        (tmp_path / "capabilities.txt").write_text("")
        assert parse_capabilities(tmp_path) == []

    def test_blank_lines_skipped(self, tmp_path):
        content = "\n/bin/ping = cap_net_raw+ep\n\n"
        (tmp_path / "capabilities.txt").write_text(content)
        assert len(parse_capabilities(tmp_path)) == 1


# ── parse_world_writable ──────────────────────────────────────────────────────

class TestParseWorldWritable:
    def test_missing_file_returns_defaults(self, tmp_path):
        result = parse_world_writable(tmp_path)
        assert result == {"files": [], "dirs": [], "setgid": []}

    def test_returns_json_content(self, tmp_path):
        data = {"files": ["/tmp/foo"], "dirs": ["/var/run"], "setgid": []}
        (tmp_path / "world_writable.json").write_text(json.dumps(data))
        assert parse_world_writable(tmp_path) == data


# ── parse_init_services ───────────────────────────────────────────────────────

class TestParseInitServices:
    def test_missing_file_returns_defaults(self, tmp_path):
        result = parse_init_services(tmp_path)
        assert result["detected_services"] == []
        assert result["has_command_injection"] is False
        assert result["has_hardcoded_creds"] is False

    def test_returns_json_content(self, tmp_path):
        data = {
            "detected_services": ["httpd", "dropbear"],
            "explicit_ports": [8080],
            "has_command_injection": True,
            "injection_evidence": ["eval $ARG"],
            "has_hardcoded_creds": True,
            "vendor_services": ["tdpServer"],
            "outbound_connections": [],
            "has_firewall_rules": False,
        }
        (tmp_path / "init_scripts.json").write_text(json.dumps(data))
        result = parse_init_services(tmp_path)
        assert result["detected_services"] == ["httpd", "dropbear"]
        assert result["has_command_injection"] is True
        assert result["vendor_services"] == ["tdpServer"]


# ── parse_web ─────────────────────────────────────────────────────────────────

class TestParseWeb:
    def test_all_missing_returns_defaults(self, tmp_path):
        result = parse_web(tmp_path)
        assert result["httpd_binaries"] == []
        assert result["cgi_scripts"] == []
        assert result["inferred_ports"] == [80]

    def test_web_interface_json_populates_cgi_and_lua(self, tmp_path):
        data = {"cgi_scripts": ["/cgi-bin/login.cgi"], "lua_handlers": ["/handler.lua"], "api_endpoints": []}
        (tmp_path / "web_interface.json").write_text(json.dumps(data))
        result = parse_web(tmp_path)
        assert result["cgi_scripts"] == ["/cgi-bin/login.cgi"]
        assert result["lua_handlers"] == ["/handler.lua"]

    def test_web_server_configs_populates_ports(self, tmp_path):
        data = {"config_files": ["/etc/httpd.conf"], "inferred_ports": [80, 443]}
        (tmp_path / "web_server_configs.json").write_text(json.dumps(data))
        result = parse_web(tmp_path)
        assert result["inferred_ports"] == [80, 443]
        assert result["config_files"] == ["/etc/httpd.conf"]

    def test_inferred_ports_defaults_to_80_when_key_missing(self, tmp_path):
        (tmp_path / "web_server_configs.json").write_text(json.dumps({"config_files": []}))
        assert parse_web(tmp_path)["inferred_ports"] == [80]

    def test_httpd_binaries_json_populated(self, tmp_path):
        data = {"binaries": ["/usr/sbin/httpd"]}
        (tmp_path / "httpd_binaries.json").write_text(json.dumps(data))
        assert parse_web(tmp_path)["httpd_binaries"] == ["/usr/sbin/httpd"]


# ── parse_protocols ───────────────────────────────────────────────────────────

class TestParseProtocols:
    def test_missing_file_returns_four_protocol_defaults(self, tmp_path):
        result = parse_protocols(tmp_path)
        for proto in ("snmp", "upnp", "tr069", "mqtt"):
            assert proto in result
            assert result[proto]["present"] is False

    def test_returns_json_content(self, tmp_path):
        data = {
            "snmp": {"present": True, "evidence": ["snmpd binary found"]},
            "upnp": {"present": False, "evidence": []},
            "tr069": {"present": False, "evidence": []},
            "mqtt": {"present": False, "evidence": []},
        }
        (tmp_path / "protocols.json").write_text(json.dumps(data))
        result = parse_protocols(tmp_path)
        assert result["snmp"]["present"] is True
        assert result["snmp"]["evidence"] == ["snmpd binary found"]


# ── parse_credentials ─────────────────────────────────────────────────────────

class TestParseCredentials:
    def test_all_missing_returns_empty_defaults(self, tmp_path):
        result = parse_credentials(tmp_path)
        assert result == {
            "hardcoded_in_configs": [],
            "default_credentials": [],
            "ssh_key_files": [],
            "cloud_endpoints": [],
        }

    def test_credentials_json_populates_hardcoded_and_cloud(self, tmp_path):
        data = {"hardcoded_in_configs": ["/etc/config"], "cloud_endpoints": ["https://example.com"]}
        (tmp_path / "credentials.json").write_text(json.dumps(data))
        result = parse_credentials(tmp_path)
        assert result["hardcoded_in_configs"] == ["/etc/config"]
        assert result["cloud_endpoints"] == ["https://example.com"]

    def test_default_credentials_json_populates_defaults(self, tmp_path):
        (tmp_path / "default_credentials.json").write_text(json.dumps({"defaults": ["admin:admin"]}))
        assert parse_credentials(tmp_path)["default_credentials"] == ["admin:admin"]

    def test_ssh_keys_json_populates_key_files(self, tmp_path):
        (tmp_path / "ssh_keys.json").write_text(json.dumps({"files": ["/etc/dropbear/key"]}))
        assert parse_credentials(tmp_path)["ssh_key_files"] == ["/etc/dropbear/key"]

    def test_merges_all_three_sources(self, tmp_path):
        (tmp_path / "credentials.json").write_text(
            json.dumps({"hardcoded_in_configs": ["/etc/a"], "cloud_endpoints": ["https://x"]})
        )
        (tmp_path / "default_credentials.json").write_text(json.dumps({"defaults": ["root:root"]}))
        (tmp_path / "ssh_keys.json").write_text(json.dumps({"files": ["/etc/dropbear/key"]}))
        result = parse_credentials(tmp_path)
        assert result["hardcoded_in_configs"] == ["/etc/a"]
        assert result["default_credentials"] == ["root:root"]
        assert result["ssh_key_files"] == ["/etc/dropbear/key"]
        assert result["cloud_endpoints"] == ["https://x"]


# ── parse_weak_crypto ─────────────────────────────────────────────────────────

class TestParseWeakCrypto:
    def test_missing_returns_empty(self, tmp_path):
        assert parse_weak_crypto(tmp_path) == []

    def test_returns_list(self, tmp_path):
        data = [{"algorithm": "MD5", "context": "/bin/login"}]
        (tmp_path / "weak_crypto.json").write_text(json.dumps(data))
        assert parse_weak_crypto(tmp_path) == data


# ── parse_debug ───────────────────────────────────────────────────────────────

class TestParseDebug:
    def test_missing_returns_empty(self, tmp_path):
        assert parse_debug(tmp_path) == []

    def test_returns_list(self, tmp_path):
        data = [{"context": "Debug Files", "items": ["/web/debug.htm"]}]
        (tmp_path / "debug_artifacts.json").write_text(json.dumps(data))
        assert parse_debug(tmp_path) == data


# ── parse_ipc ─────────────────────────────────────────────────────────────────

class TestParseIpc:
    def test_missing_returns_defaults(self, tmp_path):
        result = parse_ipc(tmp_path)
        assert result == {"socket_files": [], "references": []}

    def test_returns_json_content(self, tmp_path):
        data = {"socket_files": ["/var/run/ubus.sock"], "references": []}
        (tmp_path / "unix_sockets.json").write_text(json.dumps(data))
        assert parse_ipc(tmp_path) == data


# ── parse_certs ───────────────────────────────────────────────────────────────

class TestParseCerts:
    def test_missing_returns_defaults(self, tmp_path):
        result = parse_certs(tmp_path)
        assert result == {"files": [], "embedded_in_binaries": []}

    def test_returns_json_content(self, tmp_path):
        data = {"files": ["/etc/ssl/ca.pem"], "embedded_in_binaries": ["httpd"]}
        (tmp_path / "certificates_keys.json").write_text(json.dumps(data))
        assert parse_certs(tmp_path) == data


# ── parse_architecture ────────────────────────────────────────────────────────

class TestParseArchitecture:
    def test_missing_returns_defaults(self, tmp_path):
        result = parse_architecture(tmp_path)
        assert result["arch"] == "unknown"
        assert result["bits"] == 0
        assert result["confidence"] == 0.0

    def test_returns_json_content(self, tmp_path):
        data = {"arch": "mips", "bits": 32, "endianness": "big",
                "endianness_short": "BE", "confidence": 0.95, "elf_count": 42}
        (tmp_path / "architecture.json").write_text(json.dumps(data))
        result = parse_architecture(tmp_path)
        assert result["arch"] == "mips"
        assert result["bits"] == 32


# ── parse_hardening ───────────────────────────────────────────────────────────

class TestParseHardening:
    def test_missing_returns_defaults(self, tmp_path):
        result = parse_hardening(tmp_path)
        assert result == {"summary": {}, "binaries": []}

    def test_returns_json_content(self, tmp_path):
        data = {"summary": {"nx": 10}, "binaries": [{"name": "httpd", "nx": True}]}
        (tmp_path / "hardening.json").write_text(json.dumps(data))
        assert parse_hardening(tmp_path) == data


# ── parse_shellcheck ──────────────────────────────────────────────────────────

class TestParseShellcheck:
    _default = {"total": 0, "by_level": {}, "by_file": {}}

    def test_missing_returns_defaults(self, tmp_path):
        assert parse_shellcheck(tmp_path) == self._default

    def test_non_list_json_returns_defaults(self, tmp_path):
        (tmp_path / "shellcheck.json").write_text(json.dumps({"error": "something"}))
        assert parse_shellcheck(tmp_path) == self._default

    def test_single_finding(self, tmp_path):
        data = [{"file": "/etc/init.sh", "code": 2086, "level": "warning",
                 "message": "Double quote to prevent globbing", "line": 5}]
        (tmp_path / "shellcheck.json").write_text(json.dumps(data))
        result = parse_shellcheck(tmp_path)
        assert result["total"] == 1
        assert result["by_level"] == {"warning": 1}
        assert "/etc/init.sh" in result["by_file"]
        assert result["by_file"]["/etc/init.sh"][0]["code"] == 2086

    def test_duplicate_file_code_deduplicated_in_by_file(self, tmp_path):
        # Same (file, code) pair twice — by_file gets one entry, total counts both
        finding = {"file": "/etc/init.sh", "code": 2086, "level": "warning",
                   "message": "msg", "line": 5}
        (tmp_path / "shellcheck.json").write_text(json.dumps([finding, finding]))
        result = parse_shellcheck(tmp_path)
        assert result["total"] == 2
        assert len(result["by_file"]["/etc/init.sh"]) == 1

    def test_by_level_counts_all_including_duplicates(self, tmp_path):
        finding = {"file": "/etc/rc", "code": 2086, "level": "error", "message": "m", "line": 1}
        (tmp_path / "shellcheck.json").write_text(json.dumps([finding, finding]))
        result = parse_shellcheck(tmp_path)
        assert result["by_level"]["error"] == 2

    def test_multiple_files_each_get_own_entry(self, tmp_path):
        data = [
            {"file": "/etc/a.sh", "code": 1, "level": "error", "message": "e", "line": 1},
            {"file": "/etc/b.sh", "code": 2, "level": "warning", "message": "w", "line": 2},
        ]
        (tmp_path / "shellcheck.json").write_text(json.dumps(data))
        result = parse_shellcheck(tmp_path)
        assert "/etc/a.sh" in result["by_file"]
        assert "/etc/b.sh" in result["by_file"]
        assert result["total"] == 2

    def test_missing_optional_fields_use_defaults(self, tmp_path):
        # A finding with only a file key — all other fields missing
        (tmp_path / "shellcheck.json").write_text(json.dumps([{"file": "/etc/x.sh"}]))
        result = parse_shellcheck(tmp_path)
        entry = result["by_file"]["/etc/x.sh"][0]
        assert entry["code"] == ""
        assert entry["level"] == ""
        assert entry["message"] == ""
        assert entry["line"] == 0


# ── parse_nvram ───────────────────────────────────────────────────────────────

class TestParseNvram:
    def test_missing_returns_empty(self, tmp_path):
        assert parse_nvram(tmp_path) == []

    def test_returns_evidence_list(self, tmp_path):
        data = {"evidence": ["nvram get http_passwd", "nvram set key=val"]}
        (tmp_path / "nvram.json").write_text(json.dumps(data))
        assert parse_nvram(tmp_path) == data["evidence"]

    def test_missing_evidence_key_returns_empty(self, tmp_path):
        (tmp_path / "nvram.json").write_text(json.dumps({"other": []}))
        assert parse_nvram(tmp_path) == []


# ── parse_dangerous_functions ─────────────────────────────────────────────────

class TestParseDangerousFunctions:
    def test_missing_returns_empty_list(self, tmp_path):
        assert parse_dangerous_functions(tmp_path) == []

    def test_returns_list_as_is(self, tmp_path):
        data = [
            {"binary": "usr/bin/httpd", "functions": ["gets", "strcpy"]},
            {"binary": "usr/sbin/telnetd", "functions": ["sprintf"]},
        ]
        (tmp_path / "dangerous_functions.json").write_text(json.dumps(data))
        assert parse_dangerous_functions(tmp_path) == data

    def test_empty_list_in_file_returns_empty(self, tmp_path):
        (tmp_path / "dangerous_functions.json").write_text("[]")
        assert parse_dangerous_functions(tmp_path) == []

    def test_malformed_json_returns_empty(self, tmp_path):
        (tmp_path / "dangerous_functions.json").write_text("{not valid json")
        assert parse_dangerous_functions(tmp_path) == []


class TestParseCertificateIssues:
    def test_missing_returns_empty_list(self, tmp_path):
        assert parse_certificate_issues(tmp_path) == []

    def test_returns_list_as_is(self, tmp_path):
        data = [
            {"file": "etc/ssl/ca.pem", "flags": ["expired"], "subject": "CN=test",
             "issuer": "CN=test", "not_after": "2020-01-01", "key_type": "RSA", "key_bits": 2048},
            {"file": "etc/ssl/weak.pem", "flags": ["weak-key (RSA 1024-bit)"], "subject": "CN=weak",
             "issuer": "CN=ca", "not_after": "2030-01-01", "key_type": "RSA", "key_bits": 1024},
        ]
        (tmp_path / "certificate_issues.json").write_text(json.dumps(data))
        assert parse_certificate_issues(tmp_path) == data

    def test_empty_list_in_file_returns_empty(self, tmp_path):
        (tmp_path / "certificate_issues.json").write_text("[]")
        assert parse_certificate_issues(tmp_path) == []

    def test_malformed_json_returns_empty(self, tmp_path):
        (tmp_path / "certificate_issues.json").write_text("{not valid json")
        assert parse_certificate_issues(tmp_path) == []


class TestParseTlsConfigIssues:
    def test_missing_returns_empty_list(self, tmp_path):
        assert parse_tls_config_issues(tmp_path) == []

    def test_returns_list_as_is(self, tmp_path):
        data = [
            {"file": "etc/httpd.conf", "line": 12, "text": "SSLv2", "issue": "SSLv2 enabled", "cve_note": "CVE-2016-0800"},
            {"file": "etc/nginx.conf", "line": 7,  "text": "RC4",   "issue": "RC4 cipher",    "cve_note": "CVE-2015-2808"},
        ]
        (tmp_path / "tls_config_issues.json").write_text(json.dumps(data))
        assert parse_tls_config_issues(tmp_path) == data

    def test_empty_list_in_file_returns_empty(self, tmp_path):
        (tmp_path / "tls_config_issues.json").write_text("[]")
        assert parse_tls_config_issues(tmp_path) == []

    def test_malformed_json_returns_empty(self, tmp_path):
        (tmp_path / "tls_config_issues.json").write_text("{not valid json")
        assert parse_tls_config_issues(tmp_path) == []
