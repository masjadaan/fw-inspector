"""Fixture-based integration test against the Archer A5V6 analysis output.

Runs the full parse → build_entry_points → infer_attack_paths pipeline
against real analyzer output in analysis/Archer_A5V6/raw/.

These tests pin the known findings of that firmware so any regression in
a parser or inferrer that silently changes the output will be caught here.
"""

import pytest
from pathlib import Path

from parsers import (
    parse_architecture,
    parse_capabilities,
    parse_certs,
    parse_credentials,
    parse_debug,
    parse_init_services,
    parse_protocols,
    parse_setuid,
    parse_shellcheck,
    parse_users,
    parse_weak_crypto,
    parse_web,
    parse_world_writable,
)
from attack_paths import build_entry_points, infer_attack_paths

FIXTURE = Path(__file__).parent.parent.parent / "analysis" / "Archer_A5V6" / "raw"


@pytest.fixture(scope="module")
def parsed():
    """Parse all fixture files once and return a dict of results."""
    assert FIXTURE.is_dir(), f"Fixture directory missing: {FIXTURE}"
    return {
        "users":         parse_users(FIXTURE),
        "setuid":        parse_setuid(FIXTURE),
        "caps":          parse_capabilities(FIXTURE),
        "world_writable": parse_world_writable(FIXTURE),
        "init":          parse_init_services(FIXTURE),
        "web":           parse_web(FIXTURE),
        "protocols":     parse_protocols(FIXTURE),
        "credentials":   parse_credentials(FIXTURE),
        "weak_crypto":   parse_weak_crypto(FIXTURE),
        "debug":         parse_debug(FIXTURE),
        "certs":         parse_certs(FIXTURE),
        "arch":          parse_architecture(FIXTURE),
        "shellcheck":    parse_shellcheck(FIXTURE),
    }


@pytest.fixture(scope="module")
def entry_points(parsed):
    return build_entry_points(parsed["init"], parsed["web"], parsed["protocols"])


@pytest.fixture(scope="module")
def attack_paths(parsed, entry_points):
    return infer_attack_paths(
        entry_points=entry_points,
        init=parsed["init"],
        web=parsed["web"],
        users=parsed["users"],
        credentials=parsed["credentials"],
        privesc={
            "setuid_binaries": parsed["setuid"],
            "world_writable":  parsed["world_writable"],
        },
        protocols=parsed["protocols"],
        weak_crypto=parsed["weak_crypto"],
        debug=parsed["debug"],
        certs=parsed["certs"],
    )


# ── Parser assertions ─────────────────────────────────────────────────────────

class TestArcherA5Parsers:
    def test_architecture_is_mips_32bit(self, parsed):
        arch = parsed["arch"]
        assert arch["arch"] == "MIPS"
        assert arch["bits"] == 32
        assert arch["endianness"] == "little-endian"

    def test_init_has_dropbear_service(self, parsed):
        assert "dropbear" in parsed["init"]["detected_services"]

    def test_init_has_hardcoded_creds(self, parsed):
        assert parsed["init"]["has_hardcoded_creds"] is True

    def test_init_has_no_command_injection(self, parsed):
        assert parsed["init"]["has_command_injection"] is False

    def test_no_users_in_passwd(self, parsed):
        assert parsed["users"] == []

    def test_no_setuid_binaries(self, parsed):
        assert parsed["setuid"] == []

    def test_no_capabilities(self, parsed):
        assert parsed["caps"] == []

    def test_no_world_writable_files_or_dirs(self, parsed):
        ww = parsed["world_writable"]
        assert ww["files"] == []
        assert ww["dirs"] == []

    def test_httpd_binary_present(self, parsed):
        assert len(parsed["web"]["httpd_binaries"]) == 1
        assert "httpd" in parsed["web"]["httpd_binaries"][0]

    def test_no_cgi_scripts(self, parsed):
        assert parsed["web"]["cgi_scripts"] == []

    def test_web_inferred_port_is_80(self, parsed):
        assert 80 in parsed["web"]["inferred_ports"]

    def test_no_protocols_active(self, parsed):
        for proto in ("snmp", "upnp", "tr069", "mqtt"):
            assert parsed["protocols"][proto]["present"] is False

    def test_no_hardcoded_in_configs(self, parsed):
        assert parsed["credentials"]["hardcoded_in_configs"] == []

    def test_default_credentials_present(self, parsed):
        assert len(parsed["credentials"]["default_credentials"]) > 0

    def test_no_cloud_endpoints(self, parsed):
        assert parsed["credentials"]["cloud_endpoints"] == []

    def test_weak_crypto_detected(self, parsed):
        assert len(parsed["weak_crypto"]) > 0

    def test_weak_crypto_includes_des_or_rc4(self, parsed):
        all_evidence = " ".join(
            e for item in parsed["weak_crypto"] for e in item.get("evidence", [])
        )
        assert any(algo in all_evidence for algo in ("DES", "RC4", "MD5"))

    def test_debug_artifacts_present(self, parsed):
        items = [i for f in parsed["debug"] for i in f.get("items", [])]
        assert len(items) > 0

    def test_no_cert_files_on_filesystem(self, parsed):
        assert parsed["certs"]["files"] == []

    def test_cert_embedded_in_binary(self, parsed):
        assert len(parsed["certs"]["embedded_in_binaries"]) > 0

    def test_shellcheck_finds_no_issues(self, parsed):
        # Archer A5 has no shell scripts picked up by shellcheck
        assert parsed["shellcheck"]["total"] == 0


# ── Entry point assertions ────────────────────────────────────────────────────

class TestArcherA5EntryPoints:
    def test_ssh_entry_point_from_dropbear(self, entry_points):
        ssh_eps = [e for e in entry_points if e["type"] == "ssh"]
        assert len(ssh_eps) == 1
        assert ssh_eps[0]["port"] == 22
        assert ssh_eps[0]["protocol"] == "tcp"
        assert ssh_eps[0]["source"] == "init_scripts"

    def test_http_entry_point_from_httpd_binary(self, entry_points):
        http_eps = [e for e in entry_points if e["type"] == "http"]
        assert len(http_eps) == 1
        assert http_eps[0]["port"] == 80
        assert http_eps[0]["source"] == "web_server_config"

    def test_no_telnet_entry_point(self, entry_points):
        assert not any(e["type"] == "telnet" for e in entry_points)

    def test_no_protocol_entry_points(self, entry_points):
        assert not any(e["source"] == "protocols_config" for e in entry_points)

    def test_exactly_two_entry_points(self, entry_points):
        assert len(entry_points) == 2


# ── Attack path assertions ────────────────────────────────────────────────────

class TestArcherA5AttackPaths:
    def _ids(self, attack_paths):
        return {p["id"] for p in attack_paths}

    # Paths that MUST fire given this firmware's findings
    def test_http_admin_fires(self, attack_paths):
        assert "ap-http-admin" in self._ids(attack_paths)

    def test_default_creds_fires(self, attack_paths):
        assert "ap-default-creds" in self._ids(attack_paths)

    def test_cert_extraction_fires(self, attack_paths):
        assert "ap-cert-extraction" in self._ids(attack_paths)

    def test_weak_crypto_fires(self, attack_paths):
        assert "ap-weak-crypto" in self._ids(attack_paths)

    def test_debug_interface_fires(self, attack_paths):
        assert "ap-debug" in self._ids(attack_paths)

    # Paths that must NOT fire — absence is as important as presence
    def test_telnet_does_not_fire(self, attack_paths):
        assert "ap-telnet" not in self._ids(attack_paths)

    def test_cgi_injection_does_not_fire(self, attack_paths):
        assert "ap-cgi-injection" not in self._ids(attack_paths)

    def test_snmp_does_not_fire(self, attack_paths):
        assert "ap-snmp" not in self._ids(attack_paths)

    def test_upnp_does_not_fire(self, attack_paths):
        assert "ap-upnp" not in self._ids(attack_paths)

    def test_tr069_does_not_fire(self, attack_paths):
        assert "ap-tr069" not in self._ids(attack_paths)

    def test_setuid_does_not_fire(self, attack_paths):
        assert "ap-setuid" not in self._ids(attack_paths)

    def test_world_writable_does_not_fire(self, attack_paths):
        assert "ap-world-writable" not in self._ids(attack_paths)

    def test_static_creds_does_not_fire(self, attack_paths):
        assert "ap-static-creds" not in self._ids(attack_paths)

    def test_update_mitm_does_not_fire(self, attack_paths):
        assert "ap-update-mitm" not in self._ids(attack_paths)

    def test_vendor_backdoor_does_not_fire(self, attack_paths):
        assert "ap-vendor-backdoor" not in self._ids(attack_paths)

    # Structural checks on fired paths
    def test_all_fired_paths_have_required_keys(self, attack_paths):
        for path in attack_paths:
            for key in ("id", "title", "severity", "description", "entry_point", "steps", "evidence"):
                assert key in path, f"Path {path.get('id')} missing key: {key}"

    def test_no_empty_evidence_lists(self, attack_paths):
        for path in attack_paths:
            assert len(path["evidence"]) > 0, f"Path {path['id']} has empty evidence"

    def test_no_empty_steps_lists(self, attack_paths):
        for path in attack_paths:
            assert len(path["steps"]) > 0, f"Path {path['id']} has empty steps"
