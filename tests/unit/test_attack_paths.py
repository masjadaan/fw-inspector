"""Unit tests for firmware_analysis/surface/attack_paths.py.

Each _ap_* inferrer is tested in isolation: once confirming it returns None
when its guard condition is not met, and once confirming it fires with the
correct id/severity when the condition is met.

build_entry_points is tested for source routing, port/protocol assignment,
and deduplication.
"""

import pytest
from attack_paths import (
    _ap_cert_extraction,
    _ap_cert_issues,
    _ap_cgi_injection,
    _ap_debug,
    _ap_default_creds,
    _ap_http_admin,
    _ap_memory_unsafe_binaries,
    _ap_setuid,
    _ap_snmp,
    _ap_static_creds,
    _ap_telnet,
    _ap_tls_config,
    _ap_tr069,
    _ap_update_mitm,
    _ap_upnp,
    _ap_vendor_backdoor,
    _ap_weak_crypto,
    _ap_world_writable,
    build_entry_points,
    infer_attack_paths,
)


# ── Minimal builders ──────────────────────────────────────────────────────────
# These produce the smallest valid inputs each function needs.

def _init(**overrides):
    base = {
        "detected_services": [],
        "explicit_ports": [],
        "has_command_injection": False,
        "injection_evidence": [],
        "has_hardcoded_creds": False,
        "vendor_services": [],
        "outbound_connections": [],
        "has_firewall_rules": False,
    }
    return {**base, **overrides}


def _web(**overrides):
    base = {
        "httpd_binaries": [],
        "cgi_scripts": [],
        "lua_handlers": [],
        "api_endpoints": [],
        "config_files": [],
        "inferred_ports": [80],
    }
    return {**base, **overrides}


def _protocols(**overrides):
    base = {p: {"present": False, "evidence": []} for p in ("snmp", "upnp", "tr069", "mqtt")}
    for k, v in overrides.items():
        base[k] = v
    return base


def _credentials(**overrides):
    base = {
        "hardcoded_in_configs": [],
        "default_credentials": [],
        "ssh_key_files": [],
        "cloud_endpoints": [],
    }
    return {**base, **overrides}


def _privesc(**overrides):
    base = {"setuid_binaries": [], "world_writable": {"files": [], "dirs": [], "setgid": []}}
    return {**base, **overrides}


def _certs(**overrides):
    base = {"files": [], "embedded_in_binaries": []}
    return {**base, **overrides}


def _ep(type_, port, protocol):
    return {"type": type_, "port": port, "protocol": protocol,
            "binary": None, "interface": "unknown", "source": "test"}


# ── build_entry_points ────────────────────────────────────────────────────────

class TestBuildEntryPoints:
    def test_known_service_adds_entry(self):
        eps = build_entry_points(_init(detected_services=["httpd"]), _web(), _protocols())
        # httpd also triggers the web path, so filter by source
        init_eps = [e for e in eps if e["source"] == "init_scripts"]
        assert any(e["port"] == 80 and e["protocol"] == "tcp" and e["type"] == "http"
                   for e in init_eps)

    def test_unknown_service_is_ignored(self):
        eps = build_entry_points(_init(detected_services=["unknownd"]), _web(), _protocols())
        assert all(e["source"] != "init_scripts" for e in eps)

    def test_dropbear_maps_to_ssh_port_22(self):
        eps = build_entry_points(_init(detected_services=["dropbear"]), _web(), _protocols())
        init_eps = [e for e in eps if e["source"] == "init_scripts"]
        assert len(init_eps) == 1
        assert init_eps[0]["port"] == 22
        assert init_eps[0]["type"] == "ssh"

    def test_telnetd_maps_to_port_23(self):
        eps = build_entry_points(_init(detected_services=["telnetd"]), _web(), _protocols())
        init_eps = [e for e in eps if e["source"] == "init_scripts"]
        assert init_eps[0]["port"] == 23
        assert init_eps[0]["type"] == "telnet"

    def test_web_port_added_when_httpd_binaries_present(self):
        eps = build_entry_points(_init(), _web(httpd_binaries=["/sbin/httpd"]), _protocols())
        web_eps = [e for e in eps if e["source"] == "web_server_config"]
        assert len(web_eps) == 1
        assert web_eps[0]["port"] == 80
        assert web_eps[0]["binary"] == "/sbin/httpd"

    def test_web_port_added_when_cgi_scripts_present(self):
        eps = build_entry_points(_init(), _web(cgi_scripts=["/cgi-bin/login.cgi"]), _protocols())
        assert any(e["source"] == "web_server_config" for e in eps)

    def test_web_port_not_added_when_no_binaries_or_handlers(self):
        eps = build_entry_points(_init(), _web(), _protocols())
        assert not any(e["source"] == "web_server_config" for e in eps)

    def test_port_443_gets_type_https(self):
        eps = build_entry_points(
            _init(),
            _web(inferred_ports=[443], httpd_binaries=["/sbin/httpd"]),
            _protocols(),
        )
        web_eps = [e for e in eps if e["source"] == "web_server_config"]
        assert web_eps[0]["type"] == "https"

    def test_web_binary_defaults_to_httpd_string_when_no_binaries(self):
        eps = build_entry_points(_init(), _web(cgi_scripts=["/cgi.sh"]), _protocols())
        web_eps = [e for e in eps if e["source"] == "web_server_config"]
        assert web_eps[0]["binary"] == "httpd"

    def test_snmp_protocol_present_adds_entry(self):
        eps = build_entry_points(
            _init(), _web(),
            _protocols(snmp={"present": True, "evidence": []}),
        )
        proto_eps = [e for e in eps if e["source"] == "protocols_config"]
        assert len(proto_eps) == 1
        assert proto_eps[0]["port"] == 161
        assert proto_eps[0]["protocol"] == "udp"

    def test_protocol_not_present_not_added(self):
        eps = build_entry_points(_init(), _web(), _protocols())
        assert not any(e["source"] == "protocols_config" for e in eps)

    def test_dedup_same_port_proto_from_two_services(self):
        # sshd and dropbear both map to port 22/tcp — only one entry should appear
        eps = build_entry_points(
            _init(detected_services=["sshd", "dropbear"]), _web(), _protocols()
        )
        port_22 = [e for e in eps if e["port"] == 22]
        assert len(port_22) == 1

    def test_explicit_port_not_in_seen_is_added(self):
        eps = build_entry_points(_init(explicit_ports=[8080]), _web(), _protocols())
        explicit_eps = [e for e in eps if e["source"] == "init_script_port_binding"]
        assert len(explicit_eps) == 1
        assert explicit_eps[0]["port"] == 8080
        assert explicit_eps[0]["type"] == "unknown"

    def test_explicit_port_already_seen_is_not_duplicated(self):
        # httpd adds port 80; explicit_ports=[80] should not add a second entry
        eps = build_entry_points(
            _init(detected_services=["httpd"], explicit_ports=[80]),
            _web(httpd_binaries=["/sbin/httpd"]),
            _protocols(),
        )
        port_80 = [e for e in eps if e["port"] == 80]
        assert len(port_80) == 1

    def test_empty_inputs_returns_empty_list(self):
        assert build_entry_points(_init(), _web(), _protocols()) == []


# ── _ap_telnet ────────────────────────────────────────────────────────────────

class TestApTelnet:
    def test_no_telnet_returns_none(self):
        assert _ap_telnet(entry_points=[_ep("http", 80, "tcp")]) is None

    def test_no_entry_points_returns_none(self):
        assert _ap_telnet(entry_points=[]) is None

    def test_telnet_entry_point_fires(self):
        result = _ap_telnet(entry_points=[_ep("telnet", 23, "tcp")])
        assert result is not None
        assert result["id"] == "ap-telnet"
        assert result["severity"] == "critical"


# ── _ap_http_admin ────────────────────────────────────────────────────────────

class TestApHttpAdmin:
    def test_no_http_entry_points_returns_none(self):
        assert _ap_http_admin(entry_points=[], web=_web()) is None

    def test_http_entry_point_fires(self):
        result = _ap_http_admin(
            entry_points=[_ep("http", 80, "tcp")],
            web=_web(httpd_binaries=["/sbin/httpd"]),
        )
        assert result is not None
        assert result["id"] == "ap-http-admin"
        assert result["severity"] == "high"

    def test_https_entry_point_also_fires(self):
        result = _ap_http_admin(
            entry_points=[_ep("https", 443, "tcp")],
            web=_web(httpd_binaries=["/sbin/httpd"]),
        )
        assert result is not None

    def test_cgi_count_appears_in_evidence(self):
        result = _ap_http_admin(
            entry_points=[_ep("http", 80, "tcp")],
            web=_web(httpd_binaries=["/sbin/httpd"], cgi_scripts=["/a.cgi", "/b.cgi"]),
        )
        assert any("2 CGI" in e for e in result["evidence"])

    def test_lua_count_appears_in_evidence(self):
        result = _ap_http_admin(
            entry_points=[_ep("http", 80, "tcp")],
            web=_web(httpd_binaries=["/sbin/httpd"], lua_handlers=["/h.lua"]),
        )
        assert any("1 Lua" in e for e in result["evidence"])

    def test_entry_point_port_reflected_in_step(self):
        result = _ap_http_admin(
            entry_points=[_ep("http", 8080, "tcp")],
            web=_web(httpd_binaries=["/sbin/httpd"]),
        )
        assert any("8080" in step for step in result["steps"])


# ── _ap_cgi_injection ─────────────────────────────────────────────────────────

class TestApCgiInjection:
    def test_no_injection_returns_none(self):
        assert _ap_cgi_injection(
            init=_init(has_command_injection=False, cgi_scripts=["/a.cgi"]),
            web=_web(cgi_scripts=["/a.cgi"]),
        ) is None

    def test_injection_without_handlers_returns_none(self):
        assert _ap_cgi_injection(
            init=_init(has_command_injection=True),
            web=_web(),
        ) is None

    def test_injection_with_cgi_fires(self):
        result = _ap_cgi_injection(
            init=_init(has_command_injection=True, injection_evidence=["eval $ARG"]),
            web=_web(cgi_scripts=["/login.cgi"]),
        )
        assert result is not None
        assert result["id"] == "ap-cgi-injection"
        assert result["severity"] == "critical"

    def test_injection_with_lua_fires(self):
        result = _ap_cgi_injection(
            init=_init(has_command_injection=True, injection_evidence=["$(cmd)"]),
            web=_web(lua_handlers=["/handler.lua"]),
        )
        assert result is not None


# ── _ap_default_creds ─────────────────────────────────────────────────────────

class TestApDefaultCreds:
    def test_no_creds_returns_none(self):
        assert _ap_default_creds(credentials=_credentials(), init=_init()) is None

    def test_default_credentials_fires(self):
        result = _ap_default_creds(
            credentials=_credentials(default_credentials=["admin:admin"]),
            init=_init(),
        )
        assert result is not None
        assert result["id"] == "ap-default-creds"
        assert result["severity"] == "high"

    def test_hardcoded_creds_in_init_fires(self):
        result = _ap_default_creds(
            credentials=_credentials(),
            init=_init(has_hardcoded_creds=True),
        )
        assert result is not None

    def test_both_sources_fire(self):
        result = _ap_default_creds(
            credentials=_credentials(default_credentials=["root:root"]),
            init=_init(has_hardcoded_creds=True),
        )
        assert result is not None
        assert len(result["evidence"]) == 2


# ── _ap_static_creds ──────────────────────────────────────────────────────────

class TestApStaticCreds:
    def test_empty_hardcoded_returns_none(self):
        assert _ap_static_creds(credentials=_credentials()) is None

    def test_hardcoded_in_configs_fires(self):
        result = _ap_static_creds(
            credentials=_credentials(hardcoded_in_configs=["/etc/config.cfg"]),
        )
        assert result is not None
        assert result["id"] == "ap-static-creds"
        assert result["severity"] == "high"


# ── _ap_tr069 ─────────────────────────────────────────────────────────────────

class TestApTr069:
    def test_not_present_returns_none(self):
        assert _ap_tr069(protocols=_protocols()) is None

    def test_present_fires(self):
        result = _ap_tr069(protocols=_protocols(tr069={"present": True, "evidence": []}))
        assert result is not None
        assert result["id"] == "ap-tr069"
        assert result["severity"] == "high"


# ── _ap_upnp ──────────────────────────────────────────────────────────────────

class TestApUpnp:
    def test_not_present_returns_none(self):
        assert _ap_upnp(protocols=_protocols()) is None

    def test_present_fires(self):
        result = _ap_upnp(protocols=_protocols(upnp={"present": True, "evidence": []}))
        assert result is not None
        assert result["id"] == "ap-upnp"
        assert result["severity"] == "medium"


# ── _ap_snmp ──────────────────────────────────────────────────────────────────

class TestApSnmp:
    def test_not_present_returns_none(self):
        assert _ap_snmp(protocols=_protocols()) is None

    def test_present_fires(self):
        result = _ap_snmp(
            protocols=_protocols(snmp={"present": True, "evidence": ["community: public"]}),
        )
        assert result is not None
        assert result["id"] == "ap-snmp"
        assert result["severity"] == "medium"

    def test_evidence_included_up_to_two_items(self):
        evidence_items = ["e1", "e2", "e3"]
        result = _ap_snmp(
            protocols=_protocols(snmp={"present": True, "evidence": evidence_items}),
        )
        # base evidence line + up to 2 from snmp evidence
        assert len(result["evidence"]) <= 3


# ── _ap_setuid ────────────────────────────────────────────────────────────────

class TestApSetuid:
    def test_no_setuid_binaries_returns_none(self):
        assert _ap_setuid(privesc=_privesc()) is None

    def test_setuid_present_fires(self):
        result = _ap_setuid(privesc=_privesc(setuid_binaries=["/usr/bin/passwd"]))
        assert result is not None
        assert result["id"] == "ap-setuid"
        assert result["severity"] == "medium"

    def test_first_binary_named_in_steps(self):
        result = _ap_setuid(privesc=_privesc(setuid_binaries=["/usr/bin/passwd", "/bin/su"]))
        assert any("/usr/bin/passwd" in step for step in result["steps"])


# ── _ap_world_writable ────────────────────────────────────────────────────────

class TestApWorldWritable:
    def test_no_files_or_dirs_returns_none(self):
        assert _ap_world_writable(privesc=_privesc()) is None

    def test_writable_files_fires(self):
        result = _ap_world_writable(
            privesc=_privesc(world_writable={"files": ["/tmp/foo"], "dirs": [], "setgid": []}),
        )
        assert result is not None
        assert result["id"] == "ap-world-writable"
        assert result["severity"] == "medium"

    def test_writable_dirs_fires(self):
        result = _ap_world_writable(
            privesc=_privesc(world_writable={"files": [], "dirs": ["/var/run"], "setgid": []}),
        )
        assert result is not None

    def test_total_count_in_evidence(self):
        result = _ap_world_writable(
            privesc=_privesc(world_writable={"files": ["/a", "/b"], "dirs": ["/c"], "setgid": []}),
        )
        assert any("3" in e for e in result["evidence"])


# ── _ap_cert_extraction ───────────────────────────────────────────────────────

class TestApCertExtraction:
    def test_no_certs_returns_none(self):
        assert _ap_cert_extraction(certs=_certs()) is None

    def test_cert_files_fires(self):
        result = _ap_cert_extraction(certs=_certs(files=["/etc/ssl/ca.pem"]))
        assert result is not None
        assert result["id"] == "ap-cert-extraction"
        assert result["severity"] == "high"

    def test_embedded_in_binaries_fires(self):
        result = _ap_cert_extraction(certs=_certs(embedded_in_binaries=["httpd"]))
        assert result is not None

    def test_embedded_mention_in_evidence_when_present(self):
        result = _ap_cert_extraction(
            certs=_certs(files=["/etc/ssl/ca.pem"], embedded_in_binaries=["httpd"]),
        )
        assert any("embedded" in e.lower() for e in result["evidence"])

    def test_no_embedded_mention_when_absent(self):
        result = _ap_cert_extraction(certs=_certs(files=["/etc/ssl/ca.pem"]))
        assert not any("embedded" in e.lower() for e in result["evidence"])


# ── _ap_weak_crypto ───────────────────────────────────────────────────────────

class TestApWeakCrypto:
    def test_empty_list_returns_none(self):
        assert _ap_weak_crypto(weak_crypto=[]) is None

    def test_non_empty_fires(self):
        result = _ap_weak_crypto(weak_crypto=[{"algorithm": "MD5"}])
        assert result is not None
        assert result["id"] == "ap-weak-crypto"
        assert result["severity"] == "medium"

    def test_count_in_evidence(self):
        result = _ap_weak_crypto(weak_crypto=[{"algorithm": "MD5"}, {"algorithm": "DES"}])
        assert any("2" in e for e in result["evidence"])


# ── _ap_debug ─────────────────────────────────────────────────────────────────

class TestApDebug:
    def test_empty_list_returns_none(self):
        assert _ap_debug(debug=[]) is None

    def test_list_with_no_items_returns_none(self):
        assert _ap_debug(debug=[{"context": "Debug Files", "items": []}]) is None

    def test_list_with_items_fires(self):
        result = _ap_debug(debug=[{"context": "Debug Files", "items": ["/web/debug.htm"]}])
        assert result is not None
        assert result["id"] == "ap-debug"
        assert result["severity"] == "medium"

    def test_items_count_in_evidence(self):
        result = _ap_debug(debug=[
            {"context": "A", "items": ["/a", "/b"]},
            {"context": "B", "items": ["/c"]},
        ])
        assert any("3" in e for e in result["evidence"])


# ── _ap_update_mitm ───────────────────────────────────────────────────────────

class TestApUpdateMitm:
    def test_no_cloud_endpoints_returns_none(self):
        assert _ap_update_mitm(credentials=_credentials()) is None

    def test_cloud_endpoints_fires(self):
        result = _ap_update_mitm(
            credentials=_credentials(cloud_endpoints=["https://update.example.com"]),
        )
        assert result is not None
        assert result["id"] == "ap-update-mitm"
        assert result["severity"] == "medium"


# ── _ap_vendor_backdoor ───────────────────────────────────────────────────────

class TestApVendorBackdoor:
    def test_no_vendor_services_returns_none(self):
        assert _ap_vendor_backdoor(init=_init()) is None

    def test_vendor_services_fires(self):
        result = _ap_vendor_backdoor(init=_init(vendor_services=["tdpServer"]))
        assert result is not None
        assert result["id"] == "ap-vendor-backdoor"
        assert result["severity"] == "high"

    def test_vendor_services_in_evidence(self):
        result = _ap_vendor_backdoor(init=_init(vendor_services=["tdpServer", "tddp"]))
        assert any("tdpServer" in e for e in result["evidence"])


# ── _ap_cert_issues ───────────────────────────────────────────────────────────

def _cert_issue(file: str, flags: list, key_bits: int = 2048, key_type: str = "RSA") -> dict:
    return {
        "file":     file,
        "flags":    flags,
        "subject":  "CN=test",
        "issuer":   "CN=ca",
        "not_after": "2020-01-01",
        "key_type": key_type,
        "key_bits": key_bits,
    }


class TestApCertIssues:
    def test_empty_list_returns_none(self):
        assert _ap_cert_issues(certificate_issues=[]) is None

    def test_expired_cert_fires_high(self):
        result = _ap_cert_issues(
            certificate_issues=[_cert_issue("etc/ssl/ca.pem", ["expired"])],
        )
        assert result is not None
        assert result["id"] == "ap-cert-issues"
        assert result["severity"] == "high"

    def test_weak_key_fires_high(self):
        result = _ap_cert_issues(
            certificate_issues=[_cert_issue("etc/ssl/weak.pem", ["weak-key (RSA 1024-bit)"], key_bits=1024)],
        )
        assert result is not None
        assert result["severity"] == "high"

    def test_self_signed_only_fires_medium(self):
        result = _ap_cert_issues(
            certificate_issues=[_cert_issue("etc/ssl/self.pem", ["self-signed"])],
        )
        assert result is not None
        assert result["severity"] == "medium"

    def test_expired_and_weak_key_fires_high(self):
        result = _ap_cert_issues(
            certificate_issues=[
                _cert_issue("etc/ssl/a.pem", ["expired"]),
                _cert_issue("etc/ssl/b.pem", ["weak-key (RSA 1024-bit)"], key_bits=1024),
            ],
        )
        assert result["severity"] == "high"

    def test_self_signed_with_expired_fires_high(self):
        result = _ap_cert_issues(
            certificate_issues=[_cert_issue("etc/ssl/x.pem", ["expired", "self-signed"])],
        )
        assert result["severity"] == "high"

    def test_file_appears_in_evidence(self):
        result = _ap_cert_issues(
            certificate_issues=[_cert_issue("etc/ssl/ca.pem", ["expired"])],
        )
        assert any("etc/ssl/ca.pem" in e for e in result["evidence"])

    def test_flags_appear_in_evidence(self):
        result = _ap_cert_issues(
            certificate_issues=[_cert_issue("etc/ssl/ca.pem", ["expired", "self-signed"])],
        )
        assert any("expired" in e for e in result["evidence"])

    def test_count_in_evidence(self):
        result = _ap_cert_issues(
            certificate_issues=[
                _cert_issue("a.pem", ["expired"]),
                _cert_issue("b.pem", ["self-signed"]),
            ],
        )
        assert any("2" in e for e in result["evidence"])

    def test_all_required_keys_present(self):
        result = _ap_cert_issues(
            certificate_issues=[_cert_issue("etc/ssl/ca.pem", ["expired"])],
        )
        for key in ("id", "title", "severity", "description", "entry_point", "steps", "evidence"):
            assert key in result

    def test_expired_mention_in_description(self):
        result = _ap_cert_issues(
            certificate_issues=[_cert_issue("etc/ssl/a.pem", ["expired"])],
        )
        assert "expired" in result["description"].lower()

    def test_weak_key_mention_in_description(self):
        result = _ap_cert_issues(
            certificate_issues=[_cert_issue("etc/ssl/b.pem", ["weak-key (RSA 1024-bit)"], key_bits=1024)],
        )
        assert "weak" in result["description"].lower() or "1024" in result["description"]

    def test_evidence_capped_at_max(self):
        certs = [_cert_issue(f"etc/ssl/cert{i}.pem", ["expired"]) for i in range(10)]
        result = _ap_cert_issues(certificate_issues=certs)
        # First evidence line is summary; remaining are per-cert (capped at _MAX_EVIDENCE=5)
        assert len(result["evidence"]) <= 6  # 1 summary + 5 capped


# ── _ap_tls_config ────────────────────────────────────────────────────────────

def _tls_issue(issue: str, file: str = "etc/httpd.conf", line: int = 1) -> dict:
    return {"file": file, "line": line, "text": issue, "issue": issue, "cve_note": ""}


class TestApTlsConfig:
    def test_empty_list_returns_none(self):
        assert _ap_tls_config(tls_config_issues=[]) is None

    def test_sslv2_fires_critical(self):
        result = _ap_tls_config(tls_config_issues=[_tls_issue("SSLv2 enabled")])
        assert result is not None
        assert result["id"] == "ap-tls-config"
        assert result["severity"] == "critical"

    def test_sslv3_fires_high(self):
        result = _ap_tls_config(tls_config_issues=[_tls_issue("SSLv3 enabled")])
        assert result is not None
        assert result["severity"] == "high"

    def test_rc4_fires_high(self):
        result = _ap_tls_config(tls_config_issues=[_tls_issue("RC4 cipher")])
        assert result["severity"] == "high"

    def test_null_cipher_fires_high(self):
        result = _ap_tls_config(tls_config_issues=[_tls_issue("NULL cipher")])
        assert result["severity"] == "high"

    def test_export_cipher_fires_high(self):
        result = _ap_tls_config(tls_config_issues=[_tls_issue("EXPORT cipher")])
        assert result["severity"] == "high"

    def test_anon_dh_fires_high(self):
        result = _ap_tls_config(tls_config_issues=[_tls_issue("anonymous DH cipher")])
        assert result["severity"] == "high"

    def test_tls10_only_fires_medium(self):
        result = _ap_tls_config(tls_config_issues=[_tls_issue("TLS 1.0/1.1 configured")])
        assert result is not None
        assert result["severity"] == "medium"

    def test_sslv2_overrides_medium(self):
        result = _ap_tls_config(tls_config_issues=[
            _tls_issue("TLS 1.0/1.1 configured"),
            _tls_issue("SSLv2 enabled"),
        ])
        assert result["severity"] == "critical"

    def test_high_issue_overrides_medium(self):
        result = _ap_tls_config(tls_config_issues=[
            _tls_issue("TLS 1.0/1.1 configured"),
            _tls_issue("RC4 cipher"),
        ])
        assert result["severity"] == "high"

    def test_file_and_line_in_evidence(self):
        result = _ap_tls_config(
            tls_config_issues=[_tls_issue("SSLv3 enabled", file="etc/ssl.conf", line=42)],
        )
        assert any("etc/ssl.conf" in e for e in result["evidence"])
        assert any("42" in e for e in result["evidence"])

    def test_count_in_evidence(self):
        result = _ap_tls_config(tls_config_issues=[
            _tls_issue("RC4 cipher"),
            _tls_issue("SSLv3 enabled"),
        ])
        assert any("2" in e for e in result["evidence"])

    def test_issue_name_in_description(self):
        result = _ap_tls_config(tls_config_issues=[_tls_issue("SSLv2 enabled")])
        assert "SSLv2" in result["description"]

    def test_evidence_capped_at_max(self):
        issues = [_tls_issue("RC4 cipher", file=f"cfg{i}.conf", line=i) for i in range(10)]
        result = _ap_tls_config(tls_config_issues=issues)
        assert len(result["evidence"]) <= 6  # 1 summary + 5 capped

    def test_all_required_keys_present(self):
        result = _ap_tls_config(tls_config_issues=[_tls_issue("RC4 cipher")])
        for key in ("id", "title", "severity", "description", "entry_point", "steps", "evidence"):
            assert key in result


# ── infer_attack_paths ────────────────────────────────────────────────────────

def _dangerous(binary: str, functions: list) -> dict:
    return {"binary": binary, "functions": functions}


# ── _ap_memory_unsafe_binaries ────────────────────────────────────────────────

class TestApMemoryUnsafeBinaries:
    def test_empty_list_returns_none(self):
        assert _ap_memory_unsafe_binaries(
            dangerous_functions=[], entry_points=[], init=_init(),
        ) is None

    def test_non_empty_with_no_reachable_binaries_fires_medium(self):
        result = _ap_memory_unsafe_binaries(
            dangerous_functions=[_dangerous("usr/bin/tool", ["gets"])],
            entry_points=[],
            init=_init(),
        )
        assert result is not None
        assert result["id"] == "ap-memory-unsafe"
        assert result["severity"] == "medium"

    def test_binary_matching_entry_point_fires_high(self):
        ep = {"type": "http", "port": 80, "protocol": "tcp",
              "binary": "httpd", "interface": "unknown", "source": "test"}
        result = _ap_memory_unsafe_binaries(
            dangerous_functions=[_dangerous("usr/bin/httpd", ["strcpy"])],
            entry_points=[ep],
            init=_init(),
        )
        assert result is not None
        assert result["severity"] == "high"

    def test_binary_matching_init_service_fires_high(self):
        result = _ap_memory_unsafe_binaries(
            dangerous_functions=[_dangerous("usr/sbin/telnetd", ["sprintf"])],
            entry_points=[],
            init=_init(detected_services=["telnetd"]),
        )
        assert result is not None
        assert result["severity"] == "high"

    def test_matching_uses_basename_not_full_path(self):
        ep = {"type": "http", "port": 80, "protocol": "tcp",
              "binary": "httpd", "interface": "unknown", "source": "test"}
        result = _ap_memory_unsafe_binaries(
            dangerous_functions=[_dangerous("usr/bin/httpd", ["gets"])],
            entry_points=[ep],
            init=_init(),
        )
        assert result["severity"] == "high"

    def test_non_reachable_binary_does_not_elevate_to_high(self):
        ep = {"type": "http", "port": 80, "protocol": "tcp",
              "binary": "httpd", "interface": "unknown", "source": "test"}
        result = _ap_memory_unsafe_binaries(
            dangerous_functions=[_dangerous("usr/bin/other_tool", ["gets"])],
            entry_points=[ep],
            init=_init(),
        )
        assert result["severity"] == "medium"

    def test_exposed_binary_count_in_evidence(self):
        ep = {"type": "http", "port": 80, "protocol": "tcp",
              "binary": "httpd", "interface": "unknown", "source": "test"}
        result = _ap_memory_unsafe_binaries(
            dangerous_functions=[_dangerous("usr/bin/httpd", ["strcpy", "gets"])],
            entry_points=[ep],
            init=_init(),
        )
        assert any("1" in e for e in result["evidence"])

    def test_binary_path_appears_in_evidence(self):
        result = _ap_memory_unsafe_binaries(
            dangerous_functions=[_dangerous("usr/bin/vuln", ["gets"])],
            entry_points=[],
            init=_init(),
        )
        assert any("usr/bin/vuln" in e for e in result["evidence"])

    def test_all_required_keys_present(self):
        result = _ap_memory_unsafe_binaries(
            dangerous_functions=[_dangerous("bin/tool", ["gets"])],
            entry_points=[],
            init=_init(),
        )
        for key in ("id", "title", "severity", "description", "entry_point", "steps", "evidence"):
            assert key in result

    def test_multiple_exposed_binaries_counted(self):
        eps = [
            {"type": "http",   "port": 80, "protocol": "tcp", "binary": "httpd",   "interface": "unknown", "source": "t"},
            {"type": "telnet", "port": 23, "protocol": "tcp", "binary": "telnetd", "interface": "unknown", "source": "t"},
        ]
        result = _ap_memory_unsafe_binaries(
            dangerous_functions=[
                _dangerous("usr/bin/httpd",   ["strcpy"]),
                _dangerous("usr/sbin/telnetd", ["gets"]),
            ],
            entry_points=eps,
            init=_init(),
        )
        assert result["severity"] == "high"
        assert any("2" in e for e in result["evidence"])


# ── infer_attack_paths ────────────────────────────────────────────────────────

class TestInferAttackPaths:
    def _call(self, **overrides):
        defaults = dict(
            entry_points=[], init=_init(), web=_web(), users=[],
            credentials=_credentials(), privesc=_privesc(),
            protocols=_protocols(), weak_crypto=[], debug=[], certs=_certs(),
            dangerous_functions=[], certificate_issues=[], tls_config_issues=[],
        )
        return infer_attack_paths(**{**defaults, **overrides})

    def test_no_conditions_returns_empty(self):
        assert self._call() == []

    def test_returns_only_fired_paths(self):
        paths = self._call(entry_points=[_ep("telnet", 23, "tcp")])
        ids = {p["id"] for p in paths}
        assert "ap-telnet" in ids
        assert "ap-http-admin" not in ids

    def test_multiple_conditions_return_multiple_paths(self):
        paths = self._call(
            entry_points=[_ep("telnet", 23, "tcp")],
            credentials=_credentials(default_credentials=["admin:admin"]),
        )
        ids = {p["id"] for p in paths}
        assert "ap-telnet" in ids
        assert "ap-default-creds" in ids

    def test_all_paths_have_required_keys(self):
        paths = self._call(
            entry_points=[_ep("telnet", 23, "tcp")],
            weak_crypto=[{"algorithm": "MD5"}],
        )
        for path in paths:
            for key in ("id", "title", "severity", "description", "entry_point", "steps", "evidence"):
                assert key in path

    def test_dangerous_functions_produces_ap_memory_unsafe(self):
        paths = self._call(dangerous_functions=[_dangerous("bin/tool", ["gets"])])
        assert any(p["id"] == "ap-memory-unsafe" for p in paths)

    def test_no_dangerous_functions_no_memory_unsafe_path(self):
        paths = self._call(dangerous_functions=[])
        assert not any(p["id"] == "ap-memory-unsafe" for p in paths)

    def test_missing_dangerous_functions_defaults_to_no_path(self):
        # Called without dangerous_functions kwarg at all — should not crash
        defaults = dict(
            entry_points=[], init=_init(), web=_web(), users=[],
            credentials=_credentials(), privesc=_privesc(),
            protocols=_protocols(), weak_crypto=[], debug=[], certs=_certs(),
        )
        paths = infer_attack_paths(**defaults)
        assert not any(p["id"] == "ap-memory-unsafe" for p in paths)

    def test_certificate_issues_produces_ap_cert_issues(self):
        paths = self._call(
            certificate_issues=[_cert_issue("etc/ssl/ca.pem", ["expired"])],
        )
        assert any(p["id"] == "ap-cert-issues" for p in paths)

    def test_no_certificate_issues_no_cert_issues_path(self):
        paths = self._call(certificate_issues=[])
        assert not any(p["id"] == "ap-cert-issues" for p in paths)

    def test_missing_certificate_issues_defaults_to_no_path(self):
        # Called without certificate_issues kwarg at all — should not crash
        defaults = dict(
            entry_points=[], init=_init(), web=_web(), users=[],
            credentials=_credentials(), privesc=_privesc(),
            protocols=_protocols(), weak_crypto=[], debug=[], certs=_certs(),
        )
        paths = infer_attack_paths(**defaults)
        assert not any(p["id"] == "ap-cert-issues" for p in paths)

    def test_tls_config_issues_produces_ap_tls_config(self):
        paths = self._call(tls_config_issues=[_tls_issue("SSLv3 enabled")])
        assert any(p["id"] == "ap-tls-config" for p in paths)

    def test_no_tls_config_issues_no_tls_config_path(self):
        paths = self._call(tls_config_issues=[])
        assert not any(p["id"] == "ap-tls-config" for p in paths)

    def test_missing_tls_config_issues_defaults_to_no_path(self):
        # Called without tls_config_issues kwarg at all — should not crash
        defaults = dict(
            entry_points=[], init=_init(), web=_web(), users=[],
            credentials=_credentials(), privesc=_privesc(),
            protocols=_protocols(), weak_crypto=[], debug=[], certs=_certs(),
        )
        paths = infer_attack_paths(**defaults)
        assert not any(p["id"] == "ap-tls-config" for p in paths)
