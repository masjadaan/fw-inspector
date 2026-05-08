#!/usr/bin/env python3
"""
Synthesizes a structured attack surface model from analyze.py output files.
Reads from an analysis directory produced by analyze.py and writes attack_surface.json.

Usage:
    python3 surface.py ./analysis/Archer_A5V6/
    python3 surface.py ./analysis/Archer_A5V6/ --output ./report/
"""

import argparse
import json
import re
from pathlib import Path


# ── File I/O ──────────────────────────────────────────────────────────────────

def read_file(path: Path) -> str:
    return path.read_text(errors="replace") if path.exists() else ""


def parse_sections(content: str) -> dict:
    """Parse a multi-section file (=== Title === / content) into {title: content}."""
    sections = {}
    pattern = re.compile(
        r"={60}\n\s+(.+?)\s*\n={60}\n(.*?)(?=\n={60}|\Z)", re.DOTALL
    )
    for m in pattern.finditer(content):
        title = m.group(1).strip()
        body = m.group(2).strip()
        sections[title] = body if body != "(nothing found)" else ""
    return sections


def non_empty_lines(text: str) -> list:
    return [l.strip() for l in text.splitlines() if l.strip()]


# ── Parsers ───────────────────────────────────────────────────────────────────

def parse_users(analysis_dir: Path) -> list:
    sections = parse_sections(read_file(analysis_dir / "users_groups.txt"))
    passwd = sections.get("etc/passwd", "")
    shadow = sections.get("etc/shadow", "")

    shadow_hashes = {}
    for line in shadow.splitlines():
        parts = line.split(":")
        if len(parts) >= 2:
            shadow_hashes[parts[0]] = parts[1]

    EMPTY_HASH = {"*", "!", "x", ""}
    users = []
    for line in passwd.splitlines():
        parts = line.split(":")
        if len(parts) < 7:
            continue
        name, pw, uid, gid, _, home, shell = parts[:7]
        effective_hash = shadow_hashes.get(name, pw)
        users.append({
            "name": name,
            "uid": int(uid) if uid.isdigit() else uid,
            "gid": int(gid) if gid.isdigit() else gid,
            "home": home,
            "shell": shell,
            "has_password": effective_hash not in EMPTY_HASH,
            "password_hash": effective_hash if effective_hash not in EMPTY_HASH else None,
        })
    return users


def parse_setuid(analysis_dir: Path) -> list:
    return non_empty_lines(read_file(analysis_dir / "setuid_binaries.txt"))


def parse_capabilities(analysis_dir: Path) -> list:
    caps = []
    for line in read_file(analysis_dir / "capabilities.txt").splitlines():
        m = re.match(r"^(.+?)\s*=\s*(.+)$", line.strip())
        if m:
            caps.append({"path": m.group(1).strip(), "capabilities": m.group(2).strip()})
    return caps


def parse_world_writable(analysis_dir: Path) -> dict:
    sections = parse_sections(read_file(analysis_dir / "world_writable.txt"))
    return {
        "files": non_empty_lines(sections.get("World-Writable Files", "")),
        "dirs": non_empty_lines(sections.get("World-Writable Directories", "")),
        "setgid": non_empty_lines(sections.get("SetGID Binaries", "")),
    }


def parse_init_services(analysis_dir: Path) -> dict:
    sections = parse_sections(read_file(analysis_dir / "init_scripts.txt"))

    services_raw = sections.get("Network-Exposed Services", "")
    port_raw = sections.get("Explicit Port Bindings", "")
    injection_raw = sections.get("Command Injection Vectors", "")
    creds_raw = sections.get("Hardcoded Credentials", "")
    telnet_raw = sections.get("Telnet and Debug Interfaces", "")
    vendor_raw = sections.get("Vendor-Specific Backdoor Services (TP-Link)", "")
    outbound_raw = sections.get("Outbound Connections", "")
    firewall_raw = sections.get("Firewall Rules", "")

    KNOWN = ["telnetd", "ftpd", "dropbear", "sshd", "httpd", "dnsd",
             "dhcpd", "tftpd", "snmpd", "upnpd", "tr069"]
    combined = services_raw + " " + telnet_raw + " " + vendor_raw
    detected = [svc for svc in KNOWN if svc in combined]

    return {
        "detected_services": detected,
        "explicit_ports": list({int(p) for p in re.findall(r"-p\s+(\d+)", port_raw)}),
        "has_command_injection": bool(injection_raw),
        "injection_evidence": non_empty_lines(injection_raw)[:5],
        "has_hardcoded_creds": bool(creds_raw),
        "vendor_services": non_empty_lines(vendor_raw)[:10],
        "outbound_connections": non_empty_lines(outbound_raw)[:10],
        "has_firewall_rules": bool(firewall_raw),
    }


def parse_web(analysis_dir: Path) -> dict:
    web_sections = parse_sections(read_file(analysis_dir / "web_interface.txt"))
    ws_sections = parse_sections(read_file(analysis_dir / "web_server_configs.txt"))
    httpd_bins = non_empty_lines(read_file(analysis_dir / "httpd_binaries.txt"))

    cgi_files = non_empty_lines(web_sections.get("CGI Scripts", ""))
    lua_handlers = non_empty_lines(web_sections.get("Lua Handlers", ""))
    api_endpoints = non_empty_lines(web_sections.get("API Endpoints in Web Root", ""))

    ports = []
    for body in ws_sections.values():
        for m in re.finditer(r"(?:port|listen)[^\d]*(\d{2,5})", body, re.IGNORECASE):
            p = int(m.group(1))
            if 1 <= p <= 65535:
                ports.append(p)

    return {
        "httpd_binaries": httpd_bins,
        "cgi_scripts": cgi_files,
        "lua_handlers": lua_handlers,
        "api_endpoints": api_endpoints[:20],
        "config_files": [k for k in ws_sections if k != "Web Server Config Files Found"],
        "inferred_ports": list(set(ports)) or [80],
    }


def parse_protocols(analysis_dir: Path) -> dict:
    sections = parse_sections(read_file(analysis_dir / "protocols.txt"))
    proto_map = {
        "snmp":  "SNMP Community Strings",
        "upnp":  "UPnP / SSDP",
        "tr069": "TR-069 / CWMP",
        "mqtt":  "MQTT",
    }
    result = {}
    for proto, title in proto_map.items():
        body = sections.get(title, "")
        evidence = non_empty_lines(body)
        result[proto] = {"present": bool(evidence), "evidence": evidence[:5]}
    return result


def parse_credentials(analysis_dir: Path) -> dict:
    cred_sections = parse_sections(read_file(analysis_dir / "credentials.txt"))
    def_sections = parse_sections(read_file(analysis_dir / "default_credentials.txt"))
    ssh_sections = parse_sections(read_file(analysis_dir / "ssh_keys.txt"))

    ssh_keys = non_empty_lines(ssh_sections.get("SSH Key Files Found", ""))
    hardcoded = [
        l for l in non_empty_lines(cred_sections.get("Passwords and Secrets (all config files)", ""))
        if not l.startswith("Binary file")
    ][:20]
    cloud_urls = non_empty_lines(cred_sections.get("Cloud and Update Endpoints (all config files)", ""))[:20]
    defaults = non_empty_lines(
        def_sections.get("Default Passwords / SSIDs in Configs", "") + "\n" +
        def_sections.get("Default Credentials in Scripts", "")
    )[:20]

    return {
        "hardcoded_in_configs": hardcoded,
        "default_credentials": defaults,
        "ssh_key_files": ssh_keys,
        "cloud_endpoints": cloud_urls,
    }


def parse_weak_crypto(analysis_dir: Path) -> list:
    findings = []
    for title, body in parse_sections(read_file(analysis_dir / "weak_crypto.txt")).items():
        evidence = non_empty_lines(body)
        if evidence:
            findings.append({"context": title, "evidence": evidence[:5]})
    return findings


def parse_debug(analysis_dir: Path) -> list:
    findings = []
    for title, body in parse_sections(read_file(analysis_dir / "debug_artifacts.txt")).items():
        items = non_empty_lines(body)
        if items:
            findings.append({"context": title, "items": items[:10]})
    return findings


def parse_ipc(analysis_dir: Path) -> dict:
    sections = parse_sections(read_file(analysis_dir / "unix_sockets.txt"))
    return {
        "socket_files": non_empty_lines(sections.get("Unix Socket Files", "")),
        "references": non_empty_lines(sections.get("Unix Socket References", ""))[:10],
    }


def parse_certs(analysis_dir: Path) -> dict:
    sections = parse_sections(read_file(analysis_dir / "certificates_keys.txt"))
    return {
        "files": non_empty_lines(sections.get("Certificate and Key Files", "")),
        "embedded_in_binaries": non_empty_lines(sections.get("Embedded Keys / Certs in Files", ""))[:10],
    }


def parse_architecture(analysis_dir: Path) -> dict:
    _EMPTY = {"arch": "unknown", "bits": 0, "endianness": "unknown",
              "endianness_short": "?", "confidence": 0.0, "elf_count": 0}
    _PAT   = re.compile(r'ELF\s+(\d+)-bit\s+(LSB|MSB)\s+\w+,\s+([^,]+)')
    _NAME  = {"Intel": "x86", "AArch64": "ARM64"}

    arch_txt = analysis_dir / "architecture.txt"
    if arch_txt.exists():
        sections = parse_sections(read_file(arch_txt))
        body = sections.get("Detected Architecture", "")
        kv = {}
        for line in body.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                kv[k.strip()] = v.strip()
        if kv.get("arch", "unknown") != "unknown":
            return {
                "arch":             kv.get("arch", "unknown"),
                "bits":             int(kv["bits"]) if kv.get("bits", "").isdigit() else 0,
                "endianness":       kv.get("endianness", "unknown"),
                "endianness_short": kv.get("endianness_short", "?"),
                "confidence":       float(kv.get("confidence", 0)),
                "elf_count":        int(kv.get("elf_count", 0)),
            }

    # Fallback: parse architecture from binary_inventory.txt
    votes: dict = {}
    for line in read_file(analysis_dir / "binary_inventory.txt").splitlines():
        line = line.strip()
        if not line.startswith("type :"):
            continue
        m = _PAT.search(line[len("type :"):])
        if not m:
            continue
        bits        = int(m.group(1))
        endian_short = m.group(2)
        arch_word   = m.group(3).strip().split()[0]
        arch        = _NAME.get(arch_word, arch_word)
        key         = (arch, bits, endian_short)
        votes[key]  = votes.get(key, 0) + 1

    if not votes:
        return _EMPTY

    dominant    = max(votes, key=votes.__getitem__)
    arch, bits, endian_short = dominant
    agreeing    = votes[dominant]
    total       = sum(votes.values())
    return {
        "arch":             arch,
        "bits":             bits,
        "endianness":       "little-endian" if endian_short == "LSB" else "big-endian",
        "endianness_short": endian_short,
        "confidence":       round(agreeing / total, 2) if total else 0.0,
        "elf_count":        total,
    }


def parse_hardening(analysis_dir: Path) -> dict:
    h_path = analysis_dir / "hardening.json"
    if not h_path.exists():
        return {"summary": {}, "binaries": []}
    try:
        return json.loads(h_path.read_text())
    except (json.JSONDecodeError, OSError):
        return {"summary": {}, "binaries": []}


def parse_shellcheck(analysis_dir: Path) -> dict:
    sc_path = analysis_dir / "shellcheck.json"
    if not sc_path.exists():
        return {"total": 0, "by_level": {}, "by_file": {}}
    try:
        findings = json.loads(sc_path.read_text())
    except (json.JSONDecodeError, OSError):
        return {"total": 0, "by_level": {}, "by_file": {}}

    by_level: dict = {}
    seen: set = set()
    by_file: dict = {}
    for f in findings:
        lvl = f.get("level", "")
        by_level[lvl] = by_level.get(lvl, 0) + 1
        key = (f["file"], f["code"])
        if key in seen:
            continue
        seen.add(key)
        by_file.setdefault(f["file"], []).append({
            "code": f["code"],
            "level": lvl,
            "message": f.get("message", ""),
            "line": f.get("line", 0),
        })

    return {"total": len(findings), "by_level": by_level, "by_file": by_file}


def parse_nvram(analysis_dir: Path) -> list:
    evidence = []
    for _, body in parse_sections(read_file(analysis_dir / "nvram.txt")).items():
        evidence.extend(non_empty_lines(body)[:5])
    return evidence[:20]


# ── Model Builders ────────────────────────────────────────────────────────────

_SERVICE_PORT_MAP = {
    "httpd":    (80,   "tcp", "http"),
    "sshd":     (22,   "tcp", "ssh"),
    "dropbear": (22,   "tcp", "ssh"),
    "telnetd":  (23,   "tcp", "telnet"),
    "ftpd":     (21,   "tcp", "ftp"),
    "tftpd":    (69,   "udp", "tftp"),
    "snmpd":    (161,  "udp", "snmp"),
    "upnpd":    (1900, "udp", "upnp"),
    "dhcpd":    (67,   "udp", "dhcp"),
    "dnsd":     (53,   "udp", "dns"),
}

_PROTO_PORT_MAP = {
    "snmp":  (161,  "udp", "snmp"),
    "upnp":  (1900, "udp", "upnp"),
    "tr069": (7547, "tcp", "tr069"),
    "mqtt":  (1883, "tcp", "mqtt"),
}


def build_entry_points(init: dict, web: dict, protocols: dict) -> list:
    eps = []
    seen = set()

    for svc in init["detected_services"]:
        if svc in _SERVICE_PORT_MAP:
            port, proto, svc_type = _SERVICE_PORT_MAP[svc]
            if (port, proto) not in seen:
                seen.add((port, proto))
                eps.append({
                    "type": svc_type,
                    "port": port,
                    "protocol": proto,
                    "binary": svc,
                    "interface": "unknown",
                    "source": "init_scripts",
                })

    for port in web["inferred_ports"]:
        key = (port, "tcp")
        if key not in seen and (web["httpd_binaries"] or web["cgi_scripts"] or web["lua_handlers"]):
            seen.add(key)
            svc_type = "https" if port == 443 else "http"
            eps.append({
                "type": svc_type,
                "port": port,
                "protocol": "tcp",
                "binary": web["httpd_binaries"][0] if web["httpd_binaries"] else "httpd",
                "interface": "unknown",
                "source": "web_server_config",
            })

    for proto, info in protocols.items():
        if info["present"] and proto in _PROTO_PORT_MAP:
            port, net_proto, ep_type = _PROTO_PORT_MAP[proto]
            if (port, net_proto) not in seen:
                seen.add((port, net_proto))
                eps.append({
                    "type": ep_type,
                    "port": port,
                    "protocol": net_proto,
                    "binary": None,
                    "interface": "unknown",
                    "source": "protocols_config",
                })

    for port in init["explicit_ports"]:
        if not any(p == port for p, _ in seen):
            seen.add((port, "tcp"))
            eps.append({
                "type": "unknown",
                "port": port,
                "protocol": "tcp",
                "binary": None,
                "interface": "unknown",
                "source": "init_script_port_binding",
            })

    return eps


def infer_attack_paths(
    entry_points: list,
    init: dict,
    web: dict,
    users: list,
    credentials: dict,
    privesc: dict,
    protocols: dict,
    weak_crypto: list,
    debug: list,
    certs: dict,
) -> list:
    paths = []

    telnet_eps = [ep for ep in entry_points if ep["type"] == "telnet"]
    if telnet_eps:
        paths.append({
            "id": "ap-telnet",
            "title": "Unencrypted Telnet Remote Shell",
            "severity": "critical",
            "description": (
                "Telnet daemon exposes an unencrypted remote shell. "
                "All traffic is cleartext and trivially interceptable on the LAN."
            ),
            "entry_point": "telnet:23",
            "steps": [
                "Connect to port 23 (telnet) on the LAN interface",
                "Attempt login with default or hardcoded credentials",
                "Gain interactive shell (typically as root on embedded devices)",
            ],
            "evidence": ["init_scripts.txt: telnetd detected in network services"],
        })

    http_eps = [ep for ep in entry_points if ep["type"] in ("http", "https")]
    if http_eps:
        evidence = [f"web_server_config: httpd binary found — {', '.join(web['httpd_binaries'][:3])}"]
        if web["cgi_scripts"]:
            evidence.append(f"web_interface.txt: {len(web['cgi_scripts'])} CGI scripts")
        if web["lua_handlers"]:
            evidence.append(f"web_interface.txt: {len(web['lua_handlers'])} Lua handlers")

        paths.append({
            "id": "ap-http-admin",
            "title": "HTTP Admin Interface Exposure",
            "severity": "high",
            "description": (
                "HTTP admin interface is reachable. "
                "CGI handlers and Lua scripts may accept unauthenticated or weakly authenticated requests."
            ),
            "entry_point": f"http:{http_eps[0]['port']}",
            "steps": [
                f"Access HTTP interface on port {http_eps[0]['port']}",
                "Enumerate endpoints: CGI scripts, Lua handlers, HTML forms",
                "Attempt authentication bypass or default credential login",
                "Exploit any unsanitized parameter to achieve RCE",
            ],
            "evidence": evidence,
        })

    if init["has_command_injection"] and (web["cgi_scripts"] or web["lua_handlers"]):
        paths.append({
            "id": "ap-cgi-injection",
            "title": "Remote Code Execution via CGI/Lua Command Injection",
            "severity": "critical",
            "description": (
                "Command injection patterns (eval, backtick, $()) found in init scripts "
                "alongside CGI or Lua HTTP handlers. Unsanitized HTTP parameters likely reach shell commands."
            ),
            "entry_point": "http",
            "steps": [
                "Identify CGI or Lua endpoints that accept user-controlled parameters",
                "Inject shell metacharacters: semicolon, backtick, $(), pipes",
                "Achieve remote command execution, typically as root",
            ],
            "evidence": [
                f"init_scripts.txt: injection patterns — {', '.join(init['injection_evidence'][:3])}",
                f"web_interface.txt: {len(web['cgi_scripts'])} CGI, {len(web['lua_handlers'])} Lua handlers",
            ],
        })

    if credentials["default_credentials"] or init["has_hardcoded_creds"]:
        paths.append({
            "id": "ap-default-creds",
            "title": "Authentication Bypass via Default or Hardcoded Credentials",
            "severity": "high",
            "description": (
                "Default or hardcoded credentials found in firmware. "
                "These frequently remain unchanged on deployed devices."
            ),
            "entry_point": "any authenticated service",
            "steps": [
                "Identify login interfaces: HTTP admin, SSH, Telnet",
                "Try common default credentials: admin/admin, admin/password, root/root",
                "If credentials match, gain privileged access",
            ],
            "evidence": (
                ["init_scripts.txt: hardcoded credential patterns in init scripts"] if init["has_hardcoded_creds"] else []
            ) + (
                [f"default_credentials.txt: {len(credentials['default_credentials'])} default credential references"] if credentials["default_credentials"] else []
            ),
        })

    if credentials["hardcoded_in_configs"]:
        paths.append({
            "id": "ap-static-creds",
            "title": "Credential Extraction from Firmware Image",
            "severity": "high",
            "description": (
                "Passwords, API keys, or secrets hardcoded in configuration files. "
                "Extractable from any firmware image download without device access."
            ),
            "entry_point": "offline — firmware image",
            "steps": [
                "Obtain firmware image (vendor download page or TFTP/HTTP update URL)",
                "Extract and mount root filesystem with unsquashfs",
                "Read plaintext credentials from config files",
                "Authenticate to live device or cloud API using extracted credentials",
            ],
            "evidence": [f"credentials.txt: {len(credentials['hardcoded_in_configs'])} credential references in config files"],
        })

    if protocols.get("tr069", {}).get("present"):
        paths.append({
            "id": "ap-tr069",
            "title": "TR-069/CWMP Remote Management Exploitation",
            "severity": "high",
            "description": (
                "TR-069 (CWMP) allows ISP remote management of the device. "
                "ACS impersonation or CWMP authentication weaknesses grant full remote control."
            ),
            "entry_point": "tr069:7547",
            "steps": [
                "Reach port 7547 from WAN (or perform ACS impersonation via DNS/MITM)",
                "Exploit weak CWMP authentication or unauthenticated endpoints",
                "Use SetParameterValues or Download RPC to push arbitrary config or firmware",
            ],
            "evidence": ["protocols.txt: TR-069/CWMP references found"],
        })

    if protocols.get("upnp", {}).get("present"):
        paths.append({
            "id": "ap-upnp",
            "title": "UPnP/SSDP Port Forwarding Abuse",
            "severity": "medium",
            "description": (
                "UPnP on LAN allows unauthorized port forwarding rules to be added, "
                "potentially exposing internal services to the WAN."
            ),
            "entry_point": "upnp:1900/udp",
            "steps": [
                "Discover device via SSDP (port 1900 UDP multicast)",
                "Query IGD profile via SOAP",
                "Add port forwarding rules or exploit known UPnP implementation CVEs",
            ],
            "evidence": ["protocols.txt: UPnP/SSDP references found"],
        })

    if protocols.get("snmp", {}).get("present"):
        paths.append({
            "id": "ap-snmp",
            "title": "SNMP Community String Enumeration and Write Access",
            "severity": "medium",
            "description": (
                "SNMP with predictable community strings allows full device enumeration. "
                "SNMPv2c write access enables configuration modification."
            ),
            "entry_point": "snmp:161/udp",
            "steps": [
                "Send SNMP GET to port 161 with community 'public' or 'private'",
                "Walk MIB tree to enumerate device configuration",
                "Use SNMP SET (if write community known) to modify running config",
            ],
            "evidence": [
                "protocols.txt: SNMP community string references",
            ] + protocols["snmp"]["evidence"][:2],
        })

    if privesc["setuid_binaries"]:
        paths.append({
            "id": "ap-setuid",
            "title": "Local Privilege Escalation via SetUID Binary",
            "severity": "medium",
            "description": (
                "SetUID binaries execute as root regardless of the calling user. "
                "A vulnerability in any of these binaries allows escalation from web/daemon user to root."
            ),
            "entry_point": "local — requires initial code execution",
            "steps": [
                "Gain low-privilege code execution (e.g., RCE as www-data via web handler)",
                f"Target SetUID binary: {privesc['setuid_binaries'][0]}",
                "Exploit buffer overflow, path traversal, or argument injection",
                "Obtain root shell",
            ],
            "evidence": [f"setuid_binaries.txt: {len(privesc['setuid_binaries'])} SetUID binaries found"],
        })

    ww = privesc.get("world_writable", {})
    ww_total = len(ww.get("files", [])) + len(ww.get("dirs", []))
    if ww_total:
        paths.append({
            "id": "ap-world-writable",
            "title": "Privilege Escalation via World-Writable Path",
            "severity": "medium",
            "description": (
                "World-writable files or directories allow a low-privilege process to "
                "inject content that a privileged process later reads or executes."
            ),
            "entry_point": "local — requires initial code execution",
            "steps": [
                "Gain low-privilege code execution",
                "Write malicious payload to world-writable file or directory",
                "Wait for privileged daemon to execute or read the modified path",
            ],
            "evidence": [f"world_writable.txt: {ww_total} world-writable files/directories"],
        })

    if certs["files"] or certs["embedded_in_binaries"]:
        paths.append({
            "id": "ap-cert-extraction",
            "title": "TLS Private Key Extraction for MITM",
            "severity": "high",
            "description": (
                "SSL/TLS private keys or certificates found in firmware. "
                "Extracted keys enable man-in-the-middle attacks against the device or its cloud connections."
            ),
            "entry_point": "offline — firmware image",
            "steps": [
                "Extract private key from firmware filesystem (.pem, .key files)",
                "Set up MITM proxy presenting the extracted certificate",
                "Decrypt captured TLS traffic or impersonate the device to its cloud backend",
            ],
            "evidence": [
                f"certificates_keys.txt: {len(certs['files'])} cert/key files found",
            ] + (["certificates_keys.txt: private key material embedded in binary"] if certs["embedded_in_binaries"] else []),
        })

    if weak_crypto:
        paths.append({
            "id": "ap-weak-crypto",
            "title": "Cryptographic Weakness (MD5/DES/RC4/ECB)",
            "severity": "medium",
            "description": (
                "Broken cryptographic algorithms found in firmware. "
                "MD5 is collision-prone, DES/RC4 are broken, ECB mode leaks patterns."
            ),
            "entry_point": "offline or network",
            "steps": [
                "Capture ciphertext or hash from device (via SNMP, config backup, or MITM)",
                "Apply known attack: MD5 collision, RC4 BEAST/RC4 biases, ECB plaintext recovery",
                "Recover plaintext, forge authentication token, or bypass integrity check",
            ],
            "evidence": [f"weak_crypto.txt: {len(weak_crypto)} weak crypto contexts found"],
        })

    debug_items = [item for f in debug for item in f.get("items", [])]
    if debug_items:
        paths.append({
            "id": "ap-debug",
            "title": "Debug/Factory Interface Access",
            "severity": "medium",
            "description": (
                "Debug, factory, or diagnostic artifacts found in firmware. "
                "These may expose undocumented commands, reduced authentication, or UART shell access."
            ),
            "entry_point": "local (UART) or network (undocumented endpoint)",
            "steps": [
                "Connect to UART console (physical access) or find debug HTTP parameter",
                "Trigger factory/diagnostic mode to bypass authentication",
                "Access privileged shell or extract runtime secrets via debug output",
            ],
            "evidence": [f"debug_artifacts.txt: {len(debug_items)} debug/factory/test artifacts"],
        })

    if credentials["cloud_endpoints"]:
        paths.append({
            "id": "ap-update-mitm",
            "title": "Malicious Firmware Delivery via Update MITM",
            "severity": "medium",
            "description": (
                "Hardcoded firmware update URLs found. "
                "If update integrity verification is absent or uses a weak hash, "
                "a MITM attacker can serve malicious firmware."
            ),
            "entry_point": "network — update channel",
            "steps": [
                "Intercept firmware update request via DNS spoofing or MITM on update URL",
                "Serve crafted firmware that passes signature/hash check (or bypasses it)",
                "Device installs attacker-controlled firmware on next update cycle",
            ],
            "evidence": [f"credentials.txt: {len(credentials['cloud_endpoints'])} cloud/update URLs hardcoded"],
        })

    if init["vendor_services"]:
        paths.append({
            "id": "ap-vendor-backdoor",
            "title": "Vendor-Specific Service Attack Surface (TP-Link)",
            "severity": "high",
            "description": (
                "TP-Link proprietary services (tdpServer, tddp, omcid, cwmp) found in init scripts. "
                "These vendor daemons have historically contained undocumented commands and authentication bypasses."
            ),
            "entry_point": "network — vendor daemon port",
            "steps": [
                "Identify vendor daemon port via protocol fingerprinting",
                "Send crafted vendor protocol packets (TDDP, TDP, OMCI)",
                "Exploit known CVEs or undocumented command execution paths",
            ],
            "evidence": [f"init_scripts.txt: vendor services — {', '.join(init['vendor_services'][:5])}"],
        })

    return paths


def build_model(analysis_dir: Path, firmware_id: str) -> dict:
    print(f"[*] Parsing analysis files from {analysis_dir}/")

    users = parse_users(analysis_dir)
    setuid = parse_setuid(analysis_dir)
    caps = parse_capabilities(analysis_dir)
    world_writable = parse_world_writable(analysis_dir)
    init = parse_init_services(analysis_dir)
    web = parse_web(analysis_dir)
    protocols = parse_protocols(analysis_dir)
    credentials = parse_credentials(analysis_dir)
    weak_crypto = parse_weak_crypto(analysis_dir)
    debug = parse_debug(analysis_dir)
    ipc = parse_ipc(analysis_dir)
    certs = parse_certs(analysis_dir)
    nvram = parse_nvram(analysis_dir)
    shellcheck = parse_shellcheck(analysis_dir)
    hardening = parse_hardening(analysis_dir)
    arch = parse_architecture(analysis_dir)

    privesc = {
        "setuid_binaries": setuid,
        "capabilities": caps,
        "world_writable": world_writable,
    }

    entry_points = build_entry_points(init, web, protocols)
    attack_paths = infer_attack_paths(
        entry_points, init, web, users, credentials,
        privesc, protocols, weak_crypto, debug, certs,
    )

    return {
        "firmware": {
            "id": firmware_id,
            "analysis_dir": str(analysis_dir),
            "arch": arch["arch"],
            "bits": arch["bits"],
            "endianness": arch["endianness"],
            "endianness_short": arch["endianness_short"],
            "arch_confidence": arch["confidence"],
            "arch_elf_count": arch["elf_count"],
        },
        "summary": {
            "entry_points_count": len(entry_points),
            "attack_paths_count": len(attack_paths),
            "critical_paths": sum(1 for p in attack_paths if p["severity"] == "critical"),
            "high_paths": sum(1 for p in attack_paths if p["severity"] == "high"),
            "users_with_password": sum(1 for u in users if u["has_password"]),
            "setuid_binaries_count": len(setuid),
            "world_writable_count": len(world_writable["files"]) + len(world_writable["dirs"]),
        },
        "entry_points": entry_points,
        "users": users,
        "privilege_escalation": privesc,
        "credentials": credentials,
        "protocols": protocols,
        "weak_crypto": weak_crypto,
        "debug_artifacts": debug,
        "ipc": ipc,
        "certificates": certs,
        "nvram_references": nvram,
        "shellcheck": shellcheck,
        "hardening": hardening,
        "web": web,
        "attack_paths": attack_paths,
    }


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Build a structured attack surface model from analyze.py output."
    )
    parser.add_argument(
        "analysis_dir",
        type=Path,
        help="Directory produced by analyze.py (e.g. ./analysis/Archer_A5V6/).",
    )
    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=None,
        help="Output JSON file (default: <analysis_dir>/attack_surface.json).",
    )
    args = parser.parse_args()

    analysis_dir = args.analysis_dir.resolve()
    if not analysis_dir.is_dir():
        print(f"[!] Not a directory: {analysis_dir}")
        raise SystemExit(1)

    firmware_id = analysis_dir.name
    out_file = args.output or Path(f"{firmware_id}_attack_surface.json")

    model = build_model(analysis_dir, firmware_id)

    out_file.write_text(json.dumps(model, indent=2))
    print(f"\n[+] Attack surface model written to {out_file}")

    summary = model["summary"]
    print(f"\n    Entry points  : {summary['entry_points_count']}")
    print(f"    Attack paths  : {summary['attack_paths_count']}  "
          f"({summary['critical_paths']} critical, {summary['high_paths']} high)")
    print(f"    Users w/ creds: {summary['users_with_password']}")
    print(f"    SetUID bins   : {summary['setuid_binaries_count']}")
    print(f"    World-writable: {summary['world_writable_count']}")


if __name__ == "__main__":
    main()
