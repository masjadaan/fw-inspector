"""Parse analyze.py output files into typed dicts for the attack surface model."""

import json
import re
from pathlib import Path
from typing import Optional, TypedDict


# ── Types ─────────────────────────────────────────────────────────────────────

class User(TypedDict):
    name: str
    uid: int | str
    gid: int | str
    home: str
    shell: str
    has_password: bool
    password_hash: Optional[str]


# ── Constants ─────────────────────────────────────────────────────────────────

_EMPTY_HASH   = {"*", "!", "x", ""}
_MAX_EVIDENCE = 5
_MAX_ITEMS    = 10
_MAX_LIST     = 20

# Shared with attack_paths: maps service binary name → (default_port, protocol, service_type)
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
        body  = m.group(2).strip()
        sections[title] = body if body != "(nothing found)" else ""
    return sections


def non_empty_lines(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip()]


def _section_lines(sections: dict, title: str) -> list[str]:
    return non_empty_lines(sections.get(title, ""))


# ── Parsers ───────────────────────────────────────────────────────────────────

def parse_users(analysis_dir: Path) -> list[User]:
    sections = parse_sections(read_file(analysis_dir / "users_groups.txt"))
    passwd = sections.get("etc/passwd", "")
    shadow = sections.get("etc/shadow", "")

    shadow_hashes = {}
    for line in shadow.splitlines():
        parts = line.split(":")
        if len(parts) >= 2:
            shadow_hashes[parts[0]] = parts[1]

    users: list[User] = []
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
            "has_password": effective_hash not in _EMPTY_HASH,
            "password_hash": effective_hash if effective_hash not in _EMPTY_HASH else None,
        })
    return users


def parse_setuid(analysis_dir: Path) -> list[str]:
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
        "files":  _section_lines(sections, "World-Writable Files"),
        "dirs":   _section_lines(sections, "World-Writable Directories"),
        "setgid": _section_lines(sections, "SetGID Binaries"),
    }


def parse_init_services(analysis_dir: Path) -> dict:
    sections = parse_sections(read_file(analysis_dir / "init_scripts.txt"))

    services_raw  = sections.get("Network-Exposed Services", "")
    port_raw      = sections.get("Explicit Port Bindings", "")
    injection_raw = sections.get("Command Injection Vectors", "")
    creds_raw     = sections.get("Hardcoded Credentials", "")
    telnet_raw    = sections.get("Telnet and Debug Interfaces", "")
    vendor_raw    = sections.get("Vendor-Specific Backdoor Services (TP-Link)", "")
    outbound_raw  = sections.get("Outbound Connections", "")
    firewall_raw  = sections.get("Firewall Rules", "")

    combined = services_raw + " " + telnet_raw + " " + vendor_raw
    detected = [svc for svc in _SERVICE_PORT_MAP if svc in combined]

    return {
        "detected_services":    detected,
        "explicit_ports":       list({int(p) for p in re.findall(r"-p\s+(\d+)", port_raw)}),
        "has_command_injection": bool(injection_raw),
        "injection_evidence":   non_empty_lines(injection_raw)[:_MAX_EVIDENCE],
        "has_hardcoded_creds":  bool(creds_raw),
        "vendor_services":      non_empty_lines(vendor_raw)[:_MAX_ITEMS],
        "outbound_connections": non_empty_lines(outbound_raw)[:_MAX_ITEMS],
        "has_firewall_rules":   bool(firewall_raw),
    }


def parse_web(analysis_dir: Path) -> dict:
    web_sections = parse_sections(read_file(analysis_dir / "web_interface.txt"))
    ws_sections  = parse_sections(read_file(analysis_dir / "web_server_configs.txt"))
    httpd_bins   = non_empty_lines(read_file(analysis_dir / "httpd_binaries.txt"))

    cgi_files     = _section_lines(web_sections, "CGI Scripts")
    lua_handlers  = _section_lines(web_sections, "Lua Handlers")
    api_endpoints = _section_lines(web_sections, "API Endpoints in Web Root")

    ports = []
    for body in ws_sections.values():
        for m in re.finditer(r"(?:port|listen)[^\d]*(\d{2,5})", body, re.IGNORECASE):
            p = int(m.group(1))
            if 1 <= p <= 65535:
                ports.append(p)

    return {
        "httpd_binaries": httpd_bins,
        "cgi_scripts":    cgi_files,
        "lua_handlers":   lua_handlers,
        "api_endpoints":  api_endpoints[:_MAX_LIST],
        "config_files":   [k for k in ws_sections if k != "Web Server Config Files Found"],
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
        evidence = _section_lines(sections, title)
        result[proto] = {"present": bool(evidence), "evidence": evidence[:_MAX_EVIDENCE]}
    return result


def parse_credentials(analysis_dir: Path) -> dict:
    cred_sections = parse_sections(read_file(analysis_dir / "credentials.txt"))
    def_sections  = parse_sections(read_file(analysis_dir / "default_credentials.txt"))
    ssh_sections  = parse_sections(read_file(analysis_dir / "ssh_keys.txt"))

    ssh_keys  = _section_lines(ssh_sections, "SSH Key Files Found")
    hardcoded = [
        line for line in _section_lines(cred_sections, "Passwords and Secrets (all config files)")
        if not line.startswith("Binary file")
    ][:_MAX_LIST]
    cloud_urls = _section_lines(cred_sections, "Cloud and Update Endpoints (all config files)")[:_MAX_LIST]
    defaults = (
        _section_lines(def_sections, "Default Passwords / SSIDs in Configs") +
        _section_lines(def_sections, "Default Credentials in Scripts")
    )[:_MAX_LIST]

    return {
        "hardcoded_in_configs": hardcoded,
        "default_credentials":  defaults,
        "ssh_key_files":        ssh_keys,
        "cloud_endpoints":      cloud_urls,
    }


def parse_weak_crypto(analysis_dir: Path) -> list:
    findings = []
    for title, body in parse_sections(read_file(analysis_dir / "weak_crypto.txt")).items():
        evidence = non_empty_lines(body)
        if evidence:
            findings.append({"context": title, "evidence": evidence[:_MAX_EVIDENCE]})
    return findings


def parse_debug(analysis_dir: Path) -> list:
    findings = []
    for title, body in parse_sections(read_file(analysis_dir / "debug_artifacts.txt")).items():
        items = non_empty_lines(body)
        if items:
            findings.append({"context": title, "items": items[:_MAX_ITEMS]})
    return findings


def parse_ipc(analysis_dir: Path) -> dict:
    sections = parse_sections(read_file(analysis_dir / "unix_sockets.txt"))
    return {
        "socket_files": _section_lines(sections, "Unix Socket Files"),
        "references":   _section_lines(sections, "Unix Socket References")[:_MAX_ITEMS],
    }


def parse_certs(analysis_dir: Path) -> dict:
    sections = parse_sections(read_file(analysis_dir / "certificates_keys.txt"))
    return {
        "files":               _section_lines(sections, "Certificate and Key Files"),
        "embedded_in_binaries": _section_lines(sections, "Embedded Keys / Certs in Files")[:_MAX_ITEMS],
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

    votes: dict = {}
    for line in read_file(analysis_dir / "binary_inventory.txt").splitlines():
        line = line.strip()
        if not line.startswith("type :"):
            continue
        m = _PAT.search(line.removeprefix("type :"))
        if not m:
            continue
        bits         = int(m.group(1))
        endian_short = m.group(2)
        arch_word    = m.group(3).strip().split()[0]
        arch         = _NAME.get(arch_word, arch_word)
        key          = (arch, bits, endian_short)
        votes[key]   = votes.get(key, 0) + 1

    if not votes:
        return _EMPTY

    dominant             = max(votes, key=votes.__getitem__)
    arch, bits, endian_short = dominant
    agreeing             = votes[dominant]
    total                = sum(votes.values())
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
        file_path = f.get("file", "")
        code = f.get("code", "")
        key = (file_path, code)
        if key in seen:
            continue
        seen.add(key)
        by_file.setdefault(file_path, []).append({
            "code":    code,
            "level":   lvl,
            "message": f.get("message", ""),
            "line":    f.get("line", 0),
        })

    return {"total": len(findings), "by_level": by_level, "by_file": by_file}


def parse_nvram(analysis_dir: Path) -> list:
    evidence = []
    for _, body in parse_sections(read_file(analysis_dir / "nvram.txt")).items():
        evidence.extend(non_empty_lines(body)[:_MAX_EVIDENCE])
    return evidence[:_MAX_LIST]
