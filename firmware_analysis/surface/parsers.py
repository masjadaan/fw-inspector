"""Parse analyze.py output files into typed dicts for the attack surface model.

All functions read structured JSON sidecars produced by the analyzers.
Two exceptions remain text-based because their format is determined by OS
commands (find / getcap), not by our own code:
  - parse_setuid()      reads setuid_binaries.txt  (find -perm -4000 output)
  - parse_capabilities() reads capabilities.txt     (getcap -r output)
"""

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

_MAX_EVIDENCE = 5   # shared with attack_paths

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


# ── Helpers ───────────────────────────────────────────────────────────────────

def _load(path: Path, default):
    """Read a JSON file; return default if missing or malformed."""
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return default


def non_empty_lines(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip()]


# ── Parsers ───────────────────────────────────────────────────────────────────

def parse_users(analysis_dir: Path) -> list[User]:
    return _load(analysis_dir / "users_groups.json", {}).get("users", [])


def parse_setuid(analysis_dir: Path) -> list[str]:
    path = analysis_dir / "setuid_binaries.txt"
    return non_empty_lines(path.read_text(errors="replace") if path.exists() else "")


def parse_capabilities(analysis_dir: Path) -> list:
    caps = []
    path = analysis_dir / "capabilities.txt"
    if not path.exists():
        return caps
    for line in path.read_text(errors="replace").splitlines():
        m = re.match(r"^(.+?)\s*=\s*(.+)$", line.strip())
        if m:
            caps.append({"path": m.group(1).strip(), "capabilities": m.group(2).strip()})
    return caps


def parse_world_writable(analysis_dir: Path) -> dict:
    return _load(analysis_dir / "world_writable.json",
                 {"files": [], "dirs": [], "setgid": []})


def parse_init_services(analysis_dir: Path) -> dict:
    return _load(analysis_dir / "init_scripts.json", {
        "detected_services": [], "explicit_ports": [], "has_command_injection": False,
        "injection_evidence": [], "has_hardcoded_creds": False,
        "vendor_services": [], "outbound_connections": [], "has_firewall_rules": False,
    })


def parse_web(analysis_dir: Path) -> dict:
    wi = _load(analysis_dir / "web_interface.json",      {})
    ws = _load(analysis_dir / "web_server_configs.json", {})
    hb = _load(analysis_dir / "httpd_binaries.json",     {})
    return {
        "httpd_binaries": hb.get("binaries",      []),
        "cgi_scripts":    wi.get("cgi_scripts",   []),
        "lua_handlers":   wi.get("lua_handlers",  []),
        "api_endpoints":  wi.get("api_endpoints", []),
        "config_files":   ws.get("config_files",  []),
        "inferred_ports": ws.get("inferred_ports", [80]),
    }


def parse_protocols(analysis_dir: Path) -> dict:
    default = {p: {"present": False, "evidence": []} for p in ("snmp", "upnp", "tr069", "mqtt")}
    return _load(analysis_dir / "protocols.json", default)


def parse_credentials(analysis_dir: Path) -> dict:
    cred = _load(analysis_dir / "credentials.json",         {})
    dfl  = _load(analysis_dir / "default_credentials.json", {})
    ssh  = _load(analysis_dir / "ssh_keys.json",            {})
    return {
        "hardcoded_in_configs": cred.get("hardcoded_in_configs", []),
        "default_credentials":  dfl.get("defaults", []),
        "ssh_key_files":        ssh.get("files", []),
        "cloud_endpoints":      cred.get("cloud_endpoints", []),
    }


def parse_weak_crypto(analysis_dir: Path) -> list:
    return _load(analysis_dir / "weak_crypto.json", [])


def parse_debug(analysis_dir: Path) -> list:
    return _load(analysis_dir / "debug_artifacts.json", [])


def parse_ipc(analysis_dir: Path) -> dict:
    return _load(analysis_dir / "unix_sockets.json",
                 {"socket_files": [], "references": []})


def parse_certs(analysis_dir: Path) -> dict:
    return _load(analysis_dir / "certificates_keys.json",
                 {"files": [], "embedded_in_binaries": []})


def parse_architecture(analysis_dir: Path) -> dict:
    return _load(analysis_dir / "architecture.json", {
        "arch": "unknown", "bits": 0, "endianness": "unknown",
        "endianness_short": "?", "confidence": 0.0, "elf_count": 0,
    })


def parse_hardening(analysis_dir: Path) -> dict:
    return _load(analysis_dir / "hardening.json", {"summary": {}, "binaries": []})


def parse_shellcheck(analysis_dir: Path) -> dict:
    findings = _load(analysis_dir / "shellcheck.json", [])
    if not isinstance(findings, list):
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
    return _load(analysis_dir / "nvram.json", {"evidence": []}).get("evidence", [])


def parse_dangerous_functions(analysis_dir: Path) -> list:
    return _load(analysis_dir / "dangerous_functions.json", [])


def parse_certificate_issues(analysis_dir: Path) -> list:
    return _load(analysis_dir / "certificate_issues.json", [])


def parse_tls_config_issues(analysis_dir: Path) -> list:
    return _load(analysis_dir / "tls_config_issues.json", [])
