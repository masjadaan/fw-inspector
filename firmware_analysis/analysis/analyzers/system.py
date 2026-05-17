import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa

from .context import AnalysisContext, section, existing, multi_section_file

# Known service binary names — used for init-script detection
_KNOWN_SERVICES = {"httpd", "sshd", "dropbear", "telnetd", "ftpd",
                   "tftpd", "snmpd", "upnpd", "dhcpd", "dnsd"}

_EMPTY_HASH = {"*", "!", "x", ""}
_MAX_EVIDENCE = 5
_MAX_ITEMS    = 10
_MAX_LIST     = 20

# ── SSH server config checks ──────────────────────────────────────────────────

# Each tuple: (canonical_directive, risky_value, severity, note).
# Matching is case-insensitive on both directive and value.
_SSHD_CHECKS: list[tuple[str, str, str, str]] = [
    ("PermitRootLogin",
     "yes",    "critical",
     "Direct root login enabled — credential compromise grants immediate root shell"),
    ("PermitEmptyPasswords",
     "yes",    "critical",
     "Accounts with empty passwords can log in — no credentials required"),
    ("Protocol",
     "1",      "high",
     "SSH protocol version 1 is cryptographically broken (weak key exchange, BEAST)"),
    ("PasswordAuthentication",
     "yes",    "medium",
     "Password-based auth enabled — exposes service to brute-force and credential-stuffing"),
    ("GatewayPorts",
     "yes",    "medium",
     "Remote port forwarding binds on all interfaces — can bypass firewall rules"),
    ("StrictModes",
     "no",     "medium",
     "Permission checks on key files disabled — world-writable authorized_keys accepted"),
    ("PermitUserEnvironment",
     "yes",    "medium",
     "Users may set env vars via authorized_keys — bypasses LD_PRELOAD / PATH restrictions"),
    ("IgnoreRhosts",
     "no",     "medium",
     "Rhosts/shosts files trusted — host-based authentication without passwords"),
    ("X11Forwarding",
     "yes",    "low",
     "X11 forwarding enabled — rarely needed on embedded devices, extends attack surface"),
]


def analyze_scripts(ctx: AnalysisContext):
    EXTENSIONS = {".sh", ".py", ".lua", ".pl", ".rb", ".php", ".js", ".expect"}
    found = sorted(
        p for p in ctx.rootfs.rglob("*")
        if p.is_file() and p.suffix.lower() in EXTENSIONS
    )

    index_file = ctx.out_dir / "scripts.txt"
    index_file.write_text("\n".join(str(p.relative_to(ctx.rootfs)) for p in found))
    print(f"  {'scripts.txt':45s}  {len(found)} files")

    sections = []
    for p in found:
        try:
            content = p.read_text(errors="replace")
        except Exception as e:
            content = f"(could not read: {e})"
        sections.append(
            f"{'=' * 60}\n"
            f"  {p.relative_to(ctx.rootfs)}  ({p.suffix})\n"
            f"{'=' * 60}\n"
            f"{content}\n"
        )
    content_file = ctx.out_dir / "scripts_content.txt"
    content_file.write_text("\n".join(sections))
    total_lines = sum(len(s.splitlines()) for s in sections)
    print(f"  {'scripts_content.txt':45s}  {total_lines} lines")


def analyze_systemd_services(ctx: AnalysisContext):
    found = sorted(ctx.rootfs.rglob("*.service"))

    index_file = ctx.out_dir / "services.txt"
    index_file.write_text("\n".join(str(p.relative_to(ctx.rootfs)) for p in found))
    print(f"  {'services.txt':45s}  {len(found)} files")

    if not found:
        return

    sections = []
    for p in found:
        try:
            content = p.read_text(errors="replace")
        except Exception as e:
            content = f"(could not read: {e})"
        sections.append(
            f"{'=' * 60}\n"
            f"  {p.relative_to(ctx.rootfs)}\n"
            f"{'=' * 60}\n"
            f"{content}\n"
        )
    content_file = ctx.out_dir / "services_content.txt"
    content_file.write_text("\n".join(sections))
    total_lines = sum(len(s.splitlines()) for s in sections)
    print(f"  {'services_content.txt':45s}  {total_lines} lines")


def analyze_init_scripts(ctx: AnalysisContext):
    out_file  = ctx.out_dir / "init_scripts.txt"
    json_file = ctx.out_dir / "init_scripts.json"
    init_dirs = existing(ctx.rootfs / "etc/init.d", ctx.rootfs / "etc/rc.d")

    _empty = {
        "detected_services": [], "explicit_ports": [], "has_command_injection": False,
        "injection_evidence": [], "has_hardcoded_creds": False,
        "vendor_services": [], "outbound_connections": [], "has_firewall_rules": False,
    }

    if not init_dirs:
        out_file.write_text("No init.d / rc.d directories found.\n")
        json_file.write_text(json.dumps(_empty, indent=2))
        print(f"  {'init_scripts.txt':45s}  no init dirs found")
        return

    captured = multi_section_file([
        ("Network-Exposed Services",
         ["grep", "-rE", "telnetd|ftpd|dropbear|sshd|httpd|dnsd|dhcpd|tftpd|snmpd|upnpd|tr069"] + init_dirs),
        ("Explicit Port Bindings",
         ["grep", "-rE", r"\-p\s+[0-9]+"] + init_dirs),
        ("Hardcoded Credentials",
         ["grep", "-rEi", "password|passwd|secret|admin|root|login|credential|token|key="] + init_dirs),
        ("Telnet and Debug Interfaces",
         ["grep", "-rE", r"telnetd|uart|ttyS[0-9]|console|debug_mode"] + init_dirs),
        ("Command Injection Vectors",
         ["grep", "-rE", r"eval|`|\$\(|IFS"] + init_dirs),
        ("Firewall Rules",
         ["grep", "-rE", "iptables|ip6tables|nftables|INPUT|ACCEPT|DROP"] + init_dirs),
        ("Outbound Connections",
         ["grep", "-rE", "wget|curl|tftp|ftp|tr069|cwmp|acs_url"] + init_dirs),
        ("Insecure File Permissions",
         ["grep", "-rE", r"chmod\s+(777|666|a\+w|o\+w)"] + init_dirs),
        ("Sensitive Data Written to /tmp",
         ["grep", "-rE", "/tmp|/var/run"] + init_dirs),
        ("Vendor-Specific Backdoor Services (TP-Link)",
         ["grep", "-rE", "tdpServer|tddp|cloud|onemesh|cwmp|omcid"] + init_dirs),
    ], out_file, "init_scripts.txt")

    combined = (
        " ".join(captured.get("Network-Exposed Services", [])) + " " +
        " ".join(captured.get("Telnet and Debug Interfaces", [])) + " " +
        " ".join(captured.get("Vendor-Specific Backdoor Services (TP-Link)", []))
    )
    port_raw         = "\n".join(captured.get("Explicit Port Bindings", []))
    injection_lines  = captured.get("Command Injection Vectors", [])
    creds_lines      = captured.get("Hardcoded Credentials", [])
    vendor_lines     = captured.get("Vendor-Specific Backdoor Services (TP-Link)", [])
    outbound_lines   = captured.get("Outbound Connections", [])
    firewall_lines   = captured.get("Firewall Rules", [])

    json_file.write_text(json.dumps({
        "detected_services":     [s for s in _KNOWN_SERVICES if s in combined],
        "explicit_ports":        list({int(p) for p in re.findall(r"-p\s+(\d+)", port_raw)}),
        "has_command_injection": bool(injection_lines),
        "injection_evidence":    injection_lines[:_MAX_EVIDENCE],
        "has_hardcoded_creds":   bool(creds_lines),
        "vendor_services":       vendor_lines[:_MAX_ITEMS],
        "outbound_connections":  outbound_lines[:_MAX_ITEMS],
        "has_firewall_rules":    bool(firewall_lines),
    }, indent=2))


def analyze_users_groups(ctx: AnalysisContext):
    out_file  = ctx.out_dir / "users_groups.txt"
    json_file = ctx.out_dir / "users_groups.json"

    HASH_ALGOS = {
        "$1$":  "MD5-crypt       [WEAK — crackable]",
        "$2a$": "bcrypt",
        "$2b$": "bcrypt",
        "$5$":  "SHA-256-crypt",
        "$6$":  "SHA-512-crypt",
        "$y$":  "yescrypt",
    }
    sections = []
    for name in ("etc/passwd", "etc/shadow", "etc/group"):
        p = ctx.rootfs / name
        sections.append(section(name, p.read_text(errors="replace") if p.exists() else "(not found)"))

    shadow_p = ctx.rootfs / "etc/shadow"
    shadow_hashes: dict = {}
    if shadow_p.exists():
        lines = []
        for line in shadow_p.read_text(errors="replace").splitlines():
            parts = line.split(":")
            if len(parts) < 2:
                continue
            user, pw = parts[0], parts[1]
            shadow_hashes[user] = pw
            if pw in ("*", "!"):
                status = "locked / no login"
            elif pw == "":
                status = "NO PASSWORD  [CRITICAL]"
            else:
                status = next((v for k, v in HASH_ALGOS.items() if pw.startswith(k)), "unknown algorithm")
            lines.append(f"  {user:20s}  {status}")
        sections.append(section("Password Hash Classification", "\n".join(lines)))

    out_file.write_text("".join(sections))
    print(f"  {'users_groups.txt':45s}  {sum(len(s.splitlines()) for s in sections)} lines")

    # Parse passwd + shadow into structured user list
    users = []
    passwd_p = ctx.rootfs / "etc/passwd"
    if passwd_p.exists():
        for line in passwd_p.read_text(errors="replace").splitlines():
            parts = line.split(":")
            if len(parts) < 7:
                continue
            name, pw, uid, gid, _, home, shell = parts[:7]
            effective = shadow_hashes.get(name, pw)
            users.append({
                "name":          name,
                "uid":           int(uid) if uid.isdigit() else uid,
                "gid":           int(gid) if gid.isdigit() else gid,
                "home":          home,
                "shell":         shell,
                "has_password":  effective not in _EMPTY_HASH,
                "password_hash": effective if effective not in _EMPTY_HASH else None,
            })

    json_file.write_text(json.dumps({"users": users}, indent=2))


def analyze_ssh_keys(ctx: AnalysisContext):
    out_file  = ctx.out_dir / "ssh_keys.txt"
    json_file = ctx.out_dir / "ssh_keys.json"

    r = subprocess.run(
        ["find", str(ctx.rootfs),
         "-name", "authorized_keys", "-o", "-name", "id_rsa", "-o", "-name", "id_ecdsa",
         "-o", "-name", "id_ed25519", "-o", "-name", "dropbear_*_host_key",
         "-o", "-name", "*.pub"],
        capture_output=True, text=True,
    )
    sections = [section("SSH Key Files Found", r.stdout)]
    key_files = [l.strip() for l in r.stdout.splitlines() if l.strip()]
    for path_str in key_files:
        p = Path(path_str)
        if p.is_file():
            sections.append(section(str(p.relative_to(ctx.rootfs)), p.read_text(errors="replace")))
    out_file.write_text("".join(sections))
    print(f"  {'ssh_keys.txt':45s}  {sum(len(s.splitlines()) for s in sections)} lines")

    json_file.write_text(json.dumps({"files": key_files}, indent=2))


def _parse_sshd_directives(text: str) -> dict[str, tuple[str, int]]:
    """Return {directive_lower: (value_lower, first_lineno)} from sshd_config text.

    First-occurrence-wins mirrors sshd behaviour: subsequent duplicate keys are ignored.
    Comment lines, blank lines, and lines without a value are skipped.
    Inline comments (everything after the first unquoted #) are stripped.
    """
    directives: dict[str, tuple[str, int]] = {}
    for lineno, raw_line in enumerate(text.splitlines(), 1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        code = stripped.split("#")[0].strip()
        parts = code.split(None, 1)
        if len(parts) < 2:
            continue
        key = parts[0].lower()
        if key not in directives:
            directives[key] = (parts[1].strip().lower(), lineno)
    return directives


def analyze_sshd_config(ctx: AnalysisContext):
    """Parse sshd_config files for dangerous SSH server settings."""
    out_file  = ctx.out_dir / "sshd_config.txt"
    json_file = ctx.out_dir / "sshd_config.json"

    config_paths = sorted(ctx.rootfs.rglob("sshd_config"))

    _empty = {
        "config_files": [],
        "findings":     [],
        "summary":      {"critical": 0, "high": 0, "medium": 0, "low": 0},
    }
    if not config_paths:
        out_file.write_text(section("SSH Server Configuration", "(no sshd_config found)"))
        json_file.write_text(json.dumps(_empty, indent=2))
        print(f"  {'sshd_config.txt':45s}  no sshd_config found")
        return

    config_files: list[str] = []
    findings: list[dict] = []

    for path in config_paths:
        try:
            content = path.read_text(errors="replace")
        except Exception:
            continue
        try:
            rel = str(path.relative_to(ctx.rootfs))
        except ValueError:
            rel = str(path)
        config_files.append(rel)

        directives = _parse_sshd_directives(content)
        for canonical, risky_val, severity, note in _SSHD_CHECKS:
            val_lineno = directives.get(canonical.lower())
            if val_lineno and val_lineno[0] == risky_val:
                findings.append({
                    "file":      rel,
                    "line":      val_lineno[1],
                    "directive": canonical,
                    "value":     val_lineno[0],
                    "severity":  severity,
                    "note":      note,
                })

    lines_out = []
    for f in findings:
        lines_out.append(f"  {f['file']}:{f['line']}")
        lines_out.append(f"    directive : {f['directive']} = {f['value']}")
        lines_out.append(f"    severity  : {f['severity']}")
        lines_out.append(f"    note      : {f['note']}")
        lines_out.append("")

    out_file.write_text(
        section(
            "SSH Server Configuration Issues  [dangerous sshd_config directives]",
            "\n".join(lines_out) if lines_out else "(none — no dangerous settings found)",
        )
    )

    summary: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        summary[f["severity"]] += 1

    json_file.write_text(json.dumps({
        "config_files": config_files,
        "findings":     findings,
        "summary":      summary,
    }, indent=2))

    n = len(findings)
    print(f"  {'sshd_config.txt':45s}  {len(config_files)} config file(s)  {n} finding(s)")
    if n:
        parts = "  ".join(f"{v} {k}" for k, v in sorted(summary.items()) if v)
        print(f"    → {parts}")


# ── inetd / xinetd service detection ─────────────────────────────────────────

# (service_name: (severity, note)) — matched case-insensitively.
_INETD_DANGEROUS: dict[str, tuple[str, str]] = {
    "telnet":  ("critical", "Telnet transmits credentials in plaintext — trivial MITM/sniff"),
    "rsh":     ("critical", "BSD rsh — unauthenticated remote shell, no encryption"),
    "rlogin":  ("critical", "BSD rlogin — host-based auth only, no encryption"),
    "rexec":   ("critical", "BSD rexec — password sent in cleartext over the wire"),
    "shell":   ("critical", "BSD rsh alias — unauthenticated remote shell, no encryption"),
    "login":   ("critical", "BSD rlogin alias — host-based auth only, no encryption"),
    "exec":    ("critical", "BSD rexec alias — plaintext password"),
    "ftp":     ("high",     "FTP transmits credentials in plaintext"),
    "tftp":    ("high",     "TFTP has no authentication — arbitrary file read/write possible"),
    "finger":  ("medium",   "Finger service discloses user account information"),
    "chargen": ("medium",   "Character generator — UDP reflection/amplification attack vector"),
    "echo":    ("medium",   "Echo service — reflection and amplification attack vector"),
    "pop2":    ("medium",   "POP2 — legacy plaintext mail protocol"),
    "pop3":    ("medium",   "POP3 — plaintext credentials unless STARTTLS is configured"),
    "imap":    ("medium",   "IMAP — plaintext credentials unless STARTTLS is configured"),
    "comsat":  ("low",      "Comsat/biff — may disclose mail activity, rarely needed"),
    "talk":    ("low",      "Talk service — unnecessary attack surface on embedded devices"),
    "ntalk":   ("low",      "Ntalk service — unnecessary attack surface on embedded devices"),
    "daytime": ("low",      "Daytime service — discloses system clock, unnecessary"),
    "time":    ("low",      "Time protocol (port 37) — unnecessary attack surface"),
    "discard": ("low",      "Discard service — unnecessary attack surface"),
}


def _parse_inetd_conf(text: str, source: str) -> list[dict]:
    """Parse /etc/inetd.conf format into a list of service dicts.

    Each non-comment, non-blank line: service socket_type protocol wait user server [args...]
    Lines with fewer than 6 fields are skipped (malformed or comments with leading spaces).
    Service names may carry a /protocol suffix (e.g. "ftp/tcp") — only the base name is kept.
    """
    services = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) < 6:
            continue
        name_raw, socket_type, protocol, wait, user, server = parts[:6]
        args = parts[6:]
        services.append({
            "source":      source,
            "format":      "inetd",
            "name":        name_raw.lower().split("/")[0],
            "socket_type": socket_type,
            "protocol":    protocol,
            "wait":        wait,
            "user":        user,
            "server":      server,
            "args":        args,
            "disabled":    False,
        })
    return services


def _parse_xinetd_blocks(text: str, source: str) -> list[dict]:
    """Parse xinetd config format into a list of service dicts.

    Extracts "service <name> { ... }" blocks. Within each block, "disable = yes"
    marks the service as inactive (mirroring xinetd runtime behaviour).
    """
    services = []
    for block in re.finditer(r"service\s+(\S+)\s*\{([^}]*)\}", text, re.DOTALL | re.IGNORECASE):
        name = block.group(1).lower()
        body = block.group(2)

        directives: dict[str, str] = {}
        for line in body.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if "=" in stripped:
                k, _, v = stripped.partition("=")
                key = k.strip().lower().rstrip("+").strip()
                val = v.strip().split("#")[0].strip().lower()
                if key not in directives:
                    directives[key] = val

        disabled = directives.get("disable", "no") in ("yes", "true", "1")
        services.append({
            "source":      source,
            "format":      "xinetd",
            "name":        name,
            "socket_type": directives.get("socket_type", ""),
            "protocol":    directives.get("protocol", "tcp"),
            "user":        directives.get("user", ""),
            "server":      directives.get("server", ""),
            "only_from":   directives.get("only_from", ""),
            "disabled":    disabled,
        })
    return services


def analyze_inetd(ctx: AnalysisContext):
    """Detect services registered in inetd.conf and xinetd configuration files."""
    out_file  = ctx.out_dir / "inetd.txt"
    json_file = ctx.out_dir / "inetd.json"

    _empty = {
        "config_files": [],
        "services":     [],
        "findings":     [],
        "summary":      {"critical": 0, "high": 0, "medium": 0, "low": 0},
    }

    # Collect all inetd / xinetd config paths with their format tag.
    config_paths: list[tuple[Path, str]] = []

    for rel in ("etc/inetd.conf",):
        p = ctx.rootfs / rel
        if p.is_file():
            config_paths.append((p, "inetd"))

    inetd_d = ctx.rootfs / "etc/inetd.d"
    if inetd_d.is_dir():
        for p in sorted(inetd_d.iterdir()):
            if p.is_file():
                config_paths.append((p, "inetd"))

    xinetd_conf = ctx.rootfs / "etc/xinetd.conf"
    if xinetd_conf.is_file():
        config_paths.append((xinetd_conf, "xinetd"))

    xinetd_d = ctx.rootfs / "etc/xinetd.d"
    if xinetd_d.is_dir():
        for p in sorted(xinetd_d.iterdir()):
            if p.is_file():
                config_paths.append((p, "xinetd"))

    if not config_paths:
        out_file.write_text(section("inetd / xinetd Services", "(no inetd or xinetd config found)"))
        json_file.write_text(json.dumps(_empty, indent=2))
        print(f"  {'inetd.txt':45s}  no inetd/xinetd config found")
        return

    all_services: list[dict] = []
    config_files: list[str] = []

    for path, fmt in config_paths:
        try:
            content = path.read_text(errors="replace")
        except Exception:
            continue
        try:
            rel = str(path.relative_to(ctx.rootfs))
        except ValueError:
            rel = str(path)
        config_files.append(rel)

        if fmt == "inetd":
            all_services.extend(_parse_inetd_conf(content, rel))
        else:
            all_services.extend(_parse_xinetd_blocks(content, rel))

    findings: list[dict] = []
    for svc in all_services:
        if svc.get("disabled"):
            continue
        name = svc["name"]
        if name in _INETD_DANGEROUS:
            severity, note = _INETD_DANGEROUS[name]
            findings.append({
                "file":     svc["source"],
                "service":  name,
                "server":   svc.get("server", ""),
                "user":     svc.get("user", ""),
                "severity": severity,
                "note":     note,
            })

    summary: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        summary[f["severity"]] += 1

    finding_lines: list[str] = []
    for f in findings:
        finding_lines.extend([
            f"  {f['file']}",
            f"    service  : {f['service']}",
            f"    server   : {f['server']}",
            f"    user     : {f['user']}",
            f"    severity : {f['severity']}",
            f"    note     : {f['note']}",
            "",
        ])

    svc_lines: list[str] = []
    for svc in all_services:
        status = "DISABLED" if svc.get("disabled") else "active"
        svc_lines.append(
            f"  [{status:8s}] {svc['name']:20s}"
            f" {svc.get('server', ''):40s}  user={svc.get('user', '-')}"
        )

    out_file.write_text(
        section(
            "inetd / xinetd Services  [dangerous service detection]",
            "\n".join(finding_lines) if finding_lines else "(none — no dangerous services found)",
        ) +
        section(
            "All Registered Services",
            "\n".join(svc_lines) if svc_lines else "(none)",
        )
    )

    json_file.write_text(json.dumps({
        "config_files": config_files,
        "services":     all_services,
        "findings":     findings,
        "summary":      summary,
    }, indent=2))

    n = len(findings)
    total = len(all_services)
    print(f"  {'inetd.txt':45s}  {len(config_files)} config file(s)  {total} service(s)  {n} finding(s)")
    if n:
        parts = "  ".join(f"{v} {k}" for k, v in sorted(summary.items()) if v)
        print(f"    → {parts}")


# ── Kernel sysctl hardening parameters ───────────────────────────────────────

# Each entry: (param, insecure_value, severity, note).
# Flagged when the parameter IS present with the insecure value.
_SYSCTL_CHECKS: list[tuple[str, str, str, str]] = [
    ("kernel.randomize_va_space",
     "0", "critical",
     "ASLR disabled — memory layout is predictable, exploit mitigations ineffective"),
    ("net.ipv4.tcp_syncookies",
     "0", "high",
     "SYN cookies disabled — host is vulnerable to SYN flood DoS attacks"),
    ("net.ipv4.conf.all.accept_redirects",
     "1", "high",
     "ICMP redirect acceptance enabled — routing table can be manipulated by a MITM"),
    ("net.ipv4.conf.default.accept_redirects",
     "1", "high",
     "ICMP redirect acceptance enabled on default interface — routing table manipulable"),
    ("net.ipv6.conf.all.accept_redirects",
     "1", "high",
     "IPv6 ICMP redirect acceptance enabled — routing table can be manipulated"),
    ("net.ipv4.conf.all.send_redirects",
     "1", "medium",
     "Host sends ICMP redirects — can redirect traffic on the local network segment"),
    ("net.ipv4.conf.all.rp_filter",
     "0", "medium",
     "Reverse path filtering disabled — IP source address spoofing not mitigated"),
    ("kernel.dmesg_restrict",
     "0", "medium",
     "Kernel log readable by unprivileged users — may expose kernel addresses and info"),
    ("kernel.kptr_restrict",
     "0", "medium",
     "Kernel pointer values exposed in /proc — aids exploitation of kernel vulnerabilities"),
    ("net.ipv4.conf.all.accept_source_route",
     "1", "medium",
     "IP source routing accepted — attacker can specify packet path, bypassing firewalls"),
    ("net.ipv4.conf.all.log_martians",
     "0", "low",
     "Martian packet logging disabled — spoofed or invalid source packets not logged"),
    ("kernel.sysrq",
     "1", "low",
     "SysRq keys fully enabled — physical attacker can crash/reboot/dump the system"),
]

# Each entry: (param, severity, note).
# Flagged when the parameter is absent from ALL sysctl config files found.
# Embedded kernels often ship with these parameters at their unsafe defaults.
_SYSCTL_ABSENT_CHECKS: list[tuple[str, str, str]] = [
    ("kernel.randomize_va_space", "critical",
     "ASLR (kernel.randomize_va_space) not configured — embedded kernels often default "
     "to 0 (disabled), making memory layout predictable and exploit mitigations ineffective"),
    ("net.ipv4.tcp_syncookies", "high",
     "SYN cookies (net.ipv4.tcp_syncookies) not configured — host may be vulnerable "
     "to SYN flood DoS attacks if the kernel default is 0"),
]


def _parse_sysctl_conf(text: str) -> dict[str, tuple[str, int]]:
    """Return {param: (value, first_lineno)} from sysctl.conf-format text.

    Supports 'key = value' and 'key=value'. Comments (#, ;) and blank lines skipped.
    Inline # and ; comments stripped. First-occurrence-wins per file.
    """
    params: dict[str, tuple[str, int]] = {}
    for lineno, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()
        if not stripped or stripped[0] in ("#", ";"):
            continue
        code = stripped.split("#")[0].split(";")[0].strip()
        if "=" not in code:
            continue
        key, _, val = code.partition("=")
        key = key.strip().lower()
        val = val.strip()
        if key and val and key not in params:
            params[key] = (val, lineno)
    return params


def analyze_sysctl(ctx: AnalysisContext):
    """Scan sysctl config files for insecure or absent kernel hardening parameters."""
    out_file  = ctx.out_dir / "sysctl.txt"
    json_file = ctx.out_dir / "sysctl.json"

    seen: set[Path] = set()
    config_paths: list[Path] = []

    def _add(p: Path) -> None:
        if p not in seen and p.is_file():
            seen.add(p)
            config_paths.append(p)

    for p in sorted(ctx.rootfs.rglob("sysctl.conf")):
        _add(p)

    for sysctl_d in [
        ctx.rootfs / "etc/sysctl.d",
        ctx.rootfs / "usr/lib/sysctl.d",
        ctx.rootfs / "lib/sysctl.d",
    ]:
        if sysctl_d.is_dir():
            for p in sorted(sysctl_d.iterdir()):
                if p.suffix == ".conf":
                    _add(p)

    config_files: list[str] = []
    findings: list[dict] = []
    all_params: set[str] = set()

    for path in config_paths:
        try:
            content = path.read_text(errors="replace")
        except Exception:
            continue
        try:
            rel = str(path.relative_to(ctx.rootfs))
        except ValueError:
            rel = str(path)
        config_files.append(rel)

        parsed = _parse_sysctl_conf(content)
        all_params.update(parsed.keys())

        for param, insecure_val, severity, note in _SYSCTL_CHECKS:
            val_lineno = parsed.get(param.lower())
            if val_lineno and val_lineno[0] == insecure_val:
                findings.append({
                    "type":      "explicit",
                    "file":      rel,
                    "line":      val_lineno[1],
                    "parameter": param,
                    "value":     val_lineno[0],
                    "severity":  severity,
                    "note":      note,
                })

    # Always run absent checks — embedded kernels default to unsafe values.
    for param, severity, note in _SYSCTL_ABSENT_CHECKS:
        if param.lower() not in all_params:
            findings.append({
                "type":      "absent",
                "parameter": param,
                "severity":  severity,
                "note":      note,
            })

    summary: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        summary[f["severity"]] += 1

    lines_out: list[str] = []
    for f in findings:
        if f["type"] == "explicit":
            lines_out.extend([
                f"  {f['file']}:{f['line']}",
                f"    parameter : {f['parameter']} = {f['value']}",
                f"    severity  : {f['severity']}",
                f"    note      : {f['note']}",
                "",
            ])
        else:
            lines_out.extend([
                f"  [NOT CONFIGURED]",
                f"    parameter : {f['parameter']}",
                f"    severity  : {f['severity']}",
                f"    note      : {f['note']}",
                "",
            ])

    header = (
        "Kernel sysctl Hardening Issues  [insecure / absent parameters]"
        if config_files else
        "Kernel sysctl Hardening  [no sysctl config found — absent-parameter checks still apply]"
    )
    out_file.write_text(
        section(header, "\n".join(lines_out) if lines_out else "(none — no dangerous settings found)")
    )

    json_file.write_text(json.dumps({
        "config_files": config_files,
        "findings":     findings,
        "summary":      summary,
    }, indent=2))

    n         = len(findings)
    explicit_n = sum(1 for f in findings if f["type"] == "explicit")
    absent_n   = sum(1 for f in findings if f["type"] == "absent")

    if config_files:
        print(f"  {'sysctl.txt':45s}  {len(config_files)} config file(s)  {n} finding(s)  ({explicit_n} explicit  {absent_n} absent)")
    else:
        print(f"  {'sysctl.txt':45s}  no sysctl config found  {absent_n} absent finding(s)")
    if n:
        parts = "  ".join(f"{v} {k}" for k, v in sorted(summary.items()) if v)
        print(f"    → {parts}")


def analyze_credentials(ctx: AnalysisContext):
    json_file = ctx.out_dir / "credentials.json"
    captured = multi_section_file([
        ("Passwords and Secrets (all config files)",
         ["grep", "-Ei", "password|passwd|secret|community|apikey|token|key="] + ctx.configs),
        ("Hardcoded IP Addresses (all config files)",
         ["grep", "-E", r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"] + ctx.configs),
        ("Cloud and Update Endpoints (all config files)",
         ["grep", "-E", r"https?://"] + ctx.configs),
    ], ctx.out_dir / "credentials.txt", "credentials.txt")

    hardcoded = [
        l for l in captured.get("Passwords and Secrets (all config files)", [])
        if not l.startswith("Binary file")
    ][:_MAX_LIST]
    cloud_urls = captured.get("Cloud and Update Endpoints (all config files)", [])[:_MAX_LIST]

    json_file.write_text(json.dumps({
        "hardcoded_in_configs": hardcoded,
        "cloud_endpoints":      cloud_urls,
    }, indent=2))


def analyze_default_credentials(ctx: AnalysisContext):
    json_file = ctx.out_dir / "default_credentials.json"
    captured = multi_section_file([
        ("Default Passwords / SSIDs in Configs",
         ["grep", "-Ei", r"admin|default.*pass|ssid|tplink|admin123|password=admin"] + ctx.configs),
        ("Default Credentials in Scripts",
         ["grep", "-rEi", r"admin|default.*pass|ssid|tplink|admin123",
          str(ctx.rootfs / "etc")] if (ctx.rootfs / "etc").exists() else []),
    ], ctx.out_dir / "default_credentials.txt", "default_credentials.txt")

    defaults = (
        captured.get("Default Passwords / SSIDs in Configs", []) +
        captured.get("Default Credentials in Scripts", [])
    )[:_MAX_LIST]

    json_file.write_text(json.dumps({"defaults": defaults}, indent=2))


def analyze_debug_artifacts(ctx: AnalysisContext):
    json_file = ctx.out_dir / "debug_artifacts.json"
    captured = multi_section_file([
        ("Debug / Test / Factory Files",
         ["find", str(ctx.rootfs), "-iname", "*debug*", "-o", "-iname", "*test*",
          "-o", "-iname", "*factory*", "-o", "-iname", "*diag*"]),
        ("Debug References in Configs",
         ["grep", "-rEi", "debug|verbose|factory|test.mode|diagnostic",
          str(ctx.rootfs / "etc")] if (ctx.rootfs / "etc").exists() else []),
    ], ctx.out_dir / "debug_artifacts.txt", "debug_artifacts.txt")

    findings = [
        {"context": title, "items": lines[:_MAX_ITEMS]}
        for title, lines in captured.items()
        if lines
    ]
    json_file.write_text(json.dumps(findings, indent=2))


def analyze_dns_routing(ctx: AnalysisContext):
    out_file = ctx.out_dir / "dns_routing.txt"
    sections = []
    for name in ("etc/hosts", "etc/resolv.conf", "etc/resolv.conf.d"):
        p = ctx.rootfs / name
        if p.is_file():
            sections.append(section(name, p.read_text(errors="replace")))
        elif p.is_dir():
            for f in p.iterdir():
                sections.append(section(str(f.relative_to(ctx.rootfs)), f.read_text(errors="replace")))
    if not sections:
        sections.append(section("DNS / Routing", "(no hosts or resolv.conf found)"))
    out_file.write_text("".join(sections))
    print(f"  {'dns_routing.txt':45s}  {sum(len(s.splitlines()) for s in sections)} lines")


def analyze_firewall_rules(ctx: AnalysisContext):
    out_file = ctx.out_dir / "firewall_rules.txt"
    r = subprocess.run(
        ["find", str(ctx.rootfs), "-name", "iptables.conf", "-o", "-name", "firewall*",
         "-o", "-name", "nftables*", "-o", "-name", "ip6tables*"],
        capture_output=True, text=True,
    )
    sections = [section("Firewall Config Files Found", r.stdout)]
    for path_str in r.stdout.strip().splitlines():
        p = Path(path_str)
        if p.is_file():
            sections.append(section(str(p.relative_to(ctx.rootfs)), p.read_text(errors="replace")))
    out_file.write_text("".join(sections))
    print(f"  {'firewall_rules.txt':45s}  {sum(len(s.splitlines()) for s in sections)} lines")


def analyze_scheduled_tasks(ctx: AnalysisContext):
    out_file = ctx.out_dir / "scheduled_tasks.txt"
    r = subprocess.run(["find", str(ctx.rootfs), "-path", "*/cron*"], capture_output=True, text=True)
    sections = [section("Cron Files Found", r.stdout)]
    for f in list(ctx.rootfs.rglob("crontab")) + list(ctx.rootfs.rglob("cron.d")):
        if f.is_file():
            sections.append(section(str(f.relative_to(ctx.rootfs)), f.read_text(errors="replace")))
    out_file.write_text("".join(sections))
    print(f"  {'scheduled_tasks.txt':45s}  {sum(len(s.splitlines()) for s in sections)} lines")


def analyze_mount_points(ctx: AnalysisContext):
    out_file = ctx.out_dir / "mount_points.txt"
    VOLATILE  = {"tmpfs", "overlayfs", "overlay", "ramfs"}
    SENSITIVE = {"/etc", "/var", "/sbin", "/bin", "/usr", "/lib"}
    all_sections = []
    for name in ("etc/fstab", "etc/mtab"):
        p = ctx.rootfs / name
        if p.exists():
            content = p.read_text(errors="replace")
            all_sections.append(section(name, content))
            risky = [
                l for l in content.splitlines()
                if any(v in l.lower() for v in VOLATILE) and any(s in l for s in SENSITIVE)
            ]
            if risky:
                all_sections.append(section(
                    f"Writable Overlay on Sensitive Path ({name})", "\n".join(risky)
                ))
        else:
            all_sections.append(section(name, "(not found)"))
    out_file.write_text("".join(all_sections))
    print(f"  {'mount_points.txt':45s}  {sum(len(s.splitlines()) for s in all_sections)} lines")


def analyze_firmware_update(ctx: AnalysisContext):
    multi_section_file([
        ("Update / Upgrade References",
         ["grep", "-Ei", "upgrade|update|firmware|download"] + ctx.configs),
        ("Checksum / Signature Verification",
         ["grep", "-Ei", "checksum|verify|signature|md5|sha"] + ctx.configs),
        ("TP-Link Cloud / Update URLs",
         ["grep", "-Ei", r"tplinkcloud|tplinkwifi|tp-link\.com|devs\.tplinkcloud"] + ctx.configs),
    ], ctx.out_dir / "firmware_update.txt", "firmware_update.txt")


def analyze_certificates(ctx: AnalysisContext):
    out_file  = ctx.out_dir / "certificates_keys.txt"
    json_file = ctx.out_dir / "certificates_keys.json"

    r = subprocess.run(
        ["find", str(ctx.rootfs), "-name", "*.pem", "-o", "-name", "*.key",
         "-o", "-name", "*.crt", "-o", "-name", "*.p12", "-o", "-name", "*.der"],
        capture_output=True, text=True,
    )
    r2 = subprocess.run(
        ["grep", "-rE", "BEGIN (RSA|EC|PRIVATE|CERTIFICATE)", str(ctx.rootfs)],
        capture_output=True, text=True,
    )
    out_file.write_text(
        section("Certificate and Key Files", r.stdout) +
        section("Embedded Keys / Certs in Files", r2.stdout)
    )
    print(f"  {'certificates_keys.txt':45s}  {len(r.stdout.strip().splitlines()) + len(r2.stdout.strip().splitlines())} lines")

    cert_files = [l.strip() for l in r.stdout.splitlines()  if l.strip()]
    embedded   = [l.strip() for l in r2.stdout.splitlines() if l.strip()][:_MAX_ITEMS]
    json_file.write_text(json.dumps({"files": cert_files, "embedded_in_binaries": embedded}, indent=2))


def _parse_cert_file(path: Path) -> list[dict]:
    """Parse X.509 certificate(s) from a PEM or DER file.

    Returns a list of dicts (one per cert found). Returns [] if the file
    contains no parseable X.509 certificate (e.g. private key, PKCS#12).
    """
    try:
        data = path.read_bytes()
    except Exception:
        return []

    certs = []
    if b"-----BEGIN CERTIFICATE-----" in data:
        for block in re.findall(
            b"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", data, re.DOTALL
        ):
            try:
                certs.append(x509.load_pem_x509_certificate(block))
            except Exception:
                pass
    if not certs:
        try:
            certs.append(x509.load_der_x509_certificate(data))
        except Exception:
            pass
    if not certs:
        return []

    now = datetime.now(timezone.utc)
    results = []
    for cert in certs:
        pub = cert.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            key_type, key_bits = "RSA", pub.key_size
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            key_type, key_bits = "EC", pub.key_size
        elif isinstance(pub, dsa.DSAPublicKey):
            key_type, key_bits = "DSA", pub.key_size
        else:
            key_type, key_bits = "unknown", None

        try:
            not_after  = cert.not_valid_after_utc
            not_before = cert.not_valid_before_utc
        except AttributeError:
            not_after  = cert.not_valid_after.replace(tzinfo=timezone.utc)
            not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)

        try:
            subject = cert.subject.rfc4514_string()
            issuer  = cert.issuer.rfc4514_string()
        except Exception:
            subject = str(cert.subject)
            issuer  = str(cert.issuer)

        results.append({
            "subject":     subject,
            "issuer":      issuer,
            "not_before":  not_before.isoformat(),
            "not_after":   not_after.isoformat(),
            "key_type":    key_type,
            "key_bits":    key_bits,
            "expired":     not_after < now,
            "self_signed": subject == issuer,
            "weak_key":    key_type == "RSA" and key_bits is not None and key_bits <= 1024,
        })
    return results


def analyze_certificate_issues(ctx: AnalysisContext):
    """Parse X.509 certificates and report expired, self-signed, and weak-key findings."""
    out_file  = ctx.out_dir / "certificate_issues.txt"
    json_file = ctx.out_dir / "certificate_issues.json"

    r = subprocess.run(
        ["find", str(ctx.rootfs),
         "-name", "*.pem", "-o", "-name", "*.crt", "-o", "-name", "*.der", "-o", "-name", "*.cer"],
        capture_output=True, text=True,
    )
    cert_paths = [Path(l.strip()) for l in r.stdout.splitlines() if l.strip()]

    findings = []
    for path in cert_paths:
        infos = _parse_cert_file(path)
        try:
            rel = str(path.relative_to(ctx.rootfs))
        except ValueError:
            rel = str(path)
        for info in infos:
            flags = []
            if info["expired"]:
                flags.append("expired")
            if info["self_signed"]:
                flags.append("self-signed")
            if info["weak_key"]:
                flags.append(f"weak-key ({info['key_type']} {info['key_bits']}-bit)")
            if flags:
                findings.append({
                    "file":     rel,
                    "flags":    flags,
                    "subject":  info["subject"],
                    "issuer":   info["issuer"],
                    "not_after": info["not_after"],
                    "key_type": info["key_type"],
                    "key_bits": info["key_bits"],
                })

    lines = []
    for f in findings:
        lines.append(f"  {f['file']}")
        lines.append(f"    flags   : {', '.join(f['flags'])}")
        lines.append(f"    subject : {f['subject']}")
        lines.append(f"    expires : {f['not_after']}")
        lines.append(f"    key     : {f['key_type']} {f['key_bits']}-bit")
        lines.append("")

    out_file.write_text(
        section(
            "Certificate Issues  [expired / self-signed / weak-key]",
            "\n".join(lines) if lines else "(none)",
        )
    )
    json_file.write_text(json.dumps(findings, indent=2))
    n = len(findings)
    print(f"  {'certificate_issues.txt':45s}  {n} findings across {len(cert_paths)} cert files")
    if n:
        by_flag: dict = {}
        for f in findings:
            for flag in f["flags"]:
                key = flag.split(" ")[0]
                by_flag[key] = by_flag.get(key, 0) + 1
        print("    → " + "  ".join(f"{v} {k}" for k, v in sorted(by_flag.items())))


def analyze_unix_sockets(ctx: AnalysisContext):
    out_file  = ctx.out_dir / "unix_sockets.txt"
    json_file = ctx.out_dir / "unix_sockets.json"

    r1 = subprocess.run(
        ["find", str(ctx.rootfs), "-name", "*.sock", "-o", "-name", "*.socket"],
        capture_output=True, text=True,
    )
    etc_usr = existing(ctx.rootfs / "etc", ctx.rootfs / "usr")
    r2 = subprocess.run(
        ["grep", "-rE", r"AF_UNIX|SOCK_STREAM|/var/run/.*\.sock"] + etc_usr,
        capture_output=True, text=True,
    )
    out_file.write_text(section("Unix Socket Files", r1.stdout) + section("Unix Socket References", r2.stdout))
    print(f"  {'unix_sockets.txt':45s}  {len(r1.stdout.strip().splitlines()) + len(r2.stdout.strip().splitlines())} lines")

    socket_files = [l.strip() for l in r1.stdout.splitlines() if l.strip()]
    references   = [l.strip() for l in r2.stdout.splitlines() if l.strip()][:_MAX_ITEMS]
    json_file.write_text(json.dumps({"socket_files": socket_files, "references": references}, indent=2))


def analyze_nvram(ctx: AnalysisContext):
    json_file = ctx.out_dir / "nvram.json"
    captured = multi_section_file([
        ("nvram_get / nvram_set calls",
         ["grep", "-rE", "nvram_get|nvram_set|nvram get|nvram set", str(ctx.rootfs)]),
        ("NVRAM key references",
         ["grep", "-rE", r"nvram\s+\w+", str(ctx.rootfs)]),
    ], ctx.out_dir / "nvram.txt", "nvram.txt")

    evidence: list = []
    for lines in captured.values():
        evidence.extend(lines[:_MAX_EVIDENCE])
    json_file.write_text(json.dumps({"evidence": evidence[:_MAX_LIST]}, indent=2))


def analyze_world_writable(ctx: AnalysisContext):
    json_file = ctx.out_dir / "world_writable.json"
    captured = multi_section_file([
        ("World-Writable Files",
         ["find", str(ctx.rootfs), "-type", "f", "-perm", "-002"]),
        ("World-Writable Directories",
         ["find", str(ctx.rootfs), "-type", "d", "-perm", "-002"]),
        ("SetGID Binaries",
         ["find", str(ctx.rootfs), "-perm", "-2000"]),
    ], ctx.out_dir / "world_writable.txt", "world_writable.txt")

    json_file.write_text(json.dumps({
        "files":  captured.get("World-Writable Files", []),
        "dirs":   captured.get("World-Writable Directories", []),
        "setgid": captured.get("SetGID Binaries", []),
    }, indent=2))
