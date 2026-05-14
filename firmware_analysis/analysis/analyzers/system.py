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
