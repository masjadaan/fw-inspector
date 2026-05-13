import subprocess
from pathlib import Path

from .context import AnalysisContext, section, existing, multi_section_file


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
    out_file = ctx.out_dir / "init_scripts.txt"
    init_dirs = existing(ctx.rootfs / "etc/init.d", ctx.rootfs / "etc/rc.d")
    if not init_dirs:
        out_file.write_text("No init.d / rc.d directories found.\n")
        print(f"  {'init_scripts.txt':45s}  no init dirs found")
        return
    multi_section_file([
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


def analyze_users_groups(ctx: AnalysisContext):
    out_file = ctx.out_dir / "users_groups.txt"
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
    if shadow_p.exists():
        lines = []
        for line in shadow_p.read_text(errors="replace").splitlines():
            parts = line.split(":")
            if len(parts) < 2:
                continue
            user, pw = parts[0], parts[1]
            if pw in ("*", "!"):
                status = "locked / no login"
            elif pw == "":
                status = "NO PASSWORD  [CRITICAL]"
            else:
                status = next((v for k, v in HASH_ALGOS.items() if pw.startswith(k)), "unknown algorithm")
            lines.append(f"  {user:20s}  {status}")
        sections.append(section("Password Hash Classification", "\n".join(lines)))

    out_file.write_text("".join(sections))
    total = sum(len(s.splitlines()) for s in sections)
    print(f"  {'users_groups.txt':45s}  {total} lines")


def analyze_ssh_keys(ctx: AnalysisContext):
    out_file = ctx.out_dir / "ssh_keys.txt"
    r = subprocess.run(
        ["find", str(ctx.rootfs),
         "-name", "authorized_keys", "-o", "-name", "id_rsa", "-o", "-name", "id_ecdsa",
         "-o", "-name", "id_ed25519", "-o", "-name", "dropbear_*_host_key",
         "-o", "-name", "*.pub"],
        capture_output=True, text=True,
    )
    sections = [section("SSH Key Files Found", r.stdout)]
    for path_str in r.stdout.strip().splitlines():
        p = Path(path_str)
        if p.is_file():
            sections.append(section(str(p.relative_to(ctx.rootfs)), p.read_text(errors="replace")))
    out_file.write_text("".join(sections))
    total = sum(len(s.splitlines()) for s in sections)
    print(f"  {'ssh_keys.txt':45s}  {total} lines")


def analyze_credentials(ctx: AnalysisContext):
    multi_section_file([
        ("Passwords and Secrets (all config files)",
         ["grep", "-Ei", "password|passwd|secret|community|apikey|token|key="] + ctx.configs),
        ("Hardcoded IP Addresses (all config files)",
         ["grep", "-E", r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"] + ctx.configs),
        ("Cloud and Update Endpoints (all config files)",
         ["grep", "-E", r"https?://"] + ctx.configs),
    ], ctx.out_dir / "credentials.txt", "credentials.txt")


def analyze_default_credentials(ctx: AnalysisContext):
    multi_section_file([
        ("Default Passwords / SSIDs in Configs",
         ["grep", "-Ei", r"admin|default.*pass|ssid|tplink|admin123|password=admin"] + ctx.configs),
        ("Default Credentials in Scripts",
         ["grep", "-rEi", r"admin|default.*pass|ssid|tplink|admin123",
          str(ctx.rootfs / "etc")] if (ctx.rootfs / "etc").exists() else []),
    ], ctx.out_dir / "default_credentials.txt", "default_credentials.txt")


def analyze_debug_artifacts(ctx: AnalysisContext):
    multi_section_file([
        ("Debug / Test / Factory Files",
         ["find", str(ctx.rootfs), "-iname", "*debug*", "-o", "-iname", "*test*",
          "-o", "-iname", "*factory*", "-o", "-iname", "*diag*"]),
        ("Debug References in Configs",
         ["grep", "-rEi", "debug|verbose|factory|test.mode|diagnostic",
          str(ctx.rootfs / "etc")] if (ctx.rootfs / "etc").exists() else []),
    ], ctx.out_dir / "debug_artifacts.txt", "debug_artifacts.txt")


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
    VOLATILE = {"tmpfs", "overlayfs", "overlay", "ramfs"}
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
    out_file = ctx.out_dir / "certificates_keys.txt"
    r = subprocess.run(
        ["find", str(ctx.rootfs), "-name", "*.pem", "-o", "-name", "*.key",
         "-o", "-name", "*.crt", "-o", "-name", "*.p12", "-o", "-name", "*.der"],
        capture_output=True, text=True,
    )
    sections = [section("Certificate and Key Files", r.stdout)]
    r2 = subprocess.run(
        ["grep", "-rE", "BEGIN (RSA|EC|PRIVATE|CERTIFICATE)", str(ctx.rootfs)],
        capture_output=True, text=True,
    )
    sections.append(section("Embedded Keys / Certs in Files", r2.stdout))
    out_file.write_text("".join(sections))
    print(f"  {'certificates_keys.txt':45s}  {sum(len(s.splitlines()) for s in sections)} lines")


def analyze_unix_sockets(ctx: AnalysisContext):
    out_file = ctx.out_dir / "unix_sockets.txt"
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


def analyze_nvram(ctx: AnalysisContext):
    multi_section_file([
        ("nvram_get / nvram_set calls",
         ["grep", "-rE", "nvram_get|nvram_set|nvram get|nvram set", str(ctx.rootfs)]),
        ("NVRAM key references",
         ["grep", "-rE", r"nvram\s+\w+", str(ctx.rootfs)]),
    ], ctx.out_dir / "nvram.txt", "nvram.txt")


def analyze_world_writable(ctx: AnalysisContext):
    multi_section_file([
        ("World-Writable Files",
         ["find", str(ctx.rootfs), "-type", "f", "-perm", "-002"]),
        ("World-Writable Directories",
         ["find", str(ctx.rootfs), "-type", "d", "-perm", "-002"]),
        ("SetGID Binaries",
         ["find", str(ctx.rootfs), "-perm", "-2000"]),
    ], ctx.out_dir / "world_writable.txt", "world_writable.txt")
