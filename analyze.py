#!/usr/bin/env python3
"""
Analyzes a router firmware root filesystem and collects data for
attack surface mapping across services, binaries, configs, and protocols.
"""

import argparse
import json
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


# ── Helpers ────────────────────────────────────────────────────────────────────

def run(cmd: list, out_file: Path):
    result = subprocess.run(cmd, capture_output=True, text=True)
    content = result.stdout
    if result.returncode != 0 and result.stderr.strip():
        content += f"\n--- stderr ---\n{result.stderr}"
    out_file.write_text(content)
    lines = len(content.strip().splitlines()) if content.strip() else 0
    status = f"{lines} lines" if lines else "empty"
    print(f"  {out_file.name:45s}  {status}")


def section(title: str, output: str) -> str:
    return (
        f"{'=' * 60}\n  {title}\n{'=' * 60}\n"
        f"{output.strip() if output.strip() else '  (nothing found)'}\n\n"
    )


def existing(*paths) -> list:
    return [str(p) for p in paths if Path(p).exists()]


def find_all_configs(rootfs: Path) -> list:
    EXTENSIONS = {
        ".conf", ".cfg", ".ini", ".config",
        ".json", ".xml", ".yaml", ".yml",
        ".properties", ".env",
    }
    return [
        str(p) for p in rootfs.rglob("*")
        if p.is_file() and p.suffix.lower() in EXTENSIONS
    ]


def multi_section_file(checks: list, out_file: Path, label: str):
    """Run a list of (title, cmd) checks, write all sections to one file."""
    sections = []
    total_lines = 0
    for title, cmd in checks:
        r = subprocess.run(cmd, capture_output=True, text=True)
        output = r.stdout.strip()
        total_lines += len(output.splitlines()) if output else 0
        sections.append(section(title, output))
    out_file.write_text("".join(sections))
    print(f"  {out_file.name:45s}  {total_lines} lines across {len(checks)} checks")


# ── ELF helpers ────────────────────────────────────────────────────────────────

_ELF_MAGIC = b"\x7fELF"

# Matches crypto-related dynamic symbol names (MD5_, AES_, SSL_, etc.)
_CRYPTO_SYM_PAT = re.compile(
    r"^(MD[245]|SHA[0-9]{0,3}|DES|RC[24]|AES|EVP|SSL|TLS|HMAC|RSA|RAND|BN|PKCS|X509|DSA|ECDSA)_",
    re.IGNORECASE,
)

# Subset: symbols that indicate use of broken/weak algorithms only
_WEAK_SYM_PAT = re.compile(r"^(MD[245]|DES|RC[24]|MD4)_", re.IGNORECASE)


def _is_elf(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) == _ELF_MAGIC
    except Exception:
        return False


def _elf_files(rootfs: Path) -> list:
    """Return all non-symlink ELF files under rootfs (magic-byte check, no subprocess)."""
    return [p for p in rootfs.rglob("*") if p.is_file() and not p.is_symlink() and _is_elf(p)]


def _readelf_needed(path: Path) -> list:
    """Extract NEEDED shared libraries from the ELF dynamic section via readelf -d."""
    r = subprocess.run(["readelf", "-d", str(path)], capture_output=True, text=True)
    return re.findall(r"\(NEEDED\)\s+Shared library: \[(.+?)\]", r.stdout)


def _readelf_crypto_imports(path: Path) -> list:
    """Return imported crypto-related symbols from the ELF dynamic symbol table."""
    r = subprocess.run(["readelf", "--dyn-syms", str(path)], capture_output=True, text=True)
    syms = []
    for line in r.stdout.splitlines():
        if "UND" not in line:
            continue
        parts = line.split()
        if not parts:
            continue
        # Strip Glibc-style version suffixes: func@@VERSION or func@VERSION
        name = parts[-1].split("@")[0]
        if _CRYPTO_SYM_PAT.match(name):
            syms.append(name)
    return sorted(set(syms))


# ── ELF cache (single parallel pass over all binaries) ────────────────────────

_STRINGS_TIMEOUT = 30   # seconds — prevents hangs on pathological binaries
_READELF_TIMEOUT = 30
_FILE_TIMEOUT    = 10
_ELF_WORKERS     = 8    # thread count for parallel ELF processing


class _ElfRecord:
    """Holds all per-binary data collected in one pass."""
    __slots__ = ("file_type", "needed_libs", "crypto_imports", "strings_lines", "hardening")

    def __init__(self):
        self.file_type      = ""
        self.needed_libs    = []
        self.crypto_imports = []
        self.strings_lines  = []
        self.hardening      = {}  # {nx, pie, relro, canary}


def _process_one_elf(path: Path) -> tuple:
    """Run file, readelf -d/-l/--dyn-syms, and strings on one ELF binary.
    Each subprocess has a hard timeout so a corrupt binary can't stall the pipeline.
    Returns (path, _ElfRecord).
    """
    rec = _ElfRecord()

    # Intermediate hardening variables — collected across blocks below.
    _bind_now   = False
    _has_canary = False
    _nx         = None   # True = NX on, False = NX off, None = GNU_STACK absent
    _has_relro  = False
    _has_interp = False

    try:
        r = subprocess.run(
            ["file", str(path)], capture_output=True, text=True, timeout=_FILE_TIMEOUT
        )
        rec.file_type = r.stdout.split(":", 1)[-1].strip()
    except Exception:
        rec.file_type = "(error)"

    try:
        r = subprocess.run(
            ["readelf", "-d", str(path)], capture_output=True, text=True, timeout=_READELF_TIMEOUT
        )
        rec.needed_libs = re.findall(r"\(NEEDED\)\s+Shared library: \[(.+?)\]", r.stdout)
        _bind_now = bool(re.search(r"\(BIND_NOW\)", r.stdout)) or bool(
            re.search(r"\(FLAGS_1\)[^\n]*\bNOW\b", r.stdout)
        )
    except Exception:
        pass

    try:
        r = subprocess.run(
            ["readelf", "--dyn-syms", str(path)], capture_output=True, text=True, timeout=_READELF_TIMEOUT
        )
        _has_canary = "__stack_chk_fail" in r.stdout
        syms = []
        for line in r.stdout.splitlines():
            if "UND" not in line:
                continue
            parts = line.split()
            if parts:
                name = parts[-1].split("@")[0]
                if _CRYPTO_SYM_PAT.match(name):
                    syms.append(name)
        rec.crypto_imports = sorted(set(syms))
    except Exception:
        pass

    try:
        r = subprocess.run(
            ["readelf", "-l", str(path)], capture_output=True, text=True, timeout=_READELF_TIMEOUT
        )
        ph = r.stdout
        # NX: GNU_STACK flags field — 5 address tokens follow the type, then flags.
        m = re.search(r"GNU_STACK\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\S+)", ph)
        if m:
            _nx = "E" not in m.group(1)
        _has_relro  = bool(re.search(r"^\s+GNU_RELRO\b", ph, re.MULTILINE))
        _has_interp = bool(re.search(r"^\s+INTERP\b",   ph, re.MULTILINE))
    except Exception:
        pass

    try:
        r = subprocess.run(
            ["strings", str(path)], capture_output=True, text=True, timeout=_STRINGS_TIMEOUT
        )
        rec.strings_lines = r.stdout.splitlines()
    except Exception:
        pass

    # ── Derived hardening flags ────────────────────────────────────────────────
    ft = rec.file_type.lower()
    if "pie executable" in ft:
        pie = "yes"
    elif "shared object" in ft and _has_interp:
        pie = "yes"   # PIE executable (older file(1) shows "shared object")
    elif "shared object" in ft:
        pie = "so"    # genuine shared library — hardening N/A
    elif "executable" in ft:
        pie = "no"
    else:
        pie = "unknown"

    if _has_relro and _bind_now:
        relro = "full"
    elif _has_relro:
        relro = "partial"
    else:
        relro = "none"

    rec.hardening = {
        "nx":     _nx,
        "pie":    pie,
        "relro":  relro,
        "canary": _has_canary,
    }

    return path, rec


def build_elf_cache(rootfs: Path) -> dict:
    """Process every ELF binary under rootfs once, in parallel.

    Runs file + readelf -d + readelf --dyn-syms + strings on each binary using
    a thread pool.  Returns {Path: _ElfRecord}.  All four consumers
    (binary_inventory, network_binaries, hardcoded_strings, weak_crypto) read
    from this cache instead of spawning their own subprocesses.
    """
    elf_paths = _elf_files(rootfs)
    cache: dict = {}
    with ThreadPoolExecutor(max_workers=min(_ELF_WORKERS, len(elf_paths) or 1)) as executor:
        futures = {executor.submit(_process_one_elf, p): p for p in elf_paths}
        for future in as_completed(futures):
            try:
                path, rec = future.result()
                cache[path] = rec
            except Exception:
                pass
    print(f"  {'(elf cache built)':45s}  {len(cache)} ELF binaries processed in parallel")
    return cache


# ── Analysis functions ─────────────────────────────────────────────────────────

def analyze_scripts(rootfs: Path, out_dir: Path):
    EXTENSIONS = {".sh", ".py", ".lua", ".pl", ".rb", ".php", ".js", ".expect"}
    found = sorted(
        p for p in rootfs.rglob("*")
        if p.is_file() and p.suffix.lower() in EXTENSIONS
    )

    # Index file — just paths
    index_file = out_dir / "scripts.txt"
    index_file.write_text("\n".join(str(p.relative_to(rootfs)) for p in found))
    print(f"  {'scripts.txt':45s}  {len(found)} files")

    # Content file — full source of every script
    sections = []
    for p in found:
        try:
            content = p.read_text(errors="replace")
        except Exception as e:
            content = f"(could not read: {e})"
        sections.append(
            f"{'=' * 60}\n"
            f"  {p.relative_to(rootfs)}  ({p.suffix})\n"
            f"{'=' * 60}\n"
            f"{content}\n"
        )
    content_file = out_dir / "scripts_content.txt"
    content_file.write_text("\n".join(sections))
    total_lines = sum(len(s.splitlines()) for s in sections)
    print(f"  {'scripts_content.txt':45s}  {total_lines} lines")


def analyze_systemd_services(rootfs: Path, out_dir: Path):
    found = sorted(rootfs.rglob("*.service"))

    index_file = out_dir / "services.txt"
    index_file.write_text("\n".join(str(p.relative_to(rootfs)) for p in found))
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
            f"  {p.relative_to(rootfs)}\n"
            f"{'=' * 60}\n"
            f"{content}\n"
        )
    content_file = out_dir / "services_content.txt"
    content_file.write_text("\n".join(sections))
    total_lines = sum(len(s.splitlines()) for s in sections)
    print(f"  {'services_content.txt':45s}  {total_lines} lines")


def analyze_init_scripts(rootfs: Path, out_file: Path):
    init_dirs = existing(rootfs / "etc/init.d", rootfs / "etc/rc.d")
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


def analyze_network_binaries(rootfs: Path, out_file: Path, elf_cache: dict):
    KEYWORDS = {"bind", "listen", "accept", "socket", "connect", "recv", "send"}
    results = []
    for path, rec in elf_cache.items():
        matches = [l for l in rec.strings_lines if any(kw in l.lower() for kw in KEYWORDS)]
        if matches:
            results.append(f"--- {path.relative_to(rootfs)} ---")
            results.extend(matches)
            results.append("")
    content = "\n".join(results)
    out_file.write_text(content)
    lines = len(content.strip().splitlines()) if content.strip() else 0
    print(f"  {'network_binaries.txt':45s}  {lines} lines")


def analyze_web_interface(rootfs: Path, out_file: Path):
    web_roots = existing(rootfs / "www", rootfs / "web", rootfs / "webroot", rootfs / "usr/share/www")
    checks = [section("CGI Scripts",
                       subprocess.run(["find", str(rootfs), "-name", "*.cgi"], capture_output=True, text=True).stdout)]
    checks.append(section("Lua Handlers",
                           subprocess.run(["find", str(rootfs), "-name", "*.lua"], capture_output=True, text=True).stdout))
    checks.append(section("JavaScript Files",
                           subprocess.run(["find", str(rootfs), "-name", "*.js"], capture_output=True, text=True).stdout))
    if web_roots:
        r = subprocess.run(["grep", "-rE", r"url|api|endpoint|/cgi-bin|action="] + web_roots, capture_output=True, text=True)
        checks.append(section("API Endpoints in Web Root", r.stdout))
    checks.append(section("HTML Pages",
                           subprocess.run(["find", str(rootfs), "-name", "*.html", "-o", "-name", "*.htm"],
                                          capture_output=True, text=True).stdout))
    out_file.write_text("".join(checks))
    print(f"  {'web_interface.txt':45s}  {sum(len(c.splitlines()) for c in checks)} lines")


def analyze_web_server_configs(rootfs: Path, out_file: Path):
    r = subprocess.run(
        ["find", str(rootfs), "-name", "httpd.conf", "-o", "-name", "nginx.conf",
         "-o", "-name", "lighttpd.conf", "-o", "-name", "uhttpd.conf", "-o", "-name", "boa.conf"],
        capture_output=True, text=True,
    )
    sections = [section("Web Server Config Files Found", r.stdout)]
    for path_str in r.stdout.strip().splitlines():
        p = Path(path_str)
        if p.is_file():
            sections.append(section(str(p.relative_to(rootfs)), p.read_text(errors="replace")))
    out_file.write_text("".join(sections))
    total = sum(len(s.splitlines()) for s in sections)
    print(f"  {'web_server_configs.txt':45s}  {total} lines")


def analyze_credentials(rootfs: Path, out_dir: Path, configs: list):
    multi_section_file([
        ("Passwords and Secrets (all config files)",
         ["grep", "-Ei", "password|passwd|secret|community|apikey|token|key="] + configs),
        ("Hardcoded IP Addresses (all config files)",
         ["grep", "-E", r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"] + configs),
        ("Cloud and Update Endpoints (all config files)",
         ["grep", "-E", r"https?://"] + configs),
    ], out_dir / "credentials.txt", "credentials.txt")


def analyze_users_groups(rootfs: Path, out_file: Path):
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
        p = rootfs / name
        sections.append(section(name, p.read_text(errors="replace") if p.exists() else "(not found)"))

    shadow_p = rootfs / "etc/shadow"
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


def analyze_ssh_keys(rootfs: Path, out_file: Path):
    r = subprocess.run(
        ["find", str(rootfs),
         "-name", "authorized_keys", "-o", "-name", "id_rsa", "-o", "-name", "id_ecdsa",
         "-o", "-name", "id_ed25519", "-o", "-name", "dropbear_*_host_key",
         "-o", "-name", "*.pub"],
        capture_output=True, text=True,
    )
    sections = [section("SSH Key Files Found", r.stdout)]
    for path_str in r.stdout.strip().splitlines():
        p = Path(path_str)
        if p.is_file():
            sections.append(section(str(p.relative_to(rootfs)), p.read_text(errors="replace")))
    out_file.write_text("".join(sections))
    total = sum(len(s.splitlines()) for s in sections)
    print(f"  {'ssh_keys.txt':45s}  {total} lines")


def analyze_library_versions(rootfs: Path, out_file: Path):
    libs = {
        "libc":      ["libc.so*", "libc-*.so"],
        "libssl":    ["libssl.so*"],
        "libcrypto": ["libcrypto.so*"],
        "libcurl":   ["libcurl.so*"],
        "libuClibc": ["libuClibc*.so*"],
    }
    sections = []
    for name, patterns in libs.items():
        found = [p for pat in patterns for p in rootfs.rglob(pat)]
        if not found:
            sections.append(section(name, "(not found)"))
            continue
        output_lines = []
        for lib in found:
            output_lines.append(f"  {lib.relative_to(rootfs)}")
            r = subprocess.run(["strings", str(lib)], capture_output=True, text=True)
            versions = [
                l for l in r.stdout.splitlines()
                if any(kw in l.lower() for kw in ["version", "release", name.lower()])
                and len(l) < 80
            ]
            output_lines.extend(f"    {v}" for v in versions[:10])
        sections.append(section(name, "\n".join(output_lines)))
    out_file.write_text("".join(sections))
    print(f"  {'library_versions.txt':45s}  {sum(len(s.splitlines()) for s in sections)} lines")


def analyze_binary_inventory(rootfs: Path, out_file: Path, elf_cache: dict):
    all_files = [p for p in rootfs.rglob("*") if p.is_file() and not p.is_symlink()]
    lines = []
    for f in all_files:
        rec = elf_cache.get(f)
        if rec:
            lines.append(str(f.relative_to(rootfs)))
            lines.append(f"  type : {rec.file_type}")
            lines.append(f"  libs : {', '.join(rec.needed_libs) if rec.needed_libs else 'none'}")
            if rec.crypto_imports:
                lines.append(f"  crypto imports : {', '.join(rec.crypto_imports)}")
        else:
            # Non-ELF file — file type only, no readelf data
            try:
                r = subprocess.run(
                    ["file", str(f)], capture_output=True, text=True, timeout=_FILE_TIMEOUT
                )
                file_type = r.stdout.split(":", 1)[-1].strip()
            except Exception:
                file_type = "(error)"
            lines.append(str(f.relative_to(rootfs)))
            lines.append(f"  type : {file_type}")
        lines.append("")
    out_file.write_text("\n".join(lines))
    print(f"  {'binary_inventory.txt':45s}  {len(all_files)} files")


def analyze_architecture(rootfs: Path, out_file: Path, elf_cache: dict):
    _PAT  = re.compile(r'ELF\s+(\d+)-bit\s+(LSB|MSB)\s+\w+,\s+([^,]+)')
    _NAME = {"Intel": "x86", "AArch64": "ARM64"}

    votes: dict = {}
    for path, rec in elf_cache.items():
        m = _PAT.search(rec.file_type)
        if not m:
            continue
        bits        = int(m.group(1))
        endian_short = m.group(2)
        arch_word   = m.group(3).strip().split()[0]
        arch        = _NAME.get(arch_word, arch_word)
        key         = (arch, bits, endian_short)
        votes.setdefault(key, []).append(path)

    if not votes:
        out_file.write_text(section("Detected Architecture", "(no ELF binaries found)"))
        print(f"  {'architecture.txt':45s}  no ELF binaries")
        return

    dominant = max(votes, key=lambda k: len(votes[k]))
    arch, bits, endian_short = dominant
    agreeing  = len(votes[dominant])
    total_elf = len(elf_cache)
    confidence = round(agreeing / total_elf, 2)
    endianness = "little-endian" if endian_short == "LSB" else "big-endian"

    summary = "\n".join([
        f"  arch             : {arch}",
        f"  bits             : {bits}",
        f"  endianness       : {endianness}",
        f"  endianness_short : {endian_short}",
        f"  confidence       : {confidence}",
        f"  elf_count        : {total_elf}",
        f"  agreeing_count   : {agreeing}",
    ])

    evidence = [
        f"  {p.relative_to(rootfs)}  |  {elf_cache[p].file_type[:80]}"
        for p in sorted(votes[dominant])[:20]
    ]

    out_file.write_text(
        section("Detected Architecture", summary) +
        section(f"Per-Binary Evidence ({agreeing} matching, up to 20 shown)", "\n".join(evidence))
    )
    print(f"  {'architecture.txt':45s}  {arch} {bits}-bit {endianness}  (conf={confidence}, {agreeing}/{total_elf} ELFs)")


def analyze_kernel_modules(rootfs: Path, out_file: Path):
    r = subprocess.run(["find", str(rootfs), "-name", "*.ko"], capture_output=True, text=True)
    sections = [section("Kernel Modules (.ko)", r.stdout)]
    # Also check if there is a modules.dep
    for dep in rootfs.rglob("modules.dep"):
        sections.append(section(str(dep.relative_to(rootfs)), dep.read_text(errors="replace")))
    out_file.write_text("".join(sections))
    total = sum(len(s.splitlines()) for s in sections)
    print(f"  {'kernel_modules.txt':45s}  {total} lines")


def analyze_nvram(rootfs: Path, out_file: Path):
    multi_section_file([
        ("nvram_get / nvram_set calls",
         ["grep", "-rE", "nvram_get|nvram_set|nvram get|nvram set", str(rootfs)]),
        ("NVRAM key references",
         ["grep", "-rE", r"nvram\s+\w+", str(rootfs)]),
    ], out_file, "nvram.txt")


def analyze_weak_crypto(rootfs: Path, out_file: Path, configs: list, elf_cache: dict):
    checks = [
        ("Weak Crypto in Config Files",
         ["grep", "-Ei", r"md5|des|rc4|ecb|base64.*key|static.*key"] + configs),
        ("Weak Crypto References in Binaries (string grep — approximate)",
         ["grep", "-rE", "MD5|DES|RC4|ECB", str(rootfs / "usr"), str(rootfs / "lib")]
         if (rootfs / "usr").exists() else []),
    ]
    checks = [(t, c) for t, c in checks if c]
    multi_section_file(checks, out_file, "weak_crypto.txt")

    # Concrete evidence from cache — no extra subprocess calls
    findings = []
    for path, rec in elf_cache.items():
        syms = [s for s in rec.crypto_imports if _WEAK_SYM_PAT.match(s)]
        if syms:
            findings.append(f"  {path.relative_to(rootfs)}: {', '.join(syms)}")
    sec = section(
        "Binaries Importing Weak Crypto Symbols  [readelf — concrete, not inferred]",
        "\n".join(findings) if findings else "(none)",
    )
    with open(out_file, "a") as f:
        f.write(sec)
    if findings:
        print(f"    → {len(findings)} ELF binaries import weak crypto symbols (readelf)")


def analyze_world_writable(rootfs: Path, out_file: Path):
    multi_section_file([
        ("World-Writable Files",
         ["find", str(rootfs), "-type", "f", "-perm", "-002"]),
        ("World-Writable Directories",
         ["find", str(rootfs), "-type", "d", "-perm", "-002"]),
        ("SetGID Binaries",
         ["find", str(rootfs), "-perm", "-2000"]),
    ], out_file, "world_writable.txt")


def analyze_default_credentials(rootfs: Path, out_file: Path, configs: list):
    multi_section_file([
        ("Default Passwords / SSIDs in Configs",
         ["grep", "-Ei", r"admin|default.*pass|ssid|tplink|admin123|password=admin"] + configs),
        ("Default Credentials in Scripts",
         ["grep", "-rEi", r"admin|default.*pass|ssid|tplink|admin123",
          str(rootfs / "etc")] if (rootfs / "etc").exists() else []),
    ], out_file, "default_credentials.txt")


def analyze_debug_artifacts(rootfs: Path, out_file: Path):
    multi_section_file([
        ("Debug / Test / Factory Files",
         ["find", str(rootfs), "-iname", "*debug*", "-o", "-iname", "*test*",
          "-o", "-iname", "*factory*", "-o", "-iname", "*diag*"]),
        ("Debug References in Configs",
         ["grep", "-rEi", "debug|verbose|factory|test.mode|diagnostic",
          str(rootfs / "etc")] if (rootfs / "etc").exists() else []),
    ], out_file, "debug_artifacts.txt")


def analyze_dns_routing(rootfs: Path, out_file: Path):
    sections = []
    for name in ("etc/hosts", "etc/resolv.conf", "etc/resolv.conf.d"):
        p = rootfs / name
        if p.is_file():
            sections.append(section(name, p.read_text(errors="replace")))
        elif p.is_dir():
            for f in p.iterdir():
                sections.append(section(str(f.relative_to(rootfs)), f.read_text(errors="replace")))
    if not sections:
        sections.append(section("DNS / Routing", "(no hosts or resolv.conf found)"))
    out_file.write_text("".join(sections))
    print(f"  {'dns_routing.txt':45s}  {sum(len(s.splitlines()) for s in sections)} lines")


def analyze_firewall_rules(rootfs: Path, out_file: Path):
    r = subprocess.run(
        ["find", str(rootfs), "-name", "iptables.conf", "-o", "-name", "firewall*",
         "-o", "-name", "nftables*", "-o", "-name", "ip6tables*"],
        capture_output=True, text=True,
    )
    sections = [section("Firewall Config Files Found", r.stdout)]
    for path_str in r.stdout.strip().splitlines():
        p = Path(path_str)
        if p.is_file():
            sections.append(section(str(p.relative_to(rootfs)), p.read_text(errors="replace")))
    out_file.write_text("".join(sections))
    print(f"  {'firewall_rules.txt':45s}  {sum(len(s.splitlines()) for s in sections)} lines")


def analyze_hardcoded_strings(rootfs: Path, out_file: Path, elf_cache: dict):
    PATTERNS = [r"https?://", r"api[_-]?key", r"token=", r"secret=", r"Bearer\s"]
    results = []
    for path, rec in elf_cache.items():
        matches = [
            l for l in rec.strings_lines
            if any(re.search(pat, l, re.IGNORECASE) for pat in PATTERNS)
        ]
        if matches:
            results.append(f"--- {path.relative_to(rootfs)} ---")
            results.extend(matches)
            results.append("")
    content = "\n".join(results)
    out_file.write_text(content)
    lines = len(content.strip().splitlines()) if content.strip() else 0
    print(f"  {'hardcoded_strings.txt':45s}  {lines} lines")


def analyze_protocols(rootfs: Path, out_file: Path, configs: list):
    multi_section_file([
        ("SNMP Community Strings",
         ["grep", "-Ei", "community|snmpd|public|private"] + configs),
        ("UPnP / SSDP",
         ["grep", "-Ei", "upnp|ssdp|igd"] + configs),
        ("TR-069 / CWMP",
         ["grep", "-Ei", "cwmp|tr069|acs.url|inform|tr_069"] + configs),
        ("MQTT",
         ["grep", "-Ei", "mqtt|broker"] + configs),
    ], out_file, "protocols.txt")


def analyze_interface_binding(rootfs: Path, out_file: Path, configs: list):
    multi_section_file([
        ("Interface References (LAN/WAN)",
         ["grep", "-Ei", "br-lan|eth0|eth1|wan|pppoe|interface"] + configs),
        ("Any-Interface Bindings (0.0.0.0)",
         ["grep", "-E", r"0\.0\.0\.0"] + configs),
        ("Loopback Only (127.0.0.1)",
         ["grep", "-E", r"127\.0\.0\.1"] + configs),
    ], out_file, "interface_binding.txt")


def analyze_scheduled_tasks(rootfs: Path, out_file: Path):
    r = subprocess.run(["find", str(rootfs), "-path", "*/cron*"], capture_output=True, text=True)
    sections = [section("Cron Files Found", r.stdout)]
    for f in list(rootfs.rglob("crontab")) + list(rootfs.rglob("cron.d")):
        if f.is_file():
            sections.append(section(str(f.relative_to(rootfs)), f.read_text(errors="replace")))
    out_file.write_text("".join(sections))
    print(f"  {'scheduled_tasks.txt':45s}  {sum(len(s.splitlines()) for s in sections)} lines")


def analyze_firmware_update(rootfs: Path, out_file: Path, configs: list):
    multi_section_file([
        ("Update / Upgrade References",
         ["grep", "-Ei", "upgrade|update|firmware|download"] + configs),
        ("Checksum / Signature Verification",
         ["grep", "-Ei", "checksum|verify|signature|md5|sha"] + configs),
        ("TP-Link Cloud / Update URLs",
         ["grep", "-Ei", r"tplinkcloud|tplinkwifi|tp-link\.com|devs\.tplinkcloud"] + configs),
    ], out_file, "firmware_update.txt")


def analyze_certificates(rootfs: Path, out_file: Path):
    r = subprocess.run(
        ["find", str(rootfs), "-name", "*.pem", "-o", "-name", "*.key",
         "-o", "-name", "*.crt", "-o", "-name", "*.p12", "-o", "-name", "*.der"],
        capture_output=True, text=True,
    )
    sections = [section("Certificate and Key Files", r.stdout)]
    r2 = subprocess.run(
        ["grep", "-rE", "BEGIN (RSA|EC|PRIVATE|CERTIFICATE)", str(rootfs)],
        capture_output=True, text=True,
    )
    sections.append(section("Embedded Keys / Certs in Files", r2.stdout))
    out_file.write_text("".join(sections))
    print(f"  {'certificates_keys.txt':45s}  {sum(len(s.splitlines()) for s in sections)} lines")


def analyze_unix_sockets(rootfs: Path, out_file: Path):
    r1 = subprocess.run(
        ["find", str(rootfs), "-name", "*.sock", "-o", "-name", "*.socket"],
        capture_output=True, text=True,
    )
    etc_usr = existing(rootfs / "etc", rootfs / "usr")
    r2 = subprocess.run(
        ["grep", "-rE", r"AF_UNIX|SOCK_STREAM|/var/run/.*\.sock"] + etc_usr,
        capture_output=True, text=True,
    )
    out_file.write_text(section("Unix Socket Files", r1.stdout) + section("Unix Socket References", r2.stdout))
    print(f"  {'unix_sockets.txt':45s}  {len(r1.stdout.strip().splitlines()) + len(r2.stdout.strip().splitlines())} lines")


def _points_to_busybox(link: Path) -> bool:
    try:
        target = str(link.readlink())
        return target == "busybox" or target.endswith("/busybox")
    except Exception:
        return False


def analyze_busybox(rootfs: Path, out_file: Path):
    bb_bins = [p for p in rootfs.rglob("busybox") if p.is_file() and not p.is_symlink()]
    if not bb_bins:
        out_file.write_text(section("BusyBox", "(busybox binary not found)"))
        print(f"  {'busybox.txt':45s}  not found")
        return

    all_sections = []
    total_applets = 0
    for bb in bb_bins:
        r = subprocess.run(["strings", str(bb)], capture_output=True, text=True)
        version_lines = [l for l in r.stdout.splitlines()
                         if re.search(r"BusyBox\s+v\d+", l, re.IGNORECASE)]
        all_sections.append(section(
            f"Version  ({bb.relative_to(rootfs)})",
            "\n".join(version_lines) if version_lines else "(version string not found)",
        ))
        applets = sorted(
            str(p.relative_to(rootfs))
            for p in rootfs.rglob("*")
            if p.is_symlink() and _points_to_busybox(p)
        )
        total_applets = len(applets)
        all_sections.append(section(f"Applets via symlinks  ({len(applets)} found)", "\n".join(applets)))

    out_file.write_text("".join(all_sections))
    print(f"  {'busybox.txt':45s}  {len(bb_bins)} binary(s), {total_applets} applets")


def analyze_symlinks(rootfs: Path, out_file: Path):
    valid, broken = [], []
    for p in sorted(rootfs.rglob("*")):
        if not p.is_symlink():
            continue
        try:
            raw = p.readlink()
            resolved = rootfs / str(raw).lstrip("/") if raw.is_absolute() else p.parent / raw
            entry = f"{p.relative_to(rootfs)} -> {raw}"
            (valid if resolved.exists() else broken).append(entry)
        except Exception:
            broken.append(f"{p.relative_to(rootfs)} -> (unreadable)")
    out_file.write_text(
        section(f"Valid Symlinks  ({len(valid)})", "\n".join(valid)) +
        section(f"Broken Symlinks  ({len(broken)})", "\n".join(broken) if broken else "(none)")
    )
    print(f"  {'symlinks.txt':45s}  {len(valid)} valid, {len(broken)} broken")


def analyze_php_cmdinject(rootfs: Path, out_file: Path):
    """
    Taint-flow check for PHP OS command injection.

    Sources : $_GET / $_POST / $_REQUEST / $_COOKIE / $_SERVER
    Sinks   : exec / system / shell_exec / passthru / popen / proc_open
    Sanitizers that clear a finding: escapeshellarg / escapeshellcmd

    Three finding tiers:
      HIGH — source + sink on the same line, no sanitizer on that line
      HIGH — file contains both sources and sinks, no sanitizer anywhere in the file
      VERIFY — file contains sources + sinks but also has a sanitizer (coverage may be partial)
    """
    SOURCES    = re.compile(r'\$_(GET|POST|REQUEST|COOKIE|SERVER)\b')
    SINKS      = re.compile(r'\b(exec|system|shell_exec|passthru|popen|proc_open)\s*\(')
    SANITIZERS = re.compile(r'\b(escapeshellarg|escapeshellcmd)\s*\(')

    php_files = sorted(p for p in rootfs.rglob("*.php") if p.is_file())
    if not php_files:
        out_file.write_text(section("PHP Command Injection", "(no PHP files found)"))
        print(f"  {'php_cmdinject.txt':45s}  no PHP files found")
        return

    same_line_hits = []   # (path, lineno, line)
    file_level     = []   # (path, source_lines, sink_lines, has_sanitizer)

    for php in php_files:
        try:
            file_lines = php.read_text(errors="replace").splitlines()
        except Exception:
            continue

        file_has_source    = False
        file_has_sink      = False
        file_has_sanitizer = False
        source_lines: list = []
        sink_lines:   list = []

        for i, line in enumerate(file_lines, 1):
            has_src = bool(SOURCES.search(line))
            has_snk = bool(SINKS.search(line))
            has_san = bool(SANITIZERS.search(line))

            if has_src:
                file_has_source = True
                source_lines.append((i, line.strip()))
            if has_snk:
                file_has_sink = True
                sink_lines.append((i, line.strip()))
            if has_san:
                file_has_sanitizer = True

            if has_src and has_snk and not has_san:
                same_line_hits.append((php, i, line.strip()))

        if file_has_source and file_has_sink:
            file_level.append((php, source_lines, sink_lines, file_has_sanitizer))

    all_sections = []

    # Tier 1 — same-line, highest confidence
    if same_line_hits:
        rows = []
        for path, lineno, line in same_line_hits:
            rows.append(f"  {path.relative_to(rootfs)}:{lineno}")
            rows.append(f"    {line[:160]}")
        all_sections.append(section(
            f"[HIGH] SAME-LINE: source + sink, no sanitizer  ({len(same_line_hits)} hits)",
            "\n".join(rows),
        ))
    else:
        all_sections.append(section("[HIGH] SAME-LINE: source + sink, no sanitizer", "(none)"))

    # Tier 2 — file-level, no sanitizer
    no_san = [(p, sl, kl) for p, sl, kl, hs in file_level if not hs]
    if no_san:
        rows = []
        for path, src_lines, snk_lines in no_san:
            rows.append(f"\n  FILE: {path.relative_to(rootfs)}")
            rows.append("  Sources ($_ superglobals):")
            for ln, txt in src_lines[:10]:
                rows.append(f"    line {ln:4d}: {txt[:120]}")
            if len(src_lines) > 10:
                rows.append(f"    ... {len(src_lines) - 10} more source lines")
            rows.append("  Sinks (command execution):")
            for ln, txt in snk_lines[:10]:
                rows.append(f"    line {ln:4d}: {txt[:120]}")
            if len(snk_lines) > 10:
                rows.append(f"    ... {len(snk_lines) - 10} more sink lines")
        all_sections.append(section(
            f"[HIGH] FILE-LEVEL: sources + sinks, NO sanitizer anywhere  ({len(no_san)} files)",
            "\n".join(rows),
        ))
    else:
        all_sections.append(section(
            "[HIGH] FILE-LEVEL: sources + sinks, NO sanitizer anywhere", "(none)"
        ))

    # Tier 3 — sanitizer present but coverage may be partial
    with_san = [(p, sl, kl) for p, sl, kl, hs in file_level if hs]
    if with_san:
        rows = []
        for path, _, snk_lines in with_san:
            rows.append(f"\n  FILE: {path.relative_to(rootfs)}")
            rows.append("  Sinks (verify each is guarded):")
            for ln, txt in snk_lines[:5]:
                rows.append(f"    line {ln:4d}: {txt[:120]}")
            if len(snk_lines) > 5:
                rows.append(f"    ... {len(snk_lines) - 5} more")
        all_sections.append(section(
            f"[VERIFY] FILE-LEVEL: sources + sinks + sanitizer present  ({len(with_san)} files)",
            "\n".join(rows),
        ))

    out_file.write_text("".join(all_sections))
    high = len(same_line_hits) + len(no_san)
    print(f"  {'php_cmdinject.txt':45s}  {len(php_files)} PHP files scanned")
    if high:
        print(f"    !! {len(same_line_hits)} same-line + {len(no_san)} file-level HIGH findings")


def analyze_php_codeinject(rootfs: Path, out_file: Path):
    """
    Detect PHP code injection sinks — functions that evaluate arbitrary strings as code.

    Sinks checked:
      eval()                   — executes its argument as PHP
      assert() string-arg      — acts as eval() when passed a string (PHP < 8)
      preg_replace() /e flag   — evaluates replacement as PHP code (removed in PHP 7)
      create_function()        — wraps body string in an anonymous eval
      call_user_func[_array]() — variable callable (attacker-controlled dispatch)

    Each finding is annotated with whether a $_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER
    superglobal appears on the same line (direct taint, highest confidence).
    """
    SOURCES = re.compile(r'\$_(GET|POST|REQUEST|COOKIE|SERVER)\b')

    SINKS = [
        (
            "eval()",
            re.compile(r'\beval\s*\('),
            "executes argument as PHP — any non-literal argument is injectable",
        ),
        (
            "assert() — string/variable argument",
            re.compile(r'\bassert\s*\(\s*(?:\$|[\'"])'),
            "acts as eval() when passed a string in PHP < 8",
        ),
        (
            "preg_replace() — /e modifier",
            re.compile(r"\bpreg_replace\s*\(\s*['\"][^'\"]*\/e[imsxADSUXJ]*['\"]"),
            "/e flag evaluates replacement as PHP code — removed in PHP 7, common in old firmware",
        ),
        (
            "create_function()",
            re.compile(r'\bcreate_function\s*\('),
            "wraps body string in an anonymous eval — removed in PHP 8",
        ),
        (
            "call_user_func[_array]() — variable callable",
            re.compile(r'\bcall_user_func(?:_array)?\s*\(\s*\$'),
            "variable as first argument allows attacker-controlled function dispatch",
        ),
    ]

    php_files = sorted(p for p in rootfs.rglob("*.php") if p.is_file())
    if not php_files:
        out_file.write_text(section("PHP Code Injection Sinks", "(no PHP files found)"))
        print(f"  {'php_codeinject.txt':45s}  no PHP files found")
        return

    # {sink_label: [(path, lineno, stripped_line, source_on_same_line)]}
    findings: dict = {label: [] for label, _, _ in SINKS}
    total_hits = 0

    for php in php_files:
        try:
            file_lines = php.read_text(errors="replace").splitlines()
        except Exception:
            continue
        for i, line in enumerate(file_lines, 1):
            has_source = bool(SOURCES.search(line))
            for label, pattern, _ in SINKS:
                if pattern.search(line):
                    findings[label].append((php, i, line.strip(), has_source))
                    total_hits += 1

    all_sections = []
    direct_count = 0

    for label, _, note in SINKS:
        hits = findings[label]
        if not hits:
            all_sections.append(section(f"{label}", "(none)"))
            continue

        with_src  = [(p, n, l) for p, n, l, s in hits if s]
        without   = [(p, n, l) for p, n, l, s in hits if not s]
        direct_count += len(with_src)

        rows = [
            f"  Note: {note}",
            f"  {len(hits)} hit(s) total  |  {len(with_src)} with superglobal on same line\n",
        ]
        if with_src:
            rows.append("  [HIGH — superglobal on same line]")
            for path, lineno, line in with_src:
                rows.append(f"  {path.relative_to(rootfs)}:{lineno}")
                rows.append(f"    {line[:160]}")
        if without:
            rows.append("\n  [REVIEW — trace taint manually]")
            for path, lineno, line in without:
                rows.append(f"  {path.relative_to(rootfs)}:{lineno}")
                rows.append(f"    {line[:160]}")

        all_sections.append(section(label, "\n".join(rows)))

    out_file.write_text("".join(all_sections))
    print(f"  {'php_codeinject.txt':45s}  {len(php_files)} PHP files  |  {total_hits} sink hits  |  {direct_count} with superglobal on same line")
    if total_hits:
        print(f"    !! {total_hits} code injection sink hits — review php_codeinject.txt")


def analyze_php_lfi(rootfs: Path, out_file: Path):
    """
    Local File Inclusion taint check.

    Sources : $_GET / $_POST / $_REQUEST / $_COOKIE / $_SERVER
    Sinks   : include / include_once / require / require_once
    Sanitizers that reduce confidence: basename() / realpath() / in_array() / array_key_exists()

    Extra signal — template-loading parameters: keys named page, template, file, path,
    module, view, section, lang, theme.  These are the classic ?page=foo LFI vectors.

    Finding tiers:
      [HIGH]   source superglobal on the same line as an include/require, no sanitizer
      [HIGH]   file has both sources and sinks, no sanitizer anywhere in the file
      [PAGE]   file uses a template-style GET/POST key (page=, file=, …) and also has includes
      [VERIFY] file has sources + sinks + sanitizer present (coverage may be partial)
    """
    SOURCES    = re.compile(r'\$_(GET|POST|REQUEST|COOKIE|SERVER)\b')
    SINKS      = re.compile(r'\b(include|include_once|require|require_once)\s*[\s(]')
    SANITIZERS = re.compile(r'\b(basename|realpath|in_array|array_key_exists)\s*\(')
    # Template-style parameter keys that are classic LFI entry points
    PAGE_KEYS  = re.compile(
        r'\$_(GET|POST|REQUEST)\s*\[\s*[\'"]'
        r'(?:page|template|file|path|dir|module|view|include|section|lang|language|theme)'
        r'[\'"]'
    )

    php_files = sorted(p for p in rootfs.rglob("*.php") if p.is_file())
    if not php_files:
        out_file.write_text(section("PHP Local File Inclusion", "(no PHP files found)"))
        print(f"  {'php_lfi.txt':45s}  no PHP files found")
        return

    same_line_hits = []   # (path, lineno, line)  — source + sink, no sanitizer
    file_level     = []   # (path, src_lines, snk_lines, has_sanitizer, has_page_key)

    for php in php_files:
        try:
            file_lines = php.read_text(errors="replace").splitlines()
        except Exception:
            continue

        file_has_source    = False
        file_has_sink      = False
        file_has_sanitizer = False
        file_has_page_key  = False
        src_lines: list    = []
        snk_lines: list    = []

        for i, line in enumerate(file_lines, 1):
            has_src = bool(SOURCES.search(line))
            has_snk = bool(SINKS.search(line))
            has_san = bool(SANITIZERS.search(line))
            has_pg  = bool(PAGE_KEYS.search(line))

            if has_src:
                file_has_source = True
                src_lines.append((i, line.strip()))
            if has_snk:
                file_has_sink = True
                snk_lines.append((i, line.strip()))
            if has_san:
                file_has_sanitizer = True
            if has_pg:
                file_has_page_key = True

            if has_src and has_snk and not has_san:
                same_line_hits.append((php, i, line.strip()))

        if file_has_source and file_has_sink:
            file_level.append((php, src_lines, snk_lines, file_has_sanitizer, file_has_page_key))

    all_sections = []

    # Tier 1 — same-line, direct taint
    if same_line_hits:
        rows = []
        for path, lineno, line in same_line_hits:
            rows.append(f"  {path.relative_to(rootfs)}:{lineno}")
            rows.append(f"    {line[:160]}")
        all_sections.append(section(
            f"[HIGH] SAME-LINE: source + include/require, no sanitizer  ({len(same_line_hits)} hits)",
            "\n".join(rows),
        ))
    else:
        all_sections.append(section("[HIGH] SAME-LINE: source + include/require, no sanitizer", "(none)"))

    # Tier 2 — file-level, no sanitizer at all
    no_san = [(p, sl, kl, pg) for p, sl, kl, hs, pg in file_level if not hs]
    if no_san:
        rows = []
        for path, src_lines, snk_lines, has_page_key in no_san:
            tag = "  [PAGE-PARAM PATTERN]" if has_page_key else ""
            rows.append(f"\n  FILE: {path.relative_to(rootfs)}{tag}")
            rows.append("  Sources ($_ superglobals):")
            for ln, txt in src_lines[:8]:
                rows.append(f"    line {ln:4d}: {txt[:120]}")
            if len(src_lines) > 8:
                rows.append(f"    ... {len(src_lines) - 8} more")
            rows.append("  Sinks (include/require):")
            for ln, txt in snk_lines[:8]:
                rows.append(f"    line {ln:4d}: {txt[:120]}")
            if len(snk_lines) > 8:
                rows.append(f"    ... {len(snk_lines) - 8} more")
        all_sections.append(section(
            f"[HIGH] FILE-LEVEL: sources + sinks, NO sanitizer  ({len(no_san)} files)",
            "\n".join(rows),
        ))
    else:
        all_sections.append(section("[HIGH] FILE-LEVEL: sources + sinks, NO sanitizer", "(none)"))

    # Tier 3 — page-param pattern (template-loader style) regardless of sanitizer
    page_files = [(p, sl, kl, hs) for p, sl, kl, hs, pg in file_level if pg]
    if page_files:
        rows = []
        for path, _, snk_lines, has_san in page_files:
            san_note = "  (sanitizer present — verify coverage)" if has_san else "  !! NO sanitizer"
            rows.append(f"\n  FILE: {path.relative_to(rootfs)}{san_note}")
            rows.append("  Sinks (include/require):")
            for ln, txt in snk_lines[:5]:
                rows.append(f"    line {ln:4d}: {txt[:120]}")
        all_sections.append(section(
            f"[PAGE] TEMPLATE-PARAM PATTERN: ?page=/file=/template= key with includes  ({len(page_files)} files)",
            "\n".join(rows),
        ))

    # Tier 4 — sanitizer present, coverage uncertain
    with_san = [(p, sl, kl) for p, sl, kl, hs, pg in file_level if hs]
    if with_san:
        rows = []
        for path, _, snk_lines in with_san:
            rows.append(f"\n  FILE: {path.relative_to(rootfs)}")
            for ln, txt in snk_lines[:5]:
                rows.append(f"    line {ln:4d}: {txt[:120]}")
        all_sections.append(section(
            f"[VERIFY] FILE-LEVEL: sources + sinks + sanitizer present  ({len(with_san)} files)",
            "\n".join(rows),
        ))

    high = len(same_line_hits) + len(no_san)
    out_file.write_text("".join(all_sections))
    print(f"  {'php_lfi.txt':45s}  {len(php_files)} PHP files  |  {len(same_line_hits)} same-line  |  {len(no_san)} file-level HIGH  |  {len(page_files)} page-param")
    if high:
        print(f"    !! {high} HIGH-confidence LFI findings — review php_lfi.txt")


def analyze_php_infodisclosure(rootfs: Path, out_file: Path):
    """
    Detect PHP information-disclosure patterns.

    Checks:
      phpinfo()                          — dumps interpreter config, env vars, loaded modules, paths
      ini_set('display_errors', '1'/'On') — makes stack traces and file paths visible in responses
      display_errors = 1 in php.ini / .htaccess / user ini files
      error_reporting(E_ALL)             — verbose error output in production
    """
    # Patterns: (label, compiled-regex, severity-note)
    CHECKS = [
        (
            "phpinfo()",
            re.compile(r'\bphpinfo\s*\(\s*\)'),
            "HIGH — dumps full interpreter config: env vars, loaded extensions, file paths, build flags",
        ),
        (
            "ini_set('display_errors', on)",
            re.compile(r"\bini_set\s*\(\s*['\"]display_errors['\"]\s*,\s*['\"]?\s*(?:1|On|TRUE|true)['\"]?\s*\)"),
            "HIGH — stack traces with file paths and variable names sent to the HTTP response",
        ),
        (
            "error_reporting(E_ALL)",
            re.compile(r"\berror_reporting\s*\(\s*(?:E_ALL|32767|-1|\(E_ALL\s*[|&]|\d+)"),
            "MEDIUM — verbose error output; combine with display_errors=1 for full disclosure",
        ),
    ]

    # .ini / .htaccess / .user.ini pattern — display_errors = 1 outside PHP source
    INI_DISPLAY_ERRORS = re.compile(r'^\s*display_errors\s*=\s*(?:1|On|TRUE|true)\s*$', re.MULTILINE)

    php_files = sorted(p for p in rootfs.rglob("*.php") if p.is_file())
    ini_files  = [
        p for p in rootfs.rglob("*")
        if p.is_file() and p.suffix.lower() in {".ini", ".htaccess"} or p.name == ".user.ini"
    ]

    if not php_files and not ini_files:
        out_file.write_text(section("PHP Information Disclosure", "(no PHP or ini files found)"))
        print(f"  {'php_infodisclosure.txt':45s}  no files found")
        return

    # {label: [(path, lineno, line)]}
    findings: dict = {label: [] for label, _, _ in CHECKS}
    total_hits = 0

    for php in php_files:
        try:
            file_lines = php.read_text(errors="replace").splitlines()
        except Exception:
            continue
        for i, line in enumerate(file_lines, 1):
            for label, pattern, _ in CHECKS:
                if pattern.search(line):
                    findings[label].append((php, i, line.strip()))
                    total_hits += 1

    # ini/htaccess display_errors hits collected separately
    ini_hits: list = []
    for ini in ini_files:
        try:
            content = ini.read_text(errors="replace")
        except Exception:
            continue
        for i, line in enumerate(content.splitlines(), 1):
            if INI_DISPLAY_ERRORS.match(line):
                ini_hits.append((ini, i, line.strip()))
                total_hits += 1

    all_sections = []

    for label, _, note in CHECKS:
        hits = findings[label]
        if not hits:
            all_sections.append(section(label, f"  {note}\n\n  (none)"))
            continue
        rows = [f"  {note}", f"  {len(hits)} hit(s)\n"]
        for path, lineno, line in hits:
            rows.append(f"  {path.relative_to(rootfs)}:{lineno}")
            rows.append(f"    {line[:160]}")
        all_sections.append(section(label, "\n".join(rows)))

    if ini_hits:
        rows = [
            "  MEDIUM — php.ini / .htaccess / .user.ini override enables error display",
            f"  {len(ini_hits)} hit(s)\n",
        ]
        for path, lineno, line in ini_hits:
            rows.append(f"  {path.relative_to(rootfs)}:{lineno}")
            rows.append(f"    {line[:160]}")
        all_sections.append(section("display_errors = 1 in ini/htaccess files", "\n".join(rows)))
    else:
        all_sections.append(section("display_errors = 1 in ini/htaccess files", "  (none)"))

    out_file.write_text("".join(all_sections))
    print(f"  {'php_infodisclosure.txt':45s}  {len(php_files)} PHP + {len(ini_files)} ini files  |  {total_hits} hits")
    if total_hits:
        print(f"    !! {total_hits} information-disclosure findings — review php_infodisclosure.txt")


def analyze_cgi_injection(rootfs: Path, out_file: Path):
    r_find = subprocess.run(
        ["find", str(rootfs), "-name", "*.cgi", "-o", "-name", "*.lua", "-o", "-name", "*.sh"],
        capture_output=True, text=True,
    )
    script_files = [l.strip() for l in r_find.stdout.splitlines() if l.strip()]
    if not script_files:
        out_file.write_text(section("CGI Injection", "(no CGI/Lua/shell scripts found)"))
        print(f"  {'cgi_injection.txt':45s}  no scripts found")
        return

    HTTP_VARS = (
        r"\$(QUERY_STRING|REQUEST_URI|REQUEST_METHOD|HTTP_HOST|HTTP_REFERER"
        r"|HTTP_USER_AGENT|FORM_[A-Z_]+|CGI_[A-Z_]+|PATH_INFO|CONTENT_LENGTH)"
    )
    multi_section_file([
        ("HTTP Environment Variables in Scripts",
         ["grep", "-En", HTTP_VARS] + script_files),
        ("eval / exec with Shell Variables",
         ["grep", "-En", r"(eval|exec)\s+.*\$"] + script_files),
        ("Command Substitution Using Variables",
         ["grep", "-En", r"(`[^`]*\$|\$\([^)]*\$)"] + script_files),
    ], out_file, "cgi_injection.txt")


def analyze_mount_points(rootfs: Path, out_file: Path):
    VOLATILE = {"tmpfs", "overlayfs", "overlay", "ramfs"}
    SENSITIVE = {"/etc", "/var", "/sbin", "/bin", "/usr", "/lib"}
    all_sections = []
    for name in ("etc/fstab", "etc/mtab"):
        p = rootfs / name
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


def analyze_hardening(rootfs: Path, out_file: Path, elf_cache: dict):
    """Summarise NX / PIE / RELRO / stack-canary status for every ELF executable."""
    binaries = []
    for path, rec in sorted(elf_cache.items(), key=lambda x: x[0]):
        h = rec.hardening
        if not h or h.get("pie") == "so":  # skip shared libraries
            continue
        binaries.append({
            "path":   str(path.relative_to(rootfs)),
            "nx":     h.get("nx"),
            "pie":    h.get("pie", "unknown"),
            "relro":  h.get("relro", "unknown"),
            "canary": h.get("canary"),
        })

    summary = {
        "total":         len(binaries),
        "nx_enabled":    sum(1 for b in binaries if b["nx"] is True),
        "nx_disabled":   sum(1 for b in binaries if b["nx"] is False),
        "nx_unknown":    sum(1 for b in binaries if b["nx"] is None),
        "pie_yes":       sum(1 for b in binaries if b["pie"] == "yes"),
        "pie_no":        sum(1 for b in binaries if b["pie"] == "no"),
        "pie_unknown":   sum(1 for b in binaries if b["pie"] == "unknown"),
        "relro_full":    sum(1 for b in binaries if b["relro"] == "full"),
        "relro_partial": sum(1 for b in binaries if b["relro"] == "partial"),
        "relro_none":    sum(1 for b in binaries if b["relro"] == "none"),
        "canary_yes":    sum(1 for b in binaries if b["canary"] is True),
        "canary_no":     sum(1 for b in binaries if b["canary"] is False),
    }

    out_file.write_text(json.dumps({"summary": summary, "binaries": binaries}, indent=2))
    n = summary["total"]
    print(f"  {'hardening.json':45s}  {n} executables")
    print(f"    NX     : {summary['nx_enabled']} on / {summary['nx_disabled']} off / {summary['nx_unknown']} unknown")
    print(f"    PIE    : {summary['pie_yes']} yes / {summary['pie_no']} no / {summary['pie_unknown']} unknown")
    print(f"    RELRO  : {summary['relro_full']} full / {summary['relro_partial']} partial / {summary['relro_none']} none")
    print(f"    Canary : {summary['canary_yes']} yes / {summary['canary_no']} no")


def analyze_shellcheck(rootfs: Path, out_file: Path):
    """Run shellcheck --format=json on every .sh script and write findings to shellcheck.json."""
    scripts = sorted(p for p in rootfs.rglob("*.sh") if p.is_file())
    if not scripts:
        out_file.write_text("[]")
        print(f"  {'shellcheck.json':45s}  no shell scripts found")
        return

    if subprocess.run(["which", "shellcheck"], capture_output=True).returncode != 0:
        out_file.write_text("[]")
        print(f"  {'shellcheck.json':45s}  shellcheck not available — skipped")
        return

    try:
        r = subprocess.run(
            ["shellcheck", "--format=json", "--severity=warning", "--color=never"]
            + [str(p) for p in scripts],
            capture_output=True, text=True, timeout=300,
        )
        findings = json.loads(r.stdout) if r.stdout.strip() else []
    except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
        findings = []

    out_file.write_text(json.dumps(findings, indent=2))
    by_level: dict = {}
    for f in findings:
        by_level[f["level"]] = by_level.get(f["level"], 0) + 1
    summary = "  ".join(f"{n} {lvl}" for lvl, n in sorted(by_level.items()))
    print(f"  {'shellcheck.json':45s}  {len(findings)} findings ({summary or 'none'}) in {len(scripts)} scripts")


def analyze_linker_config(rootfs: Path, out_file: Path):
    all_sections = []
    preload = rootfs / "etc/ld.so.preload"
    if preload.exists():
        r = subprocess.run(["stat", "-c", "%a %U %G", str(preload)], capture_output=True, text=True)
        all_sections.append(section(
            "etc/ld.so.preload  [PRESENT — library injection vector]",
            f"Permissions: {r.stdout.strip()}\nContent:\n{preload.read_text(errors='replace')}",
        ))
    else:
        all_sections.append(section("etc/ld.so.preload", "(not present)"))

    ld_conf = rootfs / "etc/ld.so.conf"
    if ld_conf.exists():
        all_sections.append(section("etc/ld.so.conf", ld_conf.read_text(errors="replace")))

    lib_dirs = [str(d) for d in (rootfs / "lib", rootfs / "usr/lib") if d.is_dir()]
    if lib_dirs:
        r = subprocess.run(
            ["find"] + lib_dirs + ["-type", "d", "-perm", "-002"],
            capture_output=True, text=True,
        )
        all_sections.append(section("World-Writable Library Directories", r.stdout.strip() or "(none)"))

    out_file.write_text("".join(all_sections))
    print(f"  {'linker_config.txt':45s}  {sum(len(s.splitlines()) for s in all_sections)} lines")


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Analyze a router firmware root filesystem.")
    parser.add_argument("rootfs", type=Path, help="Path to extracted root filesystem.")
    parser.add_argument("--firmware", "-f", type=Path, default=None,
                        help="Original firmware binary path (names the output subdirectory).")
    parser.add_argument("--firmware-id", default=None,
                        help="Override output subdirectory name directly.")
    parser.add_argument("--output", "-o", type=Path, default=Path("/output/analysis"),
                        help="Base output directory (default: /output/analysis).")
    args = parser.parse_args()

    rootfs = args.rootfs.resolve()
    if not rootfs.is_dir():
        print(f"[!] Not a directory: {rootfs}")
        sys.exit(1)

    if args.firmware_id:
        firmware_id = args.firmware_id
    elif args.firmware:
        firmware_id = Path(args.firmware).stem
    else:
        firmware_id = rootfs.parent.name

    out_dir = args.output / firmware_id
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Rootfs : {rootfs}")
    print(f"[*] Output : {out_dir}/\n")

    all_configs = find_all_configs(rootfs)
    (out_dir / "config_files.txt").write_text("\n".join(all_configs))
    print(f"[*] Config files found : {len(all_configs)} — saved to config_files.txt")

    sections = []
    for path_str in all_configs:
        p = Path(path_str)
        try:
            content = p.read_text(errors="replace")
        except Exception as e:
            content = f"(could not read: {e})"
        sections.append(
            f"{'=' * 60}\n"
            f"  {p.relative_to(rootfs)}  ({p.suffix})\n"
            f"{'=' * 60}\n"
            f"{content}\n"
        )
    (out_dir / "config_files_content.txt").write_text("\n".join(sections))
    total_lines = sum(len(s.splitlines()) for s in sections)
    print(f"[*] Config files content saved to config_files_content.txt  ({total_lines} lines)\n")

    elf_cache: dict = {}

    steps = [
        ("[*] Scripts",
         lambda: analyze_scripts(rootfs, out_dir)),
        ("[*] ShellCheck static analysis",
         lambda: analyze_shellcheck(rootfs, out_dir / "shellcheck.json")),
        ("[*] Init scripts",
         lambda: analyze_init_scripts(rootfs, out_dir / "init_scripts.txt")),
        ("[*] Systemd services",
         lambda: analyze_systemd_services(rootfs, out_dir)),
        ("[*] Users and groups",
         lambda: analyze_users_groups(rootfs, out_dir / "users_groups.txt")),
        ("[*] SSH keys",
         lambda: analyze_ssh_keys(rootfs, out_dir / "ssh_keys.txt")),
        ("[*] Web interface",
         lambda: analyze_web_interface(rootfs, out_dir / "web_interface.txt")),
        ("[*] Web server configs",
         lambda: analyze_web_server_configs(rootfs, out_dir / "web_server_configs.txt")),
        ("[*] CGI and web handler injection vectors",
         lambda: analyze_cgi_injection(rootfs, out_dir / "cgi_injection.txt")),
        ("[*] PHP OS command injection  (taint: $_GET/$_POST/... → exec/system/...)",
         lambda: analyze_php_cmdinject(rootfs, out_dir / "php_cmdinject.txt")),
        ("[*] PHP code injection sinks  (eval / assert / preg_replace-/e / create_function / call_user_func)",
         lambda: analyze_php_codeinject(rootfs, out_dir / "php_codeinject.txt")),
        ("[*] PHP local file inclusion  (taint: $_GET/$_POST/... → include/require)",
         lambda: analyze_php_lfi(rootfs, out_dir / "php_lfi.txt")),
        ("[*] PHP information disclosure  (phpinfo / display_errors / error_reporting)",
         lambda: analyze_php_infodisclosure(rootfs, out_dir / "php_infodisclosure.txt")),
        ("[*] Credentials and secrets",
         lambda: analyze_credentials(rootfs, out_dir, all_configs)),
        ("[*] Default credentials / SSIDs",
         lambda: analyze_default_credentials(rootfs, out_dir / "default_credentials.txt", all_configs)),
        ("[*] Library versions",
         lambda: analyze_library_versions(rootfs, out_dir / "library_versions.txt")),
        ("[*] ELF analysis cache  (parallel: file + readelf + strings on every ELF binary)",
         lambda: elf_cache.update(build_elf_cache(rootfs))),
        ("[*] Architecture and endianness detection",
         lambda: analyze_architecture(rootfs, out_dir / "architecture.txt", elf_cache)),
        ("[*] Binary inventory",
         lambda: analyze_binary_inventory(rootfs, out_dir / "binary_inventory.txt", elf_cache)),
        ("[*] Binary hardening (NX / PIE / RELRO / stack canary)",
         lambda: analyze_hardening(rootfs, out_dir / "hardening.json", elf_cache)),
        ("[*] BusyBox detection and applet enumeration",
         lambda: analyze_busybox(rootfs, out_dir / "busybox.txt")),
        ("[*] Symlink map",
         lambda: analyze_symlinks(rootfs, out_dir / "symlinks.txt")),
        ("[*] Kernel modules",
         lambda: analyze_kernel_modules(rootfs, out_dir / "kernel_modules.txt")),
        ("[*] Network-capable binaries",
         lambda: analyze_network_binaries(rootfs, out_dir / "network_binaries.txt", elf_cache)),
        ("[*] Hardcoded strings in binaries",
         lambda: analyze_hardcoded_strings(rootfs, out_dir / "hardcoded_strings.txt", elf_cache)),
        ("[*] Protocol exposure  (SNMP / UPnP / TR-069 / MQTT)",
         lambda: analyze_protocols(rootfs, out_dir / "protocols.txt", all_configs)),
        ("[*] Interface binding  (LAN / WAN)",
         lambda: analyze_interface_binding(rootfs, out_dir / "interface_binding.txt", all_configs)),
        ("[*] NVRAM references",
         lambda: analyze_nvram(rootfs, out_dir / "nvram.txt")),
        ("[*] Weak cryptography",
         lambda: analyze_weak_crypto(rootfs, out_dir / "weak_crypto.txt", all_configs, elf_cache)),
        ("[*] World-writable files and SetGID",
         lambda: analyze_world_writable(rootfs, out_dir / "world_writable.txt")),
        ("[*] Linker configuration and library paths",
         lambda: analyze_linker_config(rootfs, out_dir / "linker_config.txt")),
        ("[*] SetUID binaries",
         lambda: run(["find", str(rootfs), "-perm", "-4000"], out_dir / "setuid_binaries.txt")),
        ("[*] Capabilities",
         lambda: run(["getcap", "-r", str(rootfs)], out_dir / "capabilities.txt")),
        ("[*] Extended attributes",
         lambda: run(["getfattr", "-R", "-n", "security.capability", str(rootfs)],
                     out_dir / "xattr_capabilities.txt")),
        ("[*] Scheduled tasks",
         lambda: analyze_scheduled_tasks(rootfs, out_dir / "scheduled_tasks.txt")),
        ("[*] Mount points and writable overlays",
         lambda: analyze_mount_points(rootfs, out_dir / "mount_points.txt")),
        ("[*] Firmware update mechanism",
         lambda: analyze_firmware_update(rootfs, out_dir / "firmware_update.txt", all_configs)),
        ("[*] SSL/TLS certificates and keys",
         lambda: analyze_certificates(rootfs, out_dir / "certificates_keys.txt")),
        ("[*] Unix sockets and IPC",
         lambda: analyze_unix_sockets(rootfs, out_dir / "unix_sockets.txt")),
        ("[*] Port / listen references",
         lambda: run(["grep", "-E", "port|listen|bind"] + all_configs, out_dir / "ports_listen.txt")
                 if all_configs else None),
        ("[*] HTTP server binaries",
         lambda: run(["find", str(rootfs),
                      "-name", "*httpd*", "-o", "-name", "*nginx*", "-o", "-name", "*boa*",
                      "-o", "-name", "*lighttpd*", "-o", "-name", "*uhttpd*"],
                     out_dir / "httpd_binaries.txt")),
        ("[*] Debug artifacts",
         lambda: analyze_debug_artifacts(rootfs, out_dir / "debug_artifacts.txt")),
        ("[*] DNS and routing",
         lambda: analyze_dns_routing(rootfs, out_dir / "dns_routing.txt")),
        ("[*] Firewall rules",
         lambda: analyze_firewall_rules(rootfs, out_dir / "firewall_rules.txt")),
        ("[*] Strings on HTTP binaries",
         lambda: _strings_http_binaries(rootfs, out_dir)),
    ]

    for label, fn in steps:
        print(label)
        fn()
        print()

    print(f"[+] Analysis complete. Results in {out_dir}/")


def _strings_http_binaries(rootfs: Path, out_dir: Path):
    KEYWORDS = {"bind", "listen", "socket", "port", "http", "tcp", "udp", "accept"}
    patterns = ["*httpd*", "*nginx*", "*boa*", "*lighttpd*", "*uhttpd*", "*mini_httpd*"]
    http_bins = [p for pat in patterns for p in rootfs.rglob(pat) if p.is_file()]
    for binary in http_bins:
        r = subprocess.run(["strings", str(binary)], capture_output=True, text=True)
        matches = [l for l in r.stdout.splitlines() if any(kw in l.lower() for kw in KEYWORDS)]
        out_file = out_dir / f"strings_{binary.name}.txt"
        out_file.write_text("\n".join(matches))
        print(f"  {out_file.name:45s}  {len(matches)} matching lines")


if __name__ == "__main__":
    main()
