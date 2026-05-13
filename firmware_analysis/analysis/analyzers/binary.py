import json
import re
import subprocess

from .context import AnalysisContext, section, multi_section_file, run
from .elf_cache import _WEAK_SYM_PAT, _FILE_TIMEOUT


def _points_to_busybox(link) -> bool:
    try:
        target = str(link.readlink())
        return target == "busybox" or target.endswith("/busybox")
    except Exception:
        return False


def analyze_network_binaries(ctx: AnalysisContext):
    out_file = ctx.out_dir / "network_binaries.txt"
    KEYWORDS = {"bind", "listen", "accept", "socket", "connect", "recv", "send"}
    results = []
    for path, rec in ctx.elf_cache.items():
        matches = [l for l in rec.strings_lines if any(kw in l.lower() for kw in KEYWORDS)]
        if matches:
            results.append(f"--- {path.relative_to(ctx.rootfs)} ---")
            results.extend(matches)
            results.append("")
    content = "\n".join(results)
    out_file.write_text(content)
    lines = len(content.strip().splitlines()) if content.strip() else 0
    print(f"  {'network_binaries.txt':45s}  {lines} lines")


def analyze_binary_inventory(ctx: AnalysisContext):
    out_file = ctx.out_dir / "binary_inventory.txt"
    all_files = [p for p in ctx.rootfs.rglob("*") if p.is_file() and not p.is_symlink()]
    lines = []
    for f in all_files:
        rec = ctx.elf_cache.get(f)
        if rec:
            lines.append(str(f.relative_to(ctx.rootfs)))
            lines.append(f"  type : {rec.file_type}")
            lines.append(f"  libs : {', '.join(rec.needed_libs) if rec.needed_libs else 'none'}")
            if rec.crypto_imports:
                lines.append(f"  crypto imports : {', '.join(rec.crypto_imports)}")
        else:
            try:
                r = subprocess.run(
                    ["file", str(f)], capture_output=True, text=True, timeout=_FILE_TIMEOUT
                )
                file_type = r.stdout.split(":", 1)[-1].strip()
            except Exception:
                file_type = "(error)"
            lines.append(str(f.relative_to(ctx.rootfs)))
            lines.append(f"  type : {file_type}")
        lines.append("")
    out_file.write_text("\n".join(lines))
    print(f"  {'binary_inventory.txt':45s}  {len(all_files)} files")


def analyze_architecture(ctx: AnalysisContext):
    out_file  = ctx.out_dir / "architecture.txt"
    json_file = ctx.out_dir / "architecture.json"
    _PAT  = re.compile(r'ELF\s+(\d+)-bit\s+(LSB|MSB)\s+\w+,\s+([^,]+)')
    _NAME = {"Intel": "x86", "AArch64": "ARM64"}
    _EMPTY = {"arch": "unknown", "bits": 0, "endianness": "unknown",
              "endianness_short": "?", "confidence": 0.0, "elf_count": 0}

    votes: dict = {}
    for path, rec in ctx.elf_cache.items():
        m = _PAT.search(rec.file_type)
        if not m:
            continue
        bits         = int(m.group(1))
        endian_short = m.group(2)
        arch_word    = m.group(3).strip().split()[0]
        arch         = _NAME.get(arch_word, arch_word)
        key          = (arch, bits, endian_short)
        votes.setdefault(key, []).append(path)

    if not votes:
        out_file.write_text(section("Detected Architecture", "(no ELF binaries found)"))
        json_file.write_text(json.dumps(_EMPTY, indent=2))
        print(f"  {'architecture.txt':45s}  no ELF binaries")
        return

    dominant     = max(votes, key=lambda k: len(votes[k]))
    arch, bits, endian_short = dominant
    agreeing     = len(votes[dominant])
    total_elf    = len(ctx.elf_cache)
    confidence   = round(agreeing / total_elf, 2)
    endianness   = "little-endian" if endian_short == "LSB" else "big-endian"

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
        f"  {p.relative_to(ctx.rootfs)}  |  {ctx.elf_cache[p].file_type[:80]}"
        for p in sorted(votes[dominant])[:20]
    ]
    out_file.write_text(
        section("Detected Architecture", summary) +
        section(f"Per-Binary Evidence ({agreeing} matching, up to 20 shown)", "\n".join(evidence))
    )
    json_file.write_text(json.dumps({
        "arch":             arch,
        "bits":             bits,
        "endianness":       endianness,
        "endianness_short": endian_short,
        "confidence":       confidence,
        "elf_count":        total_elf,
    }, indent=2))
    print(f"  {'architecture.txt':45s}  {arch} {bits}-bit {endianness}  (conf={confidence}, {agreeing}/{total_elf} ELFs)")


def analyze_hardcoded_strings(ctx: AnalysisContext):
    out_file = ctx.out_dir / "hardcoded_strings.txt"
    PATTERNS = [r"https?://", r"api[_-]?key", r"token=", r"secret=", r"Bearer\s"]
    results = []
    for path, rec in ctx.elf_cache.items():
        matches = [
            l for l in rec.strings_lines
            if any(re.search(pat, l, re.IGNORECASE) for pat in PATTERNS)
        ]
        if matches:
            results.append(f"--- {path.relative_to(ctx.rootfs)} ---")
            results.extend(matches)
            results.append("")
    content = "\n".join(results)
    out_file.write_text(content)
    lines = len(content.strip().splitlines()) if content.strip() else 0
    print(f"  {'hardcoded_strings.txt':45s}  {lines} lines")


def analyze_weak_crypto(ctx: AnalysisContext):
    out_file  = ctx.out_dir / "weak_crypto.txt"
    json_file = ctx.out_dir / "weak_crypto.json"
    checks = [
        ("Weak Crypto in Config Files",
         ["grep", "-Ei", r"md5|des|rc4|ecb|base64.*key|static.*key"] + ctx.configs),
        ("Weak Crypto References in Binaries (string grep — approximate)",
         ["grep", "-rE", "MD5|DES|RC4|ECB", str(ctx.rootfs / "usr"), str(ctx.rootfs / "lib")]
         if (ctx.rootfs / "usr").exists() else []),
    ]
    checks = [(t, c) for t, c in checks if c]
    captured = multi_section_file(checks, out_file, "weak_crypto.txt")

    elf_findings = []
    for path, rec in ctx.elf_cache.items():
        syms = [s for s in rec.crypto_imports if _WEAK_SYM_PAT.match(s)]
        if syms:
            elf_findings.append(f"  {path.relative_to(ctx.rootfs)}: {', '.join(syms)}")
    sec = section(
        "Binaries Importing Weak Crypto Symbols  [readelf — concrete, not inferred]",
        "\n".join(elf_findings) if elf_findings else "(none)",
    )
    with open(out_file, "a") as f:
        f.write(sec)
    if elf_findings:
        print(f"    → {len(elf_findings)} ELF binaries import weak crypto symbols (readelf)")

    json_data = [
        {"context": title, "evidence": lines[:5]}
        for title, lines in captured.items()
        if lines
    ]
    if elf_findings:
        json_data.append({
            "context":  "Binaries Importing Weak Crypto Symbols",
            "evidence": elf_findings[:5],
        })
    json_file.write_text(json.dumps(json_data, indent=2))


def analyze_hardening(ctx: AnalysisContext):
    """Summarise NX / PIE / RELRO / stack-canary status for every ELF executable."""
    out_file = ctx.out_dir / "hardening.json"
    binaries = []
    for path, rec in sorted(ctx.elf_cache.items(), key=lambda x: x[0]):
        h = rec.hardening
        if not h or h.get("pie") == "so":
            continue
        binaries.append({
            "path":   str(path.relative_to(ctx.rootfs)),
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


def analyze_busybox(ctx: AnalysisContext):
    out_file = ctx.out_dir / "busybox.txt"
    bb_bins = [p for p in ctx.rootfs.rglob("busybox") if p.is_file() and not p.is_symlink()]
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
            f"Version  ({bb.relative_to(ctx.rootfs)})",
            "\n".join(version_lines) if version_lines else "(version string not found)",
        ))
        applets = sorted(
            str(p.relative_to(ctx.rootfs))
            for p in ctx.rootfs.rglob("*")
            if p.is_symlink() and _points_to_busybox(p)
        )
        total_applets = len(applets)
        all_sections.append(section(f"Applets via symlinks  ({len(applets)} found)", "\n".join(applets)))

    out_file.write_text("".join(all_sections))
    print(f"  {'busybox.txt':45s}  {len(bb_bins)} binary(s), {total_applets} applets")


def analyze_symlinks(ctx: AnalysisContext):
    out_file = ctx.out_dir / "symlinks.txt"
    valid, broken = [], []
    for p in sorted(ctx.rootfs.rglob("*")):
        if not p.is_symlink():
            continue
        try:
            raw = p.readlink()
            resolved = ctx.rootfs / str(raw).lstrip("/") if raw.is_absolute() else p.parent / raw
            entry = f"{p.relative_to(ctx.rootfs)} -> {raw}"
            (valid if resolved.exists() else broken).append(entry)
        except Exception:
            broken.append(f"{p.relative_to(ctx.rootfs)} -> (unreadable)")
    out_file.write_text(
        section(f"Valid Symlinks  ({len(valid)})", "\n".join(valid)) +
        section(f"Broken Symlinks  ({len(broken)})", "\n".join(broken) if broken else "(none)")
    )
    print(f"  {'symlinks.txt':45s}  {len(valid)} valid, {len(broken)} broken")


def analyze_kernel_modules(ctx: AnalysisContext):
    out_file = ctx.out_dir / "kernel_modules.txt"
    r = subprocess.run(["find", str(ctx.rootfs), "-name", "*.ko"], capture_output=True, text=True)
    sections = [section("Kernel Modules (.ko)", r.stdout)]
    for dep in ctx.rootfs.rglob("modules.dep"):
        sections.append(section(str(dep.relative_to(ctx.rootfs)), dep.read_text(errors="replace")))
    out_file.write_text("".join(sections))
    total = sum(len(s.splitlines()) for s in sections)
    print(f"  {'kernel_modules.txt':45s}  {total} lines")


def analyze_library_versions(ctx: AnalysisContext):
    out_file = ctx.out_dir / "library_versions.txt"
    libs = {
        "libc":      ["libc.so*", "libc-*.so"],
        "libssl":    ["libssl.so*"],
        "libcrypto": ["libcrypto.so*"],
        "libcurl":   ["libcurl.so*"],
        "libuClibc": ["libuClibc*.so*"],
    }
    sections = []
    for name, patterns in libs.items():
        found = [p for pat in patterns for p in ctx.rootfs.rglob(pat)]
        if not found:
            sections.append(section(name, "(not found)"))
            continue
        output_lines = []
        for lib in found:
            output_lines.append(f"  {lib.relative_to(ctx.rootfs)}")
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


def analyze_shellcheck(ctx: AnalysisContext):
    """Run shellcheck --format=json on every .sh script and write findings to shellcheck.json."""
    out_file = ctx.out_dir / "shellcheck.json"
    scripts = sorted(p for p in ctx.rootfs.rglob("*.sh") if p.is_file())
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


def analyze_linker_config(ctx: AnalysisContext):
    out_file = ctx.out_dir / "linker_config.txt"
    all_sections = []
    preload = ctx.rootfs / "etc/ld.so.preload"
    if preload.exists():
        r = subprocess.run(["stat", "-c", "%a %U %G", str(preload)], capture_output=True, text=True)
        all_sections.append(section(
            "etc/ld.so.preload  [PRESENT — library injection vector]",
            f"Permissions: {r.stdout.strip()}\nContent:\n{preload.read_text(errors='replace')}",
        ))
    else:
        all_sections.append(section("etc/ld.so.preload", "(not present)"))

    ld_conf = ctx.rootfs / "etc/ld.so.conf"
    if ld_conf.exists():
        all_sections.append(section("etc/ld.so.conf", ld_conf.read_text(errors="replace")))

    lib_dirs = [str(d) for d in (ctx.rootfs / "lib", ctx.rootfs / "usr/lib") if d.is_dir()]
    if lib_dirs:
        r = subprocess.run(
            ["find"] + lib_dirs + ["-type", "d", "-perm", "-002"],
            capture_output=True, text=True,
        )
        all_sections.append(section("World-Writable Library Directories", r.stdout.strip() or "(none)"))

    out_file.write_text("".join(all_sections))
    print(f"  {'linker_config.txt':45s}  {sum(len(s.splitlines()) for s in all_sections)} lines")


def analyze_httpd_binaries(ctx: AnalysisContext):
    """Find HTTP server binaries and write httpd_binaries.txt + httpd_binaries.json."""
    out_file  = ctx.out_dir / "httpd_binaries.txt"
    json_file = ctx.out_dir / "httpd_binaries.json"
    r = subprocess.run(
        ["find", str(ctx.rootfs),
         "-name", "*httpd*", "-o", "-name", "*nginx*", "-o", "-name", "*boa*",
         "-o", "-name", "*lighttpd*", "-o", "-name", "*uhttpd*"],
        capture_output=True, text=True,
    )
    out_file.write_text(r.stdout)
    binaries = [l.strip() for l in r.stdout.splitlines() if l.strip()]
    json_file.write_text(json.dumps({"binaries": binaries}, indent=2))
    status = f"{len(binaries)} found" if binaries else "empty"
    print(f"  {out_file.name:45s}  {status}")


def _strings_http_binaries(ctx: AnalysisContext):
    KEYWORDS = {"bind", "listen", "socket", "port", "http", "tcp", "udp", "accept"}
    patterns = ["*httpd*", "*nginx*", "*boa*", "*lighttpd*", "*uhttpd*", "*mini_httpd*"]
    http_bins = [p for pat in patterns for p in ctx.rootfs.rglob(pat) if p.is_file()]
    for binary in http_bins:
        r = subprocess.run(["strings", str(binary)], capture_output=True, text=True)
        matches = [l for l in r.stdout.splitlines() if any(kw in l.lower() for kw in KEYWORDS)]
        out_file = ctx.out_dir / f"strings_{binary.name}.txt"
        out_file.write_text("\n".join(matches))
        print(f"  {out_file.name:45s}  {len(matches)} matching lines")
