#!/usr/bin/env python3
"""
Analyzes a router firmware root filesystem and collects data for
attack surface mapping across services, binaries, configs, and protocols.
"""

import argparse
import io
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import redirect_stdout
from pathlib import Path

from analyzers.binary import (
    _strings_http_binaries,
    analyze_architecture,
    analyze_binary_inventory,
    analyze_busybox,
    analyze_hardcoded_strings,
    analyze_hardening,
    analyze_kernel_modules,
    analyze_library_versions,
    analyze_linker_config,
    analyze_network_binaries,
    analyze_shellcheck,
    analyze_symlinks,
    analyze_weak_crypto,
)
from analyzers.context import AnalysisContext, Analyzer, find_all_configs, run
from analyzers.elf_cache import build_elf_cache
from analyzers.network import analyze_interface_binding, analyze_protocols
from analyzers.system import (
    analyze_certificates,
    analyze_credentials,
    analyze_debug_artifacts,
    analyze_default_credentials,
    analyze_dns_routing,
    analyze_firewall_rules,
    analyze_firmware_update,
    analyze_init_scripts,
    analyze_mount_points,
    analyze_nvram,
    analyze_scheduled_tasks,
    analyze_scripts,
    analyze_ssh_keys,
    analyze_systemd_services,
    analyze_unix_sockets,
    analyze_users_groups,
    analyze_world_writable,
)
from analyzers.web import (
    analyze_cgi_injection,
    analyze_php_cmdinject,
    analyze_php_codeinject,
    analyze_php_infodisclosure,
    analyze_php_lfi,
    analyze_web_interface,
    analyze_web_server_configs,
)

# ── Parallel execution ─────────────────────────────────────────────────────────

_STEP_WORKERS = 8
_print_lock   = threading.Lock()


def _run_step(step: Analyzer, ctx: AnalysisContext) -> None:
    """Run one pipeline step, buffer its stdout, then print label + output atomically."""
    buf = io.StringIO()
    try:
        with redirect_stdout(buf):
            step.run(ctx)
    except Exception as e:
        buf.write(f"  [ERROR] {e}\n")
    with _print_lock:
        print(step.label)
        print(buf.getvalue(), end="")
        print()


def _run_parallel(steps: list[Analyzer], ctx: AnalysisContext) -> None:
    """Execute Analyzer steps concurrently, capped at _STEP_WORKERS threads."""
    n = min(_STEP_WORKERS, len(steps) or 1)
    with ThreadPoolExecutor(max_workers=n) as executor:
        futures = {executor.submit(_run_step, step, ctx): step.label for step in steps}
        for future in as_completed(futures):
            future.result()


# ── Pipeline steps ─────────────────────────────────────────────────────────────

# Each Analyzer declares label, fn(ctx), and needs_elf.
# needs_elf=True  → reads ctx.elf_cache; runs after the cache is built (phase 3).
# needs_elf=False → independent of ELF data; runs concurrently in phase 1.
STEPS: list[Analyzer] = [
    Analyzer("[*] Scripts",                                                          analyze_scripts),
    Analyzer("[*] ShellCheck static analysis",                                       analyze_shellcheck),
    Analyzer("[*] Init scripts",                                                     analyze_init_scripts),
    Analyzer("[*] Systemd services",                                                 analyze_systemd_services),
    Analyzer("[*] Users and groups",                                                 analyze_users_groups),
    Analyzer("[*] SSH keys",                                                         analyze_ssh_keys),
    Analyzer("[*] Web interface",                                                    analyze_web_interface),
    Analyzer("[*] Web server configs",                                               analyze_web_server_configs),
    Analyzer("[*] CGI and web handler injection vectors",                            analyze_cgi_injection),
    Analyzer("[*] PHP OS command injection  (taint: $_GET/$_POST/... → exec/system/...)",
             analyze_php_cmdinject),
    Analyzer("[*] PHP code injection sinks  (eval / assert / preg_replace-/e / create_function / call_user_func)",
             analyze_php_codeinject),
    Analyzer("[*] PHP local file inclusion  (taint: $_GET/$_POST/... → include/require)",
             analyze_php_lfi),
    Analyzer("[*] PHP information disclosure  (phpinfo / display_errors / error_reporting)",
             analyze_php_infodisclosure),
    Analyzer("[*] Credentials and secrets",                                          analyze_credentials),
    Analyzer("[*] Default credentials / SSIDs",                                      analyze_default_credentials),
    Analyzer("[*] Library versions",                                                 analyze_library_versions),
    Analyzer("[*] BusyBox detection and applet enumeration",                         analyze_busybox),
    Analyzer("[*] Symlink map",                                                      analyze_symlinks),
    Analyzer("[*] Kernel modules",                                                   analyze_kernel_modules),
    Analyzer("[*] Protocol exposure  (SNMP / UPnP / TR-069 / MQTT)",               analyze_protocols),
    Analyzer("[*] Interface binding  (LAN / WAN)",                                  analyze_interface_binding),
    Analyzer("[*] NVRAM references",                                                 analyze_nvram),
    Analyzer("[*] World-writable files and SetGID",                                  analyze_world_writable),
    Analyzer("[*] Linker configuration and library paths",                           analyze_linker_config),
    Analyzer("[*] SetUID binaries",
             lambda ctx: run(["find", str(ctx.rootfs), "-perm", "-4000"],
                             ctx.out_dir / "setuid_binaries.txt")),
    Analyzer("[*] Capabilities",
             lambda ctx: run(["getcap", "-r", str(ctx.rootfs)],
                             ctx.out_dir / "capabilities.txt")),
    Analyzer("[*] Extended attributes",
             lambda ctx: run(["getfattr", "-R", "-n", "security.capability", str(ctx.rootfs)],
                             ctx.out_dir / "xattr_capabilities.txt")),
    Analyzer("[*] Scheduled tasks",                                                  analyze_scheduled_tasks),
    Analyzer("[*] Mount points and writable overlays",                               analyze_mount_points),
    Analyzer("[*] Firmware update mechanism",                                        analyze_firmware_update),
    Analyzer("[*] SSL/TLS certificates and keys",                                    analyze_certificates),
    Analyzer("[*] Unix sockets and IPC",                                             analyze_unix_sockets),
    Analyzer("[*] Port / listen references",
             lambda ctx: run(["grep", "-E", "port|listen|bind"] + ctx.configs,
                             ctx.out_dir / "ports_listen.txt") if ctx.configs else None),
    Analyzer("[*] HTTP server binaries",
             lambda ctx: run(["find", str(ctx.rootfs),
                              "-name", "*httpd*", "-o", "-name", "*nginx*", "-o", "-name", "*boa*",
                              "-o", "-name", "*lighttpd*", "-o", "-name", "*uhttpd*"],
                             ctx.out_dir / "httpd_binaries.txt")),
    Analyzer("[*] Debug artifacts",                                                  analyze_debug_artifacts),
    Analyzer("[*] DNS and routing",                                                  analyze_dns_routing),
    Analyzer("[*] Firewall rules",                                                   analyze_firewall_rules),
    Analyzer("[*] Strings on HTTP binaries",                                         _strings_http_binaries),
    # ── ELF-dependent (phase 3) ────────────────────────────────────────────────
    Analyzer("[*] Architecture and endianness detection",  analyze_architecture,    needs_elf=True),
    Analyzer("[*] Binary inventory",                       analyze_binary_inventory, needs_elf=True),
    Analyzer("[*] Binary hardening (NX / PIE / RELRO / stack canary)",
             analyze_hardening,                                                      needs_elf=True),
    Analyzer("[*] Network-capable binaries",               analyze_network_binaries, needs_elf=True),
    Analyzer("[*] Hardcoded strings in binaries",          analyze_hardcoded_strings, needs_elf=True),
    Analyzer("[*] Weak cryptography",                      analyze_weak_crypto,      needs_elf=True),
]

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

    ctx = AnalysisContext(rootfs=rootfs, out_dir=out_dir, configs=all_configs)

    pre_steps  = [s for s in STEPS if not s.needs_elf]
    post_steps = [s for s in STEPS if s.needs_elf]

    # Phase 1: all ELF-independent steps in parallel.
    _run_parallel(pre_steps, ctx)

    # Phase 2: build the ELF cache (its own internal thread pool; runs once).
    print("[*] ELF analysis cache  (parallel: file + readelf + strings on every ELF binary)")
    ctx.elf_cache.update(build_elf_cache(ctx.rootfs))
    print()

    # Phase 3: all ELF-dependent steps in parallel.
    _run_parallel(post_steps, ctx)

    print(f"[+] Analysis complete. Results in {out_dir}/")


if __name__ == "__main__":
    main()
