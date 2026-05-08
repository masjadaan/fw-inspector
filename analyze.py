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
from analyzers.context import AnalysisContext, find_all_configs, run
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


def _run_step(label: str, fn) -> None:
    """Run one pipeline step, buffer its stdout, then print label + output atomically."""
    buf = io.StringIO()
    try:
        with redirect_stdout(buf):
            fn()
    except Exception as e:
        buf.write(f"  [ERROR] {e}\n")
    with _print_lock:
        print(label)
        print(buf.getvalue(), end="")
        print()


def _run_parallel(steps) -> None:
    """Execute (label, fn) pairs concurrently, capped at _STEP_WORKERS threads."""
    n = min(_STEP_WORKERS, len(steps) or 1)
    with ThreadPoolExecutor(max_workers=n) as executor:
        futures = {executor.submit(_run_step, label, fn): label for label, fn in steps}
        for future in as_completed(futures):
            future.result()


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

    # Each step: (label, fn, needs_elf).
    # needs_elf=True  → reads ctx.elf_cache; must run after the cache is built.
    # needs_elf=False → independent of ELF data; runs in the first parallel wave.
    steps = [
        ("[*] Scripts",
         lambda: analyze_scripts(ctx),                                                          False),
        ("[*] ShellCheck static analysis",
         lambda: analyze_shellcheck(ctx),                                                       False),
        ("[*] Init scripts",
         lambda: analyze_init_scripts(ctx),                                                     False),
        ("[*] Systemd services",
         lambda: analyze_systemd_services(ctx),                                                 False),
        ("[*] Users and groups",
         lambda: analyze_users_groups(ctx),                                                     False),
        ("[*] SSH keys",
         lambda: analyze_ssh_keys(ctx),                                                         False),
        ("[*] Web interface",
         lambda: analyze_web_interface(ctx),                                                    False),
        ("[*] Web server configs",
         lambda: analyze_web_server_configs(ctx),                                               False),
        ("[*] CGI and web handler injection vectors",
         lambda: analyze_cgi_injection(ctx),                                                    False),
        ("[*] PHP OS command injection  (taint: $_GET/$_POST/... → exec/system/...)",
         lambda: analyze_php_cmdinject(ctx),                                                    False),
        ("[*] PHP code injection sinks  (eval / assert / preg_replace-/e / create_function / call_user_func)",
         lambda: analyze_php_codeinject(ctx),                                                   False),
        ("[*] PHP local file inclusion  (taint: $_GET/$_POST/... → include/require)",
         lambda: analyze_php_lfi(ctx),                                                          False),
        ("[*] PHP information disclosure  (phpinfo / display_errors / error_reporting)",
         lambda: analyze_php_infodisclosure(ctx),                                               False),
        ("[*] Credentials and secrets",
         lambda: analyze_credentials(ctx),                                                      False),
        ("[*] Default credentials / SSIDs",
         lambda: analyze_default_credentials(ctx),                                              False),
        ("[*] Library versions",
         lambda: analyze_library_versions(ctx),                                                 False),
        ("[*] BusyBox detection and applet enumeration",
         lambda: analyze_busybox(ctx),                                                          False),
        ("[*] Symlink map",
         lambda: analyze_symlinks(ctx),                                                         False),
        ("[*] Kernel modules",
         lambda: analyze_kernel_modules(ctx),                                                   False),
        ("[*] Protocol exposure  (SNMP / UPnP / TR-069 / MQTT)",
         lambda: analyze_protocols(ctx),                                                        False),
        ("[*] Interface binding  (LAN / WAN)",
         lambda: analyze_interface_binding(ctx),                                                False),
        ("[*] NVRAM references",
         lambda: analyze_nvram(ctx),                                                            False),
        ("[*] World-writable files and SetGID",
         lambda: analyze_world_writable(ctx),                                                   False),
        ("[*] Linker configuration and library paths",
         lambda: analyze_linker_config(ctx),                                                    False),
        ("[*] SetUID binaries",
         lambda: run(["find", str(ctx.rootfs), "-perm", "-4000"], ctx.out_dir / "setuid_binaries.txt"),
                                                                                                False),
        ("[*] Capabilities",
         lambda: run(["getcap", "-r", str(ctx.rootfs)], ctx.out_dir / "capabilities.txt"),     False),
        ("[*] Extended attributes",
         lambda: run(["getfattr", "-R", "-n", "security.capability", str(ctx.rootfs)],
                     ctx.out_dir / "xattr_capabilities.txt"),                                   False),
        ("[*] Scheduled tasks",
         lambda: analyze_scheduled_tasks(ctx),                                                  False),
        ("[*] Mount points and writable overlays",
         lambda: analyze_mount_points(ctx),                                                     False),
        ("[*] Firmware update mechanism",
         lambda: analyze_firmware_update(ctx),                                                  False),
        ("[*] SSL/TLS certificates and keys",
         lambda: analyze_certificates(ctx),                                                     False),
        ("[*] Unix sockets and IPC",
         lambda: analyze_unix_sockets(ctx),                                                     False),
        ("[*] Port / listen references",
         lambda: run(["grep", "-E", "port|listen|bind"] + ctx.configs,
                     ctx.out_dir / "ports_listen.txt") if ctx.configs else None,               False),
        ("[*] HTTP server binaries",
         lambda: run(["find", str(ctx.rootfs),
                      "-name", "*httpd*", "-o", "-name", "*nginx*", "-o", "-name", "*boa*",
                      "-o", "-name", "*lighttpd*", "-o", "-name", "*uhttpd*"],
                     ctx.out_dir / "httpd_binaries.txt"),                                       False),
        ("[*] Debug artifacts",
         lambda: analyze_debug_artifacts(ctx),                                                  False),
        ("[*] DNS and routing",
         lambda: analyze_dns_routing(ctx),                                                      False),
        ("[*] Firewall rules",
         lambda: analyze_firewall_rules(ctx),                                                   False),
        ("[*] Strings on HTTP binaries",
         lambda: _strings_http_binaries(ctx),                                                   False),
        # ── ELF-dependent steps (run after cache is built) ─────────────────────
        ("[*] Architecture and endianness detection",
         lambda: analyze_architecture(ctx),                                                     True),
        ("[*] Binary inventory",
         lambda: analyze_binary_inventory(ctx),                                                 True),
        ("[*] Binary hardening (NX / PIE / RELRO / stack canary)",
         lambda: analyze_hardening(ctx),                                                        True),
        ("[*] Network-capable binaries",
         lambda: analyze_network_binaries(ctx),                                                 True),
        ("[*] Hardcoded strings in binaries",
         lambda: analyze_hardcoded_strings(ctx),                                                True),
        ("[*] Weak cryptography",
         lambda: analyze_weak_crypto(ctx),                                                      True),
    ]

    pre_steps  = [(label, fn) for label, fn, needs_elf in steps if not needs_elf]
    post_steps = [(label, fn) for label, fn, needs_elf in steps if needs_elf]

    # Phase 1: all ELF-independent steps in parallel.
    _run_parallel(pre_steps)

    # Phase 2: build the ELF cache (its own internal thread pool; runs once).
    print("[*] ELF analysis cache  (parallel: file + readelf + strings on every ELF binary)")
    ctx.elf_cache.update(build_elf_cache(ctx.rootfs))
    print()

    # Phase 3: all ELF-dependent steps in parallel.
    _run_parallel(post_steps)

    print(f"[+] Analysis complete. Results in {out_dir}/")


if __name__ == "__main__":
    main()
