#!/usr/bin/env python3
"""
Analyzes a router firmware root filesystem and collects data for
attack surface mapping across services, binaries, configs, and protocols.
"""

import argparse
import sys
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

    steps = [
        ("[*] Scripts",
         lambda: analyze_scripts(ctx)),
        ("[*] ShellCheck static analysis",
         lambda: analyze_shellcheck(ctx)),
        ("[*] Init scripts",
         lambda: analyze_init_scripts(ctx)),
        ("[*] Systemd services",
         lambda: analyze_systemd_services(ctx)),
        ("[*] Users and groups",
         lambda: analyze_users_groups(ctx)),
        ("[*] SSH keys",
         lambda: analyze_ssh_keys(ctx)),
        ("[*] Web interface",
         lambda: analyze_web_interface(ctx)),
        ("[*] Web server configs",
         lambda: analyze_web_server_configs(ctx)),
        ("[*] CGI and web handler injection vectors",
         lambda: analyze_cgi_injection(ctx)),
        ("[*] PHP OS command injection  (taint: $_GET/$_POST/... → exec/system/...)",
         lambda: analyze_php_cmdinject(ctx)),
        ("[*] PHP code injection sinks  (eval / assert / preg_replace-/e / create_function / call_user_func)",
         lambda: analyze_php_codeinject(ctx)),
        ("[*] PHP local file inclusion  (taint: $_GET/$_POST/... → include/require)",
         lambda: analyze_php_lfi(ctx)),
        ("[*] PHP information disclosure  (phpinfo / display_errors / error_reporting)",
         lambda: analyze_php_infodisclosure(ctx)),
        ("[*] Credentials and secrets",
         lambda: analyze_credentials(ctx)),
        ("[*] Default credentials / SSIDs",
         lambda: analyze_default_credentials(ctx)),
        ("[*] Library versions",
         lambda: analyze_library_versions(ctx)),
        ("[*] ELF analysis cache  (parallel: file + readelf + strings on every ELF binary)",
         lambda: ctx.elf_cache.update(build_elf_cache(ctx.rootfs))),
        ("[*] Architecture and endianness detection",
         lambda: analyze_architecture(ctx)),
        ("[*] Binary inventory",
         lambda: analyze_binary_inventory(ctx)),
        ("[*] Binary hardening (NX / PIE / RELRO / stack canary)",
         lambda: analyze_hardening(ctx)),
        ("[*] BusyBox detection and applet enumeration",
         lambda: analyze_busybox(ctx)),
        ("[*] Symlink map",
         lambda: analyze_symlinks(ctx)),
        ("[*] Kernel modules",
         lambda: analyze_kernel_modules(ctx)),
        ("[*] Network-capable binaries",
         lambda: analyze_network_binaries(ctx)),
        ("[*] Hardcoded strings in binaries",
         lambda: analyze_hardcoded_strings(ctx)),
        ("[*] Protocol exposure  (SNMP / UPnP / TR-069 / MQTT)",
         lambda: analyze_protocols(ctx)),
        ("[*] Interface binding  (LAN / WAN)",
         lambda: analyze_interface_binding(ctx)),
        ("[*] NVRAM references",
         lambda: analyze_nvram(ctx)),
        ("[*] Weak cryptography",
         lambda: analyze_weak_crypto(ctx)),
        ("[*] World-writable files and SetGID",
         lambda: analyze_world_writable(ctx)),
        ("[*] Linker configuration and library paths",
         lambda: analyze_linker_config(ctx)),
        ("[*] SetUID binaries",
         lambda: run(["find", str(ctx.rootfs), "-perm", "-4000"], ctx.out_dir / "setuid_binaries.txt")),
        ("[*] Capabilities",
         lambda: run(["getcap", "-r", str(ctx.rootfs)], ctx.out_dir / "capabilities.txt")),
        ("[*] Extended attributes",
         lambda: run(["getfattr", "-R", "-n", "security.capability", str(ctx.rootfs)],
                     ctx.out_dir / "xattr_capabilities.txt")),
        ("[*] Scheduled tasks",
         lambda: analyze_scheduled_tasks(ctx)),
        ("[*] Mount points and writable overlays",
         lambda: analyze_mount_points(ctx)),
        ("[*] Firmware update mechanism",
         lambda: analyze_firmware_update(ctx)),
        ("[*] SSL/TLS certificates and keys",
         lambda: analyze_certificates(ctx)),
        ("[*] Unix sockets and IPC",
         lambda: analyze_unix_sockets(ctx)),
        ("[*] Port / listen references",
         lambda: run(["grep", "-E", "port|listen|bind"] + ctx.configs, ctx.out_dir / "ports_listen.txt")
                 if ctx.configs else None),
        ("[*] HTTP server binaries",
         lambda: run(["find", str(ctx.rootfs),
                      "-name", "*httpd*", "-o", "-name", "*nginx*", "-o", "-name", "*boa*",
                      "-o", "-name", "*lighttpd*", "-o", "-name", "*uhttpd*"],
                     ctx.out_dir / "httpd_binaries.txt")),
        ("[*] Debug artifacts",
         lambda: analyze_debug_artifacts(ctx)),
        ("[*] DNS and routing",
         lambda: analyze_dns_routing(ctx)),
        ("[*] Firewall rules",
         lambda: analyze_firewall_rules(ctx)),
        ("[*] Strings on HTTP binaries",
         lambda: _strings_http_binaries(ctx)),
    ]

    for label, fn in steps:
        print(label)
        fn()
        print()

    print(f"[+] Analysis complete. Results in {out_dir}/")


if __name__ == "__main__":
    main()
