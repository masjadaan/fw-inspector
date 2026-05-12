"""
Generate a CycloneDX 1.5 SBOM from the ELF cache and filesystem scan.

Component mapping:
  shared libraries (.so*)  → type=library
  ELF executables          → type=application
  BusyBox                  → type=application  (applets as properties)
  kernel modules (.ko)     → type=firmware     (subtype=kernel-module)

Version resolution order:
  1. soname suffix in filename  (libssl.so.1.0.0 → 1.0.0)
  2. version string in binary's strings output
  3. omitted (unknown)

Hardening flags (NX/PIE/RELRO/canary) are attached as CycloneDX
properties on every executable so downstream tools can filter on them.
"""

import hashlib
import json
import re
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .context import AnalysisContext


# ── Patterns ──────────────────────────────────────────────────────────────────

_VER_PAT = re.compile(r'\b(\d+\.\d+(?:\.\d+){0,3}(?:[-+][a-zA-Z0-9._-]+)?)\b')
_SONAME_VER_PAT = re.compile(r'\.so\.(\d[\d.]+)')
_BUSYBOX_VER_PAT = re.compile(r'BusyBox\s+v?(\d+\.\d+[\d.]*)', re.IGNORECASE)
_NAME_VER_PAT = re.compile(r'-(\d+\.\d+[\d.]*)')   # libcrypt-0.9.33.2 → 0.9.33.2


# ── CPE mapping ───────────────────────────────────────────────────────────────
# Maps a regex matched against the canonical component name to (vendor, product).
# CPE format: cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*:*
# Only components with a known vendor/product AND a resolved version get a CPE.

_CPE_MAP: list[tuple[re.Pattern, str, str]] = [
    # OpenSSL — covers both the libraries and the CLI binary
    (re.compile(r'^lib(ssl|crypto)$',      re.I), 'openssl',          'openssl'),
    (re.compile(r'^openssl$',              re.I), 'openssl',          'openssl'),
    # cURL
    (re.compile(r'^libcurl$',             re.I), 'haxx',             'libcurl'),
    (re.compile(r'^curl$',                re.I), 'haxx',             'curl'),
    # BusyBox
    (re.compile(r'^busybox$',             re.I), 'busybox',          'busybox'),
    # Dropbear SSH (binary ships as dropbearmulti)
    (re.compile(r'^dropbear(multi)?$',    re.I), 'matt_johnston',    'dropbear_ssh_server'),
    # uClibc family — libc, libm, libdl, libpthread, libresolv, librt,
    #                 libutil, libnsl, libcrypt, ld-uClibc, libuClibc
    (re.compile(r'^(ld-uclibc|libuClibc|libc|libm|libdl|libpthread'
                r'|libresolv|librt|libutil|libnsl|libcrypt)(-\S+)?$',
                re.I), 'uclibc',           'uclibc'),
    # libupnp (Portable SDK for UPnP)
    (re.compile(r'^libupnp$',             re.I), 'libupnp_project',  'libupnp'),
    # libxml2
    (re.compile(r'^libxml2?$',            re.I), 'xmlsoft',          'libxml2'),
    # cJSON
    (re.compile(r'^libcjson$',            re.I), 'cjson_project',    'cjson'),
    # zlib
    (re.compile(r'^libz$',               re.I), 'zlib',             'zlib'),
    # PPP daemon
    (re.compile(r'^pppd$',               re.I), 'ppp_project',      'ppp'),
    # xl2tpd
    (re.compile(r'^xl2tpd$',             re.I), 'xl2tpd',           'xl2tpd'),
    # Zebra / Quagga routing daemon
    (re.compile(r'^zebra$',              re.I), 'quagga',           'quagga'),
    # radvd
    (re.compile(r'^radvd$',              re.I), 'radvd',            'radvd'),
    # ebtables
    (re.compile(r'^ebtables$',           re.I), 'ebtables',         'ebtables'),
    # iptables (ships as xtables-multi in BusyBox-style firmware)
    (re.compile(r'^(xtables-multi|iptables)$', re.I), 'netfilter',  'iptables'),
    # miniupnpd
    (re.compile(r'^upnpd$',              re.I), 'miniupnp_project', 'miniupnpd'),
    # dhcpd / ISC DHCP
    (re.compile(r'^dhcpd$',              re.I), 'isc',              'dhcp'),
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def _ver_from_soname(filename: str) -> str:
    m = _SONAME_VER_PAT.search(filename)
    return m.group(1) if m else ""


def _ver_from_name(name: str) -> str:
    """Extract version embedded in component name: libcrypt-0.9.33.2 → 0.9.33.2."""
    m = _NAME_VER_PAT.search(name)
    return m.group(1) if m else ""


def _cpe(name: str, version: str) -> str:
    """Return a CPE 2.3 string for a known component, or '' if unknown/versionless."""
    ver = version or _ver_from_name(name)
    if not ver:
        return ""
    ver_safe = ver.replace(":", "_").replace("/", "_")
    for pat, vendor, product in _CPE_MAP:
        if pat.match(name):
            return f"cpe:2.3:a:{vendor}:{product}:{ver_safe}:*:*:*:*:*:*:*"
    return ""


def _ver_from_strings(strings_lines: list[str], hint: str) -> str:
    """Scan strings output for a version number near a name hint."""
    hint_l = hint.lower()
    for line in strings_lines:
        if len(line) > 120 or len(line) < 4:
            continue
        line_l = line.lower()
        if hint_l in line_l or "version" in line_l or " v" in line_l or "release" in line_l:
            m = _VER_PAT.search(line)
            if m:
                return m.group(1)
    return ""


def _points_to_busybox(link: Path) -> bool:
    try:
        target = str(link.readlink())
        return target == "busybox" or target.endswith("/busybox")
    except Exception:
        return False


def _component(
    name: str,
    version: str,
    cdx_type: str,
    rel_path: str,
    sha256: str,
    properties: list[dict] | None = None,
) -> dict:
    comp: dict = {
        "type":    cdx_type,
        "bom-ref": str(uuid.uuid4()),
        "name":    name,
    }
    if version:
        comp["version"] = version
        comp["purl"] = f"pkg:generic/{name}@{version}"
    else:
        comp["purl"] = f"pkg:generic/{name}"

    cpe_str = _cpe(name, version)
    if cpe_str:
        comp["cpe"] = cpe_str

    comp["description"] = rel_path

    if sha256:
        comp["hashes"] = [{"alg": "SHA-256", "content": sha256}]

    if properties:
        comp["properties"] = properties

    return comp


# ── Section builders ──────────────────────────────────────────────────────────

def _collect_libraries(ctx: AnalysisContext) -> list[dict]:
    """One CycloneDX library component per unique (canonical-name, version) pair."""
    components: list[dict] = []
    seen: set[tuple[str, str]] = set()

    lib_dirs = [ctx.rootfs / "lib", ctx.rootfs / "usr/lib"]
    so_files = sorted(
        p
        for d in lib_dirs if d.is_dir()
        for p in d.rglob("*.so*")
        if p.is_file() and not p.is_symlink()
    )

    for lib_path in so_files:
        canon = re.sub(r'\.so.*$', '', lib_path.name)   # libssl.so.1.0.0 → libssl
        version = _ver_from_soname(lib_path.name)

        rec = ctx.elf_cache.get(lib_path)
        strings = rec.strings_lines if rec else []
        if not version:
            version = _ver_from_strings(strings, canon)

        key = (canon, version)
        if key in seen:
            continue
        seen.add(key)

        props = []
        if rec and rec.crypto_imports:
            props.append({"name": "firmware:crypto_imports",
                          "value": ", ".join(rec.crypto_imports[:20])})
        if rec and rec.needed_libs:
            props.append({"name": "firmware:needed_libs",
                          "value": ", ".join(rec.needed_libs)})

        components.append(_component(
            name=canon,
            version=version,
            cdx_type="library",
            rel_path=str(lib_path.relative_to(ctx.rootfs)),
            sha256=_sha256(lib_path),
            properties=props or None,
        ))

    return components


def _collect_executables(ctx: AnalysisContext) -> list[dict]:
    """One CycloneDX application component per ELF executable (not shared objects, not busybox)."""
    components: list[dict] = []

    for path, rec in sorted(ctx.elf_cache.items(), key=lambda x: x[0]):
        ft = rec.file_type.lower()
        if "shared object" in ft:
            continue
        if path.name == "busybox":
            continue

        rel = str(path.relative_to(ctx.rootfs))
        version = _ver_from_strings(rec.strings_lines, path.name)

        props = [{"name": "firmware:path", "value": rel}]
        h = rec.hardening
        if h:
            props += [
                {"name": "firmware:nx",     "value": str(h.get("nx"))},
                {"name": "firmware:pie",    "value": str(h.get("pie",   "unknown"))},
                {"name": "firmware:relro",  "value": str(h.get("relro", "unknown"))},
                {"name": "firmware:canary", "value": str(h.get("canary"))},
            ]
        if rec.needed_libs:
            props.append({"name": "firmware:needed_libs",
                          "value": ", ".join(rec.needed_libs)})

        components.append(_component(
            name=path.name,
            version=version,
            cdx_type="application",
            rel_path=rel,
            sha256=_sha256(path),
            properties=props,
        ))

    return components


def _collect_busybox(ctx: AnalysisContext) -> list[dict]:
    """One CycloneDX application component per busybox binary with applet list as property."""
    components: list[dict] = []

    bb_bins = [p for p in ctx.rootfs.rglob("busybox")
               if p.is_file() and not p.is_symlink()]

    for bb in bb_bins:
        rec = ctx.elf_cache.get(bb)
        strings = rec.strings_lines if rec else []

        version = ""
        for line in strings:
            m = _BUSYBOX_VER_PAT.search(line)
            if m:
                version = m.group(1)
                break

        applets = sorted(
            p.name for p in ctx.rootfs.rglob("*")
            if p.is_symlink() and _points_to_busybox(p)
        )

        rel = str(bb.relative_to(ctx.rootfs))
        props = [
            {"name": "firmware:path",                "value": rel},
            {"name": "firmware:busybox_applet_count", "value": str(len(applets))},
        ]
        if applets:
            props.append({"name": "firmware:busybox_applets",
                          "value": ", ".join(applets)})

        components.append(_component(
            name="busybox",
            version=version,
            cdx_type="application",
            rel_path=rel,
            sha256=_sha256(bb),
            properties=props,
        ))

    return components


def _collect_kernel_modules(ctx: AnalysisContext) -> list[dict]:
    """One CycloneDX firmware component per .ko kernel module."""
    components: list[dict] = []

    for ko in sorted(ctx.rootfs.rglob("*.ko")):
        if ko.is_symlink():
            continue

        version = ""
        try:
            r = subprocess.run(
                ["modinfo", str(ko)], capture_output=True, text=True, timeout=10
            )
            m = re.search(r'^version:\s+(.+)', r.stdout, re.MULTILINE)
            if m:
                version = m.group(1).strip()
        except Exception:
            pass

        rel = str(ko.relative_to(ctx.rootfs))
        props = [
            {"name": "firmware:path",    "value": rel},
            {"name": "firmware:subtype", "value": "kernel-module"},
        ]

        components.append(_component(
            name=ko.stem,
            version=version,
            cdx_type="firmware",
            rel_path=rel,
            sha256=_sha256(ko),
            properties=props,
        ))

    return components


# ── Entry point ───────────────────────────────────────────────────────────────

def generate_sbom(ctx: AnalysisContext) -> None:
    """Build a CycloneDX 1.5 SBOM and write sbom.cdx.json to ctx.out_dir."""
    firmware_id = ctx.out_dir.name

    components = (
        _collect_libraries(ctx)
        + _collect_executables(ctx)
        + _collect_busybox(ctx)
        + _collect_kernel_modules(ctx)
    )

    bom = {
        "bomFormat":    "CycloneDX",
        "specVersion":  "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version":      1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": {
                "components": [
                    {
                        "type":    "application",
                        "name":    "FirmwareAnalysis",
                        "version": "1.0",
                    }
                ]
            },
            "component": {
                "type":        "firmware",
                "bom-ref":     str(uuid.uuid4()),
                "name":        firmware_id,
                "description": "Router firmware image",
            },
        },
        "components": components,
    }

    out_file = ctx.out_dir / "sbom.cdx.json"
    out_file.write_text(json.dumps(bom, indent=2))

    n_lib = sum(1 for c in components if c["type"] == "library")
    n_app = sum(1 for c in components if c["type"] == "application")
    n_fw  = sum(1 for c in components if c["type"] == "firmware")
    print(f"  {'sbom.cdx.json':45s}  {len(components)} components  "
          f"({n_lib} libraries, {n_app} applications, {n_fw} kernel modules)")
