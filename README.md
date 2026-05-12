# Firmware Analysis Inspector

Static security analysis pipeline for router firmware images. Extracts firmware components inside Docker, runs 40+ security checks against the root filesystem, synthesizes an attack surface model, and builds a typed entity-relationship graph for attack path analysis.

Developed and tested against TP-Link Archer A5 V6 (`Archer_A5V6.bin`).

---

## Pipeline Overview

```
firmware.bin
    │
    ▼
[1] extract.py          ← orchestrates Docker build + run
    │
    ├─ carve.py         ← binwalk scan → carve bootloader / kernel / rootfs
    └─ analyze.py       ← 40+ checks against extracted rootfs
    │                      Phase 4: generates sbom.cdx.json (CycloneDX 1.5)
    ▼
analysis/<firmware>/    ← raw findings (txt, json) + sbom.cdx.json
    │
    ▼
[2] surface.py          ← synthesize structured attack surface model
    │
    ▼
<firmware>_attack_surface.json
    │
    ▼
[3] graph.py            ← build typed entity-relationship graph
    │
    ▼
<firmware>_graph.json   ← nodes, edges, derived attack paths
<firmware>_graph.dot    ← Graphviz visualization (optional)
    │
    ▼
[4] cve.py              ← CVE enrichment (host-side, requires grype)
    │                      cross-references CVEs with hardening flags
    │                      and network reachability from attack surface
    ▼
analysis/<firmware>/cve_report.json
```

---

## Requirements

- Docker
- Python 3.12+

No Python dependencies are required on the host. All extraction tooling runs inside the container.

---

## Usage

### Step 1 — Extract and Analyze

```bash
python3 extract.py input/TP-Link/Archer_A5_v6.20/Archer_A5V6.bin
```

This builds the Docker image (first run only), then runs `carve.py` and `analyze.py` inside the container against the firmware. Analysis output lands in `./analysis/<firmware_name>/`.

Options:

```
positional:
  firmware          Path to firmware binary

optional:
  --output, -o      Host directory for analysis output (default: ./analysis)
  --skip-build      Skip Docker image rebuild
```

### Step 2 — Synthesize Attack Surface

```bash
python3 surface.py ./analysis/Archer_A5V6/
```

Reads all analysis text files and produces `<firmware>_attack_surface.json` — a structured summary covering entry points, credentials, weak crypto, debug artifacts, certificates, IPC, and more.

Options:

```
positional:
  analysis_dir      Directory produced by analyze.py

optional:
  --output, -o      Output directory (default: current directory)
```

### Step 3 — Build Entity-Relationship Graph

```bash
python3 graph.py Archer_A5V6_attack_surface.json
python3 graph.py Archer_A5V6_attack_surface.json --dot
```

### Step 4 — CVE Enrichment (host-side)

Requires [grype](https://github.com/anchore/grype) on the host:

```bash
# Install grype (once)
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh

# Run CVE enrichment
python3 cve.py analysis/Archer_A5V6/
```

The attack surface JSON is auto-detected if present in the working directory. You can also pass it explicitly:

```bash
python3 cve.py analysis/Archer_A5V6/ --attack-surface Archer_A5V6_attack_surface.json
```

Options:

```
positional:
  analysis_dir          Directory produced by analyze.py (must contain sbom.cdx.json)

optional:
  --attack-surface, -a  Attack surface JSON for network-reachability cross-referencing
  --output, -o          Output path for CVE report JSON (default: <analysis_dir>/cve_report.json)
```

CVE severity is adjusted beyond the base CVSS score using two firmware-specific signals:

| Signal | Escalation |
|---|---|
| Library linked by a network-reachable binary (httpd, dropbear) | +2 levels |
| NX disabled | +1 level |
| No PIE | +1 level |
| No RELRO | +1 level |
| No stack canary | +1 level |

Builds a typed property graph from the attack surface JSON. Attack paths are derived algorithmically via BFS traversal — never hand-authored.

Options:

```
positional:
  surface_json      attack_surface.json produced by surface.py

optional:
  --output, -o      Output path for graph JSON
  --dot             Also write a Graphviz DOT file for visualization
```

---

## Docker Environment

The container is built from `ubuntu:22.04` and includes:

| Category | Tools |
|---|---|
| Firmware analysis | binwalk, binutils, python3-pyelftools |
| Filesystem extraction | squashfs-tools, mtd-utils, e2fsprogs |
| Specialty extractors | jefferson (JFFS2), ubi_reader (UBI/UBIFS) |
| Compression | lzma, xz-utils, p7zip-full, lzop, cabextract |
| Python | python3-magic, python3-matplotlib, python3-numpy |
| Package management | uv |

Volumes:
- `/input` — firmware directory (read-only)
- `/output` — extraction and analysis output

---

## Analysis Checks (`analyze.py`)

40+ checks run in parallel against the extracted root filesystem:

| Check | Output File |
|---|---|
| Services and init scripts | `services.txt`, `init_scripts.txt` |
| Systemd services | `services.txt` |
| Listening ports | `ports_listen.txt` |
| Network-facing binaries | `network_binaries.txt`, `httpd_binaries.txt` |
| Strings in HTTP server binaries | `strings_httpd.txt` |
| SUID/SGID binaries | `setuid_binaries.txt` |
| World-writable files | `world_writable.txt` |
| Linux capabilities | `capabilities.txt`, `xattr_capabilities.txt` |
| Users and groups | `users_groups.txt` |
| Credentials in configs | `credentials.txt`, `default_credentials.txt` |
| Hardcoded strings | `hardcoded_strings.txt` |
| Weak cryptographic symbols | `weak_crypto.txt` |
| Certificates and SSH keys | `certificates_keys.txt`, `ssh_keys.txt` |
| CGI injection patterns | `cgi_injection.txt` |
| PHP OS command injection | `php_cmdinject.txt` |
| PHP code injection sinks | `php_codeinject.txt` |
| PHP local file inclusion | `php_lfi.txt` |
| PHP information disclosure | `php_infodisclosure.txt` |
| Debug artifacts | `debug_artifacts.txt` |
| Web interface and configs | `web_interface.txt`, `web_server_configs.txt` |
| Config file contents | `config_files.txt`, `config_files_content.txt` |
| Kernel modules | `kernel_modules.txt` |
| Binary inventory | `binary_inventory.txt`, `busybox.txt` |
| Architecture and endianness detection | `architecture.txt` |
| Binary hardening (NX / PIE / RELRO / stack canary) | `hardening.json` |
| ShellCheck static analysis | `shellcheck.json` |
| Symlink map | `symlinks.txt` |
| Linker configuration and library paths | `linker_config.txt` |
| Library versions | `library_versions.txt` |
| Unix sockets | `unix_sockets.txt` |
| Interface binding | `interface_binding.txt` |
| Firewall rules | `firewall_rules.txt` |
| DNS and routing | `dns_routing.txt` |
| NVRAM references | `nvram.txt` |
| Scheduled tasks | `scheduled_tasks.txt` |
| Mount points and writable overlays | `mount_points.txt` |
| Firmware update mechanism | `firmware_update.txt` |
| Protocols | `protocols.txt` |
| Scripts | `scripts.txt`, `scripts_content.txt` |

---

## Graph Schema

### Entity Types

| Type | Description |
|---|---|
| `Firmware` | Top-level firmware artifact |
| `Binary` | ELF executable or shared library |
| `Service` | Running service (e.g. dropbear, httpd) |
| `Port` | Network port with protocol |
| `ProcessContext` | uid/gid/capabilities of a running service |
| `Config` | Configuration file |
| `Credential` | Password hash, API key, or secret |
| `Certificate` | TLS certificate or SSH key |
| `FilesystemObject` | File with notable permission or attribute |
| `CryptoPrimitive` | Cryptographic symbol import (DES, RC4, MD5, etc.) |
| `Weakness` | Concrete weakness instance (e.g. world-writable binary) |
| `WeaknessClass` | CWE-based weakness class |
| `TrustZone` | Network exposure zone: WAN / LAN / LOCAL |

### Relationship Types

| Relationship | Meaning |
|---|---|
| `PROVIDES` | Firmware provides a service |
| `EXPOSES` | Service exposes a port |
| `RUNS_AS` | Service runs under a process context |
| `REACHABLE_FROM` | Port is reachable from a trust zone |
| `USES_CRYPTO` | Binary imports a cryptographic symbol |
| `ASSOCIATED_WITH` | Credential or cert is associated with a service |
| `EXPOSES_WEAKNESS` | Entity has a concrete weakness |
| `CONTAINS_SECRET` | Binary or config contains a hardcoded secret |
| `LINKS_TO` | Binary dynamically links a library |
| `LOADS_CONFIG` | Service loads a config file |

### Provenance

Every node and edge carries a provenance block:

```json
{
  "type": "extracted | inferred | hypothesized",
  "source": "weak_crypto.txt",
  "confidence": 0.95
}
```

`extracted` — directly observed in the firmware. `inferred` — derived from observed facts (e.g. zone assignment). `hypothesized` — plausible but unconfirmed.

### Severity Scoring

Attack paths are scored using:

```
score = zone_weight + root_execution + crypto_weaknesses + structural_weaknesses
```

| Score | Severity |
|---|---|
| ≥ 6 | CRITICAL |
| ≥ 4 | HIGH |
| ≥ 2 | MEDIUM |
| < 2 | LOW |

WAN-reachable paths receive a higher zone weight than LAN-only paths.

---

## Output Files

| File | Description |
|---|---|
| `analysis/<firmware>/*.txt` | Raw per-check findings (text) |
| `analysis/<firmware>/hardening.json` | Binary hardening flags (NX / PIE / RELRO / canary) |
| `analysis/<firmware>/shellcheck.json` | ShellCheck static analysis findings |
| `analysis/<firmware>/sbom.cdx.json` | CycloneDX 1.5 SBOM — libraries, executables, kernel modules |
| `analysis/<firmware>/cve_report.json` | CVE findings enriched with hardening and reachability context |
| `<firmware>_attack_surface.json` | Structured attack surface model |
| `<firmware>_graph.json` | Entity-relationship graph with derived attack paths |
| `<firmware>_graph.dot` | Graphviz DOT for visualization (`--dot` flag) |

### Visualizing the Graph

```bash
# Install graphviz
sudo apt install graphviz

# Render to SVG
dot -Tsvg Archer_A5V6_graph.dot -o Archer_A5V6_graph.svg

# Interactive viewer
sudo apt install xdot
xdot Archer_A5V6_graph.dot
```

---

## Example Output — Archer A5 V6

```
Nodes : 59
          Binary                 5
          Certificate            1
          Credential             14
          CryptoPrimitive        5
          FilesystemObject       12
          Firmware               1
          Port                   2
          ProcessContext         1
          Service                2
          TrustZone              3
          Weakness               12
          WeaknessClass          1

Edges : 31
          ASSOCIATED_WITH        5
          EXPOSES                2
          EXPOSES_WEAKNESS       12
          PROVIDES               2
          REACHABLE_FROM         2
          RUNS_AS                2
          USES_CRYPTO            6

Derived attack paths : 2
  [!!!] [CRITICAL] LAN → SSH :22/tcp
  [!!!] [CRITICAL] LAN → HTTP :80/tcp
```

**Key findings:**
- Dropbear SSH (port 22) and httpd (port 80) exposed on LAN
- openssl imports DES, 3DES, RC2, RC4 (CWE-327)
- tdpd and libssl.so.1.0.0 import MD5 (CWE-327)
- `admin` password hash uses MD5-crypt (CWE-916) in `passwd.bak`
- `/usr/sbin/bpalogin` is world-writable (CWE-732)
- Diagnostic web interface exposed (`web/main/diagnostic.htm`)

---

## Firmware Components — Archer A5 V6

Identified from binwalk scan of `Archer_A5V6.bin` (7,930,368 bytes):

| Offset | Type | Details |
|---|---|---|
| `0x13F50` | Bootloader | U-Boot 1.1.3, built 2023-08-10 |
| `0x20400` | Kernel | LZMA compressed, ~3.4 MB uncompressed |
| `0x160200` | Root filesystem | SquashFS v4.0, little-endian, xz-compressed, 739 inodes |
