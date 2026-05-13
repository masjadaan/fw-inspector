#!/usr/bin/env python3
"""
Carves bootloader, kernel, and root filesystem from router firmware
using binwalk scan output, then extracts each component into a clean
directory structure.
"""

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path


def scan(firmware_path: Path) -> list:
    result = subprocess.run(
        ["binwalk", str(firmware_path)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"[!] binwalk scan failed:\n{result.stderr}")
        sys.exit(1)
    entries = []
    for line in result.stdout.splitlines():
        m = re.match(r"^(\d+)\s+(0x[0-9A-Fa-f]+)\s+(.+)$", line.strip())
        if m:
            entries.append({"offset": int(m.group(1)), "description": m.group(3).strip()})
    return entries


def identify(entries: list, firmware_size: int) -> dict:
    kernel = None
    rootfs = None

    for e in entries:
        desc = e["description"]
        offset = e["offset"]

        if kernel is None and "LZMA compressed" in desc:
            kernel = {"offset": offset}

        if rootfs is None and "Squashfs" in desc:
            m = re.search(r"size:\s*(\d+)\s*bytes", desc)
            rootfs = {
                "offset": offset,
                "size": int(m.group(1)) if m else firmware_size - offset,
            }

    if not kernel or not rootfs:
        print("[!] Could not identify all three components.")
        print(f"    kernel: {kernel}")
        print(f"    rootfs: {rootfs}")
        sys.exit(1)

    return {
        "bootloader": {"offset": 0,               "size": kernel["offset"]},
        "kernel":     {"offset": kernel["offset"], "size": rootfs["offset"] - kernel["offset"]},
        "rootfs":     {"offset": rootfs["offset"], "size": rootfs["size"]},
    }


def carve(firmware_path: Path, offset: int, size: int, out: Path):
    with open(firmware_path, "rb") as f:
        f.seek(offset)
        data = f.read(size)
    out.write_bytes(data)
    print(f"  {out.name:20s}  offset=0x{offset:08X}  size={len(data):>10,} bytes")


def extract_kernel(carved_dir: Path, extracted_dir: Path):
    out = extracted_dir / "kernel"
    out.mkdir(parents=True, exist_ok=True)
    subprocess.run([
        "binwalk", "-e",
        str(carved_dir / "kernel.lzma"),
        "--directory", str(out),
    ])
    subdir = out / "_kernel.lzma.extracted"
    if (subdir / "0").exists():
        shutil.move(str(subdir / "0"), str(out / "kernel.bin"))
    if subdir.exists():
        shutil.rmtree(subdir)


def extract_rootfs(carved_dir: Path, extracted_dir: Path):
    out = extracted_dir / "rootfs"
    out.mkdir(parents=True, exist_ok=True)
    subprocess.run([
        "binwalk", "-e",
        str(carved_dir / "rootfs.squashfs"),
        "--directory", str(out),
    ])
    subdir = out / "_rootfs.squashfs.extracted"
    if (subdir / "squashfs-root").exists():
        shutil.move(str(subdir / "squashfs-root"), str(out / "squashfs-root"))
    if subdir.exists():
        shutil.rmtree(subdir)


def main():
    parser = argparse.ArgumentParser(
        description="Carve and extract firmware components using binwalk scan output."
    )
    parser.add_argument("firmware", type=Path, help="Path to firmware binary.")
    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=Path("/output"),
        help="Output directory (default: /output).",
    )
    args = parser.parse_args()

    if not args.firmware.is_file():
        print(f"[!] Not a file: {args.firmware}")
        sys.exit(1)

    carved_dir    = args.output / "carved"
    extracted_dir = args.output / "extracted"
    carved_dir.mkdir(parents=True, exist_ok=True)

    firmware_size = args.firmware.stat().st_size

    print(f"[*] Scanning {args.firmware.name} with binwalk ...")
    entries = scan(args.firmware)

    print(f"[*] Identifying components ...")
    components = identify(entries, firmware_size)

    print(f"\n[*] Carving to {carved_dir}/\n")
    carve(args.firmware, **components["bootloader"], out=carved_dir / "bootloader.bin")
    carve(args.firmware, **components["kernel"],     out=carved_dir / "kernel.lzma")
    carve(args.firmware, **components["rootfs"],     out=carved_dir / "rootfs.squashfs")

    print(f"\n[*] Extracting to {extracted_dir}/\n")
    print("  [kernel]")
    extract_kernel(carved_dir, extracted_dir)
    print("  [rootfs]")
    extract_rootfs(carved_dir, extracted_dir)

    print(f"\n[+] Done. Results in {args.output}/")


if __name__ == "__main__":
    main()
