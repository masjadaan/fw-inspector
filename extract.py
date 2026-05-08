#!/usr/bin/env python3

import argparse
import subprocess
import sys
from pathlib import Path

IMAGE_NAME = "firmware-analysis"
DOCKERFILE_DIR = Path(__file__).parent


def build_image():
    print(f"[*] Building Docker image '{IMAGE_NAME}'...")
    result = subprocess.run(
        ["docker", "build", "-t", IMAGE_NAME, str(DOCKERFILE_DIR)]
    )
    if result.returncode != 0:
        print("[!] Docker build failed.")
        sys.exit(result.returncode)
    print("[+] Image built successfully.\n")


def run_extraction(firmware_path: Path, analysis_output: Path):
    firmware_path = firmware_path.resolve()
    analysis_output = analysis_output.resolve()
    analysis_output.mkdir(parents=True, exist_ok=True)

    input_dir = firmware_path.parent
    container_firmware = f"/input/{firmware_path.name}"
    binwalk_cmd = (
        f"python3 /opt/carve.py {container_firmware} --output /output"
        f" && python3 /opt/analyze.py /output/extracted/rootfs/squashfs-root/"
        f" --firmware {container_firmware}"
        f" && exec bash"
    )

    print(f"[*] Firmware        : {firmware_path}")
    print(f"[*] Analysis output : {analysis_output}\n")

    subprocess.run([
        "docker", "run", "--rm", "-it",
        "-v", f"{input_dir}:/input:ro",
        "-v", f"{analysis_output}:/output/analysis",
        IMAGE_NAME,
        "bash", "-c", binwalk_cmd,
    ])


def main():
    parser = argparse.ArgumentParser(
        description="Extract firmware components using binwalk inside Docker."
    )
    parser.add_argument(
        "firmware",
        type=Path,
        help="Path to the firmware binary file.",
    )
    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=Path("./analysis"),
        help="Host directory to receive analysis output (default: ./analysis).",
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="Skip the Docker image build step.",
    )
    args = parser.parse_args()

    if not args.firmware.exists():
        print(f"[!] File not found: {args.firmware}")
        sys.exit(1)
    if not args.firmware.is_file():
        print(f"[!] Not a file: {args.firmware}")
        sys.exit(1)

    if not args.skip_build:
        build_image()

    run_extraction(args.firmware, args.output)


if __name__ == "__main__":
    main()
