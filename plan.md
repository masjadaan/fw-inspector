I have router firmware
I want to use binwalk to extract the firmware components
extracton should occur inside a docker 
the input is a directory that contians firmware
don't consider encrypted firmware
current firmware is from TP-Link
I need dockerfile to setup the docker
Base image: Debian/Ubuntu
Core extraction: binwalk, python3, pip
Filesystem tools: squashfs-tools (unsquashfs), mtd-utils, e2fsprogs
Compression: lzma, xz-utils, liblzma-dev, p7zip-full, lzop, cabextract
Python libs: python-magic, pyelftools, matplotlib, numpy (for entropy analysis)
Specialty extractors: jefferson (JFFS2), ubi_reader (UBI/UBIFS), standard squashfs
Misc: wget, git, build-essential (some tools need compiling from source)
use uv as package managment tool



docker build -t firmware-analysis .

docker run -it \
  -v $(pwd)/input:/input:ro \
  -v $(pwd)/output:/output \
  firmware-analysis


binwalk -eM --run-as=root /input/TP-Link/Archer_A5_v6.20/Archer_A5V6.bin --directory /output


## binwalk output — Archer_A5V6.bin (run 2026-05-06)

File: `input/TP-Link/Archer_A5_v6.20/Archer_A5V6.bin` (7,930,368 bytes)

```
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
39173         0x9905          JBOOT STAG header, image id: 6, timestamp 0x18027118, image size: 4019174400 bytes, image JBOOT checksum: 0x60FF, header JBOOT checksum: 0x14
39657         0x9AE9          JBOOT STAG header, image id: 16, timestamp 0x21240400, image size: 822083624 bytes, image JBOOT checksum: 0xA600, header JBOOT checksum: 0x127
51573         0xC975          JBOOT STAG header, image id: 16, timestamp 0x21100000, image size: 33554576 bytes, image JBOOT checksum: 0x0, header JBOOT checksum: 0x2110
76929         0x12C81         JBOOT STAG header, image id: 6, timestamp 0xCB10, image size: 799836416 bytes, image JBOOT checksum: 0x4000, header JBOOT checksum: 0x2110
76997         0x12CC5         JBOOT STAG header, image id: 6, timestamp 0x1F00CB10, image size: 554713088 bytes, image JBOOT checksum: 0xA010, header JBOOT checksum: 0xFF00
81744         0x13F50         U-Boot version string, "U-Boot 1.1.3 (Aug 10 2023 - 10:55:56)"
132096        0x20400         LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 3441784 bytes
1442304       0x160200        Squashfs filesystem, little endian, version 4.0, compression:xz, size: 6360112 bytes, 739 inodes, blocksize: 131072 bytes, created: 2023-08-10 03:07:45
```

### Identified components

| Offset (hex) | Type | Notes |
|---|---|---|
| 0x13F50 | Bootloader | U-Boot 1.1.3, built 2023-08-10 |
| 0x20400 | Kernel | LZMA compressed, ~3.4 MB uncompressed |
| 0x160200 | Root filesystem | SquashFS v4.0, little-endian, xz-compressed, 739 inodes |

JBOOT STAG entries are false positives (implausible image sizes).
