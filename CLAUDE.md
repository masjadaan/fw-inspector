# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Firmware Extraction Agent — Phase 1. Extracts and categorizes all components from a packed router firmware image into a structured workspace. See `plan.md` for the full architecture spec.

## Environment

- **Runtime**: Docker container (Debian slim), Python 3.12+, non-privileged, no network
- **Package manager**: `uv` with committed `uv.lock` — always `uv sync --frozen` at build time
- **Mounts**: `/input` read-only, `/workspace` writable
- **Loopback mounts are prohibited** — all filesystem extraction must use userspace tools only (no `CAP_SYS_ADMIN`)

## Tooling Constraints

All tool versions are pinned in the Dockerfile. Version drift silently changes extraction output.

- **binwalk v2.3.4 pinned** — v2 and v3 have diverged CLI behavior; upgrading requires a deliberate versioned decision
- Other tools: jefferson, ubireader, unsquashfs, 7z, cpio, file, strings, readelf

## Architecture

### Pipeline Stages (plan.md §Pipeline Stages)

Six sequential stages; each emits `success | partial | failed | skipped` and the pipeline **never halts on a single failure**:

1. **Ingest & Validate** — SHA256 hash, detect container format, size bounds
2. **Top-Level Unpack** — binwalk, capture offsets and signatures
3. **Recursive Unpack** — bounded recursion on nested archives/filesystems
4. **Filesystem Reconstruction** — userspace extraction per type (unsquashfs, jefferson, ubireader, cpio)
5. **Component Classification** — rule-based typing, writes to `/workspace/components/`
6. **Manifest Finalization** — write `manifest.json`, verify paths, compute hashes

### Plugin Model

Each extraction format is an `ExtractionHandler` plugin with a stable interface:

```python
class ExtractionHandler:
    def can_handle(self, artifact: Artifact) -> bool: ...
    def extract(self, artifact: Artifact, workspace: Path) -> ExtractionResult: ...
    def tool_version(self) -> str: ...
```

`ExtractionResult` carries: `status`, `output_paths`, `warnings`, `duration_ms`. New formats are added as plugins without modifying the orchestrator.

### Component Classification

Rule-based only. Rules live in `classifier_rules.yaml` — tunable without code changes. Component types: `rootfs | kernel | bootloader | dtb | nvram | unclassified`. Nothing is silently dropped; unmatched artifacts go to `unclassified/`.

### Recursive Unpack Guards

- Max recursion depth: 5
- Max extracted size: 20× input firmware size
- Deduplication by SHA256 — skip re-processing identical blobs
- Per-subprocess timeout: 120s

### Workspace Layout

```
/input/                      ← read-only firmware artifacts
/workspace/
  raw/                       ← binwalk initial extraction output
  extracted/                 ← reconstructed filesystems
  components/
    rootfs/ kernel/ bootloader/ dtb/ nvram/ unclassified/
  logs/pipeline.log
  manifest.json              ← structured extraction index (contract for downstream agents)
```

### Manifest Schema

`manifest.json` is the contract between the extractor and all downstream agents. See `plan.md §Manifest Schema` for the full JSON structure. Key fields per component: `id` (uuid), `type`, `source_offset`, `size_bytes`, `sha256`, `extraction_tool`, `output_path`, `confidence`.

## Deferred to Phase 2

Loop-device mounting, entropy/YARA scanning, QEMU emulation, multi-firmware diffing.
