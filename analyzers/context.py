import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path


def run(cmd: list, out_file: Path):
    result = subprocess.run(cmd, capture_output=True, text=True)
    content = result.stdout
    if result.returncode != 0 and result.stderr.strip():
        content += f"\n--- stderr ---\n{result.stderr}"
    out_file.write_text(content)
    lines = len(content.strip().splitlines()) if content.strip() else 0
    status = f"{lines} lines" if lines else "empty"
    print(f"  {out_file.name:45s}  {status}")


def section(title: str, output: str) -> str:
    return (
        f"{'=' * 60}\n  {title}\n{'=' * 60}\n"
        f"{output.strip() if output.strip() else '  (nothing found)'}\n\n"
    )


def existing(*paths) -> list:
    return [str(p) for p in paths if Path(p).exists()]


def find_all_configs(rootfs: Path) -> list:
    EXTENSIONS = {
        ".conf", ".cfg", ".ini", ".config",
        ".json", ".xml", ".yaml", ".yml",
        ".properties", ".env",
    }
    return [
        str(p) for p in rootfs.rglob("*")
        if p.is_file() and p.suffix.lower() in EXTENSIONS
    ]


def multi_section_file(checks: list, out_file: Path, label: str):
    """Run a list of (title, cmd) checks, write all sections to one file."""
    sections = []
    total_lines = 0
    for title, cmd in checks:
        r = subprocess.run(cmd, capture_output=True, text=True)
        output = r.stdout.strip()
        total_lines += len(output.splitlines()) if output else 0
        sections.append(section(title, output))
    out_file.write_text("".join(sections))
    print(f"  {out_file.name:45s}  {total_lines} lines across {len(checks)} checks")


@dataclass
class AnalysisContext:
    rootfs:    Path
    out_dir:   Path
    configs:   list
    elf_cache: dict = field(default_factory=dict)


@dataclass
class Analyzer:
    """One pipeline step: a label, the function to run, and whether it needs the ELF cache."""
    label:     str
    fn:        Callable[["AnalysisContext"], None]
    needs_elf: bool = False

    def run(self, ctx: AnalysisContext) -> None:
        self.fn(ctx)
