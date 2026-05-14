import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


_ELF_MAGIC = b"\x7fELF"

_CRYPTO_SYM_PAT = re.compile(
    r"^(MD[245]|SHA[0-9]{0,3}|DES|RC[24]|AES|EVP|SSL|TLS|HMAC|RSA|RAND|BN|PKCS|X509|DSA|ECDSA)_",
    re.IGNORECASE,
)

_WEAK_SYM_PAT = re.compile(r"^(MD[245]|DES|RC[24]|MD4)_", re.IGNORECASE)

_DANGEROUS_SYM_PAT = re.compile(
    r"^(gets|strcpy|strcat|sprintf|vsprintf|scanf|fscanf|sscanf|mktemp|tmpnam|tempnam|system|popen|rand|srand)$"
)

_STRINGS_TIMEOUT = 30
_READELF_TIMEOUT = 30
_FILE_TIMEOUT    = 10
_ELF_WORKERS     = 8


def _is_elf(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) == _ELF_MAGIC
    except Exception:
        return False


def _elf_files(rootfs: Path) -> list:
    """Return all non-symlink ELF files under rootfs (magic-byte check, no subprocess)."""
    return [p for p in rootfs.rglob("*") if p.is_file() and not p.is_symlink() and _is_elf(p)]


def _readelf_needed(path: Path) -> list:
    """Extract NEEDED shared libraries from the ELF dynamic section via readelf -d."""
    r = subprocess.run(["readelf", "-d", str(path)], capture_output=True, text=True)
    return re.findall(r"\(NEEDED\)\s+Shared library: \[(.+?)\]", r.stdout)


def _readelf_crypto_imports(path: Path) -> list:
    """Return imported crypto-related symbols from the ELF dynamic symbol table."""
    r = subprocess.run(["readelf", "--dyn-syms", str(path)], capture_output=True, text=True)
    syms = []
    for line in r.stdout.splitlines():
        if "UND" not in line:
            continue
        parts = line.split()
        if not parts:
            continue
        name = parts[-1].split("@")[0]
        if _CRYPTO_SYM_PAT.match(name):
            syms.append(name)
    return sorted(set(syms))


class _ElfRecord:
    """Holds all per-binary data collected in one pass."""
    __slots__ = ("file_type", "needed_libs", "crypto_imports", "dangerous_imports", "strings_lines", "hardening")

    def __init__(self):
        self.file_type         = ""
        self.needed_libs       = []
        self.crypto_imports    = []
        self.dangerous_imports = []
        self.strings_lines     = []
        self.hardening         = {}


def _process_one_elf(path: Path) -> tuple:
    """Run file, readelf -d/-l/--dyn-syms, and strings on one ELF binary.
    Each subprocess has a hard timeout so a corrupt binary can't stall the pipeline.
    Returns (path, _ElfRecord).
    """
    rec = _ElfRecord()

    _bind_now   = False
    _has_canary = False
    _nx         = None
    _has_relro  = False
    _has_interp = False

    try:
        r = subprocess.run(
            ["file", str(path)], capture_output=True, text=True, timeout=_FILE_TIMEOUT
        )
        rec.file_type = r.stdout.split(":", 1)[-1].strip()
    except Exception:
        rec.file_type = "(error)"

    try:
        r = subprocess.run(
            ["readelf", "-d", str(path)], capture_output=True, text=True, timeout=_READELF_TIMEOUT
        )
        rec.needed_libs = re.findall(r"\(NEEDED\)\s+Shared library: \[(.+?)\]", r.stdout)
        _bind_now = bool(re.search(r"\(BIND_NOW\)", r.stdout)) or bool(
            re.search(r"\(FLAGS_1\)[^\n]*\bNOW\b", r.stdout)
        )
    except Exception:
        pass

    try:
        r = subprocess.run(
            ["readelf", "--dyn-syms", str(path)], capture_output=True, text=True, timeout=_READELF_TIMEOUT
        )
        _has_canary = "__stack_chk_fail" in r.stdout
        crypto_syms = []
        danger_syms = []
        for line in r.stdout.splitlines():
            if "UND" not in line:
                continue
            parts = line.split()
            if parts:
                name = parts[-1].split("@")[0]
                if _CRYPTO_SYM_PAT.match(name):
                    crypto_syms.append(name)
                if _DANGEROUS_SYM_PAT.match(name):
                    danger_syms.append(name)
        rec.crypto_imports    = sorted(set(crypto_syms))
        rec.dangerous_imports = sorted(set(danger_syms))
    except Exception:
        pass

    try:
        r = subprocess.run(
            ["readelf", "-l", str(path)], capture_output=True, text=True, timeout=_READELF_TIMEOUT
        )
        ph = r.stdout
        m = re.search(r"GNU_STACK\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\S+)", ph)
        if m:
            _nx = "E" not in m.group(1)
        _has_relro  = bool(re.search(r"^\s+GNU_RELRO\b", ph, re.MULTILINE))
        _has_interp = bool(re.search(r"^\s+INTERP\b",   ph, re.MULTILINE))
    except Exception:
        pass

    try:
        r = subprocess.run(
            ["strings", str(path)], capture_output=True, text=True, timeout=_STRINGS_TIMEOUT
        )
        rec.strings_lines = r.stdout.splitlines()
    except Exception:
        pass

    ft = rec.file_type.lower()
    if "pie executable" in ft:
        pie = "yes"
    elif "shared object" in ft and _has_interp:
        pie = "yes"
    elif "shared object" in ft:
        pie = "so"
    elif "executable" in ft:
        pie = "no"
    else:
        pie = "unknown"

    if _has_relro and _bind_now:
        relro = "full"
    elif _has_relro:
        relro = "partial"
    else:
        relro = "none"

    rec.hardening = {
        "nx":     _nx,
        "pie":    pie,
        "relro":  relro,
        "canary": _has_canary,
    }

    return path, rec


def build_elf_cache(rootfs: Path) -> dict:
    """Process every ELF binary under rootfs once, in parallel.

    Runs file + readelf -d + readelf --dyn-syms + strings on each binary using
    a thread pool.  Returns {Path: _ElfRecord}.  All four consumers
    (binary_inventory, network_binaries, hardcoded_strings, weak_crypto) read
    from this cache instead of spawning their own subprocesses.
    """
    elf_paths = _elf_files(rootfs)
    cache: dict = {}
    with ThreadPoolExecutor(max_workers=min(_ELF_WORKERS, len(elf_paths) or 1)) as executor:
        futures = {executor.submit(_process_one_elf, p): p for p in elf_paths}
        for future in as_completed(futures):
            try:
                path, rec = future.result()
                cache[path] = rec
            except Exception:
                pass
    print(f"  {'(elf cache built)':45s}  {len(cache)} ELF binaries processed in parallel")
    return cache
