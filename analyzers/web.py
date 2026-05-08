import re
import subprocess
from pathlib import Path

from .context import AnalysisContext, section, existing, multi_section_file


def analyze_web_interface(ctx: AnalysisContext):
    out_file = ctx.out_dir / "web_interface.txt"
    web_roots = existing(ctx.rootfs / "www", ctx.rootfs / "web", ctx.rootfs / "webroot", ctx.rootfs / "usr/share/www")
    checks = [section("CGI Scripts",
                       subprocess.run(["find", str(ctx.rootfs), "-name", "*.cgi"], capture_output=True, text=True).stdout)]
    checks.append(section("Lua Handlers",
                           subprocess.run(["find", str(ctx.rootfs), "-name", "*.lua"], capture_output=True, text=True).stdout))
    checks.append(section("JavaScript Files",
                           subprocess.run(["find", str(ctx.rootfs), "-name", "*.js"], capture_output=True, text=True).stdout))
    if web_roots:
        r = subprocess.run(["grep", "-rE", r"url|api|endpoint|/cgi-bin|action="] + web_roots, capture_output=True, text=True)
        checks.append(section("API Endpoints in Web Root", r.stdout))
    checks.append(section("HTML Pages",
                           subprocess.run(["find", str(ctx.rootfs), "-name", "*.html", "-o", "-name", "*.htm"],
                                          capture_output=True, text=True).stdout))
    out_file.write_text("".join(checks))
    print(f"  {'web_interface.txt':45s}  {sum(len(c.splitlines()) for c in checks)} lines")


def analyze_web_server_configs(ctx: AnalysisContext):
    out_file = ctx.out_dir / "web_server_configs.txt"
    r = subprocess.run(
        ["find", str(ctx.rootfs), "-name", "httpd.conf", "-o", "-name", "nginx.conf",
         "-o", "-name", "lighttpd.conf", "-o", "-name", "uhttpd.conf", "-o", "-name", "boa.conf"],
        capture_output=True, text=True,
    )
    sections = [section("Web Server Config Files Found", r.stdout)]
    for path_str in r.stdout.strip().splitlines():
        p = Path(path_str)
        if p.is_file():
            sections.append(section(str(p.relative_to(ctx.rootfs)), p.read_text(errors="replace")))
    out_file.write_text("".join(sections))
    total = sum(len(s.splitlines()) for s in sections)
    print(f"  {'web_server_configs.txt':45s}  {total} lines")


def analyze_cgi_injection(ctx: AnalysisContext):
    out_file = ctx.out_dir / "cgi_injection.txt"
    r_find = subprocess.run(
        ["find", str(ctx.rootfs), "-name", "*.cgi", "-o", "-name", "*.lua", "-o", "-name", "*.sh"],
        capture_output=True, text=True,
    )
    script_files = [l.strip() for l in r_find.stdout.splitlines() if l.strip()]
    if not script_files:
        out_file.write_text(section("CGI Injection", "(no CGI/Lua/shell scripts found)"))
        print(f"  {'cgi_injection.txt':45s}  no scripts found")
        return

    HTTP_VARS = (
        r"\$(QUERY_STRING|REQUEST_URI|REQUEST_METHOD|HTTP_HOST|HTTP_REFERER"
        r"|HTTP_USER_AGENT|FORM_[A-Z_]+|CGI_[A-Z_]+|PATH_INFO|CONTENT_LENGTH)"
    )
    multi_section_file([
        ("HTTP Environment Variables in Scripts",
         ["grep", "-En", HTTP_VARS] + script_files),
        ("eval / exec with Shell Variables",
         ["grep", "-En", r"(eval|exec)\s+.*\$"] + script_files),
        ("Command Substitution Using Variables",
         ["grep", "-En", r"(`[^`]*\$|\$\([^)]*\$)"] + script_files),
    ], out_file, "cgi_injection.txt")


def analyze_php_cmdinject(ctx: AnalysisContext):
    out_file = ctx.out_dir / "php_cmdinject.txt"
    rootfs = ctx.rootfs
    """
    Taint-flow check for PHP OS command injection.

    Sources : $_GET / $_POST / $_REQUEST / $_COOKIE / $_SERVER
    Sinks   : exec / system / shell_exec / passthru / popen / proc_open
    Sanitizers that clear a finding: escapeshellarg / escapeshellcmd

    Three finding tiers:
      HIGH — source + sink on the same line, no sanitizer on that line
      HIGH — file contains both sources and sinks, no sanitizer anywhere in the file
      VERIFY — file contains sources + sinks but also has a sanitizer (coverage may be partial)
    """
    SOURCES    = re.compile(r'\$_(GET|POST|REQUEST|COOKIE|SERVER)\b')
    SINKS      = re.compile(r'\b(exec|system|shell_exec|passthru|popen|proc_open)\s*\(')
    SANITIZERS = re.compile(r'\b(escapeshellarg|escapeshellcmd)\s*\(')

    php_files = sorted(p for p in rootfs.rglob("*.php") if p.is_file())
    if not php_files:
        out_file.write_text(section("PHP Command Injection", "(no PHP files found)"))
        print(f"  {'php_cmdinject.txt':45s}  no PHP files found")
        return

    same_line_hits = []
    file_level     = []

    for php in php_files:
        try:
            file_lines = php.read_text(errors="replace").splitlines()
        except Exception:
            continue

        file_has_source    = False
        file_has_sink      = False
        file_has_sanitizer = False
        source_lines: list = []
        sink_lines:   list = []

        for i, line in enumerate(file_lines, 1):
            has_src = bool(SOURCES.search(line))
            has_snk = bool(SINKS.search(line))
            has_san = bool(SANITIZERS.search(line))

            if has_src:
                file_has_source = True
                source_lines.append((i, line.strip()))
            if has_snk:
                file_has_sink = True
                sink_lines.append((i, line.strip()))
            if has_san:
                file_has_sanitizer = True

            if has_src and has_snk and not has_san:
                same_line_hits.append((php, i, line.strip()))

        if file_has_source and file_has_sink:
            file_level.append((php, source_lines, sink_lines, file_has_sanitizer))

    all_sections = []

    if same_line_hits:
        rows = []
        for path, lineno, line in same_line_hits:
            rows.append(f"  {path.relative_to(rootfs)}:{lineno}")
            rows.append(f"    {line[:160]}")
        all_sections.append(section(
            f"[HIGH] SAME-LINE: source + sink, no sanitizer  ({len(same_line_hits)} hits)",
            "\n".join(rows),
        ))
    else:
        all_sections.append(section("[HIGH] SAME-LINE: source + sink, no sanitizer", "(none)"))

    no_san = [(p, sl, kl) for p, sl, kl, hs in file_level if not hs]
    if no_san:
        rows = []
        for path, src_lines, snk_lines in no_san:
            rows.append(f"\n  FILE: {path.relative_to(rootfs)}")
            rows.append("  Sources ($_ superglobals):")
            for ln, txt in src_lines[:10]:
                rows.append(f"    line {ln:4d}: {txt[:120]}")
            if len(src_lines) > 10:
                rows.append(f"    ... {len(src_lines) - 10} more source lines")
            rows.append("  Sinks (command execution):")
            for ln, txt in snk_lines[:10]:
                rows.append(f"    line {ln:4d}: {txt[:120]}")
            if len(snk_lines) > 10:
                rows.append(f"    ... {len(snk_lines) - 10} more sink lines")
        all_sections.append(section(
            f"[HIGH] FILE-LEVEL: sources + sinks, NO sanitizer anywhere  ({len(no_san)} files)",
            "\n".join(rows),
        ))
    else:
        all_sections.append(section(
            "[HIGH] FILE-LEVEL: sources + sinks, NO sanitizer anywhere", "(none)"
        ))

    with_san = [(p, sl, kl) for p, sl, kl, hs in file_level if hs]
    if with_san:
        rows = []
        for path, _, snk_lines in with_san:
            rows.append(f"\n  FILE: {path.relative_to(rootfs)}")
            rows.append("  Sinks (verify each is guarded):")
            for ln, txt in snk_lines[:5]:
                rows.append(f"    line {ln:4d}: {txt[:120]}")
            if len(snk_lines) > 5:
                rows.append(f"    ... {len(snk_lines) - 5} more")
        all_sections.append(section(
            f"[VERIFY] FILE-LEVEL: sources + sinks + sanitizer present  ({len(with_san)} files)",
            "\n".join(rows),
        ))

    out_file.write_text("".join(all_sections))
    high = len(same_line_hits) + len(no_san)
    print(f"  {'php_cmdinject.txt':45s}  {len(php_files)} PHP files scanned")
    if high:
        print(f"    !! {len(same_line_hits)} same-line + {len(no_san)} file-level HIGH findings")


def analyze_php_codeinject(ctx: AnalysisContext):
    out_file = ctx.out_dir / "php_codeinject.txt"
    rootfs = ctx.rootfs
    """
    Detect PHP code injection sinks — functions that evaluate arbitrary strings as code.

    Sinks checked:
      eval()                   — executes its argument as PHP
      assert() string-arg      — acts as eval() when passed a string (PHP < 8)
      preg_replace() /e flag   — evaluates replacement as PHP code (removed in PHP 7)
      create_function()        — wraps body string in an anonymous eval
      call_user_func[_array]() — variable callable (attacker-controlled dispatch)

    Each finding is annotated with whether a $_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER
    superglobal appears on the same line (direct taint, highest confidence).
    """
    SOURCES = re.compile(r'\$_(GET|POST|REQUEST|COOKIE|SERVER)\b')

    SINKS = [
        (
            "eval()",
            re.compile(r'\beval\s*\('),
            "executes argument as PHP — any non-literal argument is injectable",
        ),
        (
            "assert() — string/variable argument",
            re.compile(r'\bassert\s*\(\s*(?:\$|[\'"])'),
            "acts as eval() when passed a string in PHP < 8",
        ),
        (
            "preg_replace() — /e modifier",
            re.compile(r"\bpreg_replace\s*\(\s*['\"][^'\"]*\/e[imsxADSUXJ]*['\"]"),
            "/e flag evaluates replacement as PHP code — removed in PHP 7, common in old firmware",
        ),
        (
            "create_function()",
            re.compile(r'\bcreate_function\s*\('),
            "wraps body string in an anonymous eval — removed in PHP 8",
        ),
        (
            "call_user_func[_array]() — variable callable",
            re.compile(r'\bcall_user_func(?:_array)?\s*\(\s*\$'),
            "variable as first argument allows attacker-controlled function dispatch",
        ),
    ]

    php_files = sorted(p for p in rootfs.rglob("*.php") if p.is_file())
    if not php_files:
        out_file.write_text(section("PHP Code Injection Sinks", "(no PHP files found)"))
        print(f"  {'php_codeinject.txt':45s}  no PHP files found")
        return

    findings: dict = {label: [] for label, _, _ in SINKS}
    total_hits = 0

    for php in php_files:
        try:
            file_lines = php.read_text(errors="replace").splitlines()
        except Exception:
            continue
        for i, line in enumerate(file_lines, 1):
            has_source = bool(SOURCES.search(line))
            for label, pattern, _ in SINKS:
                if pattern.search(line):
                    findings[label].append((php, i, line.strip(), has_source))
                    total_hits += 1

    all_sections = []
    direct_count = 0

    for label, _, note in SINKS:
        hits = findings[label]
        if not hits:
            all_sections.append(section(f"{label}", "(none)"))
            continue

        with_src  = [(p, n, l) for p, n, l, s in hits if s]
        without   = [(p, n, l) for p, n, l, s in hits if not s]
        direct_count += len(with_src)

        rows = [
            f"  Note: {note}",
            f"  {len(hits)} hit(s) total  |  {len(with_src)} with superglobal on same line\n",
        ]
        if with_src:
            rows.append("  [HIGH — superglobal on same line]")
            for path, lineno, line in with_src:
                rows.append(f"  {path.relative_to(rootfs)}:{lineno}")
                rows.append(f"    {line[:160]}")
        if without:
            rows.append("\n  [REVIEW — trace taint manually]")
            for path, lineno, line in without:
                rows.append(f"  {path.relative_to(rootfs)}:{lineno}")
                rows.append(f"    {line[:160]}")

        all_sections.append(section(label, "\n".join(rows)))

    out_file.write_text("".join(all_sections))
    print(f"  {'php_codeinject.txt':45s}  {len(php_files)} PHP files  |  {total_hits} sink hits  |  {direct_count} with superglobal on same line")
    if total_hits:
        print(f"    !! {total_hits} code injection sink hits — review php_codeinject.txt")


def analyze_php_lfi(ctx: AnalysisContext):
    out_file = ctx.out_dir / "php_lfi.txt"
    rootfs = ctx.rootfs
    """
    Local File Inclusion taint check.

    Sources : $_GET / $_POST / $_REQUEST / $_COOKIE / $_SERVER
    Sinks   : include / include_once / require / require_once
    Sanitizers that reduce confidence: basename() / realpath() / in_array() / array_key_exists()

    Extra signal — template-loading parameters: keys named page, template, file, path,
    module, view, section, lang, theme.  These are the classic ?page=foo LFI vectors.

    Finding tiers:
      [HIGH]   source superglobal on the same line as an include/require, no sanitizer
      [HIGH]   file has both sources and sinks, no sanitizer anywhere in the file
      [PAGE]   file uses a template-style GET/POST key (page=, file=, …) and also has includes
      [VERIFY] file has sources + sinks + sanitizer present (coverage may be partial)
    """
    SOURCES    = re.compile(r'\$_(GET|POST|REQUEST|COOKIE|SERVER)\b')
    SINKS      = re.compile(r'\b(include|include_once|require|require_once)\s*[\s(]')
    SANITIZERS = re.compile(r'\b(basename|realpath|in_array|array_key_exists)\s*\(')
    PAGE_KEYS  = re.compile(
        r'\$_(GET|POST|REQUEST)\s*\[\s*[\'"]'
        r'(?:page|template|file|path|dir|module|view|include|section|lang|language|theme)'
        r'[\'"]'
    )

    php_files = sorted(p for p in rootfs.rglob("*.php") if p.is_file())
    if not php_files:
        out_file.write_text(section("PHP Local File Inclusion", "(no PHP files found)"))
        print(f"  {'php_lfi.txt':45s}  no PHP files found")
        return

    same_line_hits = []
    file_level     = []

    for php in php_files:
        try:
            file_lines = php.read_text(errors="replace").splitlines()
        except Exception:
            continue

        file_has_source    = False
        file_has_sink      = False
        file_has_sanitizer = False
        file_has_page_key  = False
        src_lines: list    = []
        snk_lines: list    = []

        for i, line in enumerate(file_lines, 1):
            has_src = bool(SOURCES.search(line))
            has_snk = bool(SINKS.search(line))
            has_san = bool(SANITIZERS.search(line))
            has_pg  = bool(PAGE_KEYS.search(line))

            if has_src:
                file_has_source = True
                src_lines.append((i, line.strip()))
            if has_snk:
                file_has_sink = True
                snk_lines.append((i, line.strip()))
            if has_san:
                file_has_sanitizer = True
            if has_pg:
                file_has_page_key = True

            if has_src and has_snk and not has_san:
                same_line_hits.append((php, i, line.strip()))

        if file_has_source and file_has_sink:
            file_level.append((php, src_lines, snk_lines, file_has_sanitizer, file_has_page_key))

    all_sections = []

    if same_line_hits:
        rows = []
        for path, lineno, line in same_line_hits:
            rows.append(f"  {path.relative_to(rootfs)}:{lineno}")
            rows.append(f"    {line[:160]}")
        all_sections.append(section(
            f"[HIGH] SAME-LINE: source + include/require, no sanitizer  ({len(same_line_hits)} hits)",
            "\n".join(rows),
        ))
    else:
        all_sections.append(section("[HIGH] SAME-LINE: source + include/require, no sanitizer", "(none)"))

    no_san = [(p, sl, kl, pg) for p, sl, kl, hs, pg in file_level if not hs]
    if no_san:
        rows = []
        for path, src_lines, snk_lines, has_page_key in no_san:
            tag = "  [PAGE-PARAM PATTERN]" if has_page_key else ""
            rows.append(f"\n  FILE: {path.relative_to(rootfs)}{tag}")
            rows.append("  Sources ($_ superglobals):")
            for ln, txt in src_lines[:8]:
                rows.append(f"    line {ln:4d}: {txt[:120]}")
            if len(src_lines) > 8:
                rows.append(f"    ... {len(src_lines) - 8} more")
            rows.append("  Sinks (include/require):")
            for ln, txt in snk_lines[:8]:
                rows.append(f"    line {ln:4d}: {txt[:120]}")
            if len(snk_lines) > 8:
                rows.append(f"    ... {len(snk_lines) - 8} more")
        all_sections.append(section(
            f"[HIGH] FILE-LEVEL: sources + sinks, NO sanitizer  ({len(no_san)} files)",
            "\n".join(rows),
        ))
    else:
        all_sections.append(section("[HIGH] FILE-LEVEL: sources + sinks, NO sanitizer", "(none)"))

    page_files = [(p, sl, kl, hs) for p, sl, kl, hs, pg in file_level if pg]
    if page_files:
        rows = []
        for path, _, snk_lines, has_san in page_files:
            san_note = "  (sanitizer present — verify coverage)" if has_san else "  !! NO sanitizer"
            rows.append(f"\n  FILE: {path.relative_to(rootfs)}{san_note}")
            rows.append("  Sinks (include/require):")
            for ln, txt in snk_lines[:5]:
                rows.append(f"    line {ln:4d}: {txt[:120]}")
        all_sections.append(section(
            f"[PAGE] TEMPLATE-PARAM PATTERN: ?page=/file=/template= key with includes  ({len(page_files)} files)",
            "\n".join(rows),
        ))

    with_san = [(p, sl, kl) for p, sl, kl, hs, pg in file_level if hs]
    if with_san:
        rows = []
        for path, _, snk_lines in with_san:
            rows.append(f"\n  FILE: {path.relative_to(rootfs)}")
            for ln, txt in snk_lines[:5]:
                rows.append(f"    line {ln:4d}: {txt[:120]}")
        all_sections.append(section(
            f"[VERIFY] FILE-LEVEL: sources + sinks + sanitizer present  ({len(with_san)} files)",
            "\n".join(rows),
        ))

    high = len(same_line_hits) + len(no_san)
    out_file.write_text("".join(all_sections))
    print(f"  {'php_lfi.txt':45s}  {len(php_files)} PHP files  |  {len(same_line_hits)} same-line  |  {len(no_san)} file-level HIGH  |  {len(page_files)} page-param")
    if high:
        print(f"    !! {high} HIGH-confidence LFI findings — review php_lfi.txt")


def analyze_php_infodisclosure(ctx: AnalysisContext):
    out_file = ctx.out_dir / "php_infodisclosure.txt"
    rootfs = ctx.rootfs
    """
    Detect PHP information-disclosure patterns.

    Checks:
      phpinfo()                          — dumps interpreter config, env vars, loaded modules, paths
      ini_set('display_errors', '1'/'On') — makes stack traces and file paths visible in responses
      display_errors = 1 in php.ini / .htaccess / user ini files
      error_reporting(E_ALL)             — verbose error output in production
    """
    CHECKS = [
        (
            "phpinfo()",
            re.compile(r'\bphpinfo\s*\(\s*\)'),
            "HIGH — dumps full interpreter config: env vars, loaded extensions, file paths, build flags",
        ),
        (
            "ini_set('display_errors', on)",
            re.compile(r"\bini_set\s*\(\s*['\"]display_errors['\"]\s*,\s*['\"]?\s*(?:1|On|TRUE|true)['\"]?\s*\)"),
            "HIGH — stack traces with file paths and variable names sent to the HTTP response",
        ),
        (
            "error_reporting(E_ALL)",
            re.compile(r"\berror_reporting\s*\(\s*(?:E_ALL|32767|-1|\(E_ALL\s*[|&]|\d+)"),
            "MEDIUM — verbose error output; combine with display_errors=1 for full disclosure",
        ),
    ]

    INI_DISPLAY_ERRORS = re.compile(r'^\s*display_errors\s*=\s*(?:1|On|TRUE|true)\s*$', re.MULTILINE)

    php_files = sorted(p for p in rootfs.rglob("*.php") if p.is_file())
    ini_files  = [
        p for p in rootfs.rglob("*")
        if p.is_file() and p.suffix.lower() in {".ini", ".htaccess"} or p.name == ".user.ini"
    ]

    if not php_files and not ini_files:
        out_file.write_text(section("PHP Information Disclosure", "(no PHP or ini files found)"))
        print(f"  {'php_infodisclosure.txt':45s}  no files found")
        return

    findings: dict = {label: [] for label, _, _ in CHECKS}
    total_hits = 0

    for php in php_files:
        try:
            file_lines = php.read_text(errors="replace").splitlines()
        except Exception:
            continue
        for i, line in enumerate(file_lines, 1):
            for label, pattern, _ in CHECKS:
                if pattern.search(line):
                    findings[label].append((php, i, line.strip()))
                    total_hits += 1

    ini_hits: list = []
    for ini in ini_files:
        try:
            content = ini.read_text(errors="replace")
        except Exception:
            continue
        for i, line in enumerate(content.splitlines(), 1):
            if INI_DISPLAY_ERRORS.match(line):
                ini_hits.append((ini, i, line.strip()))
                total_hits += 1

    all_sections = []

    for label, _, note in CHECKS:
        hits = findings[label]
        if not hits:
            all_sections.append(section(label, f"  {note}\n\n  (none)"))
            continue
        rows = [f"  {note}", f"  {len(hits)} hit(s)\n"]
        for path, lineno, line in hits:
            rows.append(f"  {path.relative_to(rootfs)}:{lineno}")
            rows.append(f"    {line[:160]}")
        all_sections.append(section(label, "\n".join(rows)))

    if ini_hits:
        rows = [
            "  MEDIUM — php.ini / .htaccess / .user.ini override enables error display",
            f"  {len(ini_hits)} hit(s)\n",
        ]
        for path, lineno, line in ini_hits:
            rows.append(f"  {path.relative_to(rootfs)}:{lineno}")
            rows.append(f"    {line[:160]}")
        all_sections.append(section("display_errors = 1 in ini/htaccess files", "\n".join(rows)))
    else:
        all_sections.append(section("display_errors = 1 in ini/htaccess files", "  (none)"))

    out_file.write_text("".join(all_sections))
    print(f"  {'php_infodisclosure.txt':45s}  {len(php_files)} PHP + {len(ini_files)} ini files  |  {total_hits} hits")
    if total_hits:
        print(f"    !! {total_hits} information-disclosure findings — review php_infodisclosure.txt")
