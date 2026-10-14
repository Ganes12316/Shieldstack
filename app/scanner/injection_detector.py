import re
from pathlib import Path
from .ast_utils import get_parser, node_text
from .findings import Finding, Severity

# Sources: places user-controlled input typically enters a function
TAINT_SOURCE_PATTERNS = re.compile(
    r"(?i)(request\.(args|form|json|query_params)\.get\(|req\.(query|body|params)\.|"
    r"req\.query\[|req\.body\[|req\.params\[|\$_(GET|POST|REQUEST|COOKIE)\[)"
)

SQL_SINK_PATTERN = re.compile(
    r"(\.execute\s*\(|\.query\s*\(|mysqli_query\s*\(|->query\s*\(|->exec\s*\()"
)
FSTRING_OR_CONCAT = re.compile(
    r"f['\"]|['\"]\s*\+|\+\s*['\"]|%\s*\(|['\"]\s*\.\s*\$|\$\w+\s*\.\s*['\"]|\$\{"
)

XSS_SINK_PATTERN = re.compile(r"(?i)(\.innerHTML\s*=|dangerouslySetInnerHTML)")

SUPPORTED_EXTENSIONS = (".py", ".php", ".js", ".jsx", ".ts", ".tsx")
PY_PHP_EXTENSIONS = (".py", ".php")

# Handles: "name = ...", "$name = ..." (PHP), "const/let/var name = ..." (JS/TS)
ASSIGNMENT_PATTERN = re.compile(
    r"^\s*(?:(?:const|let|var)\s+)?(?:\$)?([a-zA-Z_][a-zA-Z0-9_]*)\s*="
)

# JS/TS function-like node types — route handlers are usually arrow functions or
# inline function expressions passed as callback arguments, not named declarations
FUNCTION_NODE_TYPES = ("function_definition", "function_declaration",
                        "arrow_function", "function_expression")


def _walk(node):
    yield node
    for child in node.children:
        yield from _walk(child)


def _get_function_nodes(tree):
    return [n for n in _walk(tree.root_node) if n.type in FUNCTION_NODE_TYPES]


def _function_name(node, source):
    name_node = node.child_by_field_name("name")
    return node_text(name_node, source) if name_node else None


def _param_names(node, source):
    params_node = node.child_by_field_name("parameters")
    if not params_node:
        return []
    names = []
    for child in params_node.children:
        if child.type == "identifier":
            names.append(node_text(child, source))
        elif child.type in ("typed_parameter", "default_parameter", "typed_default_parameter"):
            for sub in child.children:
                if sub.type == "identifier":
                    names.append(node_text(sub, source))
                    break
    return names


def detect_sql_injection(file_path: Path) -> list[Finding]:
    """
    Same-function taint tracking, plus ONE hop through locally-defined
    function calls. Supports Python, PHP, and JavaScript/TypeScript.

    Python/PHP: also treats FastAPI/Flask-style typed function parameters
    as taint sources directly (untyped params are NOT auto-tainted for JS,
    since that would over-taint 'req'/'res' themselves rather than the
    specific req.body/req.query accesses that actually carry user input).

    Does NOT track across files, imports, class attributes, or more than
    one call hop — deliberate scope limit, not an oversight.
    """
    findings = []
    if file_path.suffix not in SUPPORTED_EXTENSIONS:
        return findings
    parser = get_parser(file_path.suffix)
    if parser is None:
        return findings

    try:
        source = file_path.read_bytes()
    except Exception:
        return findings

    tree = parser.parse(source)
    lines = source.decode("utf-8", errors="ignore").splitlines()
    functions = _get_function_nodes(tree)
    func_by_name = {_function_name(f, source): f for f in functions if _function_name(f, source)}

    for fn in functions:
        tainted_vars = set()
        start, end = fn.start_point[0], fn.end_point[0]

        # FastAPI/Flask idiom: typed (or untyped) function parameters ARE the
        # taint source directly — Python/PHP only. For JS, req/res parameters
        # stay untainted; only their .body/.query/.params accesses do (below).
        if file_path.suffix in PY_PHP_EXTENSIONS:
            params_node = fn.child_by_field_name("parameters")
            if params_node:
                for child in params_node.children:
                    if child.type == "identifier":
                        tainted_vars.add(node_text(child, source))
                    elif child.type in ("typed_parameter", "default_parameter", "typed_default_parameter"):
                        for sub in child.children:
                            if sub.type == "identifier":
                                tainted_vars.add(node_text(sub, source))
                                break

        # Explicit request.args / req.body / $_POST-style taint sources assigned to a variable
        for line_no in range(start, end + 1):
            line = lines[line_no]
            if TAINT_SOURCE_PATTERNS.search(line):
                m = ASSIGNMENT_PATTERN.match(line)
                if m:
                    tainted_vars.add(m.group(1))

        # One hop: tainted var passed into a locally-defined function
        scan_ranges = [(start, end)]
        for line_no in range(start, end + 1):
            call_match = re.search(r"([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)", lines[line_no])
            if call_match and call_match.group(1) in func_by_name:
                callee = func_by_name[call_match.group(1)]
                if callee is fn:
                    continue
                args = [a.strip() for a in call_match.group(2).split(",")]
                for arg, pname in zip(args, _param_names(callee, source)):
                    if arg in tainted_vars:
                        tainted_vars.add(pname)
                scan_ranges.append((callee.start_point[0], callee.end_point[0]))

        # Track variables built from tainted input via f-string/concat/template-literal
        risky_query_vars = set()
        seen = set()
        for r_start, r_end in scan_ranges:
            for line_no in range(r_start, r_end + 1):
                if line_no in seen:
                    continue
                seen.add(line_no)
                line = lines[line_no]

                if FSTRING_OR_CONCAT.search(line) and any(re.search(rf"\b{re.escape(v)}\b", line) for v in tainted_vars):
                    m = ASSIGNMENT_PATTERN.match(line)
                    if m:
                        risky_query_vars.add(m.group(1))

                # Direct case: sink and taint on the same line
                if SQL_SINK_PATTERN.search(line) and FSTRING_OR_CONCAT.search(line):
                    if any(re.search(rf"\b{re.escape(v)}\b", line) for v in tainted_vars):
                        findings.append(_make_sql_finding(file_path, line_no, line))
                # Sink uses a variable already flagged as a risky query string
                elif SQL_SINK_PATTERN.search(line):
                    if any(re.search(rf"\b{re.escape(v)}\b", line) for v in risky_query_vars):
                        findings.append(_make_sql_finding(file_path, line_no, line))

    # Dedupe: the same line can be reached both as its own top-level function
    # AND as a one-hop callee from another function, producing duplicate findings
    # for the same real vulnerability.
    seen_findings = set()
    deduped = []
    for f in findings:
        key = (f.file_path, f.line_number, f.evidence)
        if key not in seen_findings:
            seen_findings.add(key)
            deduped.append(f)
    return deduped


def _make_sql_finding(file_path, line_no, line):
    return Finding(
        category="sql_injection",
        file_path=str(file_path),
        line_number=line_no + 1,
        evidence=line.strip()[:150],
        severity=Severity.CRITICAL,
        confidence=0.85,
        description=(
            "User-controlled input appears to flow into a raw SQL query via "
            "string formatting/concatenation instead of a parameterized query."
        ),
        recommended_fix=(
            "Use parameterized queries (e.g. prepared statements with mysqli/PDO in PHP, "
            "placeholder-based queries with mysql2/pg in Node.js, or cursor.execute(query, "
            "(param,)) in Python) instead of building SQL strings with concatenation or interpolation."
        ),
    )


def detect_xss(file_path: Path) -> list[Finding]:
    """Same-file heuristic taint tracking for JSX/JS. No cross-file tracking."""
    findings = []
    if file_path.suffix not in (".js", ".jsx", ".ts", ".tsx"):
        return findings
    try:
        lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return findings

    tainted_vars = set()
    source_pattern = re.compile(r"(?i)(props\.|location\.(search|hash)|window\.location|req\.(query|body|params))")
    sanitizer_pattern = re.compile(r"(?i)(dompurify|sanitize|escape\()")

    for i, line in enumerate(lines):
        if source_pattern.search(line):
            if sanitizer_pattern.search(line):
                continue
            m = ASSIGNMENT_PATTERN.match(line)
            if m:
                tainted_vars.add(m.group(1))

        if XSS_SINK_PATTERN.search(line):
            uses_tainted = any(re.search(rf"\b{re.escape(v)}\b", line) for v in tainted_vars)
            inline_unsanitized_source = source_pattern.search(line) and not sanitizer_pattern.search(line)
            if uses_tainted or inline_unsanitized_source:
                findings.append(Finding(
                    category="xss_unsanitized_render",
                    file_path=str(file_path),
                    line_number=i + 1,
                    evidence=line.strip()[:150],
                    severity=Severity.HIGH,
                    confidence=0.7,
                    description=(
                        "Potentially user-controlled data is rendered via innerHTML/"
                        "dangerouslySetInnerHTML without visible sanitization."
                    ),
                    recommended_fix=(
                        "Avoid raw HTML injection with unsanitized input; use safe text "
                        "rendering, or sanitize with a library like DOMPurify first."
                    ),
                ))
    return findings