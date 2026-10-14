import re
from pathlib import Path
from .ast_utils import get_parser, node_text
from .findings import Finding, Severity

# Common auth-guard signatures across frameworks
AUTH_MIDDLEWARE_PATTERNS = (
    "requireauth", "isauthenticated", "authmiddleware", "@login_required",
    "depends(get_current_user", "verifytoken",
    "checkauth", "authorize", "protect",
)

ROUTE_PATTERNS = {
    # Express-style: app.delete('/api/users/:id', ...handlers)
    "express": re.compile(
        r"(?i)\.(get|post|put|delete|patch)\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*(.*)"
    ),
    # FastAPI-style: @app.delete("/api/users/{id}")
    "fastapi": re.compile(
        r"(?i)@\w+\.(get|post|put|delete|patch)\s*\(\s*['\"]([^'\"]+)['\"]"
    ),
}

def normalize_path(path: str) -> str:
    """Turn /api/users/:id or /api/users/{id} into /api/users/<param> for matching."""
    path = re.sub(r":[a-zA-Z_]+", "<param>", path)
    path = re.sub(r"\$?\{[a-zA-Z_]+\}", "<param>", path)
    return path.rstrip("/")

def extract_backend_routes(file_path: Path) -> list[dict]:
    """Returns list of {method, path, line_no, has_auth_guard, raw_line}."""
    routes = []
    try:
        lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return routes

    for i, line in enumerate(lines):
        for framework, pattern in ROUTE_PATTERNS.items():
            match = pattern.search(line)
            if not match:
                continue
            method = match.group(1).upper()
            raw_path = match.group(2)

            # Look at this line plus the next few lines for an auth guard
            # (covers both inline middleware args and decorator-then-function patterns)
            window = " ".join(lines[i:i + 4]).lower().replace("_", "")         
            has_guard = any(p in window for p in AUTH_MIDDLEWARE_PATTERNS)

            routes.append({
                "method": method,
                "path": normalize_path(raw_path),
                "line_no": i + 1,
                "has_auth_guard": has_guard,
                "file_path": str(file_path),
            })
    return routes

def extract_frontend_calls(file_path: Path) -> list[dict]:
    """Reuses tree-sitter to find fetch/axios calls and their target paths + method."""
    calls = []
    parser = get_parser(file_path.suffix)
    if parser is None:
        return calls
    try:
        source = file_path.read_bytes()
    except Exception:
        return calls

    tree = parser.parse(source)

    def walk(node):
        yield node
        for child in node.children:
            yield from walk(child)

    method_re = re.compile(r"(?i)method\s*:\s*['\"](\w+)['\"]")
    path_re = re.compile(r"['\"`](/api/[^'\"`]+)['\"`]")

    for node in walk(tree.root_node):
        if node.type != "call_expression":
            continue
        text = node_text(node, source)
        if "fetch" not in text.lower() and "axios" not in text.lower():
            continue

        method_match = method_re.search(text)
        path_match = path_re.search(text)
        if not path_match:
            continue

        method = method_match.group(1).upper() if method_match else "GET"
        calls.append({
            "method": method,
            "path": normalize_path(path_match.group(1)),
            "line_no": node.start_point[0] + 1,
            "file_path": str(file_path),
            "raw": text.strip()[:120],
        })
    return calls

def cross_reference(frontend_calls: list[dict], backend_routes: list[dict]) -> list[Finding]:
    findings = []
    for call in frontend_calls:
        matches = [
            r for r in backend_routes
            if r["method"] == call["method"] and r["path"] == call["path"]
        ]
        if not matches:
            continue  # can't confirm either way — route not found in scanned backend files

        for route in matches:
            if not route["has_auth_guard"]:
                findings.append(Finding(
                    category="unauthenticated_backend_route",
                    file_path=route["file_path"],
                    line_number=route["line_no"],
                    evidence=f"{route['method']} {call['path']} — called from {call['file_path']}:{call['line_no']}, no auth guard found",
                    severity=Severity.CRITICAL,
                    confidence=0.95,  # now provable, not just suspected
                    description=(
                        f"Backend route {route['method']} {call['path']} has no detected authorization "
                        "middleware, and is called from the frontend behind a client-side-only check. "
                        "This route is reachable by anyone who can construct the HTTP request directly."
                    ),
                    recommended_fix="Add server-side authorization middleware to this route before it reaches the handler logic.",
                ))
    return findings
