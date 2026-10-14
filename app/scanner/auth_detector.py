from pathlib import Path
from .ast_utils import get_parser, node_text
from .findings import Finding, Severity

AUTH_KEYWORDS = ("isauthorized", "role", "permission", "canedit", "candelete")
HTTP_CALL_NAMES = ("fetch", "axios", "delete", "post", "put", "get")
DANGEROUS_METHODS = ("delete", "put", "patch")

def _walk(node):
    yield node
    for child in node.children:
        yield from _walk(child)

def _contains_auth_check(node, source: bytes) -> bool:
    """Look for auth-flavored identifiers anywhere above this call in the tree path."""
    text = node_text(node, source).lower()
    return any(keyword in text for keyword in AUTH_KEYWORDS)

def _find_enclosing_conditional_text(node, source: bytes) -> str:
    """Walk up parent chain, collect any if-statement conditions wrapping this node."""
    conditions = []
    current = node.parent
    while current is not None:
        if current.type == "if_statement":
            condition_node = current.child_by_field_name("condition")
            if condition_node:
                conditions.append(node_text(condition_node, source))
        current = current.parent
    return " ".join(conditions).lower()

def scan_file_for_client_only_auth(file_path: Path) -> list[Finding]:
    findings = []
    parser = get_parser(file_path.suffix)
    if parser is None:
        return findings

    try:
        source = file_path.read_bytes()
    except Exception:
        return findings

    tree = parser.parse(source)

    for node in _walk(tree.root_node):
        if node.type != "call_expression":
            continue

        call_text = node_text(node, source)
        call_lower = call_text.lower()

        # Is this an HTTP call, and specifically a dangerous method (delete/put/patch)?
        if not any(name in call_lower for name in HTTP_CALL_NAMES):
            continue
        if not any(method in call_lower for method in DANGEROUS_METHODS):
            continue

        enclosing_condition = _find_enclosing_conditional_text(node, source)
        has_auth_guard = any(keyword in enclosing_condition for keyword in AUTH_KEYWORDS)

        if has_auth_guard:
            # There IS a client-side check wrapping this call — that's exactly the risky pattern:
            # auth enforced only in the UI, not proven server-side from this file alone.
            line_no = node.start_point[0] + 1
            findings.append(Finding(
                category="client_side_only_authorization",
                file_path=str(file_path),
                line_number=line_no,
                evidence=call_text.strip()[:120],
                severity=Severity.CRITICAL,
                confidence=0.75,  # capped below 0.9 — this file alone can't prove the backend is unguarded
                description=(
                    "A destructive API call (delete/put/patch) is only reachable through a UI-level "
                    f"authorization check ('{enclosing_condition.strip()[:80]}'). "
                    "This proves the frontend hides the action from unauthorized users, but does NOT "
                    "prove the backend endpoint itself rejects unauthorized requests."
                ),
                recommended_fix=(
                    "Verify the corresponding backend route enforces its own authorization check "
                    "(e.g. middleware) independent of anything the frontend sends. Never trust a "
                    "client-side condition as the only gate on a destructive action."
                ),
            ))

    return findings
