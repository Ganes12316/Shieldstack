import re
import math
from pathlib import Path
from .findings import Finding, Severity

# Known secret patterns — each AI coding tool tends to leave these in predictable spots
SECRET_PATTERNS = {
    "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "generic_api_key": re.compile(
        r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]"
    ),
    "private_key_block": re.compile(r"-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----"),
    "hardcoded_password": re.compile(
        r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}['\"]"
    ),
}
PLACEHOLDER_PATTERN = re.compile(
    r"(?i)(your[_-]?api|your[_-]?key|_here$|placeholder|example|changeme|xxx|insert[_-]?key|<[a-z_]+>)"
)
COMMENT_LINE_PATTERN = re.compile(r"^\s*(//|#|/\*|\*)")
VARIABLE_REFERENCE_PATTERN = re.compile(r"^(\$\w+|\{\w+\}|\$\{\w+\})$")  # PHP '$var', Python '{var}', JS '${var}' — a variable, not a literal

CORS_WILDCARD = re.compile(r"(?i)Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"]\*['\"]")
DEBUG_TRUE = re.compile(r"(?i)\bDEBUG\s*=\s*True\b")

SCAN_EXTENSIONS = (".py", ".js", ".jsx", ".ts", ".tsx", ".vue", ".html", ".java",
                    ".go", ".rb", ".php", ".cs", ".yml", ".yaml", ".json",
                    ".env", ".properties", ".xml")
SKIP_DIRS = {"node_modules", ".git", "venv", "__pycache__", "dist", "build", "vendor"}


def shannon_entropy(s: str) -> float:
    """High entropy = looks random = more likely a real secret, not a placeholder."""
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    length = len(s)
    return -sum((f / length) * math.log2(f / length) for f in freq.values())


def redact(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def scan_file(file_path: Path) -> list[Finding]:
    findings = []
    try:
        text = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return findings

    lines = text.splitlines()

    for line_no, line in enumerate(lines, start=1):
        if COMMENT_LINE_PATTERN.match(line):
            continue  # skip commented-out lines — not active/executing code

        # 1. Known secret patterns
        for name, pattern in SECRET_PATTERNS.items():
            match = pattern.search(line)
            if match:
                secret_value = match.group(2) if match.groups() and len(match.groups()) > 1 else match.group(0)
                entropy = shannon_entropy(secret_value)

                if PLACEHOLDER_PATTERN.search(secret_value):
                    continue
                quoted_content = re.search(r"['\"]([^'\"]*)['\"]", secret_value)
                if quoted_content and VARIABLE_REFERENCE_PATTERN.match(quoted_content.group(1)):
                    continue  # e.g. password = '$password', f"...{password}...", or `${password}` — a variable, not a literal secret
                if entropy < 3.0 and name != "private_key_block":
                    continue

                findings.append(Finding(
                    category="hardcoded_secret",
                    file_path=str(file_path),
                    line_number=line_no,
                    evidence=redact(line.strip()),
                    severity=Severity.CRITICAL,
                    confidence=min(0.6 + entropy / 10, 0.98),
                    description=f"Hardcoded {name.replace('_', ' ')} detected in source code.",
                    recommended_fix="Move this value to an environment variable (.env, not committed) and load via os.environ / process.env."
                ))

        # 2. Open CORS
        if CORS_WILDCARD.search(line):
            findings.append(Finding(
                category="open_cors",
                file_path=str(file_path),
                line_number=line_no,
                evidence=line.strip(),
                severity=Severity.HIGH,
                confidence=0.9,
                description="CORS is configured to allow requests from any origin (*).",
                recommended_fix="Restrict Access-Control-Allow-Origin to a known allowlist of frontend domains."
            ))

        # 3. Debug mode on
        if DEBUG_TRUE.search(line):
            findings.append(Finding(
                category="debug_mode_enabled",
                file_path=str(file_path),
                line_number=line_no,
                evidence=line.strip(),
                severity=Severity.MEDIUM,
                confidence=0.85,
                description="Debug mode appears to be enabled, which can leak stack traces and internals in production.",
                recommended_fix="Set DEBUG=False in production and control it via an environment variable."
            ))

    return findings


def scan_directory(root: Path, extensions=SCAN_EXTENSIONS) -> list[Finding]:
    all_findings = []
    for path in root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.name.endswith(".min.js"):
            continue
        if path.is_file() and (path.suffix in extensions or path.name == ".env"):
            all_findings.extend(scan_file(path))
    return all_findings


def get_scanned_file_count(root: Path, extensions=SCAN_EXTENSIONS) -> int:
    count = 0
    for path in root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.name.endswith(".min.js"):
            continue
        if path.is_file() and (path.suffix in extensions or path.name == ".env"):
            count += 1
    return count