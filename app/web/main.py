import json
import ipaddress
import os
import re
import shutil
import warnings
from dataclasses import replace
from pathlib import Path

import requests
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from pydantic import BaseModel

from app.scanner.repo_loader import load_repo, RepoLoadError
from app.scanner.secrets_detector import scan_directory, get_scanned_file_count, get_skipped_file_count
from app.scanner.file_selection import should_skip_path
from app.scanner.auth_detector import scan_file_for_client_only_auth
from app.scanner.injection_detector import detect_sql_injection, detect_xss
from app.scanner.backend_detector import extract_backend_routes, extract_frontend_calls, cross_reference
from app.scanner.ml.predict import refine_confidence
from app.scanner.report_generator import generate_report
from app.web.feedback import FeedbackIn, save_feedback


warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

# ─── Rate limiter ──────────────────────────────────────────────
def _client_ip(request: Request) -> str:
    direct_address = request.client.host if request.client else "unknown"
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        try:
            trusted_hops = int(os.getenv("TRUSTED_PROXY_HOPS", "1"))
        except (TypeError, ValueError):
            trusted_hops = 1
        if trusted_hops > 0:
            addresses = [address.strip() for address in forwarded_for.split(",")]
            if len(addresses) >= trusted_hops:
                candidate = addresses[-trusted_hops]
                try:
                    return str(ipaddress.ip_address(candidate))
                except ValueError:
                    pass
    return direct_address

limiter = Limiter(key_func=_client_ip, default_limits=["300/day", "60/hour"])

app = FastAPI(title="ShieldStack API")

app.state.limiter = limiter
def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded):
    retry_after = 60
    current_limit = getattr(request.state, "view_rate_limit", None)
    if current_limit:
        try:
            window_reset, _ = limiter.limiter.get_window_stats(current_limit[0], *current_limit[1])
            retry_after = max(1, int(window_reset) + 1)
        except Exception:
            pass
    return JSONResponse(
        status_code=429,
        content={"detail": "Too many requests. Please wait a minute and try again."},
        headers={"Retry-After": str(retry_after)},
    )


app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)

# ─── CORS — tightened to only needed methods ───────────────────
allowed_origins = ["http://localhost:5173"]
frontend_url = os.getenv("FRONTEND_URL", "").strip().rstrip("/")
if frontend_url and frontend_url != "*":
    allowed_origins.append(frontend_url)
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_methods=["GET", "POST"],       # Only what the frontend actually uses
    allow_headers=["Content-Type"],      # Only Content-Type needed
)


# ─── Path traversal — allowed scan roots ──────────────────────
# Only allow scanning inside known safe base directories.
# Adjust SAFE_ROOTS to the directories you want to allow for local scanning.
SAFE_ROOTS = [
    Path.home(),                          # User's home directory
    Path(r"C:\projects"),                 # Windows dev folder
    Path(r"C:\Users"),                    # Windows users folder
    Path("/tmp"),                         # Unix temp
    Path("/home"),                        # Unix home
    Path("/var/projects"),                # Unix project dirs
]

# Directories always blocked from scanning
BLOCKED_DIRS = {
    "windows", "system32", "syswow64", "program files",
    "etc", "proc", "sys", "dev", "boot",
    ".ssh", ".aws", ".gnupg",
}

SKIP_DIRS = {"node_modules", ".git", "venv", "__pycache__", "dist", "build", "vendor"}
DEFAULT_STATS_FILE = Path(__file__).resolve().parent.parent.parent / "data" / "stats.json"


def _select_stats_file() -> Path:
    configured = os.getenv("STATS_FILE")
    if configured:
        candidate = Path(configured).expanduser()
        folder = candidate.parent
        if folder.is_dir() and os.access(folder, os.W_OK):
            return candidate
    return DEFAULT_STATS_FILE


STATS_FILE = _select_stats_file()
UPSTASH_REDIS_REST_URL = os.getenv("UPSTASH_REDIS_REST_URL", "").strip().rstrip("/")
UPSTASH_REDIS_REST_TOKEN = os.getenv("UPSTASH_REDIS_REST_TOKEN", "").strip()
UPSTASH_STATS_KEYS = ("repos_tested", "bugs_found", "total_scans")

DEFAULT_STATS = {
    "repos_tested": 0,
    "automated_tests": 51,
    "languages_supported": 4,
    "bugs_found": 0,
    "total_scans": 0,
}


def load_stats() -> dict:
    if UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN:
        try:
            stats = _load_upstash_stats()
            return {**DEFAULT_STATS, **stats, "stats_backend": "upstash"}
        except Exception:
            pass
    return _load_local_stats()


def _load_local_stats() -> dict:
    try:
        if STATS_FILE.exists():
            with open(STATS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return {**DEFAULT_STATS, **data, "stats_backend": "local"}
    except Exception:
        pass
    return {**DEFAULT_STATS, "stats_backend": "local"}


def _upstash_request(command: list):
    response = requests.post(
        UPSTASH_REDIS_REST_URL,
        json=command,
        headers={"Authorization": f"Bearer {UPSTASH_REDIS_REST_TOKEN}"},
        timeout=3,
    )
    response.raise_for_status()
    payload = response.json()
    if "error" in payload:
        raise RuntimeError("Upstash Redis request failed")
    return payload.get("result")


def _load_upstash_stats() -> dict:
    values = _upstash_request(["MGET", *UPSTASH_STATS_KEYS])
    if not isinstance(values, list) or len(values) != len(UPSTASH_STATS_KEYS):
        raise ValueError("Unexpected Upstash stats response")
    return {key: int(value or 0) for key, value in zip(UPSTASH_STATS_KEYS, values)}


def save_stats(stats: dict) -> None:
    try:
        STATS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(STATS_FILE, "w", encoding="utf-8") as f:
            json.dump(stats, f, indent=2)
    except Exception:
        pass


def record_scan_stats(findings_count: int) -> dict:
    if UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN:
        try:
            _upstash_request(["INCRBY", "repos_tested", 1])
            _upstash_request(["INCRBY", "bugs_found", findings_count])
            _upstash_request(["INCRBY", "total_scans", 1])
            return {**DEFAULT_STATS, **_load_upstash_stats(), "stats_backend": "upstash"}
        except Exception:
            # A stats provider outage must never fail an otherwise successful scan.
            pass

    stats = load_stats()
    if stats.get("stats_backend") == "upstash":
        # Redis was configured but failed during an increment/read; use the
        # local file as the fallback source for this update.
        stats = _load_local_stats()
    stats["repos_tested"] += 1
    stats["bugs_found"] += findings_count
    stats["total_scans"] += 1
    save_stats(stats)
    return stats


def _should_skip(p: Path) -> bool:
    if any(part in SKIP_DIRS for part in p.parts):
        return True
    if p.name.endswith(".min.js"):
        return True
    return False


def _is_safe_path(requested: Path) -> bool:
    """Return True only if the resolved path is within a SAFE_ROOT
    and does not touch any BLOCKED_DIR names."""
    try:
        resolved = requested.resolve()
    except Exception:
        return False

    # Reject if any path component matches a blocked name
    for part in resolved.parts:
        if part.lower().strip("\\/") in BLOCKED_DIRS:
            return False

    # Must be inside at least one safe root
    for root in SAFE_ROOTS:
        try:
            resolved.relative_to(root.resolve())
            return True
        except ValueError:
            continue

    return False


# ─── Pydantic models ──────────────────────────────────────────

class ScanRequest(BaseModel):
    repo_url: str | None = None
    local_path: str | None = None
    include_fixtures: bool = False


class FindingOut(BaseModel):
    category: str
    file_path: str
    line_number: int
    evidence: str
    severity: str
    confidence: float
    description: str
    recommended_fix: str


class StatsResponse(BaseModel):
    repos_tested: int
    automated_tests: int
    languages_supported: int
    bugs_found: int
    total_scans: int
    stats_backend: str


class ScanResponse(BaseModel):
    findings: list[FindingOut]
    summary_report: str
    total: int
    critical_count: int
    skipped_files: int = 0
    stats: StatsResponse | None = None


# ─── Scanner ──────────────────────────────────────────────────

def run_full_scan(target: Path, include_fixtures: bool = False) -> list:
    findings = scan_directory(target, include_fixtures=include_fixtures)

    for p in target.rglob("*"):
        if p.is_file() and not should_skip_path(p, target, include_fixtures) and p.suffix in (".js", ".jsx", ".ts", ".tsx"):
            findings.extend(scan_file_for_client_only_auth(p))

    backend_routes, frontend_calls = [], []
    for p in target.rglob("*"):
        if p.is_file() and not should_skip_path(p, target, include_fixtures):
            if p.suffix == ".py":
                backend_routes.extend(extract_backend_routes(p))
            if p.suffix in (".js", ".jsx", ".ts", ".tsx"):
                backend_routes.extend(extract_backend_routes(p))
                frontend_calls.extend(extract_frontend_calls(p))
    findings.extend(cross_reference(frontend_calls, backend_routes))

    for p in target.rglob("*"):
        if p.is_file() and not should_skip_path(p, target, include_fixtures):
            findings.extend(detect_sql_injection(p))
            findings.extend(detect_xss(p))

    return [refine_confidence(f) for f in findings]


def _sanitize_finding_paths(findings: list, target: Path) -> list:
    """Return findings with paths relative to the scanned project root."""
    root = target.resolve()
    root_prefix = root.as_posix().rstrip("/") + "/"
    safe_findings = []

    for finding in findings:
        try:
            display_path = Path(finding.file_path).resolve().relative_to(root).as_posix()
        except (OSError, ValueError):
            display_path = Path(finding.file_path).name

        evidence = finding.evidence.replace("\\", "/")
        evidence = re.sub(re.escape(root_prefix), "", evidence, flags=re.IGNORECASE)
        safe_findings.append(replace(finding, file_path=display_path, evidence=evidence))

    return safe_findings


# ─── Routes ───────────────────────────────────────────────────

@app.get("/stats", response_model=StatsResponse)
@limiter.limit("120/minute")
def get_stats(request: Request):
    return load_stats()


@app.post("/scan", response_model=ScanResponse)
@limiter.limit("30/hour")
@limiter.limit("10/minute")
def scan(req: ScanRequest, request: Request):
    if req.repo_url:
        # Only public HTTPS GitHub repositories are supported.
        url = req.repo_url.strip()
        if not re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?/?", url):
            raise HTTPException(
                status_code=400,
                detail="Only HTTPS GitHub URLs are accepted (e.g. https://github.com/owner/repo)."
            )
        try:
            target = load_repo(url)
        except RepoLoadError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from None

    elif req.local_path:
        if os.getenv("ALLOW_LOCAL_PATH") != "1":
            raise HTTPException(
                status_code=400,
                detail="Local path scanning is disabled on this server. Use a GitHub repo URL.",
            )
        # Sanitize local path — guard against path traversal
        raw = req.local_path.strip()

        # Block obvious traversal attempts
        if ".." in raw or raw.startswith("//") or "~" in raw:
            raise HTTPException(status_code=400, detail="Invalid path.")

        target = Path(raw)

        if not target.exists():
            raise HTTPException(status_code=400, detail="Local folder not found.")
        if not target.is_dir():
            raise HTTPException(status_code=400, detail="The selected local path is not a folder.")

        # Path traversal / safe root check
        if not _is_safe_path(target):
            raise HTTPException(
                status_code=403,
                detail="Access denied. Scanning that path is not permitted."
            )
    else:
        current_stats = load_stats()
        return ScanResponse(
            findings=[],
            summary_report="Provide repo_url or local_path.",
            total=0,
            critical_count=0,
            stats=current_stats,
        )

    try:
        file_count = get_scanned_file_count(target, include_fixtures=req.include_fixtures)
        skipped_files = 0 if req.include_fixtures else get_skipped_file_count(target)
    except Exception:
        if req.repo_url:
            shutil.rmtree(target, ignore_errors=True)
        raise HTTPException(status_code=500, detail="Couldn't inspect the repository.") from None
    if file_count == 0:
        if skipped_files:
            if req.repo_url:
                shutil.rmtree(target, ignore_errors=True)
            return ScanResponse(
                findings=[],
                summary_report=f"All {skipped_files} scannable files were excluded as test or sample code. Enable ‘Include test and sample code’ to scan them.",
                total=0,
                critical_count=0,
                skipped_files=skipped_files,
                stats=load_stats(),
            )
        if req.repo_url:
            shutil.rmtree(target, ignore_errors=True)
        raise HTTPException(
            status_code=400,
            detail=(
                "No scannable files found. Secrets/config scanning covers Python, JS/TS/JSX, "
                "Vue, HTML, Java, Go, Ruby, PHP, C#, plus config files. Full detection (auth, "
                "injection, XSS) is Python/JS/TS/JSX only. This repo may use an unsupported stack."
            )
        )

    try:
        findings = run_full_scan(target, include_fixtures=req.include_fixtures)
        findings = _sanitize_finding_paths(findings, target)
    except Exception as e:
        if req.repo_url:
            shutil.rmtree(target, ignore_errors=True)
        raise HTTPException(status_code=500, detail="Scan failed. Please try again.")

    try:
        report = generate_report(findings)
    finally:
        if req.repo_url:
            shutil.rmtree(target, ignore_errors=True)

    findings_out = [
        FindingOut(
            category=f.category, file_path=f.file_path, line_number=f.line_number,
            evidence=f.evidence,
            severity=f.severity.value if hasattr(f.severity, "value") else f.severity,
            confidence=f.confidence, description=f.description, recommended_fix=f.recommended_fix,
        )
        for f in findings
    ]
    critical = sum(1 for f in findings_out if f.severity == "CRITICAL")
    try:
        updated_stats = record_scan_stats(len(findings_out))
    except Exception:
        # Counter storage is best-effort and must not turn a completed scan into
        # an API failure.
        updated_stats = {**DEFAULT_STATS, "stats_backend": "local"}

    return ScanResponse(
        findings=findings_out,
        summary_report=report,
        total=len(findings_out),
        critical_count=critical,
        skipped_files=skipped_files,
        stats=updated_stats,
    )


@app.get("/health")
@limiter.exempt
def health():
    return {"status": "ok"}


@app.get("/")
def root():
    return {"status": "ShieldStack API running", "stats": load_stats()}


@app.post("/feedback")
@limiter.limit("20/hour")
@limiter.limit("5/minute")
def submit_feedback(fb: FeedbackIn, request: Request):
    if not fb.message or not fb.message.strip():
        raise HTTPException(status_code=400, detail="Feedback message can't be empty.")
    save_feedback(fb)
    return {"status": "received"}
