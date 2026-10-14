import os
import json
import time
from pathlib import Path
from google import genai
from google.genai import types
from dotenv import load_dotenv

# Load this project's local settings regardless of the server's working directory.
# Preserve a non-empty environment value supplied by the host.
load_dotenv(
    dotenv_path=Path(__file__).resolve().parents[2] / ".env",
    override=not bool(os.environ.get("GEMINI_API_KEY")),
    encoding="utf-8-sig",
)

MODEL = os.environ.get("GEMINI_MODEL") or "gemini-3.5-flash-lite"
FALLBACK_MODELS = ("gemini-3.8-flash",)
RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}
MODEL_ATTEMPTS = 3

def _client():
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return None
    # Keep SDK-level retries off so the bounded retry loop below controls total wait time.
    return genai.Client(
        api_key=api_key,
        http_options=types.HttpOptions(
            retry_options=types.HttpRetryOptions(attempts=1),
        ),
    )


def _http_status_code(error: Exception) -> int | None:
    status = getattr(error, "code", None)
    if status is None:
        status = getattr(error, "status_code", None)
    if status is None:
        status = getattr(getattr(error, "response", None), "status_code", None)
    try:
        return int(status) if status is not None else None
    except (TypeError, ValueError):
        return None


def _generate_with_fallback(call_model, models=None, sleep_fn=time.sleep):
    """Call models in order, retrying transient failures with bounded backoff."""
    model_names = models or (MODEL, *FALLBACK_MODELS)
    last_error = None

    for model in dict.fromkeys(model_names):
        for attempt in range(MODEL_ATTEMPTS):
            try:
                return call_model(model)
            except Exception as error:
                last_error = error
                if _http_status_code(error) not in RETRYABLE_STATUS_CODES:
                    break
                sleep_fn(2 ** attempt)

    if last_error is not None:
        raise last_error
    raise RuntimeError("No Gemini models were configured.")

def _findings_to_summary(findings) -> str:
    """Compact structured summary — this is what the LLM actually sees, not raw code."""
    lines = []
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else f.severity
        lines.append(
            f"- [{sev}] {f.category} in {f.file_path}:{f.line_number} "
            f"(confidence {f.confidence:.0%}): {f.description}"
        )
    return "\n".join(lines)

SYSTEM_PROMPT = """You are a security report writer for ShieldStack, a tool that scans \
AI-generated code for common vulnerability patterns. You are given a list of POTENTIAL \
findings from deterministic static analysis — you do not decide whether something is a real \
vulnerability. Static analysis has not independently verified or exploited these issues. Your \
job is to describe the evidence and remediation:
1. Write a short executive summary (2-4 sentences) of the overall risk picture
2. Group related findings if they form a single attack chain (e.g. a client-side check + the \
   backend route it fails to protect are one story, not two)
3. Rank what to fix first, briefly explaining why it's urgent
4. For EVERY group or standalone finding in the remediation ranking, explicitly restate the \
   concrete fix action — not just why it matters, but what to actually do. Never leave a \
   remediation-priority entry with only a reason and no action; each one needs both.
5. Keep the tone factual and specific — no hype, no vague "this could be bad" language

Do not invent findings that are not in the input. Do not change severity or confidence levels. \
Describe results as potential or likely, never as confirmed vulnerabilities. Do not call the \
scanned repository "ShieldStack"; ShieldStack is the scanner, and the repository is the scan \
target. Mention confidence levels where relevant. \
Output plain text, not markdown headers. Format each remediation-priority entry as:
"Priority N: <what it is>
Why it matters: <urgency reasoning>
Fix: <concrete action to take>\""""

def generate_report(findings) -> str:
    if not findings:
        return "No issues found."

    client = _client()
    if client is None:
        return _fallback_report(findings)

    summary_input = _findings_to_summary(findings)
    try:
        return _generate_with_fallback(
            lambda model: client.models.generate_content(
                model=model,
                contents=f"{SYSTEM_PROMPT}\n\nFindings:\n{summary_input}",
            ).text,
        )
    except Exception as e:
        # Avoid returning provider exception text, which can contain request data.
        status_code = _http_status_code(e)
        if status_code is not None:
            error = f"Gemini request failed (HTTP {status_code})"
        else:
            error = f"Gemini request failed ({type(e).__name__})"
        return _fallback_report(findings, error=error)

def _fallback_report(findings, error: str = None) -> str:
    """Used when no API key is set, or the API call fails — report generation should
    never crash the whole scan just because the LLM layer is unavailable."""
    header = "[LLM synthesis unavailable"
    header += f": {error}]" if error else " — no GEMINI_API_KEY set]"
    critical = [f for f in findings if str(f.severity.value if hasattr(f.severity, 'value') else f.severity) == "CRITICAL"]
    return (
        f"{header}\n\n"
        f"{len(findings)} finding(s) total, {len(critical)} CRITICAL.\n"
        f"Highest-priority: {critical[0].category if critical else findings[0].category}\n"
        "Fall back to the detailed findings list below for full detail."
    )
