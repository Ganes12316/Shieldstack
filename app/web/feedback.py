import json
import re
from pathlib import Path
from datetime import datetime, timezone
from pydantic import BaseModel, field_validator

PROJECT_ROOT = Path(__file__).resolve().parents[2]
FEEDBACK_PATH = PROJECT_ROOT / "data" / "feedback.json"

# Basic email regex — not exhaustive but blocks garbage
_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")

ALLOWED_CATEGORIES = {"bug", "feature", "general"}

class FeedbackIn(BaseModel):
    message: str
    email: str | None = None
    category: str = "general"

    @field_validator("message")
    @classmethod
    def message_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Message cannot be empty.")
        return v[:2000]  # Hard cap

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()[:200]
        if v and not _EMAIL_RE.match(v):
            raise ValueError("Invalid email address format.")
        return v or None

    @field_validator("category")
    @classmethod
    def validate_category(cls, v: str) -> str:
        if v not in ALLOWED_CATEGORIES:
            return "general"
        return v


def _load() -> list[dict]:
    if not FEEDBACK_PATH.exists():
        return []
    try:
        entries = json.loads(FEEDBACK_PATH.read_text(encoding="utf-8"))
        return entries if isinstance(entries, list) else []
    except Exception:
        return []


def save_feedback(fb: FeedbackIn) -> dict:
    FEEDBACK_PATH.parent.mkdir(parents=True, exist_ok=True)
    entries = _load()
    entry = {
        "message": fb.message,   # Already stripped + capped by validator
        # Don't store email in plaintext — store a presence flag only
        "has_email": fb.email is not None,
        "category": fb.category,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    entries.append(entry)
    FEEDBACK_PATH.write_text(json.dumps(entries, indent=2), encoding="utf-8")
    return entry
