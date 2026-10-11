"""Small privacy-conscious append-only audit log for security actions."""

import json
import os
import re
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path

AUDIT_PATH = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "LunaGuard" / "audit.jsonl"
MAX_BYTES = 2 * 1024 * 1024
_LOCK = threading.Lock()
_ALLOWED = {"scan_id", "quarantine_id", "result", "error_category", "component_version",
            "files_scanned", "files_analyzed", "files_skipped", "issues"}
_SAFE = re.compile(r"[^\r\n\x00-\x1f]{0,200}\Z")


def record(action: str, **fields) -> None:
    """Record a fixed event category and only allowlisted, bounded metadata."""
    if not isinstance(action, str) or not re.fullmatch(r"[a-z][a-z0-9_.-]{0,63}", action):
        raise ValueError("invalid audit action")
    event = {"timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"), "action": action}
    for key, value in fields.items():
        if key in _ALLOWED and isinstance(value, str) and _SAFE.fullmatch(value):
            event[key] = value
    payload = (json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    with _LOCK:
        AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        try:
            if AUDIT_PATH.exists() and AUDIT_PATH.stat().st_size + len(payload) > MAX_BYTES:
                old = AUDIT_PATH.with_suffix(".1.jsonl")
                try:
                    old.unlink(missing_ok=True)
                except OSError:
                    pass
                os.replace(AUDIT_PATH, old)
            with AUDIT_PATH.open("ab") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        except OSError:
            # Audit failure is surfaced to the caller; it must not be hidden.
            raise


def read_recent(limit: int = 100) -> list[dict]:
    if not isinstance(limit, int) or not 1 <= limit <= 500:
        raise ValueError("invalid audit read limit")
    if not AUDIT_PATH.exists():
        return []
    try:
        rows = AUDIT_PATH.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return []
    result = []
    for row in rows[-limit:]:
        try:
            event = json.loads(row)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict) and isinstance(event.get("action"), str):
            result.append(event)
    return result
