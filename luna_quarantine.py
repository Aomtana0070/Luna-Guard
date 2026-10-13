"""Crash-aware, integrity-checked quarantine operations for Luna Guard.

The JSON index remains compatible with the original desktop format. Each state
transition is written atomically so interrupted moves can be identified rather
than mistaken for an empty quarantine.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

_INDEX_LOCK = threading.RLock()
_ID_RE = re.compile(r"(?:[0-9a-f]{32}|[0-9]{14}_[0-9a-f]{8})\Z", re.I)
_SHA_RE = re.compile(r"[0-9a-f]{64}\Z", re.I)
_CHUNK = 1024 * 1024


def valid_id(value: object) -> bool:
    return isinstance(value, str) and bool(_ID_RE.fullmatch(value))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_index(index_path: Path) -> dict:
    try:
        raw = index_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}
    except OSError as error:
        raise RuntimeError(f"อ่าน quarantine index ไม่สำเร็จ: {error}") from error
    try:
        index = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"quarantine index เสียหาย: {error}") from error
    if not isinstance(index, dict):
        raise RuntimeError("quarantine index ต้องเป็น JSON object")
    for item_id, entry in index.items():
        if not valid_id(item_id) or not isinstance(entry, dict):
            raise RuntimeError("quarantine index มีรายการที่ไม่ถูกต้อง")
        original = entry.get("original")
        if (not isinstance(original, str) or not original or len(original) > 32768
                or any(ord(char) < 32 for char in original)):
            raise RuntimeError(f"quarantine metadata ไม่ครบ: {item_id}")
        if not _SHA_RE.fullmatch(str(entry.get("sha256", ""))):
            raise RuntimeError(f"quarantine SHA-256 ไม่ถูกต้อง: {item_id}")
        reasons = entry.get("why", [])
        if (not isinstance(reasons, (str, list)) or
                (isinstance(reasons, list) and (len(reasons) > 20 or
                 any(not isinstance(reason, str) or len(reason) > 1000 for reason in reasons))) or
                (isinstance(reasons, str) and len(reasons) > 1000)):
            raise RuntimeError(f"quarantine reasons ไม่ถูกต้อง: {item_id}")
        status = entry.get("status", "committed")
        if not isinstance(status, str) or status not in {"pending", "verified", "committed", "restoring", "deleting", "recovery_required"}:
            raise RuntimeError(f"quarantine status ไม่ถูกต้อง: {item_id}")
        if isinstance(reasons, str):
            entry["why"] = [reasons]
        if "recovery_reason" in entry and (not isinstance(entry["recovery_reason"], str)
                                             or len(entry["recovery_reason"]) > 500):
            raise RuntimeError(f"quarantine recovery metadata ไม่ถูกต้อง: {item_id}")
    return index


def _atomic_write_index(index_path: Path, index: dict) -> None:
    index_path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".index-", suffix=".tmp", dir=index_path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(index, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, index_path)
        if os.name != "nt":
            dir_fd = os.open(index_path.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
    except Exception:
        try:
            Path(temp_name).unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _entry_path(quarantine_dir: Path, item_id: str, field: str = "") -> Path:
    if not valid_id(item_id):
        raise ValueError("quarantine ID ไม่ถูกต้อง")
    suffix = ".quar" if field != "temporary" else ".part"
    if field == "temporary":
        return quarantine_dir / f".{item_id}{suffix}"
    return quarantine_dir / f"{item_id}{suffix}"


def _regular_file(path: Path, label: str) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as error:
        raise RuntimeError(f"อ่าน {label} ไม่ได้: {error}") from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RuntimeError(f"{label} ต้องเป็นไฟล์ปกติและไม่ใช่ symlink")
    return info


def _copy_and_hash(source: Path, destination: Path) -> str:
    digest = hashlib.sha256()
    with source.open("rb") as src, destination.open("xb") as dst:
        while chunk := src.read(_CHUNK):
            dst.write(chunk)
            digest.update(chunk)
        dst.flush()
        os.fsync(dst.fileno())
    return digest.hexdigest()


def _record_recovery(index_path: Path, index: dict, item_id: str, message: str) -> None:
    entry = index[item_id]
    entry["status"] = "recovery_required"
    entry["recovery_reason"] = message[:500]
    entry["updated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    _atomic_write_index(index_path, index)


def quarantine_file(source_path: str | Path, expected_sha256: str, why,
                    quarantine_dir: Path, index_path: Path) -> str:
    source = Path(source_path)
    expected = str(expected_sha256).lower()
    if not _SHA_RE.fullmatch(expected):
        raise ValueError("expected SHA-256 is invalid")
    source_info = _regular_file(source, "source")
    if _sha256(source) != expected:
        raise RuntimeError("ไฟล์ต้นทางเปลี่ยนไปหลังการสแกน จึงไม่กักกัน")

    quarantine_dir.mkdir(parents=True, exist_ok=True)
    item_id = uuid.uuid4().hex
    temporary = _entry_path(quarantine_dir, item_id, "temporary")
    quarantined = _entry_path(quarantine_dir, item_id)
    with _INDEX_LOCK:
        index = load_index(index_path)
        raw_reasons = why if isinstance(why, list) else [why]
        reasons = [re.sub(r"[\x00-\x1f\x7f]", " ", str(reason))[:1000] for reason in raw_reasons[:20]]
        entry = {
            "original": str(source.resolve()),
            "sha256": expected,
            "why": reasons,
            "status": "pending",
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "temporary": temporary.name,
        }
        index[item_id] = entry
        _atomic_write_index(index_path, index)
        try:
            copied_hash = _copy_and_hash(source, temporary)
            if copied_hash != expected:
                raise RuntimeError("สำเนา quarantine มี SHA-256 ไม่ตรงกับไฟล์ที่สแกน")
            if _sha256(temporary) != expected:
                raise RuntimeError("ตรวจสอบ SHA-256 ของสำเนา quarantine ไม่ผ่าน")
            # A hard link makes the final name atomic and refuses to overwrite.
            os.link(temporary, quarantined)
            temporary.unlink()
            entry["status"] = "verified"
            entry.pop("temporary", None)
            entry["quarantine_name"] = quarantined.name
            entry["updated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
            _atomic_write_index(index_path, index)

            current_info = _regular_file(source, "source")
            if (current_info.st_dev, current_info.st_ino, current_info.st_size, current_info.st_mtime_ns) != (
                source_info.st_dev, source_info.st_ino, source_info.st_size, source_info.st_mtime_ns
            ) or _sha256(source) != expected:
                raise RuntimeError("ไฟล์ต้นทางเปลี่ยนระหว่างกักกัน จึงเก็บต้นฉบับไว้")
            source.unlink()
            entry["status"] = "committed"
            entry.pop("recovery_reason", None)
            entry["updated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
            _atomic_write_index(index_path, index)
            return item_id
        except Exception as error:
            # Keep all data and a durable explanation; startup recovery can decide safely.
            try:
                _record_recovery(index_path, index, item_id, str(error))
            except OSError:
                pass
            raise


def _safe_destination(destination: str | Path, quarantine_dir: Path) -> Path:
    requested = Path(destination)
    if not requested.is_absolute():
        raise ValueError("Restore destination must be an absolute path")
    parent = requested.parent.resolve(strict=True)
    if not parent.is_dir():
        raise ValueError("Restore parent directory is not available")
    resolved = parent / requested.name
    try:
        if os.path.commonpath((str(quarantine_dir.resolve()), str(resolved.resolve(strict=False)))) == str(quarantine_dir.resolve()):
            raise ValueError("Restore destination cannot be inside Quarantine")
    except ValueError as error:
        if "inside Quarantine" in str(error):
            raise
        # Different Windows drives cannot be within the same quarantine path.
    if os.path.lexists(resolved):
        raise FileExistsError(f"Restore destination already exists: {resolved}")
    return resolved


def restore_file(item_id: str, quarantine_dir: Path, index_path: Path,
                 destination: str | Path | None = None) -> Path:
    if not valid_id(item_id):
        raise ValueError("quarantine ID ไม่ถูกต้อง")
    with _INDEX_LOCK:
        index = load_index(index_path)
        entry = index.get(item_id)
        if not entry:
            raise KeyError("ไม่พบ quarantine ID นี้")
        state = entry.get("status", "committed")
        if state != "committed":
            raise RuntimeError(f"รายการ quarantine ต้องตรวจ recovery ก่อน (สถานะ {state})")
        if entry.get("quarantine_name", f"{item_id}.quar") != f"{item_id}.quar":
            raise RuntimeError("quarantine metadata ไม่ตรงกับชื่อไฟล์; ระงับ Restore")
        expected = entry["sha256"].lower()
        quarantined = _entry_path(quarantine_dir, item_id)
        _regular_file(quarantined, "quarantine file")
        if _sha256(quarantined) != expected:
            raise RuntimeError("SHA-256 ของไฟล์ใน Quarantine ไม่ตรง metadata; ระงับ Restore")
        requested = destination if destination is not None else entry["original"]
        target = _safe_destination(requested, quarantine_dir)
        temporary = target.parent / f".lunaguard-restore-{uuid.uuid4().hex}.tmp"
        original = Path(entry["original"])
        entry.update(status="restoring", restore_destination=str(target), updated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
        _atomic_write_index(index_path, index)
        try:
            if _copy_and_hash(quarantined, temporary) != expected:
                raise RuntimeError("สำเนาสำหรับ Restore มี SHA-256 ไม่ตรง")
            # Link creation is atomic and fails if another file appeared meanwhile.
            os.link(temporary, target)
            temporary.unlink()
            if _sha256(target) != expected:
                raise RuntimeError("Restore destination failed SHA-256 verification")
            quarantined.unlink()
            del index[item_id]
            _atomic_write_index(index_path, index)
            return target
        except Exception as error:
            entry["status"] = "recovery_required"
            entry["recovery_reason"] = str(error)[:500]
            entry["updated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
            try:
                _atomic_write_index(index_path, index)
            except OSError:
                pass
            raise


def recover_index(quarantine_dir: Path, index_path: Path) -> list[dict[str, str]]:
    """Reconcile safe, completed transitions; preserve ambiguous data for review."""
    actions = []
    with _INDEX_LOCK:
        index = load_index(index_path)
        changed = False
        for item_id, entry in list(index.items()):
            status = entry.get("status", "committed")
            qfile = _entry_path(quarantine_dir, item_id)
            source = Path(entry["original"])
            expected = entry["sha256"].lower()
            target_text = entry.get("restore_destination")
            try:
                q_ok = qfile.is_file() and not qfile.is_symlink() and _sha256(qfile) == expected
                source_exists = os.path.lexists(source)
                if status in ("verified", "recovery_required") and q_ok and not source_exists and not target_text:
                    entry["status"] = "committed"
                    entry.pop("recovery_reason", None)
                    changed = True
                    actions.append({"id": item_id, "result": "quarantine_committed"})
                elif status in ("pending", "verified") and source_exists and not target_text:
                    source_ok = source.is_file() and not source.is_symlink() and _sha256(source) == expected
                    if source_ok and (not qfile.exists() or q_ok):
                        if q_ok:
                            qfile.unlink()
                        partial = _entry_path(quarantine_dir, item_id, "temporary")
                        if partial.exists() and not partial.is_symlink() and partial.is_file():
                            partial.unlink()
                        del index[item_id]
                        changed = True
                        actions.append({"id": item_id, "result": "quarantine_rolled_back"})
                    else:
                        entry["status"] = "recovery_required"
                        entry["recovery_reason"] = "Quarantine recovery is ambiguous; retained files for review"
                        changed = True
                        actions.append({"id": item_id, "result": "review_required"})
                elif status == "deleting":
                    if not qfile.exists():
                        del index[item_id]
                        changed = True
                        actions.append({"id": item_id, "result": "delete_finalized"})
                    elif q_ok:
                        entry["status"] = "committed"
                        entry.pop("recovery_reason", None)
                        changed = True
                        actions.append({"id": item_id, "result": "delete_rolled_back"})
                    else:
                        entry["status"] = "recovery_required"
                        entry["recovery_reason"] = "Delete interrupted; integrity check failed"
                        changed = True
                        actions.append({"id": item_id, "result": "review_required"})
                elif status in ("restoring", "recovery_required") and target_text:
                    target = Path(target_text)
                    target_ok = target.is_file() and not target.is_symlink() and _sha256(target) == expected
                    if target_ok and not qfile.exists():
                        del index[item_id]
                        changed = True
                        actions.append({"id": item_id, "result": "restore_finalized"})
                    elif target_ok and q_ok:
                        qfile.unlink()
                        del index[item_id]
                        changed = True
                        actions.append({"id": item_id, "result": "restore_finalized"})
                    elif q_ok:
                        entry["status"] = "committed"
                        entry.pop("restore_destination", None)
                        entry.pop("recovery_reason", None)
                        changed = True
                        actions.append({"id": item_id, "result": "restore_rolled_back"})
                    else:
                        entry["status"] = "recovery_required"
                        entry["recovery_reason"] = "Restore interrupted; files retained for review"
                        changed = True
                        actions.append({"id": item_id, "result": "review_required"})
                elif status in ("pending", "verified", "restoring", "recovery_required"):
                    entry["status"] = "recovery_required"
                    entry.setdefault("recovery_reason", "Operation interrupted; files retained for review")
                    changed = True
                    actions.append({"id": item_id, "result": "review_required"})
            except OSError as error:
                entry["status"] = "recovery_required"
                entry["recovery_reason"] = f"Recovery check failed: {error}"[:500]
                changed = True
                actions.append({"id": item_id, "result": "review_required"})
        if changed:
            _atomic_write_index(index_path, index)
    return actions


def delete_file(item_id: str, quarantine_dir: Path, index_path: Path) -> None:
    """Permanently delete a verified quarantine entry; the caller must confirm."""
    if not valid_id(item_id):
        raise ValueError("quarantine ID ไม่ถูกต้อง")
    with _INDEX_LOCK:
        index = load_index(index_path)
        entry = index.get(item_id)
        if not entry:
            raise KeyError("ไม่พบ quarantine ID นี้")
        if entry.get("status", "committed") != "committed":
            raise RuntimeError("ลบถาวรได้เฉพาะรายการที่กักกันสมบูรณ์")
        quarantined = _entry_path(quarantine_dir, item_id)
        _regular_file(quarantined, "quarantine file")
        if _sha256(quarantined) != entry["sha256"].lower():
            raise RuntimeError("SHA-256 ของไฟล์ใน Quarantine ไม่ตรง metadata; ระงับการลบ")
        entry["status"] = "deleting"
        _atomic_write_index(index_path, index)
        quarantined.unlink()
        del index[item_id]
        _atomic_write_index(index_path, index)
