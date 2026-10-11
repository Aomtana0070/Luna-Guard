#!/usr/bin/env python3
"""
Luna Guard - ตัวตรวจจับและกำจัด XWorm + มัลแวร์ที่แฝงมากับกลโกง "MrBeast"
สำหรับ Windows (Python 3.10+, YARA เป็น optional dependency)

คำสั่ง:
  python luna_guard.py update              ดึงฐานข้อมูลภัยคุกคามล่าสุด (abuse.ch)
  python luna_guard.py scan                สแกนและรายงาน (ไม่แตะต้องไฟล์)
  python luna_guard.py scan --clean        สแกนแล้วกำจัดสิ่งที่เป็น HIGH (กักกันไฟล์, kill, ลบจุดฝังตัว)
  python luna_guard.py scan --full         สแกนทั้งไดรฟ์ C: (ช้า)
  python luna_guard.py quarantine          ดูรายการที่กักกันไว้
  python luna_guard.py restore <id>        กู้ไฟล์ที่กักกันกลับ
  python luna_guard.py add-hash <sha256>   เพิ่มแฮชของคุณเอง
  python luna_guard.py schedule            แสดงคำสั่งตั้งอัปเดตอัตโนมัติทุกวัน

คีย์ abuse.ch (ฟรี): สมัครที่ https://auth.abuse.ch แล้วตั้งผ่านปุ่ม "ตั้งค่าคีย์" ใน GUI
Settings จะใช้คีย์ที่บันทึกไว้ก่อน; ใช้ setx ABUSECH_KEY "คีย์ของคุณ" เป็นทางเลือกเมื่อไม่มีคีย์ใน Settings
"""
import argparse
from collections import Counter
import csv
import datetime as dt
import hashlib
import ipaddress
import io
import json
import math
import mimetypes
import os
import re
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time
import uuid
import urllib.parse
import urllib.error
import urllib.request
import zipfile
import zlib
from pathlib import Path
import luna_quarantine as lq
import luna_audit

try:
    import winreg  # Windows เท่านั้น
except ImportError:
    winreg = None
try:
    import pefile
except ImportError:
    pefile = None

IS_WIN = os.name == "nt"
APP_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "LunaGuard"
DB_PATH = APP_DIR / "threats.db"
QUAR_DIR = APP_DIR / "quarantine"
QUAR_INDEX = QUAR_DIR / "index.json"
ARCHIVE_EXT = {".zip", ".jar", ".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm", ".apk"}
MAX_ARCHIVE_MEMBERS = 10000
MAX_ARCHIVE_MEMBER_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_EXPANDED_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_NESTING_DEPTH = 8
MAX_ARCHIVE_SCAN_SECONDS = 180
MAX_ARCHIVE_COMPRESSION_RATIO = 1000
# Optional deep archive profile: broader bounds, no per-archive clock, and a
# free-space reserve for temporary extraction. These remain finite safeguards.
DEEP_ARCHIVE_MAX_MEMBERS = 100000
DEEP_ARCHIVE_MAX_MEMBER_BYTES = 1024 * 1024 * 1024
DEEP_ARCHIVE_MAX_EXPANDED_BYTES = 8 * 1024 * 1024 * 1024
DEEP_ARCHIVE_MAX_NESTING_DEPTH = 32
DEEP_ARCHIVE_MAX_COMPRESSION_RATIO = 5000
DEEP_ARCHIVE_MIN_FREE_BYTES = 1024 * 1024 * 1024
TAGS = ["XWorm", "MrBeast"]  # แท็กที่ดึงจาก MalwareBazaar / ThreatFox

# โดเมนหลอกลวงที่รู้จัก (เพิ่มเองได้ด้วยการแก้ลิสต์นี้)
SEED_DOMAINS = ["beastxm.com", "beast-days.com"]

SCRIPT_EXT = {".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js"}
SYSTEM_NAMES = {
    "csrss.exe", "svchost.exe", "lsass.exe", "winlogon.exe", "explorer.exe",
    "services.exe", "smss.exe", "taskhost.exe", "taskhostw.exe", "conhost.exe",
    "wininit.exe", "spoolsv.exe", "dllhost.exe", "runtimebroker.exe",
    "searchindexer.exe", "ctfmon.exe", "sipnotify.exe",
}
STRONG_PATTERNS = [rb"<xwormmm>", rb"xworm v", rb"xklog"]
WEAK_PATTERNS = [rb"xworm"]
PS_PATTERNS = [
    (r"downloadstring|downloadfile|invoke-webrequest|iwr\s|curl\s.*http", "ดาวน์โหลดจากเน็ตผ่าน PowerShell"),
    (r"\biex\b|invoke-expression", "รันโค้ดที่ดึงมา (IEX)"),
    (r"-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}", "คำสั่ง PowerShell เข้ารหัส base64"),
    (r"frombase64string", "ถอดรหัส base64 ในสคริปต์"),
    (r"mshta(\.exe)?\s+http", "mshta โหลดเพย์โหลดจากเว็บ (กลโกง CAPTCHA ปลอม)"),
    (r"i am not a robot|verify you are human|captcha", "ข้อความคล้าย CAPTCHA ปลอม"),
    (r"add-mppreference\s+-exclusion|set-mppreference\s+-disable", "พยายามปิด/ยกเว้น Defender"),
]
PATH_RE = re.compile(r'(?:[A-Za-z]:\\|/)[^"<>|*?\r\n]+?\.(?:exe|scr|bat|cmd|ps1|vbs|js|com|dll)', re.I)


# ---------------------------------------------------------------- ฐานข้อมูล
def db():
    APP_DIR.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.executescript("""
        CREATE TABLE IF NOT EXISTS hashes(sha256 TEXT PRIMARY KEY, family TEXT, source TEXT);
        CREATE TABLE IF NOT EXISTS malware_hashes(
            sha256 TEXT PRIMARY KEY, sha1 TEXT, md5 TEXT, family TEXT NOT NULL,
            threat_name TEXT NOT NULL, severity TEXT NOT NULL DEFAULT 'HIGH',
            first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, source TEXT NOT NULL,
            confidence INTEGER NOT NULL DEFAULT 100, reference TEXT
        );
        CREATE INDEX IF NOT EXISTS malware_hashes_sha1 ON malware_hashes(sha1);
        CREATE INDEX IF NOT EXISTS malware_hashes_md5 ON malware_hashes(md5);
        CREATE TABLE IF NOT EXISTS malware_hash_sources(
            sha256 TEXT NOT NULL, source TEXT NOT NULL, first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL, confidence INTEGER NOT NULL DEFAULT 50, reference TEXT,
            PRIMARY KEY(sha256,source)
        );
        CREATE TABLE IF NOT EXISTS threat_iocs(
            kind TEXT NOT NULL, value TEXT NOT NULL, source TEXT NOT NULL,
            family TEXT NOT NULL DEFAULT 'unknown', threat_name TEXT NOT NULL DEFAULT 'unknown',
            confidence INTEGER NOT NULL DEFAULT 50, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
            expires_at TEXT, state TEXT NOT NULL DEFAULT 'active', reference TEXT,
            PRIMARY KEY(kind,value,source)
        );
        CREATE INDEX IF NOT EXISTS threat_iocs_lookup ON threat_iocs(kind,value,state);
        CREATE TABLE IF NOT EXISTS iocs(value TEXT PRIMARY KEY, kind TEXT, family TEXT, source TEXT);
        CREATE TABLE IF NOT EXISTS ioc_lifecycle(
            value TEXT PRIMARY KEY, state TEXT NOT NULL DEFAULT 'active',
            first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, expires_at TEXT,
            confidence INTEGER, reference TEXT, FOREIGN KEY(value) REFERENCES iocs(value) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
        CREATE TABLE IF NOT EXISTS allow(sha256 TEXT PRIMARY KEY, path TEXT);
    """)
    now = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    for d in SEED_DOMAINS:
        con.execute("INSERT OR IGNORE INTO iocs VALUES(?,?,?,?)", (d, "domain", "MrBeast-scam", "seed"))
    # Backfill old installations without changing their IOC table or contents.
    con.execute("""INSERT OR IGNORE INTO ioc_lifecycle(value,state,first_seen,last_seen,expires_at)
        SELECT value,CASE WHEN source='seed' THEN 'active' ELSE 'expired' END,?,?,
        CASE WHEN source='seed' THEN NULL ELSE '2000-01-01T00:00:00+00:00' END FROM iocs""", (now, now))
    con.execute("UPDATE ioc_lifecycle SET state='expired' WHERE state='active' AND expires_at IS NOT NULL AND expires_at<=?", (now,))
    # Preserve each IOC source independently and migrate prior single-source rows.
    con.execute("""INSERT OR IGNORE INTO threat_iocs
        (kind,value,source,family,threat_name,confidence,first_seen,last_seen,expires_at,state,reference)
        SELECT i.kind,i.value,i.source,i.family,i.family,COALESCE(l.confidence,50),
        l.first_seen,l.last_seen,l.expires_at,l.state,l.reference
        FROM iocs i JOIN ioc_lifecycle l ON l.value=i.value""")
    con.execute("UPDATE threat_iocs SET state='stale' WHERE state='active' AND expires_at IS NOT NULL AND expires_at<=?", (now,))
    stale_cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=30)).isoformat(timespec="seconds")
    con.execute("UPDATE threat_iocs SET state='expired' WHERE state='stale' AND expires_at IS NOT NULL AND expires_at<=?", (stale_cutoff,))
    # Preserve historical SHA-256 entries and make them queryable through the richer schema.
    con.execute("""INSERT OR IGNORE INTO malware_hashes
        (sha256,sha1,md5,family,threat_name,severity,first_seen,last_seen,source,confidence)
        SELECT sha256,NULL,NULL,COALESCE(NULLIF(family,''),'unknown'),
        COALESCE(NULLIF(family,''),'unknown'),'HIGH',?,?,COALESCE(NULLIF(source,''),'legacy'),100
        FROM hashes""", (now, now))
    con.execute("""INSERT OR IGNORE INTO malware_hash_sources
        (sha256,source,first_seen,last_seen,confidence)
        SELECT sha256,COALESCE(NULLIF(source,''),'legacy'),?, ?,100 FROM hashes""", (now, now))
    con.commit()
    return con


def _feed_time(value, fallback=None):
    if not value:
        return fallback or dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    try:
        parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed.astimezone(dt.timezone.utc).isoformat(timespec="seconds")
    except (TypeError, ValueError, OverflowError):
        return fallback or dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def record_malware_hash(con, *, sha256=None, sha1=None, md5=None, family="unknown",
                        threat_name=None, severity="HIGH", first_seen=None, last_seen=None,
                        source="unknown", confidence=100, reference=None):
    """Store known-malicious file digests with provenance while maintaining the legacy table."""
    values = {"sha256": sha256, "sha1": sha1, "md5": md5}
    lengths = {"sha256": 64, "sha1": 40, "md5": 32}
    for name, value in list(values.items()):
        if value is not None:
            value = str(value).strip().lower()
            if not re.fullmatch(rf"[0-9a-f]{{{lengths[name]}}}", value):
                values[name] = None
            else:
                values[name] = value
    if not any(values.values()):
        return False
    now = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    first = _feed_time(first_seen, now)
    last = _feed_time(last_seen, first)
    family = str(family or "unknown")[:100]
    threat_name = str(threat_name or family)[:160]
    source = str(source or "unknown")[:160]
    try:
        confidence = max(0, min(100, int(confidence)))
    except (TypeError, ValueError):
        confidence = 50
    severity = str(severity or "HIGH").upper()
    if severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"}:
        severity = "HIGH"
    if values["sha256"]:
        con.execute("""INSERT INTO malware_hashes
            (sha256,sha1,md5,family,threat_name,severity,first_seen,last_seen,source,confidence,reference)
            VALUES(?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(sha256) DO UPDATE SET
              sha1=COALESCE(excluded.sha1,malware_hashes.sha1),
              md5=COALESCE(excluded.md5,malware_hashes.md5),
              family=CASE WHEN excluded.family='unknown' THEN malware_hashes.family ELSE excluded.family END,
              threat_name=CASE WHEN excluded.threat_name='unknown' THEN malware_hashes.threat_name ELSE excluded.threat_name END,
              severity=CASE WHEN excluded.severity='UNKNOWN' THEN malware_hashes.severity ELSE excluded.severity END,
              first_seen=MIN(malware_hashes.first_seen,excluded.first_seen),
              last_seen=MAX(malware_hashes.last_seen,excluded.last_seen),
              confidence=MAX(malware_hashes.confidence,excluded.confidence),
              reference=COALESCE(excluded.reference,malware_hashes.reference)""",
                    (values["sha256"], values["sha1"], values["md5"], family, threat_name,
                     severity, first, last, source, confidence,
                     str(reference)[:2048] if reference else None))
        con.execute("""INSERT INTO malware_hash_sources(sha256,source,first_seen,last_seen,confidence,reference)
            VALUES(?,?,?,?,?,?) ON CONFLICT(sha256,source) DO UPDATE SET
            first_seen=MIN(first_seen,excluded.first_seen),last_seen=MAX(last_seen,excluded.last_seen),
            confidence=MAX(confidence,excluded.confidence),reference=COALESCE(excluded.reference,reference)""",
            (values["sha256"], source, first, last, confidence,
             str(reference)[:2048] if reference else None))
        con.execute("INSERT OR IGNORE INTO hashes VALUES(?,?,?)", (values["sha256"], family, source))
    if values["sha1"] or values["md5"]:
        for algorithm in ("sha1", "md5"):
            digest = values[algorithm]
            if digest:
                con.execute("""INSERT INTO threat_iocs
                    (kind,value,source,family,threat_name,confidence,first_seen,last_seen,state,reference)
                    VALUES(?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(kind,value,source) DO UPDATE SET last_seen=MAX(last_seen,excluded.last_seen),
                    confidence=MAX(confidence,excluded.confidence), reference=COALESCE(excluded.reference,reference)""",
                    (algorithm, digest, source, family, threat_name, confidence, first, last,
                     "active", str(reference)[:2048] if reference else None))
    return True


def record_threat_ioc(con, kind, value, source, *, family="unknown", threat_name=None,
                      confidence=50, first_seen=None, last_seen=None, expires_at=None,
                      reference=None):
    now = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    first, last = _feed_time(first_seen, now), _feed_time(last_seen, now)
    expires = _feed_time(expires_at) if expires_at else None
    if not expires or expires > now:
        state = "active"
    elif dt.datetime.fromisoformat(expires) > dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=30):
        state = "stale"
    else:
        state = "expired"
    try:
        confidence = max(0, min(100, int(confidence)))
    except (TypeError, ValueError):
        confidence = 50
    con.execute("""INSERT INTO threat_iocs
        (kind,value,source,family,threat_name,confidence,first_seen,last_seen,expires_at,state,reference)
        VALUES(?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(kind,value,source) DO UPDATE SET
          family=excluded.family,threat_name=excluded.threat_name,
          confidence=MAX(threat_iocs.confidence,excluded.confidence),
          first_seen=MIN(threat_iocs.first_seen,excluded.first_seen),
          last_seen=MAX(threat_iocs.last_seen,excluded.last_seen),
          expires_at=excluded.expires_at,state=excluded.state,
          reference=COALESCE(excluded.reference,threat_iocs.reference)""",
        (kind, value, str(source)[:160], str(family or "unknown")[:100],
         str(threat_name or family or "unknown")[:160], confidence,
         first, last, expires, state, str(reference)[:2048] if reference else None))


def record_ioc(con, value, kind, family, source, *, last_seen=None, expires_at=None,
               confidence=None, reference=None):
    """Upsert an IOC and its lifecycle metadata; return True when newly added."""
    existed = con.execute("SELECT 1 FROM iocs WHERE value=?", (value,)).fetchone() is not None
    con.execute("INSERT OR REPLACE INTO iocs(value,kind,family,source) VALUES(?,?,?,?)",
                (value, kind, family, source))
    now = dt.datetime.now(dt.timezone.utc)
    seen = last_seen or now.isoformat(timespec="seconds")
    old = con.execute("SELECT first_seen FROM ioc_lifecycle WHERE value=?", (value,)).fetchone()
    first_seen = old[0] if old else seen
    expiry = expires_at
    state = "expired" if expiry and expiry <= now.isoformat(timespec="seconds") else "active"
    con.execute("""INSERT OR REPLACE INTO ioc_lifecycle
        (value,state,first_seen,last_seen,expires_at,confidence,reference)
        VALUES(?,?,?,?,?,?,?)""",
        (value, state, first_seen, seen, expiry,
         confidence if isinstance(confidence, int) else None,
         str(reference)[:2048] if reference else None))
    record_threat_ioc(con, kind, value, source, family=family,
        confidence=confidence if confidence is not None else 50,
        first_seen=seen, last_seen=seen, expires_at=expires_at, reference=reference)
    return not existed


def ioc_is_active(con, value, kind):
    now = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    con.execute("UPDATE ioc_lifecycle SET state='expired' WHERE value=? AND state='active' AND expires_at IS NOT NULL AND expires_at<=?", (value, now))
    return con.execute("""SELECT 1 FROM iocs i JOIN ioc_lifecycle l ON l.value=i.value
        WHERE i.value=? AND i.kind=? AND l.state='active'
        AND (l.expires_at IS NULL OR l.expires_at>?)""", (value, kind, now)).fetchone() is not None


def http(url, data=None, headers=None, timeout=90):
    req = urllib.request.Request(url, data=data, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


CONFIG = APP_DIR / "config.json"
HISTORY = APP_DIR / "history.json"
LAST_SCAN = {}
PROGRESS = {}
STOP = {"flag": False}
SCAN_AUDIT = {}


def scan_issue(message):
    SCAN_AUDIT["issues"] = SCAN_AUDIT.get("issues", 0) + 1
    details = SCAN_AUDIT.setdefault("details", [])
    if len(details) < 20:
        details.append(message)
        print(f"[!] {message}")
    elif len(details) == 20:
        details.append("additional scan warnings omitted")
        print("[!] มีคำเตือนการสแกนเพิ่มเติม; ดูจำนวนในสรุปผล")
SKIP_DIRS = {"cache", "code cache", "gpucache", "node_modules", ".git", "__pycache__", "$recycle.bin",
             "system volume information", "indexeddb", "service worker", "cache_data"}


def get_key():
    """Prefer the key saved in Settings; use ABUSECH_KEY only when no saved key exists."""
    try:
        saved = json.loads(CONFIG.read_text(encoding="utf-8")).get("abusech_key", "").strip()
        if saved:
            return saved
    except (OSError, ValueError, TypeError, AttributeError):
        pass
    return os.environ.get("ABUSECH_KEY", "").strip()


def save_key(k):
    if not isinstance(k, str) or len(k) > 512 or any(ord(char) < 32 for char in k):
        raise ValueError("API key has an invalid format")
    APP_DIR.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix="config-", suffix=".tmp", dir=APP_DIR)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump({"abusech_key": k.strip()}, stream, ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name != "nt":
            os.chmod(temp_name, 0o600)
        Path(temp_name).replace(CONFIG)
    finally:
        Path(temp_name).unlink(missing_ok=True)


_YARA = {"rules": None, "tried": False}


def yara_rules():
    """โหลดกฎ YARA จาก *.yar ข้างโปรแกรม และจากโฟลเดอร์ %LOCALAPPDATA%\\LunaGuard\\rules (ใส่กฎชุมชนเพิ่มได้)"""
    if _YARA["tried"]:
        return _YARA["rules"]
    _YARA["tried"] = True
    try:
        import yara
    except ImportError:
        return None
    files = {}
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    for f in sorted(base.glob("*.yar")):
        files[f"root_{f.stem}"] = str(f)
    for d in (base / "rules", APP_DIR / "rules"):
        if d.is_dir():
            for f in sorted(d.rglob("*.yar")):
                files[f"{d.name}_{f.parent.name}_{f.stem}_{len(files)}"] = str(f)
    if not files:
        return None
    try:
        _YARA["rules"] = yara.compile(filepaths=files)
    except Exception as e:
        print(f"[!] คอมไพล์กฎ YARA ไม่ผ่าน: {e}")
    return _YARA["rules"]


def yara_scan_file(path):
    r = yara_rules()
    if not r:
        return []
    try:
        return [{"rule": m.rule, "severity": str(m.meta.get("severity", "high")).lower(),
                 "family": m.meta.get("family", "unknown"),
                 "category": m.meta.get("category", "unknown"),
                 "threat_name": m.meta.get("threat_name", m.rule),
                 "confidence": _safe_confidence(m.meta.get("confidence", 50)),
                 "author": m.meta.get("author", "Unknown"),
                 "description": m.meta.get("description", "No description supplied"),
                 "source": m.meta.get("source", "Unknown; review required"),
                 "reference": m.meta.get("reference", "No external reference"),
                 "license": m.meta.get("license", "Unspecified; review before redistribution"),
                 "rule_version": m.meta.get("rule_version", "unspecified"),
                 "reviewed": m.meta.get("reviewed", "not independently reviewed"),
                 "false_positive_notes": m.meta.get("false_positive_notes", "Not documented")}
                for m in r.match(filepath=path, timeout=30)]
    except Exception as e:
        scan_issue(f"YARA ตรวจไฟล์ไม่สำเร็จ {path}: {e}")
        return []


def _safe_confidence(value):
    try:
        return max(0, min(100, int(value)))
    except (TypeError, ValueError):
        return 50


def yara_scan_process(pid):
    r = yara_rules()
    if not r:
        return []
    return r.match(pid=pid, timeout=10)


def norm_ioc(ioc, kind):
    if not isinstance(ioc, str):
        return "", ""
    ioc = ioc.strip().lower()
    if kind == "ip:port":
        host = ioc.rsplit(":", 1)[0].strip("[]")
        try:
            return ipaddress.ip_address(host).compressed, "ip"
        except ValueError:
            return "", ""
    if kind == "url":
        try:
            ioc = urllib.parse.urlparse(ioc).hostname or ""
        except ValueError:
            return "", ""
    if kind not in ("", "ip", "domain", "url"):
        return "", ""
    try:
        return ipaddress.ip_address(ioc).compressed, "ip"
    except ValueError:
        pass
    ioc = ioc.rstrip(".")
    if len(ioc) > 253 or not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", ioc):
        return "", ""
    return ioc, "domain"


def normalize_threat_ioc(value, kind):
    """Normalize supported ThreatFox types while retaining source-specific URL/name IOCs."""
    if not isinstance(value, str) or not value.strip() or any(ord(c) < 32 for c in value):
        return None
    value, raw_kind = value.strip(), str(kind or "").strip().lower().replace("-", "_")
    aliases = {
        "ip": "ip", "ipv4": "ip", "ipv6": "ip", "ip:port": "ip:port",
        "domain": "domain", "url": "url", "sha256": "sha256", "sha256_hash": "sha256",
        "sha1": "sha1", "sha1_hash": "sha1", "md5": "md5", "md5_hash": "md5",
        "filename": "filename", "file_name": "filename",
    }
    normalized_kind = aliases.get(raw_kind)
    if not normalized_kind:
        return None
    value = value.strip().lower()
    if normalized_kind in ("sha256", "sha1", "md5"):
        length = {"sha256": 64, "sha1": 40, "md5": 32}[normalized_kind]
        return (normalized_kind, value) if re.fullmatch(rf"[0-9a-f]{{{length}}}", value) else None
    if normalized_kind in ("ip", "ip:port"):
        normalized_value, actual_kind = norm_ioc(value, normalized_kind)
        return (actual_kind, normalized_value) if normalized_value else None
    if normalized_kind == "domain":
        normalized_value, actual_kind = norm_ioc(value, "domain")
        return (actual_kind, normalized_value) if normalized_value else None
    if normalized_kind == "url":
        try:
            parsed = urllib.parse.urlsplit(value)
            if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
                return None
            host = parsed.hostname.encode("idna").decode("ascii").lower()
            port = f":{parsed.port}" if parsed.port else ""
            path = urllib.parse.quote(urllib.parse.unquote(parsed.path or "/"), safe="/%:@!$&'()*+,;=-._~")
            query = f"?{parsed.query}" if parsed.query else ""
            canonical = f"{parsed.scheme}://{host}{port}{path}{query}"
            return ("url", canonical[:2048])
        except (ValueError, UnicodeError):
            return None
    if normalized_kind == "filename":
        if len(value) > 255 or "/" in value or "\\" in value or value in (".", ".."):
            return None
        return ("filename", value)
    return None


def feed_rows(data):
    """Normalize supported abuse.ch JSON row containers without treating strings as records."""
    if isinstance(data, list):
        return [row for row in data if isinstance(row, dict)]
    if isinstance(data, dict):
        if "ioc" in data or "sha256_hash" in data:
            return [data]
        return [row for row in data.values() if isinstance(row, dict)]
    return []


def update_http(url, data=None, headers=None):
    """Retry transient abuse.ch gateway/network failures, but fail promptly on other HTTP errors."""
    for attempt in range(3):
        try:
            return http(url, data, headers)
        except urllib.error.HTTPError as e:
            if e.code not in (408, 429, 500, 502, 503, 504) or attempt == 2:
                raise
        except urllib.error.URLError:
            if attempt == 2:
                raise
        time.sleep(0.5 * (attempt + 1))
    raise RuntimeError("abuse.ch request failed after retries")


def feed_error(source, error):
    """Report provider authentication failures without exposing request headers or credentials."""
    code = getattr(error, "code", None)
    if code in (401, 403):
        return f"{source}: HTTP {code} — ผู้ให้บริการปฏิเสธ Auth-Key; ตรวจว่าคีย์จาก https://auth.abuse.ch ถูกต้องและบันทึกใน Settings แล้วลองอีกครั้ง"
    return f"{source}: เรียกไม่สำเร็จ - {error}"


def fetch_mb(con, tag, hdr):
    """ดึงแฮชจาก MalwareBazaar ทั้งแบบ tag (ตัวพิมพ์ต่าง ๆ) และแบบ signature พร้อมรายงานสถานะทุกครั้ง"""
    added, successful = 0, False
    for q, k, v in dict.fromkeys([("get_taginfo", "tag", tag), ("get_taginfo", "tag", tag.lower()), ("get_siginfo", "signature", tag)]):
        try:
            body = urllib.parse.urlencode({"query": q, k: v, "limit": 1000}).encode()
            res = json.loads(update_http("https://mb-api.abuse.ch/api/v1/", body, hdr))
        except (OSError, ValueError) as e:
            print(f"[!] {feed_error(f'MalwareBazaar {q} {v}', e)}")
            continue
        if not isinstance(res, dict):
            print(f"[!] MalwareBazaar {q} {v}: รูปแบบคำตอบไม่ถูกต้อง")
            continue
        rows = feed_rows(res.get("data"))
        got = 0
        for row in rows:
            sha = str(row.get("sha256_hash", "")).lower()
            if re.fullmatch(r"[0-9a-f]{64}", sha):
                got += con.execute("SELECT 1 FROM hashes WHERE sha256=?", (sha,)).fetchone() is None
                record_malware_hash(con, sha256=sha, sha1=row.get("sha1_hash"), md5=row.get("md5_hash"),
                    family=row.get("signature") or tag, threat_name=row.get("file_name") or row.get("signature") or tag,
                    first_seen=row.get("first_seen"), last_seen=row.get("last_seen") or row.get("first_seen"),
                    source="MalwareBazaar", reference="https://bazaar.abuse.ch/")
        st = str(res.get("query_status", "unknown")).lower()
        successful |= st in ("ok", "no_results", "no_result")
        print(f"[{'+' if st in ('ok', 'no_results', 'no_result') else '!'}] "
              f"MalwareBazaar {q} {v}: สถานะ={st} พบ {len(rows)} รายการ (ใหม่ {got})")
        added += got
    return added, successful


def fetch_mb_recent(con, hdr):
    """Import recent MalwareBazaar SHA-256 detections without downloading samples."""
    body = urllib.parse.urlencode({"query": "recent_detections", "hours": 168}).encode()
    try:
        res = json.loads(update_http("https://mb-api.abuse.ch/api/v1/", body, hdr))
    except (OSError, ValueError) as e:
        print(f"[!] {feed_error('MalwareBazaar recent detections', e)}")
        return 0, False
    if not isinstance(res, dict):
        print("[!] MalwareBazaar recent detections: รูปแบบคำตอบไม่ถูกต้อง")
        return 0, False
    status = str(res.get("query_status", "unknown")).lower()
    if status not in ("ok", "no_results", "no_result"):
        print(f"[!] MalwareBazaar recent detections: สถานะ={status}")
        return 0, False
    rows = feed_rows(res.get("data"))
    added = 0
    for row in rows:
        sha = str(row.get("sha256_hash", "")).lower()
        if re.fullmatch(r"[0-9a-f]{64}", sha):
            family = str(row.get("signature") or "unknown")[:100]
            added += con.execute("SELECT 1 FROM hashes WHERE sha256=?", (sha,)).fetchone() is None
            record_malware_hash(con, sha256=sha, sha1=row.get("sha1_hash"), md5=row.get("md5_hash"),
                family=family, threat_name=row.get("file_name") or family,
                first_seen=row.get("first_seen"), last_seen=row.get("last_seen") or row.get("first_seen"),
                source="MalwareBazaar recent detections", reference="https://bazaar.abuse.ch/api/")
    print(f"[+] MalwareBazaar recent detections: พบ {len(rows)} รายการ (ใหม่ {added})")
    return added, True


def cmd_update(_args=None):
    key = get_key()
    hdr = {"Auth-Key": key} if key else {}
    con = db()
    added_h = added_i = 0
    successful_sources, failed_sources = [], []
    if not key:
        print("[!] ยังไม่ได้ตั้ง Auth-Key — ข้าม MalwareBazaar และ ThreatFox (รับคีย์ฟรีได้ที่ https://auth.abuse.ch)")
        failed_sources.extend(["MalwareBazaar", "MalwareBazaar recent detections", "ThreatFox"])
    else:
        for tag in TAGS:
            new_hashes, ok = fetch_mb(con, tag, hdr)  # MalwareBazaar: แฮชของไฟล์
            added_h += new_hashes
            if ok and "MalwareBazaar" not in successful_sources:
                successful_sources.append("MalwareBazaar")
        if "MalwareBazaar" not in successful_sources:
            failed_sources.append("MalwareBazaar")
        recent_hashes, recent_ok = fetch_mb_recent(con, hdr)
        added_h += recent_hashes
        if recent_ok:
            successful_sources.append("MalwareBazaar recent detections")
        else:
            failed_sources.append("MalwareBazaar recent detections")
    try:  # ThreatFox: IOC ล่าสุดทั้งหมด และแฮชที่เชื่อมโยงกับ IOC
        if not key:
            raise StopIteration
        body = json.dumps({"query": "get_iocs", "days": 7}).encode()
        res = json.loads(update_http("https://threatfox-api.abuse.ch/api/v1/", body,
                                     {**hdr, "Content-Type": "application/json"}))
        if not isinstance(res, dict):
            raise ValueError("รูปแบบคำตอบไม่ถูกต้อง")
        status = str(res.get("query_status", "unknown")).lower()
        rows = feed_rows(res.get("data"))
        if status in ("ok", "no_results", "no_result"):
            successful_sources.append("ThreatFox")
            for row in rows:
                val, kind = norm_ioc(row.get("ioc", ""), row.get("ioc_type", ""))
                family = str(row.get("malware_printable") or row.get("malware") or "unknown")[:100]
                raw_seen = row.get("last_seen") or row.get("first_seen")
                seen = _feed_time(raw_seen)
                seen_dt = dt.datetime.fromisoformat(seen)
                expires = (seen_dt + dt.timedelta(days=7)).isoformat(timespec="seconds")
                confidence = row.get("confidence_level")
                try:
                    confidence = int(confidence) if confidence is not None else None
                except (TypeError, ValueError):
                    confidence = None
                if val:
                    added_i += int(record_ioc(
                        con, val, kind, family, "ThreatFox", last_seen=seen, expires_at=expires,
                        confidence=confidence, reference=row.get("reference"),
                    ))
                canonical = normalize_threat_ioc(row.get("ioc", ""), row.get("ioc_type", ""))
                if canonical:
                    record_threat_ioc(con, canonical[0], canonical[1], "ThreatFox", family=family,
                        confidence=confidence if confidence is not None else 50,
                        first_seen=row.get("first_seen") or seen, last_seen=seen,
                        expires_at=expires, reference=row.get("reference"))
                    if canonical[0] == "sha256":
                        record_malware_hash(con, sha256=canonical[1], family=family,
                            threat_name=family, first_seen=row.get("first_seen") or seen,
                            last_seen=seen, source="ThreatFox", confidence=confidence or 50,
                            reference=row.get("reference"))
                for sample in feed_rows(row.get("malware_samples")):
                    sha = str(sample.get("sha256_hash", "")).lower()
                    if re.fullmatch(r"[0-9a-f]{64}", sha):
                        added_h += con.execute("SELECT 1 FROM hashes WHERE sha256=?", (sha,)).fetchone() is None
                        family = str(row.get("malware_printable") or row.get("malware") or "ThreatFox")[:100]
                        record_malware_hash(con, sha256=sha, sha1=sample.get("sha1_hash"),
                            md5=sample.get("md5_hash"), family=family, threat_name=family,
                            first_seen=sample.get("first_seen") or seen, last_seen=seen,
                            source="ThreatFox", reference=row.get("reference"))
        else:
            failed_sources.append("ThreatFox")
            print(f"[!] ThreatFox: สถานะ={status} พบ {len(rows)} รายการ")
        print(f"[{'+' if status in ('ok', 'no_results', 'no_result') else '!'}] ThreatFox: "
              f"สถานะ={status} พบ {len(rows)} รายการ (เพิ่ม IOC/แฮชที่เชื่อมโยงแล้ว)")
    except (OSError, ValueError) as e:
        failed_sources.append("ThreatFox")
        print(f"[!] {feed_error('ThreatFox', e)}")
    except StopIteration:
        pass
    try:  # URLhaus: โฮสต์ที่กำลังแจกมัลแวร์หรือเพิ่มใน 48 ชั่วโมงล่าสุด
        text = update_http("https://urlhaus.abuse.ch/downloads/hostfile/").decode("utf-8", "ignore")
        got = 0
        for line in text.splitlines():
            parts = line.split()
            if len(parts) >= 2 and not line.startswith("#"):
                val, kind = norm_ioc(parts[1], "domain")
                if val:
                    now = dt.datetime.now(dt.timezone.utc)
                    got += int(record_ioc(
                        con, val, kind, "URLhaus", "URLhaus",
                        last_seen=now.isoformat(timespec="seconds"),
                        expires_at=(now + dt.timedelta(hours=48)).isoformat(timespec="seconds"),
                    ))
                    record_threat_ioc(con, kind, val, "URLhaus", family="malware distribution",
                        confidence=85, last_seen=now.isoformat(timespec="seconds"),
                        expires_at=(now + dt.timedelta(hours=48)).isoformat(timespec="seconds"),
                        reference="https://urlhaus.abuse.ch/")
        added_i += got
        successful_sources.append("URLhaus")
        print(f"[+] URLhaus: เพิ่มโดเมน {got} จาก host feed")
    except (OSError, ValueError) as e:
        failed_sources.append("URLhaus")
        print(f"[!] {feed_error('URLhaus', e)}")
    if successful_sources:
        con.execute("INSERT OR REPLACE INTO meta VALUES('last_update',?)",
                    (dt.datetime.now().isoformat(timespec="seconds"),))
    else:
        print("[!] ทุกแหล่งข้อมูลล้มเหลว - ไม่เปลี่ยนเวลาอัปเดตล่าสุด")
    con.execute("INSERT OR REPLACE INTO meta VALUES('last_update_complete',?)",
                 ("1" if successful_sources and not failed_sources else "0",))
    con.commit()
    th = con.execute("SELECT COUNT(*) FROM hashes").fetchone()[0]
    ti = con.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
    if successful_sources and not failed_sources:
        print(f"[+] อัปเดตฐานข้อมูลสำเร็จ ({', '.join(successful_sources)}): "
              f"เพิ่มแฮช {added_h}, IOC {added_i} | รวม แฮช {th}, IOC {ti}")
    elif successful_sources:
        print(f"[!] อัปเดตฐานข้อมูลบางส่วน ({', '.join(successful_sources)}): "
              f"เพิ่มแฮช {added_h}, IOC {added_i} | แหล่งที่ยังไม่สำเร็จ: {', '.join(failed_sources)}")
    else:
        print(f"[!] อัปเดตฐานข้อมูลไม่สำเร็จ: ทุกแหล่งล้มเหลว | "
              f"แฮช {th}, IOC {ti} (คงข้อมูลเดิมไว้)")
    con.close()
    return bool(successful_sources) and not failed_sources


def cmd_add_hash(args):
    h = args.sha256.lower().strip()
    if not re.fullmatch(r"[0-9a-f]{64}", h):
        sys.exit("SHA-256 ต้องยาว 64 ตัวอักษร hex")
    con = db()
    con.execute("INSERT OR REPLACE INTO hashes VALUES(?,?,?)", (h, "manual", "user"))
    con.commit()
    print("[+] เพิ่มแฮชแล้ว")


# ---------------------------------------------------------------- วิเคราะห์ไฟล์
def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def malware_family_info(family):
    """Load the small, local family knowledge base; return no untrusted rich content."""
    name = str(family or "unknown")[:100]
    roots = [Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent)), APP_DIR]
    for root in roots:
        try:
            data = json.loads((root / "malware_knowledge.json").read_text(encoding="utf-8"))
            for key, value in data.items():
                if key.casefold() == name.casefold() and isinstance(value, dict):
                    return value
        except (OSError, ValueError, AttributeError):
            continue
    return {}


def user_writable(p):
    p = p.lower().replace("/", "\\")
    return any(s in p for s in ("\\appdata\\", "\\temp\\", "\\programdata\\", "\\users\\public\\", "\\downloads\\"))


def in_windows_dir(p):
    win = os.environ.get("WINDIR", r"C:\Windows").lower()
    return p.lower().replace("/", "\\").startswith(win.replace("/", "\\") + "\\")


def classify_analysis(path, sha, con, matches, is_pe, strong_xworm, weak_xworm, dotnet):
    row = con.execute("SELECT family,source FROM hashes WHERE sha256=?", (sha,)).fetchone()
    if row:
        return "high", [f"SHA-256 reputation: family={row[0]}, source={row[1]}"], sha
    if con.execute("SELECT 1 FROM allow WHERE sha256=?", (sha,)).fetchone():  # ผู้ใช้ยืนยันว่าปลอดภัย (แฮชในฐานข้อมูลมัลแวร์ชนะเสมอ)
        return None, [], sha
    ext = Path(path).suffix.lower()
    if ext not in SCRIPT_EXT and not is_pe:
        return None, [], sha
    ywhy = [
        f"YARA: {m['rule']} — {m.get('description', 'No description supplied')}; "
        f"author: {m.get('author', 'unknown')}; source/reference: {m.get('source', 'unknown')} / {m.get('reference', 'none')}; "
        f"license: {m.get('license', 'unspecified')}; version: {m.get('rule_version', 'unspecified')}; "
        f"review: {m.get('reviewed', 'not reviewed')}; "
        f"false-positive notes: {m.get('false_positive_notes', 'not documented')}"
        for m in matches
    ]
    rk = {"high": 3, "medium": 2, "low": 1}
    ysev = max((m["severity"] for m in matches), key=lambda x: rk.get(x, 3), default=None)
    score, why = 0, []
    if is_pe:
        if strong_xworm:
            score += 3
            why.append("พบรูปแบบสตริงที่สัมพันธ์กับ XWorm (ควรตรวจยืนยัน)")
        elif weak_xworm:
            score += 2
            why.append("พบข้อความที่อาจเกี่ยวข้องกับ XWorm (ยังไม่ยืนยันว่าเป็นมัลแวร์)")
        if Path(path).name.lower() in SYSTEM_NAMES and not in_windows_dir(path):
            score += 3
            why.append("ชื่อเลียนแบบไฟล์ระบบแต่อยู่นอกโฟลเดอร์ Windows")
        if score:  # เกณฑ์เสริม นับเมื่อมีสัญญาณหลักอยู่แล้วเท่านั้น (กัน false positive)
            if dotnet:
                score += 1
                why.append("เป็นไฟล์ .NET")
            if user_writable(path):
                score += 1
                why.append("อยู่ในโฟลเดอร์ที่ผู้ใช้เขียนได้ (Temp/AppData)")
    if ysev == "high" or (strong_xworm and score >= 5):
        return "high", ywhy + why, sha
    if ysev == "medium" or score >= 3:
        return "medium", ywhy + why, sha
    if ysev == "low":
        return "low", ywhy + why, sha
    return None, [], sha


def inspect_file_stream(path):
    """Hash arbitrary-size files and measure entropy/heuristic markers in one pass."""
    digests = {name: hashlib.new(name) for name in ("sha256", "sha1", "md5")}
    histogram = Counter()
    total_bytes = 0
    strong_patterns = [
        pattern.lower()
        for pat in STRONG_PATTERNS
        for pattern in (pat, pat.decode().encode("utf-16le"))
    ]
    weak_patterns = [
        pattern.lower()
        for pat in WEAK_PATTERNS
        for pattern in (pat, pat.decode().encode("utf-16le"))
    ]
    patterns = strong_patterns + weak_patterns
    patterns.extend((b"mscoree.dll", b"bsjb"))
    longest = max(map(len, patterns))
    carry = b""
    found = set()
    prefix = b""
    with open(path, "rb") as stream:
        while chunk := stream.read(1024 * 1024):
            for digest in digests.values():
                digest.update(chunk)
            total_bytes += len(chunk)
            histogram.update(chunk)
            if len(prefix) < 2:
                prefix += chunk[:2 - len(prefix)]
            data = (carry + chunk).lower()
            for index, pattern in enumerate(patterns):
                if index not in found and pattern in data:
                    found.add(index)
            carry = data[-(longest - 1):]
    strong_count = len(strong_patterns)
    dotnet_start = len(patterns) - 2
    return (
        {name: digest.hexdigest() for name, digest in digests.items()},
        prefix,
        any(i < strong_count for i in found),
        any(strong_count <= i < dotnet_start for i in found),
        dotnet_start in found and dotnet_start + 1 in found,
        -sum((count / total_bytes) * math.log2(count / total_bytes)
             for count in histogram.values()) if total_bytes else 0.0,
    )


def _hash_reputation(con, digests):
    row = con.execute("SELECT sha256,sha1,md5,family,threat_name,severity,source,confidence,reference FROM malware_hashes WHERE sha256=? OR (? IS NOT NULL AND sha1=?) OR (? IS NOT NULL AND md5=?)",
                      (digests["sha256"], digests["sha1"], digests["sha1"], digests["md5"], digests["md5"])).fetchone()
    if row:
        return {"algorithm": "sha256" if row[0] == digests["sha256"] else "sha1" if row[1] == digests["sha1"] else "md5",
                "family": row[3], "threat_name": row[4], "severity": row[5],
                "source": row[6], "confidence": row[7], "reference": row[8]}
    for algorithm in ("sha1", "md5"):
        row = con.execute("SELECT family,threat_name,source,confidence,reference FROM threat_iocs WHERE kind=? AND value=? AND state='active' ORDER BY confidence DESC LIMIT 1",
                          (algorithm, digests[algorithm])).fetchone()
        if row:
            return {"algorithm": algorithm, "family": row[0], "threat_name": row[1],
                    "severity": "HIGH", "source": row[2], "confidence": row[3], "reference": row[4]}
    row = con.execute("SELECT family,source FROM hashes WHERE sha256=?", (digests["sha256"],)).fetchone()
    if row:
        return {"algorithm": "sha256", "family": row[0], "threat_name": row[0],
                "severity": "HIGH", "source": row[1], "confidence": 100, "reference": None}
    return None


def analyze_detailed(path, con, logical_path=None):
    """Analyze files of any size without loading the entire file into memory."""
    display_path = logical_path or path
    try:
        size = os.path.getsize(path)
        if size == 0:
            return None, [], "", {"size": 0}
        digests, prefix, strong_xworm, weak_xworm, dotnet, entropy = inspect_file_stream(path)
    except OSError as e:
        scan_issue(f"อ่านไฟล์ไม่สำเร็จ {display_path}: {e}")
        return None, [], "", {}
    sha = digests["sha256"]
    metadata = {"sha256": sha, "sha1": digests["sha1"], "md5": digests["md5"],
                "size": size, "file_type": "PE executable" if prefix == b"MZ" else (mimetypes.guess_type(display_path)[0] or "unknown"),
                "entropy": round(entropy, 3)}
    if prefix == b"MZ":
        metadata["signature"] = "unknown (PE metadata unavailable)"
    reputation = _hash_reputation(con, digests)
    if reputation:
        metadata["hash_reputation"] = reputation
        metadata["family_intel"] = malware_family_info(reputation["family"])
        metadata["risk_score"] = 100
        metadata["risk_band"] = "CRITICAL"
        metadata["score_type"] = "risk score; not probability"
        return "high", [f"{reputation['algorithm'].upper()} reputation: {reputation['threat_name']} ({reputation['source']})"], sha, metadata
    if con.execute("SELECT 1 FROM allow WHERE sha256=?", (sha,)).fetchone():
        return None, [], sha, metadata
    is_pe = prefix == b"MZ"
    if is_pe and size <= 32 * 1024 * 1024 and pefile:
        try:
            pe = pefile.PE(path, fast_load=True)
            metadata["architecture"] = {0x14c: "x86", 0x8664: "x64", 0xaa64: "ARM64"}.get(pe.FILE_HEADER.Machine, f"unknown (0x{pe.FILE_HEADER.Machine:04x})")
            stamp = pe.FILE_HEADER.TimeDateStamp
            metadata["compile_timestamp"] = dt.datetime.fromtimestamp(stamp, dt.timezone.utc).isoformat() if stamp else None
            metadata["signature"] = "signed (authenticity not verified)" if pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress else "unsigned"
            metadata["version_info"] = {}
            for item in getattr(pe, "FileInfo", []) or []:
                for table in getattr(item, "StringTable", []) or []:
                    for key, value in table.entries.items():
                        if key.decode("utf-8", "replace") in {"CompanyName", "FileDescription", "FileVersion", "ProductName", "ProductVersion"}:
                            metadata["version_info"][key.decode("utf-8", "replace")] = value.decode("utf-8", "replace")[:256]
            metadata["sections"] = [{"name": section.Name.rstrip(b"\\0").decode("ascii", "replace"), "entropy": round(section.get_entropy(), 3)} for section in pe.sections[:32]]
            metadata["imports"] = []
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
            ])
            for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])[:64]:
                metadata["imports"].append({"dll": entry.dll.decode("ascii", "replace"), "functions": [imp.name.decode("ascii", "replace") for imp in entry.imports[:32] if imp.name]})
            pe.close()
        except Exception as exc:
            metadata["pe_analysis"] = f"unavailable: {type(exc).__name__}"
    matches = yara_scan_file(path) if Path(display_path).suffix.lower() in SCRIPT_EXT or is_pe else []
    classified = classify_analysis(
        display_path, sha, con,
        matches,
        is_pe, strong_xworm, weak_xworm, dotnet,
    )
    severity, reasons, _ = classified
    if matches:
        metadata["yara_matches"] = matches
        family = next((m.get("family") for m in matches if m.get("family") not in (None, "", "unknown")), None)
        if family:
            metadata["family_intel"] = malware_family_info(family)
    score = 0
    if matches:
        score = max((80 if m.get("severity") == "high" else
                     50 if m.get("severity") == "medium" else 25)
                    for m in matches)
    elif severity == "high":
        score = 60 if strong_xworm else 70
    elif severity == "medium":
        score = 30
    elif severity == "low":
        score = 20
    if is_pe and metadata.get("signature", "").startswith("unsigned"):
        score += 15
    if not severity and size > 0:
        score += 5
    score = min(100, score)
    metadata["risk_score"] = score
    metadata["risk_band"] = "CRITICAL" if score >= 90 else "HIGH" if score >= 70 else "MEDIUM" if score >= 40 else "LOW" if score else "CLEAN / UNKNOWN"
    metadata["score_type"] = "risk score; not probability"
    return severity, reasons, sha, metadata


def analyze(path, con, logical_path=None):
    severity, reasons, sha, _metadata = analyze_detailed(path, con, logical_path)
    return severity, reasons, sha


def scan_archive(path, con, deep=False):
    """Stream ZIP members using standard or extended deep-scan budgets."""
    findings = []
    archive_stack = []
    container = str(path)
    members_seen = 0
    expanded_bytes = 0
    started_at = time.monotonic()
    limit_hit = False
    member_bytes = 0
    member_limit = DEEP_ARCHIVE_MAX_MEMBERS if deep else MAX_ARCHIVE_MEMBERS
    member_bytes_limit = DEEP_ARCHIVE_MAX_MEMBER_BYTES if deep else MAX_ARCHIVE_MEMBER_BYTES
    expanded_bytes_limit = DEEP_ARCHIVE_MAX_EXPANDED_BYTES if deep else MAX_ARCHIVE_EXPANDED_BYTES
    nesting_depth_limit = DEEP_ARCHIVE_MAX_NESTING_DEPTH if deep else MAX_ARCHIVE_NESTING_DEPTH
    compression_ratio_limit = DEEP_ARCHIVE_MAX_COMPRESSION_RATIO if deep else MAX_ARCHIVE_COMPRESSION_RATIO
    scan_seconds_limit = None if deep else MAX_ARCHIVE_SCAN_SECONDS

    def scan_time_exceeded():
        return scan_seconds_limit is not None and time.monotonic() - started_at >= scan_seconds_limit

    def deep_disk_guard(label, next_chunk_bytes=0):
        nonlocal limit_hit
        if not deep:
            return False
        try:
            free_bytes = shutil.disk_usage(tempfile.gettempdir()).free
        except OSError as error:
            scan_issue(f"ตรวจพื้นที่ว่างสำหรับสแกน archive ลึกไม่ได้ {label}: {error}")
            limit_hit = True
            return True
        if free_bytes <= DEEP_ARCHIVE_MIN_FREE_BYTES + next_chunk_bytes:
            scan_issue(f"หยุดสแกน archive ลึกเพื่อรักษาพื้นที่ว่างอย่างน้อย 1 GiB: {label}")
            limit_hit = True
            return True
        return False

    def archive_entry_count(source):
        # Inspect the small end record before ZipFile builds its in-memory list.
        with open(source, "rb") as stream:
            end_record = zipfile._EndRecData(stream)
        if end_record is None:
            raise zipfile.BadZipFile("missing ZIP end record")
        return int(end_record[zipfile._ECD_ENTRIES_TOTAL])

    def read_member(member, amount, label):
        nonlocal expanded_bytes, member_bytes, limit_hit
        if scan_time_exceeded():
            scan_issue(f"หยุดตรวจ archive เมื่อเกินเวลาที่กำหนด: {label}")
            limit_hit = True
            return None
        if deep_disk_guard(label, amount):
            scan_issue(f"หยุดสแกน archive ลึกเพื่อรักษาพื้นที่ว่างอย่างน้อย 1 GiB: {label}")
            return None
        chunk = member.read(amount)
        if not chunk:
            return b""
        member_bytes += len(chunk)
        expanded_bytes += len(chunk)
        if member_bytes > member_bytes_limit:
            scan_issue(f"ข้ามสมาชิก archive ที่เกินขนาดต่อไฟล์: {label}")
            limit_hit = True
            return None
        if expanded_bytes > expanded_bytes_limit:
            scan_issue(f"หยุดตรวจ archive เมื่อข้อมูลคลายบีบอัดรวมเกินขีดจำกัด: {label}")
            limit_hit = True
            return None
        if scan_time_exceeded():
            scan_issue(f"หยุดตรวจ archive เมื่อเกินเวลาที่กำหนด: {label}")
            limit_hit = True
            return None
        if deep_disk_guard(label):
            scan_issue(f"หยุดสแกน archive ลึกเพื่อรักษาพื้นที่ว่างอย่างน้อย 1 GiB: {label}")
            return None
        return chunk

    def push_archive(source, label, temporary_path=None):
        archive = None
        SCAN_AUDIT.setdefault("archive", {"archives": 0, "members_seen": 0, "expanded_bytes": 0})["archives"] += 1
        try:
            entry_count = archive_entry_count(source)
            if members_seen + entry_count > member_limit:
                scan_issue(f"ข้าม archive ที่จำนวนสมาชิกเกินขีดจำกัด: {label}")
                if temporary_path:
                    remove_temporary(temporary_path, label)
                return
            archive = zipfile.ZipFile(source)
            entries = iter(archive.infolist())
        except (OSError, RuntimeError, zipfile.BadZipFile, EOFError, IndexError, struct.error, ValueError) as e:
            if archive:
                close_archive(archive, label)
            scan_issue(f"อ่าน archive ไม่สำเร็จ {label}: {e}")
            if temporary_path:
                remove_temporary(temporary_path, label)
            return
        archive_stack.append({
            "archive": archive, "entries": entries, "label": label,
            "temporary_path": temporary_path,
        })

    def remove_temporary(temporary_path, label):
        try:
            Path(temporary_path).unlink(missing_ok=True)
        except OSError as e:
            scan_issue(f"ลบไฟล์ชั่วคราวของ archive ไม่สำเร็จ {label}: {e}")

    def close_archive(archive, label):
        try:
            archive.close()
        except OSError as e:
            scan_issue(f"ปิด archive ไม่สำเร็จ {label}: {e}")

    def close_frame(frame):
        close_archive(frame["archive"], frame["label"])
        if frame["temporary_path"]:
            remove_temporary(frame["temporary_path"], frame["label"])

    push_archive(path, container)
    try:
        while archive_stack:
            if STOP["flag"]:
                break
            if scan_time_exceeded():
                scan_issue(f"หยุดตรวจ archive เมื่อเกินเวลาที่กำหนด: {archive_stack[-1]['label']}")
                limit_hit = True
                break
            if deep_disk_guard(archive_stack[-1]["label"]):
                scan_issue(f"หยุดสแกน archive ลึกเพื่อรักษาพื้นที่ว่างอย่างน้อย 1 GiB: {archive_stack[-1]['label']}")
                break
            frame = archive_stack[-1]
            try:
                info = next(frame["entries"])
            except StopIteration:
                close_frame(archive_stack.pop())
                continue
            except (OSError, RuntimeError, zipfile.BadZipFile, EOFError) as e:
                scan_issue(f"อ่านรายการ archive ไม่สำเร็จ {frame['label']}: {e}")
                close_frame(archive_stack.pop())
                continue
            if info.is_dir():
                members_seen += 1
                continue
            members_seen += 1
            if members_seen > member_limit:
                scan_issue(f"หยุดตรวจ archive เมื่อจำนวนสมาชิกเกินขีดจำกัด: {frame['label']}")
                limit_hit = True
                break
            target = f"{frame['label']}!{info.filename}"
            if info.flag_bits & 0x1:
                scan_issue(f"ข้ามไฟล์ใน archive ที่เข้ารหัสไว้: {target}")
                continue
            if info.file_size > member_bytes_limit:
                scan_issue(f"ข้ามสมาชิก archive ที่เกินขนาดต่อไฟล์: {target}")
                continue
            if info.file_size > expanded_bytes_limit - expanded_bytes:
                scan_issue(f"หยุดตรวจ archive เมื่อข้อมูลคลายบีบอัดรวมเกินขีดจำกัด: {target}")
                limit_hit = True
                break
            if info.file_size > 1024 * 1024 and info.compress_size > 0 and (
                info.file_size / info.compress_size > compression_ratio_limit
            ):
                scan_issue(f"ข้ามสมาชิก archive ที่มีอัตราขยายสูงผิดปกติ: {target}")
                continue
            suffix = Path(info.filename).suffix.lower()
            is_script = suffix in SCRIPT_EXT
            is_archive = suffix in ARCHIVE_EXT
            member_temp_path = None
            member_bytes = 0
            try:
                with frame["archive"].open(info) as member:
                    prefix = read_member(member, 4, target)
                    if prefix is None:
                        break
                    is_nested_zip = prefix.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"))
                    if not (is_script or is_archive or prefix[:2] == b"MZ" or is_nested_zip):
                        while not STOP["flag"] and not limit_hit:
                            chunk = read_member(member, 1024 * 1024, target)
                            if chunk is None:
                                break
                            if not chunk:
                                break
                        if STOP["flag"] or limit_hit:
                            break
                        continue
                    with tempfile.NamedTemporaryFile(
                        prefix="lunaguard-archive-", suffix=suffix or ".bin", delete=False
                    ) as extracted:
                        member_temp_path = extracted.name
                        extracted.write(prefix)
                        while not STOP["flag"] and not limit_hit:
                            chunk = read_member(member, 1024 * 1024, target)
                            if chunk is None:
                                break
                            if not chunk:
                                break
                            extracted.write(chunk)
                if STOP["flag"] or limit_hit:
                    break
                if is_script or prefix[:2] == b"MZ":
                    severity, reasons, _, metadata = analyze_detailed(member_temp_path, con, logical_path=info.filename)
                    if severity:
                        findings.append({
                            "sev": severity, "kind": "Archive member", "target": target,
                            "why": "; ".join(reasons), "container": container,
                            "analysis": metadata, "sha256": metadata.get("sha256"),
                            "risk_score": metadata.get("risk_score", 0),
                            "risk_band": metadata.get("risk_band", "CLEAN / UNKNOWN"),
                        })
                if is_archive or is_nested_zip:
                    if len(archive_stack) >= nesting_depth_limit:
                        scan_issue(f"ข้าม archive ซ้อนที่เกินความลึกสูงสุด: {target}")
                    else:
                        push_archive(member_temp_path, target, member_temp_path)
                        member_temp_path = None
            except (OSError, RuntimeError, zipfile.BadZipFile, EOFError, NotImplementedError, zlib.error) as e:
                scan_issue(f"อ่านหรือจัดเก็บไฟล์ใน archive ไม่สำเร็จ {target}: {e}")
            finally:
                if member_temp_path:
                    remove_temporary(member_temp_path, target)
    finally:
        while archive_stack:
            close_frame(archive_stack.pop())
        archive_stats = SCAN_AUDIT.setdefault("archive", {"archives": 0, "members_seen": 0, "expanded_bytes": 0})
        archive_stats["members_seen"] += members_seen
        archive_stats["expanded_bytes"] += expanded_bytes
    return findings


# ---------------------------------------------------------------- ตัวเก็บข้อมูลระบบ
def run(cmd, *, required=False):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120, errors="ignore",
                               stdin=subprocess.DEVNULL, creationflags=0x08000000 if IS_WIN else 0)
        if result.returncode:
            message = f"คำสั่ง {Path(cmd[0]).name} จบด้วยรหัส {result.returncode}"
            if required:
                scan_issue(message)
            else:
                print(f"[!] {message}")
            return None
        return result.stdout
    except (OSError, subprocess.SubprocessError) as error:
        message = f"เรียกคำสั่ง {Path(cmd[0]).name} ไม่สำเร็จ ({type(error).__name__})"
        if required:
            scan_issue(message)
        else:
            print(f"[!] {message}")
        return None


def default_scan_dirs():
    e = os.environ.get
    appdata = e("APPDATA")
    candidates = [
        e("TEMP"),
        appdata,
        str(Path.home() / "Downloads"),
        str(Path(appdata) / r"Microsoft\Windows\Start Menu\Programs\Startup") if appdata else None,
    ]
    dirs = list(dict.fromkeys(os.path.abspath(d) for d in candidates if d and os.path.isdir(d)))
    normalized = {directory: os.path.normcase(directory) for directory in dirs}
    roots = []
    for directory in dirs:
        current = normalized[directory]
        nested = False
        for other in dirs:
            if other == directory:
                continue
            parent = normalized[other]
            try:
                if os.path.commonpath((parent, current)) == parent:
                    nested = True
                    break
            except ValueError:
                continue
        if not nested:
            roots.append(directory)
    return roots


def walk_files(roots, full_coverage=False):
    skip = set() if full_coverage else {str(APP_DIR).lower()}
    def report_walk_error(error):
        scan_issue(f"อ่านโฟลเดอร์สแกนไม่สำเร็จ {error.filename or ''}: {error}")

    def is_reparse_point(path):
        try:
            info = os.stat(path, follow_symlinks=False)
            return bool(getattr(info, "st_file_attributes", 0) & 0x400) or os.path.islink(path)
        except OSError as error:
            scan_issue(f"ตรวจชนิดโฟลเดอร์ไม่ได้ จึงข้ามไว้ก่อน {path}: {error}")
            return True

    for root in roots:
        for dp, dn, fn in os.walk(root, onerror=report_walk_error):
            if dp.lower() in skip or (not full_coverage and (in_windows_dir(dp) or "\\windows defender" in dp.lower())):
                dn[:] = []
                continue
            if full_coverage:
                kept = []
                for directory in dn:
                    child = os.path.join(dp, directory)
                    if is_reparse_point(child):
                        scan_issue(f"ข้าม junction/reparse point เพื่อป้องกันการวนซ้ำหรือออกนอกไดรฟ์: {child}")
                    else:
                        kept.append(directory)
                dn[:] = kept
            else:
                dn[:] = [d for d in dn if d.lower() not in SKIP_DIRS]
            for n in fn:
                path = os.path.join(dp, n)
                if full_coverage and is_reparse_point(path):
                    scan_issue(f"ข้ามไฟล์ reparse point เพื่อป้องกันการออกนอกไดรฟ์: {path}")
                    continue
                yield path


def list_processes():
    out = run(["powershell", "-NoProfile", "-Command",
               "Get-CimInstance Win32_Process | Select ProcessId,Name,ExecutablePath | ConvertTo-Json -Depth 2"], required=True)
    if out is None:
        return []
    try:
        data = json.loads(out)
        processes = data if isinstance(data, list) else [data]
        if not all(isinstance(process, dict) and "ProcessId" in process for process in processes):
            raise ValueError("รูปแบบรายการ process ไม่ถูกต้อง")
        return processes
    except (TypeError, ValueError) as e:
        scan_issue(f"อ่านรายการ process ไม่สำเร็จ จึงยืนยันผลสแกนหน่วยความจำไม่ได้: {e}")
        return []


def scan_process_memory(processes):
    """YARA-scan each listed process; report permissions, timeouts, and rule failures."""
    stats = SCAN_AUDIT.setdefault("memory", {"attempted": 0, "scanned": 0, "denied": 0, "failed": 0})
    rules = yara_rules()
    if not rules:
        scan_issue("สแกนหน่วยความจำไม่ได้: ไม่พบกฎ YARA หรือโมดูล yara-python")
        return []

    findings = []
    own_pid = os.getpid()
    for index, process in enumerate(processes, 1):
        if STOP["flag"]:
            scan_issue("หยุดการสแกนหน่วยความจำตามคำสั่งผู้ใช้")
            break
        try:
            pid = int(process["ProcessId"])
        except (KeyError, TypeError, ValueError):
            stats["failed"] += 1
            scan_issue(f"ข้าม process ที่ไม่มี PID ใช้งานได้: {process!r}")
            continue
        if pid == own_pid:
            continue
        name = str(process.get("Name") or "unknown")
        PROGRESS.update(stage=f"[2/5] ตรวจหน่วยความจำ ({index}/{len(processes)})", path=f"{name} (PID {pid})")
        stats["attempted"] += 1
        try:
            matches = yara_scan_process(pid)
        except Exception as e:
            if "access denied" in str(e).lower() or "permission" in str(e).lower():
                stats["denied"] += 1
            else:
                stats["failed"] += 1
            scan_issue(f"อ่านหน่วยความจำของ process {name} (PID {pid}) ไม่สำเร็จ: {e}")
            continue
        stats["scanned"] += 1
        for match in matches:
            severity = match.meta.get("severity", "high")
            if severity not in ("high", "medium", "low"):
                severity = "high"
            findings.append({
                "sev": severity, "kind": "หน่วยความจำ", "target": f"{name} (PID {pid})",
                "why": f"YARA memory: {match.rule}",
            })

    if stats["attempted"] == 0:
        print("[+] ไม่มี process อื่นให้ตรวจหน่วยความจำ")
    else:
        print(f"[+] สแกนหน่วยความจำสำเร็จ {stats['scanned']}/{stats['attempted']} process "
              f"| ถูกปฏิเสธ {stats['denied']} | ผิดพลาด/หมดเวลา {stats['failed']}")
    return findings


def registry_run_entries():
    if not winreg:
        return
    keys = [(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM")]
    for hive, sub, label in keys:
        try:
            key = winreg.OpenKey(hive, sub)
        except FileNotFoundError:
            continue
        except OSError as error:
            scan_issue(f"เปิด Registry key ไม่สำเร็จ ({type(error).__name__})")
            continue
        try:
            with key as k:
                i = 0
                while True:
                    try:
                        name, val, _ = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    i += 1
                    yield hive, sub, label, name, str(val)
        except OSError as error:
            scan_issue(f"อ่าน Registry key ไม่สำเร็จ ({type(error).__name__})")
            continue


def extract_path(text):
    m = PATH_RE.search(os.path.expandvars(text))
    return m.group(0) if m else None


def scheduled_tasks():
    out = run(["schtasks", "/query", "/fo", "csv", "/v"], required=True)
    if out is None:
        return
    for row in csv.reader(io.StringIO(out)):
        if len(row) > 8 and row[1].startswith("\\"):
            for cell in row:
                p = extract_path(cell)
                if p:
                    yield row[1], p
                    break


def network_hits(con):
    hits = []
    out = run(["netstat", "-ano", "-p", "tcp"], required=True)
    if out is None:
        return hits
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[3] == "ESTABLISHED":
            remote = parts[2]
            ip = remote.rsplit(":", 1)[0].strip("[]")
            rows = con.execute("SELECT family,source FROM threat_iocs WHERE value=? AND kind='ip' AND state='active' ORDER BY confidence DESC", (ip,)).fetchall()
            if not rows:
                rows = con.execute("SELECT family,source FROM iocs WHERE value=? AND kind='ip'", (ip,)).fetchall()
                if rows and not ioc_is_active(con, ip, "ip"):
                    rows = []
            if rows:
                hits.append((int(parts[4]), ip, rows[0][0]))
    return hits


def dns_hits(con):
    dns_output = run(["ipconfig", "/displaydns"], required=True)
    if dns_output is None:
        return []
    seen = set(re.findall(r"[a-z0-9][a-z0-9.-]+\.[a-z]{2,}", dns_output.lower()))
    hosts = Path(os.environ.get("WINDIR", r"C:\Windows")) / r"System32\drivers\etc\hosts"
    try:
        seen |= set(re.findall(r"[a-z0-9][a-z0-9.-]+\.[a-z]{2,}", hosts.read_text(errors="ignore").lower()))
    except FileNotFoundError:
        pass
    except OSError as error:
        scan_issue(f"อ่านไฟล์ hosts ไม่สำเร็จ ({type(error).__name__})")
    found = []
    for d in seen:
        rows = con.execute("SELECT family,source FROM threat_iocs WHERE value=? AND kind='domain' AND state='active' ORDER BY confidence DESC", (d,)).fetchall()
        if not rows:
            row = con.execute("SELECT family,source FROM iocs WHERE value=? AND kind='domain'", (d,)).fetchone()
            if row and ioc_is_active(con, d, "domain"):
                rows = [row]
        if rows:
            found.append((d, rows[0][0], rows[0][1]))
    return found


def powershell_history():
    p = Path(os.environ.get("APPDATA", "")) / r"Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    res = []
    try:
        for n, line in enumerate(p.read_text(errors="ignore").splitlines(), 1):
            for rx, desc in PS_PATTERNS:
                if re.search(rx, line, re.I):
                    res.append((n, desc, line.strip()[:140]))
                    break
    except FileNotFoundError:
        pass
    except OSError as error:
        scan_issue(f"อ่าน PowerShell history ไม่สำเร็จ ({type(error).__name__})")
    return res


# ---------------------------------------------------------------- กักกัน / กำจัด
def load_index():
    return lq.load_index(QUAR_INDEX)


def quarantine_file(path, sha, why):
    return lq.quarantine_file(path, sha, why, QUAR_DIR, QUAR_INDEX)


def recover_quarantine():
    return lq.recover_index(QUAR_DIR, QUAR_INDEX)


def restore_file(item_id, destination=None):
    return lq.restore_file(item_id, QUAR_DIR, QUAR_INDEX, destination)


def delete_quarantined_file(item_id):
    return lq.delete_file(item_id, QUAR_DIR, QUAR_INDEX)


def cmd_quarantine(_args=None):
    idx = load_index()
    if not idx:
        print("ไม่มีรายการที่กักกัน")
    for qid, v in idx.items():
        print(f"{qid}  {v['original']}  ({'; '.join(v['why'])})")


def cmd_restore(args):
    try:
        target = restore_file(args.id, getattr(args, "destination", None))
    except (KeyError, OSError, RuntimeError, ValueError) as error:
        raise SystemExit(str(error)) from error
    print(f"[+] กู้ไฟล์กลับไปที่ {target}")


# ---------------------------------------------------------------- สแกนหลัก
def cmd_scan(args):
    if not IS_WIN:
        print("[!] เครื่องมือนี้ออกแบบสำหรับ Windows - บางส่วนจะข้ามไป")
    files_only = bool(getattr(args, "files_only", False))
    clean = bool(args.clean)
    deep_archives = bool(getattr(args, "deep_archives", False) or getattr(args, "full", False))
    if files_only and clean:
        raise SystemExit("โหมดสแกนไฟล์อัตโนมัติเป็นแบบดูอย่างเดียว; เลือกกักกันเองจากผลสแกน")
    if files_only and getattr(args, "full", False):
        raise SystemExit("เลือกได้เพียงโหมดสแกนไฟล์อัตโนมัติหรือสแกนทั้งไดรฟ์")
    if files_only and getattr(args, "paths", None):
        raise SystemExit("โหมดสแกนไฟล์อัตโนมัติใช้เฉพาะโฟลเดอร์ที่กำหนดไว้")
    if deep_archives:
        print("[!] โหมด archive ลึก: ใช้ขีดจำกัดที่ขยายเพิ่ม, รักษาพื้นที่ว่างอย่างน้อย 1 GiB; หยุดได้ทุกเมื่อ")
    SCAN_AUDIT.clear()
    SCAN_AUDIT.update(issues=0, details=[], files_analyzed=0, files_skipped=0,
                      archive={"archives": 0, "members_seen": 0, "expanded_bytes": 0},
                      memory={"attempted": 0, "scanned": 0, "denied": 0, "failed": 0})
    scan_id = uuid.uuid4().hex
    scan_started = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    try:
        luna_audit.record("scan.started", scan_id=scan_id)
    except OSError:
        print("[!] บันทึก scan audit ไม่สำเร็จ")
    if not IS_WIN:
        scan_issue("ไม่ใช่ Windows; การตรวจ process, registry และหน่วยความจำอาจไม่ครบ")
    con = db()
    last = con.execute("SELECT v FROM meta WHERE k='last_update'").fetchone()
    print(f"ฐานข้อมูลอัปเดตล่าสุด: {last[0] if last else 'ยังไม่เคยอัปเดต (รัน update ก่อน)'}")
    yara_available = bool(yara_rules())
    print("YARA:", "เปิดใช้งาน" if yara_available else "ไม่ได้ใช้ (pip install yara-python เพื่อเปิด)")
    if not yara_available:
        scan_issue("ไม่มี YARA rules หรือ yara-python; ข้ามการตรวจด้วยกฎและหน่วยความจำ")
    roots = [r"C:\\"] if args.full else (
        default_scan_dirs() if files_only else (args.paths or default_scan_dirs())
    )
    high_files, findings, archive_findings, file_hashes, file_metadata = {}, [], [], {}, {}

    stage_count = 1 if files_only else 5
    print(f"[1/{stage_count}] สแกนไฟล์ ({len(roots)} โฟลเดอร์)...")
    count, t0, STOP["flag"] = 0, time.time(), False
    for i, root in enumerate(roots, 1):
        rt, rc, last = time.time(), 0, time.time()
        print(f"      ▶ [{i}/{len(roots)}] เริ่ม: {root}")
        for f in walk_files([root], full_coverage=bool(getattr(args, "full", False))):
            if STOP["flag"]:
                break
            count += 1
            rc += 1
            PROGRESS.update(stage=f"[1/{stage_count}] สแกนไฟล์ ({i}/{len(roots)})", files=count, path=f)
            if time.time() - last >= 3:
                last = time.time()
                print(f"        … ตรวจแล้ว {count:,} ไฟล์ ({int(last - t0)} วิ) ตอนนี้: …{f[-80:]}")
            sev, why, sha, metadata = analyze_detailed(f, con)
            if sha:
                file_hashes[f] = sha
                file_metadata[f] = metadata
                SCAN_AUDIT["files_analyzed"] += 1
            elif Path(f).suffix.lower() not in ARCHIVE_EXT:
                SCAN_AUDIT["files_skipped"] += 1
            if sev:
                findings.append((sev, "ไฟล์", f, why))
                if sev == "high":
                    high_files[f] = (sha, why)
            if Path(f).suffix.lower() in ARCHIVE_EXT:
                if not sha:
                    try:
                        sha = sha256_of(f)
                        file_hashes[f] = sha
                        SCAN_AUDIT["files_analyzed"] += 1
                        SCAN_AUDIT["files_skipped"] = max(0, SCAN_AUDIT["files_skipped"] - 1)
                    except OSError as error:
                        scan_issue(f"คำนวณ SHA-256 ของ archive ไม่สำเร็จ ({type(error).__name__})")
                        SCAN_AUDIT["files_skipped"] += 1
                contained_findings = scan_archive(f, con, deep=deep_archives)
                for item in contained_findings:
                    item["container_sha256"] = sha
                archive_findings.extend(contained_findings)
        print(f"      ✔ จบ: {root} — {rc:,} ไฟล์ ใช้ {int(time.time() - rt)} วิ")
        if STOP["flag"]:
            print("[!] ผู้ใช้สั่งหยุดสแกนไฟล์ - ข้ามไปตรวจขั้นตอนที่เหลือ")
            break
    print(f"      รวมตรวจ {count:,} ไฟล์ ใช้ {int(time.time() - t0)} วิ")

    bad_pids, bad_reg, bad_tasks = {}, [], []
    if files_only:
        print("[+] โหมดสแกนไฟล์อัตโนมัติ: ข้ามการตรวจ process, memory, startup entries, network และ PowerShell")
    else:
        PROGRESS.update(stage="[2/5] ตรวจโปรเซสที่รันอยู่", path="")
        print("[2/5] ตรวจโปรเซสที่รันอยู่...")
        processes = list_processes()
        for p in processes:
            exe = p.get("ExecutablePath") or ""
            if exe and (exe in high_files or analyze(exe, con)[0] == "high"):
                bad_pids[p["ProcessId"]] = exe
                findings.append(("high", "โปรเซส", f"PID {p['ProcessId']} {exe}", ["รันไฟล์ที่เป็นอันตราย"]))
        for memory_finding in scan_process_memory(processes):
            findings.append((
                memory_finding["sev"], memory_finding["kind"], memory_finding["target"],
                [memory_finding["why"]],
            ))

        PROGRESS.update(stage="[3/5] ตรวจจุดฝังตัว", path="")
        print("[3/5] ตรวจจุดฝังตัว (Registry / Scheduled Task)...")
        for hive, sub, label, name, val in registry_run_entries():
            p = extract_path(val)
            if p and (p in high_files or (os.path.isfile(p) and analyze(p, con)[0] == "high")):
                bad_reg.append((hive, sub, name))
                findings.append(("high", "Registry Run", f"{label}\\{sub}\\{name} -> {p}", ["ชี้ไปยังมัลแวร์"]))
                if os.path.isfile(p) and p not in high_files:
                    high_files[p] = (sha256_of(p), ["ถูกอ้างอิงจากจุดฝังตัว"])
            elif p and user_writable(p):
                findings.append(("medium", "Registry Run", f"{label}\\{name} -> {p}", ["รันจากโฟลเดอร์ที่ผู้ใช้เขียนได้ (ตรวจสอบเอง)"]))
        for tname, p in scheduled_tasks():
            if p in high_files or (os.path.isfile(p) and analyze(p, con)[0] == "high"):
                bad_tasks.append(tname)
                findings.append(("high", "Scheduled Task", f"{tname} -> {p}", ["ชี้ไปยังมัลแวร์"]))
                if os.path.isfile(p) and p not in high_files:
                    high_files[p] = (sha256_of(p), ["ถูกอ้างอิงจาก Scheduled Task"])

        PROGRESS.update(stage="[4/5] ตรวจเครือข่าย / DNS", path="")
        print("[4/5] ตรวจการเชื่อมต่อเครือข่าย / DNS...")
        for pid, ip, fam in network_hits(con):
            findings.append(("high", "เครือข่าย", f"PID {pid} เชื่อมต่อ C2 {ip} ({fam})", ["IP อยู่ในรายการ C2"]))
            bad_pids.setdefault(pid, f"(เชื่อมต่อ {ip})")
        for d, fam, src in dns_hits(con):
            findings.append(("medium", "DNS/hosts", f"{d} ({fam}/{src})", ["เคยเข้าถึงโดเมนอันตราย - ควรเปลี่ยนรหัสผ่าน"]))

        PROGRESS.update(stage="[5/5] ตรวจประวัติ PowerShell", path="")
        print("[5/5] ตรวจประวัติ PowerShell...")
        for n, desc, line in powershell_history():
            findings.append(("medium", "PowerShell", f"PowerShell history line {n}", [desc]))

    if STOP["flag"]:
        scan_issue("หยุดการสแกนก่อนตรวจครบทุกขั้นตอน")
    PROGRESS.clear()
    saved_findings = []
    for severity, kind, target, reasons in findings:
        item = {"sev": severity, "kind": kind, "target": target, "why": "; ".join(reasons)}
        if kind == "ไฟล์" and target in file_hashes:
            item["sha256"] = file_hashes[target]
            item["analysis"] = file_metadata.get(target, {})
            item["risk_score"] = item["analysis"].get("risk_score", 0)
            item["risk_band"] = item["analysis"].get("risk_band", "CLEAN / UNKNOWN")
        saved_findings.append(item)
    saved_findings.extend(archive_findings)
    LAST_SCAN.clear()
    LAST_SCAN.update(
        scan_id=scan_id, started_at=scan_started,
        time=dt.datetime.now().astimezone().isoformat(timespec="seconds"), files=count, clean=clean,
        scope="files" if files_only else "system",
        deep_archives=deep_archives,
        findings=saved_findings, complete=SCAN_AUDIT["issues"] == 0, issues=SCAN_AUDIT["issues"],
        audit={"details": list(SCAN_AUDIT["details"]), "memory": dict(SCAN_AUDIT["memory"]),
               "files_analyzed": SCAN_AUDIT["files_analyzed"], "files_skipped": SCAN_AUDIT["files_skipped"],
               "archive": dict(SCAN_AUDIT["archive"])},
    )
    try:
        luna_audit.record("scan.finished", scan_id=scan_id,
                          result="complete" if LAST_SCAN["complete"] else "incomplete",
                          files_scanned=str(count), files_analyzed=str(SCAN_AUDIT["files_analyzed"]),
                          files_skipped=str(SCAN_AUDIT["files_skipped"]), issues=str(LAST_SCAN["issues"]))
    except OSError:
        print("[!] บันทึก scan audit ไม่สำเร็จ")
    totals = {level: sum(f["sev"] == level for f in saved_findings) for level in ("high", "medium", "low")}
    hist = []
    history_ok = True
    if HISTORY.exists():
        try:
            hist = json.loads(HISTORY.read_text(encoding="utf-8"))
            if not isinstance(hist, list):
                raise ValueError("รูปแบบประวัติไม่ใช่รายการ")
        except (OSError, ValueError) as e:
            history_ok = False
            print(f"[!] อ่านประวัติการสแกนไม่สำเร็จ จึงไม่เขียนทับไฟล์เดิม: {e}")
    if history_ok:
        hist.append({
            "scan_id": scan_id, "started_at": scan_started,
            "time": LAST_SCAN["time"], "files": count, "clean": clean, "scope": LAST_SCAN["scope"],
            "deep_archives": deep_archives,
            "complete": LAST_SCAN["complete"], "issues": LAST_SCAN["issues"], "audit": LAST_SCAN["audit"],
            **totals, "findings_total": len(LAST_SCAN["findings"]),
            "findings": LAST_SCAN["findings"][:100],
        })
        try:
            temp_history = HISTORY.with_suffix(".tmp")
            temp_history.write_text(json.dumps(hist[-30:], ensure_ascii=False), encoding="utf-8")
            temp_history.replace(HISTORY)
        except OSError as e:
            print(f"[!] บันทึกประวัติการสแกนไม่สำเร็จ: {e}")
    print(f"[+] สรุป: ตรวจ {count} ไฟล์ | HIGH {totals['high']} "
          f"| MEDIUM {totals['medium']} | LOW {totals['low']}")
    # ---- รายงาน
    print("\n" + "=" * 60)
    if not findings and not archive_findings:
        if LAST_SCAN["complete"]:
            print("ไม่พบภัยคุกคามที่ทราบในขอบเขตการสแกนนี้; ผลลบไม่ได้ยืนยันว่าเครื่องปลอดภัยทั้งหมด")
        else:
            print(f"ยังไม่พบภัยคุกคาม แต่สแกนไม่ครบ ({LAST_SCAN['issues']} รายการ); ตรวจบันทึกคำเตือนก่อนสรุปผล")
    for sev, kind, target, why in sorted(findings, key=lambda x: x[0] != "high"):
        print(f"[{sev.upper():6}] {kind}: {target}\n         เหตุผล: {'; '.join(why)}")
    for finding in sorted(archive_findings, key=lambda x: x["sev"] != "high"):
        print(f"[{finding['sev'].upper():6}] {finding['kind']}: {finding['target']}\n"
              f"         เหตุผล: {finding['why']} (กักกันทั้ง archive ได้จากตารางผลสแกน)")

    remediation_failures = 0
    if not clean:
        if high_files or bad_pids or bad_reg or bad_tasks:
            print("\nพบรายการ HIGH - รันซ้ำพร้อม --clean เพื่อกำจัด (กักกันไฟล์ ไม่ลบทิ้งทันที)")
    else:
        print("\n--- กำจัด ---")
        if archive_findings:
            print("[!] ผลตรวจพบภายใน archive จะแจ้งเตือนเท่านั้น; กักกันทั้ง archive ได้จากตารางผลสแกน")
        for pid, exe in bad_pids.items():
            if run(["taskkill", "/F", "/PID", str(pid)]) is None:
                remediation_failures += 1
            else:
                print(f"kill PID {pid}")
        for hive, sub, name in bad_reg:
            try:
                with winreg.OpenKey(hive, sub, 0, winreg.KEY_SET_VALUE) as k:
                    winreg.DeleteValue(k, name)
                print(f"ลบ Registry value: {name}")
            except OSError as e:
                print(f"ลบ {name} ไม่สำเร็จ (ต้องรันแบบ Administrator?): {e}")
                remediation_failures += 1
        for t in bad_tasks:
            if run(["schtasks", "/delete", "/tn", t, "/f"]) is None:
                remediation_failures += 1
            else:
                print(f"ลบ Scheduled Task: {t}")
        for path, (sha, why) in high_files.items():
            try:
                print(f"กักกัน {path} -> id {quarantine_file(path, sha, why)}")
            except (OSError, RuntimeError, ValueError) as e:
                print(f"กักกัน {path} ไม่สำเร็จ ({type(e).__name__})")
                remediation_failures += 1
        print("\nสำคัญ: ถ้าเคยติดจริง ให้เปลี่ยนรหัสผ่านทุกบัญชีจาก 'เครื่องอื่นที่สะอาด', เปิด 2FA, "
              "ออกจากระบบทุกอุปกรณ์ และเพิกถอน session ของ Discord/Google/Steam (มัลแวร์ขโมยรหัสไปแล้วก่อนถูกลบ)")
    con.close()
    if clean:
        try:
            luna_audit.record("remediation.finished", scan_id=scan_id,
                              result="complete" if remediation_failures == 0 else "partial")
        except OSError:
            print("[!] บันทึก remediation audit ไม่สำเร็จ")
    return bool(LAST_SCAN["complete"] and remediation_failures == 0)


def _ask_hook(args):
    if getattr(args, "ask", False) and sys.stdin and sys.stdin.isatty():
        ask_user(args)


def _find(path):
    return next((f for f in LAST_SCAN.get("findings", []) if f["kind"] == "ไฟล์" and f["target"] == path), None)


def remove_finding(path):
    """ผู้ใช้เลือกกักกันเอง - ทำได้เฉพาะไฟล์ที่อยู่ในผลสแกนล่าสุดเท่านั้น (กันถูกใช้ลบไฟล์มั่ว)"""
    f = next((item for item in LAST_SCAN.get("findings", [])
              if (item.get("kind") == "ไฟล์" and item.get("target") == path)
              or (item.get("kind") == "Archive member" and item.get("container") == path)), None)
    if not f:
        raise SystemExit("ไม่พบรายการนี้ในผลสแกนล่าสุด")
    expected = f.get("container_sha256") if f.get("kind") == "Archive member" else f.get("sha256")
    if not expected:
        raise SystemExit("ผลสแกนไม่มี SHA-256 ที่ยืนยันได้ กรุณาสแกนไฟล์นี้อีกครั้ง")
    sha = sha256_of(path)
    if sha.lower() != expected.lower():
        raise SystemExit("ไฟล์เปลี่ยนหลังการสแกน กรุณาสแกนใหม่ก่อนกักกัน")
    for p in list_processes():
        if (p.get("ExecutablePath") or "").lower() == path.lower():
            run(["taskkill", "/F", "/PID", str(p["ProcessId"])])
    qid = quarantine_file(path, sha, [f["why"]])
    LAST_SCAN["findings"].remove(f)
    print(f"[+] กักกัน {path} -> id {qid}")
    return qid


def allow_file(path):
    f = _find(path)
    if not f:
        raise SystemExit("ไม่พบรายการนี้ในผลสแกนล่าสุด")
    expected = f.get("sha256")
    if not expected or sha256_of(path).lower() != expected.lower():
        raise SystemExit("ไฟล์เปลี่ยนหลังการสแกน กรุณาสแกนใหม่ก่อนระบุว่าปลอดภัย")
    con = db()
    con.execute("INSERT OR REPLACE INTO allow VALUES(?,?)", (expected, path))
    con.commit()
    LAST_SCAN["findings"].remove(f)
    print(f"[+] ระบุว่าปลอดภัย: {path}")


def ask_user(args):
    """โหมด --ask: ถามทีละรายการที่เป็น MEDIUM/LOW"""
    for f in [x for x in LAST_SCAN.get("findings", []) if x["kind"] == "ไฟล์" and x["sev"] != "high"]:
        print(f"\n[{f['sev'].upper()}] {f['target']}\n  เหตุผล: {f['why']}")
        a = input("  กักกันไหม? [y=กักกัน / n=ข้าม / a=ปลอดภัย]: ").strip().lower()
        if a == "y":
            remove_finding(f["target"])
        elif a == "a":
            allow_file(f["target"])


def cmd_schedule(_args=None):
    exe = sys.executable
    print("รันคำสั่งนี้ใน Command Prompt (Admin) เพื่ออัปเดตฐานข้อมูลทุกวันเวลา 09:00:\n")
    print(f'schtasks /create /tn "LunaGuard Update" /sc daily /st 09:00 /tr "\\"{exe}\\" \\"{Path(__file__).resolve()}\\" update"')


def main():
    ap = argparse.ArgumentParser(description="Luna Guard")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("update").set_defaults(fn=cmd_update)
    s = sub.add_parser("scan")
    s.add_argument("--clean", action="store_true")
    s.add_argument("--ask", action="store_true", help="ถามผู้ใช้ทีละรายการที่เป็น MEDIUM/LOW")
    s.add_argument("--full", action="store_true")
    s.add_argument("--files-only", action="store_true", help="สแกนไฟล์ในโฟลเดอร์ผู้ใช้ที่พบบ่อย โดยไม่ตรวจส่วนระบบ")
    s.add_argument("--deep-archives", action="store_true", help="ตรวจ archive ด้วยขีดจำกัดที่ขยายเพิ่มและรักษาพื้นที่ว่าง 1 GiB")
    s.add_argument("--paths", nargs="*")
    s.set_defaults(fn=cmd_scan)
    sub.add_parser("quarantine").set_defaults(fn=cmd_quarantine)
    r = sub.add_parser("restore")
    r.add_argument("id")
    r.set_defaults(fn=cmd_restore)
    a = sub.add_parser("add-hash")
    a.add_argument("sha256")
    a.set_defaults(fn=cmd_add_hash)
    sub.add_parser("schedule").set_defaults(fn=cmd_schedule)
    args = ap.parse_args()
    result = args.fn(args)
    _ask_hook(args)
    return 1 if result is False else 0


if __name__ == "__main__":
    raise SystemExit(main())
