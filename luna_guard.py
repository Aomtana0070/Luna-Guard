#!/usr/bin/env python3
"""
Luna Guard - ตัวตรวจจับและกำจัด XWorm + มัลแวร์ที่แฝงมากับกลโกง "MrBeast"
สำหรับ Windows (Python 3.9+, ไม่ต้องติดตั้งไลบรารีเพิ่ม)

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
หรือ  setx ABUSECH_KEY "คีย์ของคุณ"  (เปิด Command Prompt ใหม่หลังตั้ง)
"""
import argparse
import csv
import datetime as dt
import hashlib
import ipaddress
import io
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import time
import urllib.parse
import urllib.error
import urllib.request
from pathlib import Path

try:
    import winreg  # Windows เท่านั้น
except ImportError:
    winreg = None

IS_WIN = os.name == "nt"
APP_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "LunaGuard"
DB_PATH = APP_DIR / "threats.db"
QUAR_DIR = APP_DIR / "quarantine"
QUAR_INDEX = QUAR_DIR / "index.json"
MAX_FILE = 50 * 1024 * 1024
TAGS = ["XWorm", "MrBeast"]  # แท็กที่ดึงจาก MalwareBazaar / ThreatFox

# โดเมนหลอกลวงที่รู้จัก (เพิ่มเองได้ด้วยการแก้ลิสต์นี้)
SEED_DOMAINS = ["beastxm.com", "beast-days.com"]

SCRIPT_EXT = {".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js"}
SYSTEM_NAMES = {
    "csrss.exe", "svchost.exe", "lsass.exe", "winlogon.exe", "explorer.exe",
    "services.exe", "smss.exe", "taskhost.exe", "taskhostw.exe", "conhost.exe",
    "wininit.exe", "spoolsv.exe", "dllhost.exe", "runtimebroker.exe",
    "searchindexer.exe", "wmpnscfg.exe", "ctfmon.exe", "sipnotify.exe",
}
STRONG_PATTERNS = [rb"xworm", rb"<xwormmm>", rb"xklog"]
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
        CREATE TABLE IF NOT EXISTS iocs(value TEXT PRIMARY KEY, kind TEXT, family TEXT, source TEXT);
        CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
        CREATE TABLE IF NOT EXISTS allow(sha256 TEXT PRIMARY KEY, path TEXT);
    """)
    for d in SEED_DOMAINS:
        con.execute("INSERT OR IGNORE INTO iocs VALUES(?,?,?,?)", (d, "domain", "MrBeast-scam", "seed"))
    con.commit()
    return con


def http(url, data=None, headers=None, timeout=90):
    req = urllib.request.Request(url, data=data, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


CONFIG = APP_DIR / "config.json"
HISTORY = APP_DIR / "history.json"
LAST_SCAN = {}
PROGRESS = {}
STOP = {"flag": False}
SKIP_DIRS = {"cache", "code cache", "gpucache", "node_modules", ".git", "__pycache__", "$recycle.bin",
             "system volume information", "indexeddb", "service worker", "cache_data"}


def get_key():
    """คีย์ abuse.ch: อ่านจาก env ก่อน ถ้าไม่มีอ่านจาก config.json (ตั้งผ่าน GUI ได้)"""
    k = os.environ.get("ABUSECH_KEY", "").strip()
    if k:
        return k
    try:
        return json.loads(CONFIG.read_text(encoding="utf-8")).get("abusech_key", "").strip()
    except Exception:
        return ""


def save_key(k):
    APP_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG.write_text(json.dumps({"abusech_key": k.strip()}), encoding="utf-8")


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
    for d in (base, APP_DIR / "rules"):
        if d.is_dir():
            for f in d.glob("*.yar"):
                files[f"{d.name}_{f.stem}"] = str(f)
    if not files:
        return None
    try:
        _YARA["rules"] = yara.compile(filepaths=files)
    except Exception as e:
        print(f"[!] คอมไพล์กฎ YARA ไม่ผ่าน: {e}")
    return _YARA["rules"]


def yara_scan(data):
    r = yara_rules()
    if not r:
        return []
    try:
        return [{"rule": m.rule, "severity": m.meta.get("severity", "high")} for m in r.match(data=data, timeout=30)]
    except Exception:
        return []


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


def fetch_mb(con, tag, hdr):
    """ดึงแฮชจาก MalwareBazaar ทั้งแบบ tag (ตัวพิมพ์ต่าง ๆ) และแบบ signature พร้อมรายงานสถานะทุกครั้ง"""
    added, successful = 0, False
    for q, k, v in dict.fromkeys([("get_taginfo", "tag", tag), ("get_taginfo", "tag", tag.lower()), ("get_siginfo", "signature", tag)]):
        try:
            body = urllib.parse.urlencode({"query": q, k: v, "limit": 1000}).encode()
            res = json.loads(update_http("https://mb-api.abuse.ch/api/v1/", body, hdr))
        except (OSError, ValueError) as e:
            print(f"[!] MalwareBazaar {q} {v}: เรียกไม่สำเร็จ - {e}")
            continue
        if not isinstance(res, dict):
            print(f"[!] MalwareBazaar {q} {v}: รูปแบบคำตอบไม่ถูกต้อง")
            continue
        rows = feed_rows(res.get("data"))
        got = 0
        for row in rows:
            sha = str(row.get("sha256_hash", "")).lower()
            if re.fullmatch(r"[0-9a-f]{64}", sha):
                got += con.execute("INSERT OR IGNORE INTO hashes VALUES(?,?,?)", (sha, tag, "MalwareBazaar")).rowcount
        st = str(res.get("query_status", "unknown")).lower()
        successful |= st in ("ok", "no_results", "no_result")
        print(f"[{'+' if st in ('ok', 'no_results', 'no_result') else '!'}] "
              f"MalwareBazaar {q} {v}: สถานะ={st} พบ {len(rows)} รายการ (ใหม่ {got})")
        added += got
    return added, successful


def cmd_update(_args=None):
    key = get_key()
    hdr = {"Auth-Key": key} if key else {}
    con = db()
    added_h = added_i = 0
    successful_sources = []
    if not key:
        print("[!] ยังไม่ได้ตั้ง ABUSECH_KEY - abuse.ch ต้องใช้คีย์ (ฟรี) ที่ https://auth.abuse.ch")
    for tag in TAGS:
        new_hashes, ok = fetch_mb(con, tag, hdr)  # MalwareBazaar: แฮชของไฟล์
        added_h += new_hashes
        if ok and "MalwareBazaar" not in successful_sources:
            successful_sources.append("MalwareBazaar")
    try:  # ThreatFox: IOC ล่าสุดทั้งหมด และแฮชที่เชื่อมโยงกับ IOC
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
                if val:
                    family = str(row.get("malware_printable") or row.get("malware") or "unknown")[:100]
                    cur = con.execute("INSERT OR IGNORE INTO iocs VALUES(?,?,?,?)",
                                      (val, kind, family, "ThreatFox"))
                    added_i += cur.rowcount
                for sample in feed_rows(row.get("malware_samples")):
                    sha = str(sample.get("sha256_hash", "")).lower()
                    if re.fullmatch(r"[0-9a-f]{64}", sha):
                        added_h += con.execute(
                            "INSERT OR IGNORE INTO hashes VALUES(?,?,?)",
                            (sha, str(row.get("malware_printable") or row.get("malware") or "ThreatFox")[:100],
                             "ThreatFox"),
                        ).rowcount
        print(f"[{'+' if status in ('ok', 'no_results', 'no_result') else '!'}] ThreatFox: "
              f"สถานะ={status} พบ {len(rows)} รายการ (เพิ่ม IOC/แฮชที่เชื่อมโยงแล้ว)")
    except (OSError, ValueError) as e:
        print(f"[!] ThreatFox ล้มเหลว: {e}")
    try:  # URLhaus: โฮสต์ที่กำลังแจกมัลแวร์หรือเพิ่มใน 48 ชั่วโมงล่าสุด
        text = update_http("https://urlhaus.abuse.ch/downloads/hostfile/", headers=hdr).decode("utf-8", "ignore")
        got = 0
        for line in text.splitlines():
            parts = line.split()
            if len(parts) >= 2 and not line.startswith("#"):
                val, kind = norm_ioc(parts[1], "domain")
                if val:
                    got += con.execute("INSERT OR IGNORE INTO iocs VALUES(?,?,?,?)",
                                       (val, kind, "URLhaus", "URLhaus")).rowcount
        added_i += got
        successful_sources.append("URLhaus")
        print(f"[+] URLhaus: เพิ่มโดเมน {got} จาก host feed")
    except (OSError, ValueError) as e:
        print(f"[!] URLhaus ล้มเหลว: {e}")
    if successful_sources:
        con.execute("INSERT OR REPLACE INTO meta VALUES('last_update',?)",
                    (dt.datetime.now().isoformat(timespec="seconds"),))
    else:
        print("[!] ทุกแหล่งข้อมูลล้มเหลว - ไม่เปลี่ยนเวลาอัปเดตล่าสุด")
    con.commit()
    th = con.execute("SELECT COUNT(*) FROM hashes").fetchone()[0]
    ti = con.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
    if successful_sources:
        print(f"[+] อัปเดตฐานข้อมูลสำเร็จ ({', '.join(successful_sources)}): "
              f"เพิ่มแฮช {added_h}, IOC {added_i} | รวม แฮช {th}, IOC {ti}")
    else:
        print(f"[!] อัปเดตฐานข้อมูลไม่สำเร็จ: ทุกแหล่งล้มเหลว | "
              f"แฮช {th}, IOC {ti} (คงข้อมูลเดิมไว้)")
    con.close()


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


def user_writable(p):
    p = p.lower().replace("/", "\\")
    return any(s in p for s in ("\\appdata\\", "\\temp\\", "\\programdata\\", "\\users\\public\\", "\\downloads\\"))


def in_windows_dir(p):
    win = os.environ.get("WINDIR", r"C:\Windows").lower()
    return p.lower().replace("/", "\\").startswith(win.replace("/", "\\") + "\\")


def analyze(path, con):
    """คืน (severity, [เหตุผล], sha256) ; severity = 'high' | 'medium' | None"""
    try:
        size = os.path.getsize(path)
        if size > MAX_FILE or size < 64:
            return None, [], ""
        if Path(path).suffix.lower() not in SCRIPT_EXT:  # ข้ามไฟล์ที่ไม่ใช่โปรแกรม (เร็วขึ้นมาก)
            with open(path, "rb") as fh:
                if fh.read(2) != b"MZ":
                    return None, [], ""
        sha = sha256_of(path)
    except OSError:
        return None, [], ""
    row = con.execute("SELECT family FROM hashes WHERE sha256=?", (sha,)).fetchone()
    if row:
        return "high", [f"แฮชตรงกับมัลแวร์ที่รู้จัก ({row[0]})"], sha
    if con.execute("SELECT 1 FROM allow WHERE sha256=?", (sha,)).fetchone():  # ผู้ใช้ยืนยันว่าปลอดภัย (แฮชในฐานข้อมูลมัลแวร์ชนะเสมอ)
        return None, [], sha
    ext = Path(path).suffix.lower()
    if ext not in SCRIPT_EXT:
        return None, [], sha
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return None, [], sha
    ym = yara_scan(data)
    ywhy = [f"YARA: {m['rule']}" for m in ym]
    rk = {"high": 3, "medium": 2, "low": 1}
    ysev = max((m["severity"] for m in ym), key=lambda x: rk.get(x, 3), default=None)
    score, why = 0, []
    is_pe = data[:2] == b"MZ"
    if is_pe:
        low = data.lower()
        for pat in STRONG_PATTERNS:
            if pat in low or pat.decode().encode("utf-16le") in low:
                score += 5
                why.append(f"พบสตริงเฉพาะของ XWorm ({pat.decode()})")
                break
        if Path(path).name.lower() in SYSTEM_NAMES and not in_windows_dir(path):
            score += 3
            why.append("ชื่อเลียนแบบไฟล์ระบบแต่อยู่นอกโฟลเดอร์ Windows")
        if score:  # เกณฑ์เสริม นับเมื่อมีสัญญาณหลักอยู่แล้วเท่านั้น (กัน false positive)
            if b"mscoree.dll" in data and b"BSJB" in data:
                score += 1
                why.append("เป็นไฟล์ .NET")
            if user_writable(path):
                score += 1
                why.append("อยู่ในโฟลเดอร์ที่ผู้ใช้เขียนได้ (Temp/AppData)")
    if ysev == "high" or score >= 5:
        return "high", ywhy + why, sha
    if ysev == "medium" or score >= 3:
        return "medium", ywhy + why, sha
    if ysev == "low":
        return "low", ywhy + why, sha
    return None, [], sha


# ---------------------------------------------------------------- ตัวเก็บข้อมูลระบบ
def run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=120, errors="ignore",
                              stdin=subprocess.DEVNULL, creationflags=0x08000000 if IS_WIN else 0).stdout
    except Exception:
        return ""


def default_scan_dirs():
    e = os.environ.get
    dirs = [e("TEMP"), e("APPDATA"), e("LOCALAPPDATA"), e("PROGRAMDATA"),
            r"C:\Users\Public", str(Path.home() / "Downloads"),
            str(Path(e("APPDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\Startup")]
    return [d for d in dict.fromkeys(dirs) if d and os.path.isdir(d)]


def walk_files(roots):
    skip = {str(APP_DIR).lower()}
    for root in roots:
        for dp, dn, fn in os.walk(root):
            if dp.lower() in skip or in_windows_dir(dp) or "\\windows defender" in dp.lower():
                dn[:] = []
                continue
            dn[:] = [d for d in dn if d.lower() not in SKIP_DIRS]
            for n in fn:
                yield os.path.join(dp, n)


def list_processes():
    out = run(["powershell", "-NoProfile", "-Command",
               "Get-CimInstance Win32_Process | Select ProcessId,Name,ExecutablePath | ConvertTo-Json"])
    try:
        data = json.loads(out)
        return data if isinstance(data, list) else [data]
    except Exception:
        return []


def registry_run_entries():
    if not winreg:
        return
    keys = [(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM")]
    for hive, sub, label in keys:
        try:
            with winreg.OpenKey(hive, sub) as k:
                i = 0
                while True:
                    name, val, _ = winreg.EnumValue(k, i)
                    i += 1
                    yield hive, sub, label, name, str(val)
        except OSError:
            continue


def extract_path(text):
    m = PATH_RE.search(os.path.expandvars(text))
    return m.group(0) if m else None


def scheduled_tasks():
    out = run(["schtasks", "/query", "/fo", "csv", "/v"])
    for row in csv.reader(io.StringIO(out)):
        if len(row) > 8 and row[1].startswith("\\"):
            for cell in row:
                p = extract_path(cell)
                if p:
                    yield row[1], p
                    break


def network_hits(con):
    hits = []
    out = run(["netstat", "-ano", "-p", "tcp"])
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[3] == "ESTABLISHED":
            ip = parts[2].rsplit(":", 1)[0]
            row = con.execute("SELECT family,source FROM iocs WHERE value=? AND kind='ip'", (ip,)).fetchone()
            if row:
                hits.append((int(parts[4]), ip, row[0]))
    return hits


def dns_hits(con):
    seen = set(re.findall(r"[a-z0-9][a-z0-9.-]+\.[a-z]{2,}", run(["ipconfig", "/displaydns"]).lower()))
    hosts = Path(os.environ.get("WINDIR", r"C:\Windows")) / r"System32\drivers\etc\hosts"
    try:
        seen |= set(re.findall(r"[a-z0-9][a-z0-9.-]+\.[a-z]{2,}", hosts.read_text(errors="ignore").lower()))
    except OSError:
        pass
    found = []
    for d in seen:
        row = con.execute("SELECT family,source FROM iocs WHERE value=? AND kind='domain'", (d,)).fetchone()
        if row:
            found.append((d, row[0], row[1]))
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
    except OSError:
        pass
    return res


# ---------------------------------------------------------------- กักกัน / กำจัด
def load_index():
    try:
        return json.loads(QUAR_INDEX.read_text(encoding="utf-8"))
    except Exception:
        return {}


def quarantine_file(path, sha, why):
    QUAR_DIR.mkdir(parents=True, exist_ok=True)
    qid = f"{dt.datetime.now():%Y%m%d%H%M%S}_{sha[:8]}"
    dest = QUAR_DIR / f"{qid}.quar"
    shutil.move(path, dest)
    idx = load_index()
    idx[qid] = {"original": path, "sha256": sha, "why": why}
    QUAR_INDEX.write_text(json.dumps(idx, indent=2, ensure_ascii=False), encoding="utf-8")
    return qid


def cmd_quarantine(_args=None):
    idx = load_index()
    if not idx:
        print("ไม่มีรายการที่กักกัน")
    for qid, v in idx.items():
        print(f"{qid}  {v['original']}  ({'; '.join(v['why'])})")


def cmd_restore(args):
    idx = load_index()
    v = idx.get(args.id)
    if not v:
        sys.exit("ไม่พบรหัสนี้")
    shutil.move(QUAR_DIR / f"{args.id}.quar", v["original"])
    del idx[args.id]
    QUAR_INDEX.write_text(json.dumps(idx, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[+] กู้ไฟล์กลับไปที่ {v['original']}")


# ---------------------------------------------------------------- สแกนหลัก
def cmd_scan(args):
    if not IS_WIN:
        print("[!] เครื่องมือนี้ออกแบบสำหรับ Windows - บางส่วนจะข้ามไป")
    con = db()
    last = con.execute("SELECT v FROM meta WHERE k='last_update'").fetchone()
    print(f"ฐานข้อมูลอัปเดตล่าสุด: {last[0] if last else 'ยังไม่เคยอัปเดต (รัน update ก่อน)'}")
    print("YARA:", "เปิดใช้งาน" if yara_rules() else "ไม่ได้ใช้ (pip install yara-python เพื่อเปิด)")
    roots = [r"C:\\"] if args.full else (args.paths or default_scan_dirs())
    high_files, findings = {}, []

    print(f"[1/5] สแกนไฟล์ ({len(roots)} โฟลเดอร์)...")
    count, t0, STOP["flag"] = 0, time.time(), False
    for i, root in enumerate(roots, 1):
        rt, rc, last = time.time(), 0, time.time()
        print(f"      ▶ [{i}/{len(roots)}] เริ่ม: {root}")
        for f in walk_files([root]):
            if STOP["flag"]:
                break
            count += 1
            rc += 1
            PROGRESS.update(stage=f"[1/5] สแกนไฟล์ ({i}/{len(roots)})", files=count, path=f)
            if time.time() - last >= 3:
                last = time.time()
                print(f"        … ตรวจแล้ว {count:,} ไฟล์ ({int(last - t0)} วิ) ตอนนี้: …{f[-80:]}")
            sev, why, sha = analyze(f, con)
            if sev:
                findings.append((sev, "ไฟล์", f, why))
                if sev == "high":
                    high_files[f] = (sha, why)
        print(f"      ✔ จบ: {root} — {rc:,} ไฟล์ ใช้ {int(time.time() - rt)} วิ")
        if STOP["flag"]:
            print("[!] ผู้ใช้สั่งหยุดสแกนไฟล์ - ข้ามไปตรวจขั้นตอนที่เหลือ")
            break
    print(f"      รวมตรวจ {count:,} ไฟล์ ใช้ {int(time.time() - t0)} วิ")

    PROGRESS.update(stage="[2/5] ตรวจโปรเซสที่รันอยู่", path="")
    print("[2/5] ตรวจโปรเซสที่รันอยู่...")
    bad_pids = {}
    for p in list_processes():
        exe = p.get("ExecutablePath") or ""
        if exe and (exe in high_files or analyze(exe, con)[0] == "high"):
            bad_pids[p["ProcessId"]] = exe
            findings.append(("high", "โปรเซส", f"PID {p['ProcessId']} {exe}", ["รันไฟล์ที่เป็นอันตราย"]))

    PROGRESS.update(stage="[3/5] ตรวจจุดฝังตัว", path="")
    print("[3/5] ตรวจจุดฝังตัว (Registry / Scheduled Task)...")
    bad_reg, bad_tasks = [], []
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
        findings.append(("medium", "PowerShell", f"บรรทัด {n}: {line}", [desc]))

    PROGRESS.clear()
    LAST_SCAN.clear()
    LAST_SCAN.update(time=dt.datetime.now().isoformat(timespec="seconds"), files=count, clean=bool(args.clean),
                     findings=[{"sev": a, "kind": b, "target": c, "why": "; ".join(d)} for a, b, c, d in findings])
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
        totals = {level: sum(f[0] == level for f in findings) for level in ("high", "medium", "low")}
        hist.append({
            "time": LAST_SCAN["time"], "files": count, "clean": bool(args.clean),
            **totals, "findings_total": len(LAST_SCAN["findings"]),
            "findings": LAST_SCAN["findings"][:100],
        })
        try:
            temp_history = HISTORY.with_suffix(".tmp")
            temp_history.write_text(json.dumps(hist[-30:], ensure_ascii=False), encoding="utf-8")
            temp_history.replace(HISTORY)
        except OSError as e:
            print(f"[!] บันทึกประวัติการสแกนไม่สำเร็จ: {e}")
    print(f"[+] สรุป: ตรวจ {count} ไฟล์ | HIGH {sum(f[0]=='high' for f in findings)} "
          f"| MEDIUM {sum(f[0]=='medium' for f in findings)} | LOW {sum(f[0]=='low' for f in findings)}")
    # ---- รายงาน
    print("\n" + "=" * 60)
    if not findings:
        print("ไม่พบสิ่งผิดปกติ (แต่ไม่ได้การันตีว่าสะอาด 100%)")
    for sev, kind, target, why in sorted(findings, key=lambda x: x[0] != "high"):
        print(f"[{sev.upper():6}] {kind}: {target}\n         เหตุผล: {'; '.join(why)}")

    if not args.clean:
        if high_files or bad_pids or bad_reg or bad_tasks:
            print("\nพบรายการ HIGH - รันซ้ำพร้อม --clean เพื่อกำจัด (กักกันไฟล์ ไม่ลบทิ้งทันที)")
    else:
        print("\n--- กำจัด ---")
        for pid, exe in bad_pids.items():
            run(["taskkill", "/F", "/PID", str(pid)])
            print(f"kill PID {pid}")
        for hive, sub, name in bad_reg:
            try:
                with winreg.OpenKey(hive, sub, 0, winreg.KEY_SET_VALUE) as k:
                    winreg.DeleteValue(k, name)
                print(f"ลบ Registry value: {name}")
            except OSError as e:
                print(f"ลบ {name} ไม่สำเร็จ (ต้องรันแบบ Administrator?): {e}")
        for t in bad_tasks:
            run(["schtasks", "/delete", "/tn", t, "/f"])
            print(f"ลบ Scheduled Task: {t}")
        for path, (sha, why) in high_files.items():
            try:
                print(f"กักกัน {path} -> id {quarantine_file(path, sha, why)}")
            except OSError as e:
                print(f"กักกัน {path} ไม่สำเร็จ: {e}")
        print("\nสำคัญ: ถ้าเคยติดจริง ให้เปลี่ยนรหัสผ่านทุกบัญชีจาก 'เครื่องอื่นที่สะอาด', เปิด 2FA, "
              "ออกจากระบบทุกอุปกรณ์ และเพิกถอน session ของ Discord/Google/Steam (มัลแวร์ขโมยรหัสไปแล้วก่อนถูกลบ)")
    con.close()


def _ask_hook(args):
    if getattr(args, "ask", False) and sys.stdin and sys.stdin.isatty():
        ask_user(args)


def _find(path):
    return next((f for f in LAST_SCAN.get("findings", []) if f["kind"] == "ไฟล์" and f["target"] == path), None)


def remove_finding(path):
    """ผู้ใช้เลือกกักกันเอง - ทำได้เฉพาะไฟล์ที่อยู่ในผลสแกนล่าสุดเท่านั้น (กันถูกใช้ลบไฟล์มั่ว)"""
    f = _find(path)
    if not f:
        raise SystemExit("ไม่พบรายการนี้ในผลสแกนล่าสุด")
    sha = sha256_of(path)
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
    con = db()
    con.execute("INSERT OR REPLACE INTO allow VALUES(?,?)", (sha256_of(path), path))
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
    args.fn(args)
    _ask_hook(args)


if __name__ == "__main__":
    main()
