#!/usr/bin/env python3
"""Luna Guard Dashboard - เซิร์ฟเวอร์ภายในเครื่อง (127.0.0.1) + หน้า dashboard.html  รัน: python luna_dashboard.py"""
import argparse, contextlib, ctypes, datetime as dt, json, os, re, secrets, shutil, subprocess, sys, tempfile, threading, time, webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
import luna_guard as lg
import luna_audit

BASE = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
S = {"job": None, "last_job": None, "log": [], "log_base": 0, "self": None, "history_error": None}
TOKEN = secrets.token_urlsafe(16)
LANGUAGES = {"th", "en", "zh-CN"}
LANGUAGE_FILE = lg.APP_DIR / "settings.json"
DEFENDER_STATUS = {"checked": 0.0, "value": {"available": False}}
RECOVERY_CHECKED = False
MAX_API_BODY_BYTES = 64 * 1024
API_RATE_WINDOW_SECONDS = 60
API_RATE_LIMIT = {"GET": 120, "POST": 30}
API_REQUESTS = {}
API_REQUESTS_LOCK = threading.Lock()
LOG_LOCK = threading.Lock()
JOB_LOCK = threading.Lock()
MAX_APP_LOG_LINES = 2000


def get_language():
    try:
        settings = json.loads(LANGUAGE_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return "th"
    except (OSError, ValueError) as e:
        log(f"[!] อ่านการตั้งค่าภาษาไม่สำเร็จ: {e}")
        return "th"
    language = settings.get("language") if isinstance(settings, dict) else None
    return language if language in LANGUAGES else "th"


def set_language(language):
    if not isinstance(language, str) or language not in LANGUAGES:
        raise ValueError("unsupported language")
    lg.APP_DIR.mkdir(parents=True, exist_ok=True)
    current = {}
    try:
        current = json.loads(LANGUAGE_FILE.read_text(encoding="utf-8"))
        if not isinstance(current, dict):
            current = {}
    except FileNotFoundError:
        pass
    except json.JSONDecodeError as e:
        log(f"[!] การตั้งค่าภาษาเดิมอ่านไม่ได้ จะสร้างการตั้งค่าใหม่: {e}")
    current["language"] = language
    fd, temp_name = tempfile.mkstemp(prefix="settings-", suffix=".tmp", dir=lg.APP_DIR)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(current, stream, ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())
        Path(temp_name).replace(LANGUAGE_FILE)
    finally:
        Path(temp_name).unlink(missing_ok=True)


def get_onboarding_complete():
    try:
        settings = json.loads(LANGUAGE_FILE.read_text(encoding="utf-8"))
        return isinstance(settings, dict) and settings.get("onboarding_complete") is True
    except (FileNotFoundError, OSError, ValueError):
        return False


def set_onboarding_complete(complete):
    if complete is not True:
        raise ValueError("onboarding completion must be true")
    lg.APP_DIR.mkdir(parents=True, exist_ok=True)
    settings = {}
    try:
        settings = json.loads(LANGUAGE_FILE.read_text(encoding="utf-8"))
        if not isinstance(settings, dict):
            settings = {}
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    settings["onboarding_complete"] = True
    fd, temp_name = tempfile.mkstemp(prefix="settings-", suffix=".tmp", dir=lg.APP_DIR)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(settings, stream, ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())
        Path(temp_name).replace(LANGUAGE_FILE)
    finally:
        Path(temp_name).unlink(missing_ok=True)


def check_quarantine_recovery():
    global RECOVERY_CHECKED
    if RECOVERY_CHECKED:
        return []
    RECOVERY_CHECKED = True
    try:
        actions = lg.recover_quarantine()
        for action in actions:
            luna_audit.record("quarantine.recovery", quarantine_id=action.get("id", ""),
                               result=action.get("result", "unknown"))
        return actions
    except (OSError, RuntimeError, ValueError) as error:
        RECOVERY_CHECKED = False
        log(f"[!] ตรวจ recovery ของ Quarantine ไม่สำเร็จ ({type(error).__name__})")
        return []


def log(line):
    if line.strip():
        line = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", str(line)).strip()
        for secret in (TOKEN, lg.get_key()):
            if secret:
                line = line.replace(secret, "[REDACTED]")
        line = re.sub(r"(?i)(https?://)[^/@\s:]+:[^/@\s]+@", r"\1[REDACTED]@", line)
        line = re.sub(r"(?i)([?&](?:token|api[_-]?key|auth[_-]?key|password|secret)=)[^&#\s]+", r"\1[REDACTED]", line)
        l = ("high" if line.startswith("[HIGH") else "med" if line.startswith("[MEDIUM") else
             "ok" if line.startswith(("[+]", "[PASS")) else "warn" if line.startswith(("[!]", "[FAIL")) else "info")
        with LOG_LOCK:
            S["log"].append({"t": time.strftime("%H:%M:%S"), "l": l, "m": line})
            extra = len(S["log"]) - MAX_APP_LOG_LINES
            if extra > 0:
                del S["log"][:extra]
                S["log_base"] += extra


def log_since(cursor):
    with LOG_LOCK:
        base = S["log_base"]
        current = base + len(S["log"])
        start = max(cursor - base, 0)
        return {"lines": list(S["log"][start:]), "next": current, "dropped": cursor < base}


class W:
    def __init__(s): s.b = ""
    def write(s, t):
        s.b += t
        while "\n" in s.b:
            ln, s.b = s.b.split("\n", 1); log(ln)
    def flush(s): pass


def start(name, fn):
    with JOB_LOCK:
        if S["job"]:
            return False
        S["job"] = name
    def w():
        succeeded = False
        detail = None
        try:
            with contextlib.redirect_stdout(W()):
                result = fn()
            succeeded = result is not False
            if not succeeded:
                detail = "incomplete_or_source_failure"
        except SystemExit as error:
            detail = type(error).__name__
            log(f"[!] งาน '{name}' ถูกยุติ: {error}")
        except Exception as error:
            detail = type(error).__name__
            log(f"[!] งาน '{name}' ล้มเหลว ({detail})")
        with JOB_LOCK:
            S["job"] = None
            S["last_job"] = {"name": name, "success": succeeded, "time": dt.datetime.now().astimezone().isoformat(timespec="seconds")}
        if succeeded:
            log(f"[+] งาน '{name}' เสร็จสิ้น")
        else:
            log(f"[!] งาน '{name}' เสร็จโดยไม่สำเร็จ ({detail or 'operation_failed'})")
    try:
        threading.Thread(target=w, daemon=True).start()
    except RuntimeError:
        with JOB_LOCK:
            S["job"] = None
        log(f"[!] งาน '{name}' เริ่มไม่ได้")
        return False
    return True


def selftest():
    con, d, res = lg.db(), Path(tempfile.mkdtemp(prefix="lunatest_")), []
    def chk(n, ok):
        res.append({"name": n, "ok": bool(ok)}); print(("[PASS] " if ok else "[FAIL] ") + n)
    bad, good, ps = d / "svc.exe", d / "ok.exe", d / "l.ps1"
    bad.write_bytes(b"MZ" + b"\0" * 60 + b"mscoree.dll BSJB " + "<Xwormmm>".encode("utf-16le"))
    good.write_bytes(b"MZ" + b"A" * 300)
    ps.write_bytes(b'(New-Object Net.WebClient).DownloadString("http://x");[Convert]::FromBase64String($a);-WindowStyle Hidden')
    chk("ตรวจจับตัวอย่างจำลอง XWorm", lg.analyze(str(bad), con)[0] == "high")
    chk("ไม่แจ้งผิดกับไฟล์ปกติ", lg.analyze(str(good), con)[0] is None)
    chk("กฎ YARA ทำงาน (loader script)" if lg.yara_rules() else "YARA ปิดอยู่ (ติดตั้ง yara-python เพื่อเปิด)",
        lg.yara_rules() and lg.analyze(str(ps), con)[0] == "medium")
    chk("ฐานข้อมูลภัยคุกคามมีข้อมูล", con.execute("SELECT COUNT(*) FROM iocs").fetchone()[0] > 0)
    h = lg.sha256_of(str(bad)); qid = lg.quarantine_file(str(bad), h, ["selftest"])
    chk("กักกันไฟล์ได้", not bad.exists())
    lg.cmd_restore(type("A", (), {"id": qid})()); chk("กู้คืนไฟล์ได้", bad.exists())
    con.close()
    shutil.rmtree(d, ignore_errors=True)
    S["self"] = res
    return all(item["ok"] for item in res)


def elevate():
    exe = sys.executable
    params = "" if getattr(sys, "frozen", False) else f'"{Path(sys.argv[0]).resolve()}"'
    ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
    threading.Timer(1.5, lambda: __import__("os")._exit(0)).start()


def is_admin():
    try: return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception: return False


def defender_status(force=False):
    if not lg.IS_WIN:
        return {"available": False, "error": "Windows Defender status is only available on Windows."}
    if not force and time.monotonic() - DEFENDER_STATUS["checked"] < 30:
        return dict(DEFENDER_STATUS["value"])

    command = (
        "$ErrorActionPreference='Stop'; "
        "try { $s=Get-MpComputerStatus; "
        "[pscustomobject]@{available=$true; antivirus=[bool]$s.AntivirusEnabled; "
        "realtime=[bool]$s.RealTimeProtectionEnabled; behavior=[bool]$s.BehaviorMonitorEnabled} "
        "| ConvertTo-Json -Compress } "
        "catch { [pscustomobject]@{available=$false; error=$_.Exception.Message} "
        "| ConvertTo-Json -Compress; exit 1 }"
    )
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=8,
            stdin=subprocess.DEVNULL, creationflags=0x08000000 if lg.IS_WIN else 0,
        )
        parsed = json.loads(result.stdout)
        if not isinstance(parsed, dict):
            raise ValueError("Unexpected Windows Defender status response.")
        value = parsed
    except (OSError, subprocess.SubprocessError, ValueError) as e:
        value = {"available": False, "error": str(e)}
    DEFENDER_STATUS.update(checked=time.monotonic(), value=value)
    if not value.get("available"):
        log(f"[!] ตรวจสอบสถานะ Microsoft Defender ไม่สำเร็จ: {value.get('error', 'ไม่พบสถานะ')}")
    return dict(value)


def start_defender_scan(scan_type):
    scan_types = {"quick": "QuickScan", "full": "FullScan"}
    if scan_type not in scan_types:
        raise ValueError("Unsupported Microsoft Defender scan type.")
    if not lg.IS_WIN:
        raise OSError("Microsoft Defender scans are only available on Windows.")
    command = f"Start-MpScan -ScanType {scan_types[scan_type]} -ErrorAction Stop"
    result = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60,
        stdin=subprocess.DEVNULL, creationflags=0x08000000,
    )
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise OSError(detail or "Microsoft Defender did not accept the scan request.")
    log(f"[+] ส่งคำสั่ง Microsoft Defender {scan_type} scan แล้ว; ดูผลได้ใน Windows Security")


def state():
    con = lg.db(); g = lambda k: (con.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone() or [None])[0]
    try:
        hist = json.loads(lg.HISTORY.read_text(encoding="utf-8"))
        if not isinstance(hist, list):
            raise ValueError("รูปแบบประวัติไม่ใช่รายการ")
        S["history_error"] = None
    except (OSError, ValueError) as e:
        message = str(e)
        if S["history_error"] != message:
            log(f"[!] อ่านประวัติการสแกนไม่สำเร็จ: {message}")
        S["history_error"] = message
        hist = []
    hist = [item for item in hist if isinstance(item, dict)]
    last = lg.LAST_SCAN or (hist[-1] if hist else {})
    now = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    ioc_states = {row[0]: row[1] for row in con.execute(
        "SELECT state,COUNT(DISTINCT kind||':'||value) FROM threat_iocs GROUP BY state")}
    counts = con.execute("""SELECT COUNT(DISTINCT kind||':'||value) AS total,
        COUNT(DISTINCT CASE WHEN state='active' AND (expires_at IS NULL OR expires_at>?) THEN kind||':'||value END) AS active
        FROM threat_iocs""", (now,)).fetchone()
    feed_sources = {
        "hashes": {row[0]: row[1] for row in con.execute(
            "SELECT source,COUNT(DISTINCT sha256) FROM malware_hash_sources GROUP BY source ORDER BY source")},
        "iocs": {row[0]: row[1] for row in con.execute(
            "SELECT source,COUNT(*) FROM threat_iocs WHERE state='active' "
            "AND (expires_at IS NULL OR expires_at>?) GROUP BY source ORDER BY source", (now,))},
    }
    try:
        last_update = dt.datetime.fromisoformat(g("last_update")) if g("last_update") else None
        if last_update and last_update.tzinfo is None:
            last_update = last_update.astimezone()
        update_stale = last_update is None or (dt.datetime.now(dt.timezone.utc) - last_update.astimezone(dt.timezone.utc)).total_seconds() > 7 * 86400
    except ValueError:
        update_stale = True
    r = {"hashes": con.execute("SELECT COUNT(*) FROM hashes").fetchone()[0], "iocs": counts[0] or 0,
         "active_iocs": counts[1] or 0,
         "ioc_states": ioc_states,
         "feed_sources": feed_sources,
         "updated": g("last_update"), "update_stale": update_stale,
         "update_partial": g("last_update_complete") == "0",
         "key": bool(lg.get_key()), "yara": bool(lg.yara_rules()),
         "memory_scan": bool(lg.IS_WIN and lg.yara_rules()), "admin": is_admin(), "job": S["job"], "last_job": S["last_job"],
         "onboarding_complete": get_onboarding_complete(),
         "defender": defender_status(), "audit": luna_audit.read_recent(50),
         "hist": hist[-20:], "last": last, "quar": [{"id": k, **v} for k, v in lg.load_index().items()], "self": S["self"], "prog": dict(lg.PROGRESS), "n": S["log_base"] + len(S["log"]), "language": get_language()}
    con.close(); return r


class H(BaseHTTPRequestHandler):
    def log_message(s, *a): pass
    def setup(s):
        super().setup()
        s.connection.settimeout(10)
    def local_request(s):
        host = s.headers.get("Host", "").lower()
        port = s.server.server_address[1]
        if host not in (f"127.0.0.1:{port}", f"localhost:{port}"):
            return False
        origin = s.headers.get("Origin")
        if origin is not None:
            try:
                parsed = urlsplit(origin)
            except ValueError:
                return False
            if (parsed.scheme != "http" or parsed.netloc.lower() != host
                    or parsed.path not in ("", "/") or parsed.query or parsed.fragment):
                return False
        fetch_site = s.headers.get("Sec-Fetch-Site", "").lower()
        if fetch_site and fetch_site not in ("same-origin", "same-site", "none"):
            return False
        return True
    def auth(s):
        supplied = s.headers.get("X-Luna-Token", "")
        return s.local_request() and secrets.compare_digest(supplied, TOKEN)
    def rate_limited(s):
        key = (s.client_address[0], s.command)
        now = time.monotonic()
        with API_REQUESTS_LOCK:
            for old_key, stamps in list(API_REQUESTS.items()):
                if not stamps or now - stamps[-1] >= API_RATE_WINDOW_SECONDS:
                    API_REQUESTS.pop(old_key, None)
            recent = [stamp for stamp in API_REQUESTS.get(key, [])
                      if now - stamp < API_RATE_WINDOW_SECONDS]
            if len(recent) >= API_RATE_LIMIT.get(s.command, 20):
                API_REQUESTS[key] = recent
                return True
            recent.append(now)
            API_REQUESTS[key] = recent
        return False
    def out(s, code, body, ct="application/json"):
        b = body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False).encode()
        s.send_response(code); s.send_header("Content-Type", ct + "; charset=utf-8"); s.send_header("Content-Length", str(len(b)))
        s.send_header("Cache-Control", "no-store")
        s.send_header("X-Content-Type-Options", "nosniff")
        s.send_header("Referrer-Policy", "no-referrer")
        s.send_header("X-Frame-Options", "DENY")
        s.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        s.end_headers()
        try:
            s.wfile.write(b)
        except (BrokenPipeError, ConnectionResetError):
            pass
    def read_json(s):
        if s.headers.get("Transfer-Encoding"):
            s.out(400, {"ok": False, "error": "transfer encoding is not supported"})
            return None
        content_type = s.headers.get_content_type()
        if content_type != "application/json":
            s.out(415, {"ok": False, "error": "application/json is required"})
            return None
        length_header = s.headers.get("Content-Length")
        if length_header is None or len(length_header) > 10 or not length_header.isascii() or not length_header.isdecimal():
            s.out(411, {"ok": False, "error": "valid content length is required"})
            return None
        length = int(length_header)
        if length > MAX_API_BODY_BYTES:
            s.close_connection = True
            s.out(413, {"ok": False, "error": "request body is too large"})
            return None
        timeout = s.connection.gettimeout()
        try:
            s.connection.settimeout(10)
            raw = s.rfile.read(length) if length else b"{}"
        except OSError:
            s.close_connection = True
            s.out(408, {"ok": False, "error": "request body timed out"})
            return None
        finally:
            s.connection.settimeout(timeout)
        if len(raw) != length:
            s.out(400, {"ok": False, "error": "request body length does not match"})
            return None
        def reject_duplicate_keys(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate JSON key")
                result[key] = value
            return result
        def reject_json_constant(value):
            raise ValueError(f"invalid JSON constant: {value}")
        try:
            data = json.loads(raw, object_pairs_hook=reject_duplicate_keys,
                              parse_constant=reject_json_constant)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            s.out(400, {"ok": False, "error": "invalid JSON body"})
            return None
        if not isinstance(data, dict):
            s.out(400, {"ok": False, "error": "JSON body must be an object"})
            return None
        return data
    def do_GET(s):
        if not s.local_request(): return s.out(403, {"error": "forbidden"})
        try:
            parsed = urlsplit(s.path)
            params = parse_qs(parsed.query, strict_parsing=True) if parsed.query else {}
        except ValueError:
            return s.out(400, {"error": "invalid request path"})
        p = parsed.path
        if p == "/" and not params:
            try:
                page = (BASE / "dashboard.html").read_text(encoding="utf-8")
                page = page.replace("__LUNA_TOKEN__", json.dumps(TOKEN))
                return s.out(200, page.encode("utf-8"), "text/html")
            except OSError:
                return s.out(500, {"error": "dashboard unavailable"})
        if p == "/logo/Luna_Guard.png" and not params:
            try: return s.out(200, (BASE / "logo" / "Luna_Guard.png").read_bytes(), "image/png")
            except OSError: return s.out(404, {"error": "logo not found"})
        if not s.auth(): return s.out(403, {"error": "forbidden"})
        if s.rate_limited(): return s.out(429, {"error": "rate limit exceeded"})
        if p == "/api/locales" and not params:
            try: return s.out(200, json.loads((BASE / "locales.json").read_text(encoding="utf-8")))
            except (OSError, ValueError): return s.out(500, {"error": "locales unavailable"})
        if p == "/api/state" and not params:
            try: return s.out(200, state())
            except (OSError, RuntimeError, ValueError) as e:
                log(f"[!] อ่านสถานะภายในไม่สำเร็จ: {e}")
                return s.out(500, {"error": "could not read application state"})
        if p == "/api/log" and set(params) <= {"since"}:
            try:
                if len(params.get("since", ["0"])) != 1: raise ValueError
                since = int(params.get("since", ["0"])[0])
            except (ValueError, IndexError): return s.out(400, {"error": "invalid log cursor"})
            if since < 0: return s.out(400, {"error": "invalid log cursor"})
            return s.out(200, log_since(since))
        return s.out(404, {"error": "not found"})
    def do_POST(s):
        if not s.auth(): return s.out(403, {"error": "forbidden"})
        if s.rate_limited(): return s.out(429, {"error": "rate limit exceeded"})
        try: parsed = urlsplit(s.path)
        except ValueError: return s.out(400, {"ok": False, "error": "invalid request path"})
        if parsed.query: return s.out(400, {"ok": False, "error": "query parameters are not accepted"})
        d = s.read_json()
        if d is None: return
        p = parsed.path; ok = True
        if p == "/api/update" and not d: ok = start("อัปเดตฐานข้อมูล", lg.cmd_update)
        elif p == "/api/scan":
            if any(key in d and not isinstance(d[key], bool) for key in ("files_only", "clean", "full")):
                return s.out(400, {"ok": False, "error": "scan flags must be booleans"})
            if "paths" in d and (not isinstance(d["paths"], list) or len(d["paths"]) > 100
                    or any(not isinstance(item, str) or len(item) > 32768 for item in d["paths"])):
                return s.out(400, {"ok": False, "error": "invalid scan paths"})
            files_only = bool(d.get("files_only"))
            clean = bool(d.get("clean"))
            full = bool(d.get("full"))
            if files_only and clean:
                return s.out(400, {"ok": False, "error": "file-only scans are read-only"})
            if files_only and full:
                return s.out(400, {"ok": False, "error": "choose either file-only or full-drive scan"})
            if files_only and d.get("paths"):
                return s.out(400, {"ok": False, "error": "file-only scan uses its predefined folders"})
            a = type("A", (), {
                "clean": clean, "files_only": files_only, "full": full,
                "paths": d.get("paths") or None,
            })()
            name = "สแกนไฟล์แบบอัตโนมัติ" if files_only else "สแกน+กำจัด" if clean else "สแกน"
            ok = start(name, lambda: lg.cmd_scan(a))
        elif p == "/api/selftest" and not d: ok = start("ทดสอบตัวเอง", selftest)
        elif p == "/api/defender-scan":
            scan_type = d.get("scan_type")
            if set(d) != {"scan_type"} or scan_type not in ("quick", "full"):
                return s.out(400, {"ok": False, "error": "unsupported scan type"})
            ok = start(
                f"Microsoft Defender {scan_type} scan",
                lambda: start_defender_scan(scan_type),
            )
        elif p == "/api/restore":
            if set(d) - {"id", "destination"} or not isinstance(d.get("id"), str) or (
                    "destination" in d and not isinstance(d["destination"], str)):
                return s.out(400, {"ok": False, "error": "invalid restore request"})
            try:
                destination = lg.restore_file(d["id"], d.get("destination"))
                log(f"[+] Restore สำเร็จ: {destination}")
                s.audit("restore.succeeded", quarantine_id=d["id"], result="verified")
            except (KeyError, OSError, RuntimeError, ValueError) as e:
                log(f"[!] Restore ไม่สำเร็จ ({type(e).__name__})")
                s.audit("restore.failed", quarantine_id=d.get("id", ""), error_category=type(e).__name__)
                return s.out(400, {"ok": False, "error": str(e)})
        elif p == "/api/delete-quarantine":
            if set(d) != {"id", "confirmed"} or not isinstance(d.get("id"), str) or d.get("confirmed") is not True:
                return s.out(400, {"ok": False, "error": "explicit confirmation is required"})
            try:
                lg.delete_quarantined_file(d["id"])
                log("[+] ลบรายการใน Quarantine ถาวรแล้ว")
                s.audit("quarantine.deleted", quarantine_id=d["id"], result="deleted")
            except (KeyError, OSError, RuntimeError, ValueError) as e:
                log(f"[!] ลบรายการใน Quarantine ไม่สำเร็จ ({type(e).__name__})")
                s.audit("quarantine.delete_failed", quarantine_id=d.get("id", ""), error_category=type(e).__name__)
                return s.out(400, {"ok": False, "error": str(e)})
        elif p == "/api/recover-quarantine" and not d:
            try:
                actions = lg.recover_quarantine()
                for action in actions:
                    s.audit("quarantine.recovery", quarantine_id=action.get("id", ""),
                            result=action.get("result", "unknown"))
                s.audit("quarantine.recovery_checked", result=str(len(actions)))
                ok = True
            except (OSError, RuntimeError, ValueError) as e:
                log(f"[!] ตรวจสถานะ Quarantine ไม่สำเร็จ: {e}")
                s.audit("quarantine.recovery_failed", error_category=type(e).__name__)
                return s.out(500, {"ok": False, "error": "quarantine recovery check failed"})
        elif p in ("/api/remove", "/api/allow"):
            if set(d) != {"path"} or not isinstance(d.get("path"), str) or len(d["path"]) > 32768:
                return s.out(400, {"ok": False, "error": "invalid file path"})
            ok = not S["job"]
            if ok:
                try:
                    with contextlib.redirect_stdout(W()):
                        (lg.remove_finding if p == "/api/remove" else lg.allow_file)(d["path"])
                    s.audit("quarantine.created" if p == "/api/remove" else "finding.allowed", result="success")
                except (SystemExit, OSError, RuntimeError, ValueError) as e:
                    log(f"[!] ดำเนินการไม่สำเร็จ ({type(e).__name__})")
                    s.audit("quarantine.failed" if p == "/api/remove" else "finding.allow_failed",
                            error_category=type(e).__name__)
                    return s.out(400, {"ok": False, "error": str(e)})
        elif p == "/api/stop" and not d:
            lg.STOP["flag"] = True; log("[!] สั่งหยุดสแกนไฟล์แล้ว...")
        elif p == "/api/elevate" and not d:
            try: elevate()
            except Exception as e: log(f"[!] ขอสิทธิ์ Admin ไม่สำเร็จ: {e}")
        elif p == "/api/key":
            if set(d) != {"key"} or not isinstance(d.get("key"), str) or len(d["key"]) > 512 or any(ord(c) < 32 for c in d["key"]):
                return s.out(400, {"ok": False, "error": "invalid key request"})
            try:
                lg.save_key(d["key"])
            except (OSError, ValueError):
                return s.out(500, {"ok": False, "error": "could not save API key"})
            log("[+] บันทึกคีย์แล้ว")
        elif p == "/api/language":
            if set(d) != {"language"}:
                return s.out(400, {"ok": False, "error": "invalid language request"})
            try:
                set_language(d.get("language"))
            except ValueError:
                return s.out(400, {"ok": False, "error": "unsupported language"})
            except OSError as e:
                log(f"[!] บันทึกภาษาที่เลือกไม่สำเร็จ: {e}")
                return s.out(500, {"ok": False, "error": "could not save language"})
            s.audit("settings.language_changed", result=d["language"])
        elif p == "/api/onboarding":
            if set(d) != {"complete"} or d.get("complete") is not True:
                return s.out(400, {"ok": False, "error": "invalid onboarding request"})
            try:
                set_onboarding_complete(True)
            except OSError:
                return s.out(500, {"ok": False, "error": "could not save onboarding state"})
            s.audit("onboarding.completed", result="saved")
        else: return s.out(404, {"error": "not found"})
        s.out(200 if ok else 409, {"ok": ok})
    def audit(s, action, **fields):
        try:
            luna_audit.record(action, **fields)
        except OSError as error:
            log(f"[!] บันทึก audit ไม่สำเร็จ ({action}): {error}")
    def _reject_method(s):
        body = json.dumps({"error": "method not allowed"}).encode("utf-8")
        s.send_response(405)
        s.send_header("Allow", "GET, POST")
        s.send_header("Content-Type", "application/json; charset=utf-8")
        s.send_header("Content-Length", str(len(body)))
        s.send_header("Cache-Control", "no-store")
        s.send_header("X-Content-Type-Options", "nosniff")
        s.end_headers()
        s.wfile.write(body)
    def do_PUT(s): return s._reject_method()
    def do_DELETE(s): return s._reject_method()
    def do_PATCH(s): return s._reject_method()
    def do_OPTIONS(s): return s._reject_method()
    def do_HEAD(s): return s._reject_method()
    def do_TRACE(s): return s._reject_method()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Luna Guard local dashboard API (desktop UI is launched with luna_app.py)")
    ap.add_argument("--port", type=int, default=0); ap.add_argument("--open-browser", action="store_true")
    a = ap.parse_args(); check_quarantine_recovery(); srv = ThreadingHTTPServer(("127.0.0.1", a.port), H)
    url = f"http://127.0.0.1:{srv.server_address[1]}/"; print("Luna Guard Dashboard:", url)
    if a.open_browser: webbrowser.open(url)
    srv.serve_forever()
