#!/usr/bin/env python3
"""Luna Guard Dashboard - เซิร์ฟเวอร์ภายในเครื่อง (127.0.0.1) + หน้า dashboard.html  รัน: python luna_dashboard.py"""
import argparse, contextlib, ctypes, json, re, secrets, shutil, subprocess, sys, tempfile, threading, time, webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
import luna_guard as lg

BASE = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
S = {"job": None, "log": [], "self": None, "history_error": None}
TOKEN = secrets.token_urlsafe(16)
LANGUAGES = {"th", "en", "zh-CN"}
LANGUAGE_FILE = lg.APP_DIR / "settings.json"
DEFENDER_STATUS = {"checked": 0.0, "value": {"available": False}}
MAX_API_BODY_BYTES = 64 * 1024
API_RATE_WINDOW_SECONDS = 60
API_RATE_LIMIT = 240
API_REQUESTS = {}
API_REQUESTS_LOCK = threading.Lock()


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
    temp_file = LANGUAGE_FILE.with_suffix(".tmp")
    current["language"] = language
    temp_file.write_text(json.dumps(current, ensure_ascii=False), encoding="utf-8")
    temp_file.replace(LANGUAGE_FILE)


def log(line):
    if line.strip():
        l = ("high" if line.startswith("[HIGH") else "med" if line.startswith("[MEDIUM") else
             "ok" if line.startswith(("[+]", "[PASS")) else "warn" if line.startswith(("[!]", "[FAIL")) else "info")
        S["log"].append({"t": time.strftime("%H:%M:%S"), "l": l, "m": line.strip()})


class W:
    def __init__(s): s.b = ""
    def write(s, t):
        s.b += t
        while "\n" in s.b:
            ln, s.b = s.b.split("\n", 1); log(ln)
    def flush(s): pass


def start(name, fn):
    if S["job"]:
        return False
    S["job"] = name
    def w():
        try:
            with contextlib.redirect_stdout(W()): fn()
        except SystemExit as e: log(f"[!] {e}")
        except Exception as e: log(f"[!] ผิดพลาด: {e}")
        S["job"] = None; log(f"[+] งาน '{name}' เสร็จสิ้น")
    threading.Thread(target=w, daemon=True).start()
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
    shutil.rmtree(d, ignore_errors=True); S["self"] = res


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
    con = lg.db()
    try:
        g = lambda k: (con.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone() or [None])[0]
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
        return {
            "hashes": con.execute("SELECT COUNT(*) FROM hashes").fetchone()[0],
            "iocs": con.execute("SELECT COUNT(*) FROM iocs").fetchone()[0],
            "updated": g("last_update"),
            "key": bool(lg.get_key()),
            "yara": bool(lg.yara_rules()),
            "admin": is_admin(),
            "job": S["job"],
            "defender": defender_status(),
            "hist": hist[-20:],
            "last": last,
            "quar": [{"id": k, **v} for k, v in lg.load_index().items()],
            "self": S["self"],
            "prog": dict(lg.PROGRESS),
            "n": len(S["log"]),
            "language": get_language(),
        }
    finally:
        con.close()


class H(BaseHTTPRequestHandler):
    def log_message(s, *a): pass
    def local_request(s):
        host = s.headers.get("Host", "").lower()
        port = s.server.server_address[1]
        if host not in (f"127.0.0.1:{port}", f"localhost:{port}"):
            return False
        origin = s.headers.get("Origin")
        if origin is None:
            return True
        try:
            parsed = urlsplit(origin)
        except ValueError:
            return False
        return (
            parsed.scheme == "http"
            and parsed.netloc.lower() == host
            and parsed.path in ("", "/")
            and not parsed.query
            and not parsed.fragment
        )
    def auth(s):
        supplied = s.headers.get("X-T", "")
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
            if len(recent) >= API_RATE_LIMIT:
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
        s.end_headers()
        try:
            s.wfile.write(b)
        except (BrokenPipeError, ConnectionResetError):
            pass
    def read_json(s):
        if s.headers.get("Transfer-Encoding"):
            s.out(400, {"ok": False, "error": "transfer encoding is not supported"})
            return None
        length_header = s.headers.get("Content-Length")
        if length_header is None or not length_header.isdigit():
            s.out(411, {"ok": False, "error": "valid content length is required"})
            return None
        length = int(length_header)
        if length > MAX_API_BODY_BYTES:
            if length <= MAX_API_BODY_BYTES * 2:
                previous_timeout = s.connection.gettimeout()
                try:
                    s.connection.settimeout(1)
                    remaining = length
                    while remaining:
                        chunk = s.rfile.read(min(remaining, 64 * 1024))
                        if not chunk:
                            break
                        remaining -= len(chunk)
                except OSError:
                    s.close_connection = True
                finally:
                    s.connection.settimeout(previous_timeout)
            else:
                s.close_connection = True
            s.out(413, {"ok": False, "error": "request body is too large"})
            return None
        if s.headers.get_content_type() != "application/json":
            s.out(415, {"ok": False, "error": "application/json is required"})
            return None
        try:
            data = json.loads(s.rfile.read(length) if length else b"{}")
        except (UnicodeDecodeError, json.JSONDecodeError):
            s.out(400, {"ok": False, "error": "invalid JSON body"})
            return None
        if not isinstance(data, dict):
            s.out(400, {"ok": False, "error": "JSON body must be an object"})
            return None
        return data
    def do_GET(s):
        if not s.local_request():
            return s.out(403, {"error": "forbidden"})
        try:
            parsed_path = urlsplit(s.path)
            p = parsed_path.path
            query = parse_qs(parsed_path.query, strict_parsing=True) if parsed_path.query else {}
        except ValueError:
            return s.out(400, {"error": "invalid request path"})
        if p == "/": return s.out(200, (BASE / "dashboard.html").read_bytes(), "text/html")
        if p == "/logo/Luna_Guard.png" and not query:
            return s.out(200, (BASE / "logo" / "Luna_Guard.png").read_bytes(), "image/png")
        if not s.auth(): return s.out(403, {"error": "forbidden"})
        if s.rate_limited(): return s.out(429, {"error": "rate limit exceeded"})
        if p == "/api/locales" and not query:
            return s.out(200, json.loads((BASE / "locales.json").read_text(encoding="utf-8")))
        if p == "/api/state" and not query:
            try:
                return s.out(200, state())
            except (OSError, RuntimeError, ValueError) as e:
                log(f"[!] อ่านสถานะภายในไม่สำเร็จ: {e}")
                return s.out(500, {"error": "could not read application state"})
        if p == "/api/log" and set(query) <= {"since"}:
            try:
                since = int(query.get("since", ["0"])[0])
            except (ValueError, IndexError):
                return s.out(400, {"error": "invalid log cursor"})
            if since < 0:
                return s.out(400, {"error": "invalid log cursor"})
            return s.out(200, {"lines": S["log"][since:]})
        s.out(404, {"error": "not found"})
    def do_POST(s):
        if not s.auth(): return s.out(403, {"error": "forbidden"})
        if s.rate_limited(): return s.out(429, {"error": "rate limit exceeded"})
        if urlsplit(s.path).query:
            return s.out(400, {"ok": False, "error": "query parameters are not accepted"})
        d = s.read_json()
        if d is None: return
        p = urlsplit(s.path).path; ok = True
        if p == "/api/update": ok = start("อัปเดตฐานข้อมูล", lg.cmd_update)
        elif p == "/api/scan":
            if any(key in d and not isinstance(d[key], bool) for key in ("files_only", "clean", "full")):
                return s.out(400, {"ok": False, "error": "scan flags must be booleans"})
            if "paths" in d and (
                not isinstance(d["paths"], list)
                or len(d["paths"]) > 100
                or any(not isinstance(path, str) or len(path) > 32768 for path in d["paths"])
            ):
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
        elif p == "/api/selftest": ok = start("ทดสอบตัวเอง", selftest)
        elif p == "/api/defender-scan":
            scan_type = d.get("scan_type")
            if scan_type not in ("quick", "full"):
                return s.out(400, {"ok": False, "error": "unsupported scan type"})
            ok = start(
                f"Microsoft Defender {scan_type} scan",
                lambda: start_defender_scan(scan_type),
            )
        elif p == "/api/restore":
            if not isinstance(d.get("id"), str):
                return s.out(400, {"ok": False, "error": "invalid quarantine id"})
            try:
                with contextlib.redirect_stdout(W()): lg.cmd_restore(type("A", (), {"id": d.get("id", "")})())
            except (SystemExit, OSError, RuntimeError, ValueError) as e:
                log(f"[!] {e}")
                return s.out(400, {"ok": False, "error": str(e)})
        elif p in ("/api/remove", "/api/allow"):
            if not isinstance(d.get("path"), str) or len(d["path"]) > 32768:
                return s.out(400, {"ok": False, "error": "invalid file path"})
            ok = not S["job"]
            if ok:
                try:
                    with contextlib.redirect_stdout(W()): (lg.remove_finding if p == "/api/remove" else lg.allow_file)(d.get("path", ""))
                except (SystemExit, OSError, RuntimeError, ValueError) as e:
                    log(f"[!] {e}")
                    return s.out(400, {"ok": False, "error": str(e)})
        elif p == "/api/stop":
            lg.STOP["flag"] = True; log("[!] สั่งหยุดสแกนไฟล์แล้ว...")
        elif p == "/api/elevate":
            try: elevate()
            except Exception as e: log(f"[!] ขอสิทธิ์ Admin ไม่สำเร็จ: {e}")
        elif p == "/api/key":
            if not isinstance(d.get("key"), str) or len(d["key"]) > 2048:
                return s.out(400, {"ok": False, "error": "invalid API key"})
            lg.save_key(d["key"]); log("[+] บันทึกคีย์แล้ว")
        elif p == "/api/language":
            try:
                set_language(d.get("language"))
            except ValueError:
                return s.out(400, {"ok": False, "error": "unsupported language"})
            except OSError as e:
                log(f"[!] บันทึกภาษาที่เลือกไม่สำเร็จ: {e}")
                return s.out(500, {"ok": False, "error": "could not save language"})
        else: return s.out(404, {"error": "not found"})
        s.out(200 if ok else 409, {"ok": ok})
    def do_OPTIONS(s):
        s.send_response(405)
        s.send_header("Allow", "GET, POST")
        s.send_header("Content-Length", "0")
        s.end_headers()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Luna Guard local dashboard API (desktop UI is launched with luna_app.py)")
    ap.add_argument("--port", type=int, default=0); ap.add_argument("--open-browser", action="store_true")
    a = ap.parse_args(); srv = ThreadingHTTPServer(("127.0.0.1", a.port), H)
    url = f"http://127.0.0.1:{srv.server_address[1]}/#t={TOKEN}"; print("Luna Guard Dashboard:", url)
    if a.open_browser: webbrowser.open(url)
    srv.serve_forever()
