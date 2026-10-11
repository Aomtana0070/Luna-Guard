"""Security regressions for quarantine integrity and the loopback API."""
import hashlib
import json
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from unittest import mock

import luna_dashboard as dashboard
import luna_app as app
import luna_quarantine as quarantine
import luna_guard as lg


class QuarantineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.qdir = self.root / "quarantine"
        self.index = self.qdir / "index.json"
        self.source = self.root / "sample.bin"
        self.payload = b"safe test payload" * 10
        self.source.write_bytes(self.payload)
        self.sha = hashlib.sha256(self.payload).hexdigest()

    def tearDown(self):
        self.tmp.cleanup()

    def quarantine(self):
        return quarantine.quarantine_file(self.source, self.sha, ["test"], self.qdir, self.index)

    def test_integrity_checked_quarantine_restore(self):
        item_id = self.quarantine()
        self.assertFalse(self.source.exists())
        record = quarantine.load_index(self.index)[item_id]
        self.assertEqual(record["status"], "committed")
        self.assertEqual(record["sha256"], self.sha)
        restored = quarantine.restore_file(item_id, self.qdir, self.index)
        self.assertEqual(restored.read_bytes(), self.payload)
        self.assertEqual(quarantine.load_index(self.index), {})

    def test_changed_source_is_not_quarantined(self):
        self.source.write_bytes(b"changed")
        with self.assertRaises(RuntimeError):
            self.quarantine()
        self.assertEqual(self.source.read_bytes(), b"changed")

    def test_modified_quarantine_is_not_restored(self):
        item_id = self.quarantine()
        (self.qdir / f"{item_id}.quar").write_bytes(b"tampered")
        with self.assertRaises(RuntimeError):
            quarantine.restore_file(item_id, self.qdir, self.index)
        self.assertFalse(self.source.exists())

    def test_restore_refuses_existing_destination_and_traversal_id(self):
        item_id = self.quarantine()
        self.source.write_bytes(b"existing")
        with self.assertRaises(FileExistsError):
            quarantine.restore_file(item_id, self.qdir, self.index)
        with self.assertRaises(ValueError):
            quarantine.restore_file("..\\index", self.qdir, self.index)

    def test_restore_to_explicit_existing_parent(self):
        item_id = self.quarantine()
        destination = (self.root / "restored.bin").resolve()
        restored = quarantine.restore_file(item_id, self.qdir, self.index, destination)
        self.assertEqual(restored, destination)
        self.assertEqual(destination.read_bytes(), self.payload)

    def test_recovery_rolls_verified_move_forward(self):
        item_id = self.quarantine()
        index = quarantine.load_index(self.index)
        index[item_id]["status"] = "verified"
        quarantine._atomic_write_index(self.index, index)
        actions = quarantine.recover_index(self.qdir, self.index)
        self.assertEqual(actions[0]["result"], "quarantine_committed")
        self.assertEqual(quarantine.load_index(self.index)[item_id]["status"], "committed")

    def test_corrupt_index_fails_closed(self):
        self.index.parent.mkdir(parents=True, exist_ok=True)
        self.index.write_text("{broken", encoding="utf-8")
        with self.assertRaises(RuntimeError):
            quarantine.load_index(self.index)

    def test_interrupted_restore_with_verified_copy_is_finalized(self):
        item_id = self.quarantine()
        target = self.root / "recovered.bin"
        target.write_bytes(self.payload)
        index = quarantine.load_index(self.index)
        index[item_id].update(status="restoring", restore_destination=str(target))
        quarantine._atomic_write_index(self.index, index)
        actions = quarantine.recover_index(self.qdir, self.index)
        self.assertEqual(actions[0]["result"], "restore_finalized")
        self.assertEqual(target.read_bytes(), self.payload)
        self.assertFalse((self.qdir / f"{item_id}.quar").exists())
        self.assertNotIn(item_id, quarantine.load_index(self.index))

    def test_interrupted_restore_with_conflict_rolls_back_without_overwrite(self):
        item_id = self.quarantine()
        self.source.write_bytes(b"user-created different file")
        index = quarantine.load_index(self.index)
        index[item_id].update(status="restoring", restore_destination=str(self.source))
        quarantine._atomic_write_index(self.index, index)
        actions = quarantine.recover_index(self.qdir, self.index)
        current = quarantine.load_index(self.index)[item_id]
        self.assertEqual(actions[0]["result"], "restore_rolled_back")
        self.assertEqual(current["status"], "committed")
        self.assertEqual(self.source.read_bytes(), b"user-created different file")
        self.assertEqual((self.qdir / f"{item_id}.quar").read_bytes(), self.payload)

    def test_permanent_delete_checks_hash_then_removes_item(self):
        item_id = self.quarantine()
        quarantine.delete_file(item_id, self.qdir, self.index)
        self.assertFalse((self.qdir / f"{item_id}.quar").exists())
        self.assertEqual(quarantine.load_index(self.index), {})


class ThreatLifecycleTests(unittest.TestCase):
    def test_expired_ioc_is_not_active_and_old_db_migrates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            legacy_db = root / "old.sqlite"
            import sqlite3
            con = sqlite3.connect(legacy_db)
            con.execute("CREATE TABLE iocs(value TEXT PRIMARY KEY,kind TEXT,family TEXT,source TEXT)")
            con.execute("INSERT INTO iocs VALUES('expired.example','domain','test','ThreatFox')")
            con.commit()
            con.close()
            old_app_dir, old_db_path = lg.APP_DIR, lg.DB_PATH
            try:
                lg.APP_DIR, lg.DB_PATH = root, legacy_db
                con = lg.db()
                self.assertFalse(lg.ioc_is_active(con, "expired.example", "domain"))
                self.assertEqual(con.execute("SELECT state FROM ioc_lifecycle WHERE value='expired.example'").fetchone()[0], "expired")
                lg.record_ioc(con, "fresh.example", "domain", "test", "ThreatFox", expires_at="2999-01-01T00:00:00+00:00")
                self.assertTrue(lg.ioc_is_active(con, "fresh.example", "domain"))
                con.close()
                con = lg.db()
                lg.record_ioc(con, "stale.example", "domain", "test", "ThreatFox", expires_at="2000-01-01T00:00:00+00:00")
                con.commit()
                self.assertFalse(lg.ioc_is_active(con, "stale.example", "domain"))
                self.assertEqual(con.execute("SELECT state FROM ioc_lifecycle WHERE value='stale.example'").fetchone()[0], "expired")
                con.close()
            finally:
                lg.APP_DIR, lg.DB_PATH = old_app_dir, old_db_path


class SecretStorageTests(unittest.TestCase):
    def test_windows_api_key_config_uses_protected_value_and_reads_legacy_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "config.json"
            with mock.patch.object(lg, "IS_WIN", True), mock.patch.object(lg, "APP_DIR", root), \
                    mock.patch.object(lg, "CONFIG", config), mock.patch.object(lg, "_protect_key", return_value="ciphertext") as protect:
                lg.save_key("  sample-key  ")
                saved = json.loads(config.read_text(encoding="utf-8"))
                self.assertEqual(saved, {"abusech_key_dpapi": "ciphertext"})
                protect.assert_called_once_with("sample-key")
                with mock.patch.object(lg, "_unprotect_key", return_value="sample-key") as unprotect:
                    self.assertEqual(lg.get_key(), "sample-key")
                    unprotect.assert_called_once_with("ciphertext")
                config.write_text(json.dumps({"abusech_key": "legacy-key"}), encoding="utf-8")
                self.assertEqual(lg.get_key(), "legacy-key")
                self.assertEqual(json.loads(config.read_text(encoding="utf-8")),
                                 {"abusech_key_dpapi": "ciphertext"})
                self.assertEqual(protect.call_count, 2)

    def test_corrupt_protected_key_does_not_fall_back_to_environment_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.json"
            config.write_text(json.dumps({"abusech_key_dpapi": "invalid"}), encoding="utf-8")
            with mock.patch.object(lg, "CONFIG", config), mock.patch.dict("os.environ", {"ABUSECH_KEY": "fallback-key"}), \
                    mock.patch.object(lg, "_unprotect_key", side_effect=ValueError("bad ciphertext")):
                self.assertEqual(lg.get_key(), "")


class DesktopServerTests(unittest.TestCase):
    def test_desktop_binds_the_bounded_server_to_loopback(self):
        with mock.patch.object(dashboard, "check_quarantine_recovery"):
            server, url = app.serve()
        try:
            self.assertIsInstance(server, dashboard.BoundedThreadingHTTPServer)
            self.assertEqual(server.server_address[0], "127.0.0.1")
            self.assertTrue(url.startswith("http://127.0.0.1:"))
        finally:
            server.shutdown()
            server.server_close()


class ScanCompletenessTests(unittest.TestCase):
    def test_failed_required_system_command_marks_scan_incomplete(self):
        old_audit = dict(lg.SCAN_AUDIT)
        lg.SCAN_AUDIT.clear()
        lg.SCAN_AUDIT.update(issues=0, details=[])
        result = subprocess.CompletedProcess(args=["netstat"], returncode=1, stdout="", stderr="denied")
        try:
            with mock.patch.object(lg.subprocess, "run", return_value=result):
                self.assertIsNone(__import__("test_luna").REAL_RUN(["netstat", "-ano"], required=True))
            self.assertEqual(lg.SCAN_AUDIT["issues"], 1)
            self.assertIn("netstat", lg.SCAN_AUDIT["details"][0])
        finally:
            lg.SCAN_AUDIT.clear()
            lg.SCAN_AUDIT.update(old_audit)


class BuildProvenanceTests(unittest.TestCase):
    def test_build_manifest_has_verified_sha_and_explicit_production_signing_status(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "example.bin"
            payload = b"synthetic build artifact"
            artifact.write_bytes(payload)
            script = Path(__file__).resolve().parent / "scripts" / "record_build.py"
            subprocess.run([sys.executable, str(script), str(artifact)], check=True, capture_output=True)
            manifest = (root / "SHA256SUMS.txt").read_text(encoding="ascii")
            provenance = json.loads((root / "build-provenance.json").read_text(encoding="utf-8"))
            digest = hashlib.sha256(payload).hexdigest()
            self.assertIn(digest, manifest)
            self.assertEqual(provenance["sha256"], digest)
            self.assertFalse(provenance["signed"])
            self.assertFalse(provenance["production_signed"])
            self.assertEqual(provenance["signing_identity"], "unsigned")


class DashboardSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), dashboard.H)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def request(self, route, payload=None, headers=None, method=None, raw=None):
        body = raw if raw is not None else None if payload is None else json.dumps(payload).encode()
        request_headers = dict(headers or {})
        if body is not None:
            request_headers.setdefault("Content-Type", "application/json")
            request_headers.setdefault("X-Luna-Token", dashboard.TOKEN)
        req = Request(self.base + route, data=body, headers=request_headers,
                      method=method or ("POST" if body is not None else "GET"))
        try:
            with urlopen(req, timeout=5) as response:
                return response.status, response.headers, response.read()
        except HTTPError as error:
            try:
                return error.code, error.headers, error.read()
            finally:
                error.close()

    def test_json_content_type_is_required(self):
        status, _, body = self.request("/api/language", {"language": "en"},
                                       {"X-Luna-Token": dashboard.TOKEN,
                                        "Content-Type": "text/plain"})
        self.assertEqual(status, 415)
        self.assertIn(b"application/json", body)

    def test_duplicate_json_keys_are_rejected(self):
        status, _, body = self.request("/api/language", headers={
            "X-Luna-Token": dashboard.TOKEN,
            "Content-Type": "application/json",
        }, raw=b'{"language":"en","language":"zh-CN"}')
        self.assertEqual(status, 400)
        self.assertIn(b"invalid JSON", body)

    def test_language_post_saves_with_token_and_json_header(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(dashboard, "LANGUAGE_FILE", Path(directory) / "settings.json"):
                status, _, body = self.request("/api/language", {"language": "en"})
                self.assertEqual(status, 200)
                self.assertTrue(json.loads(body)["ok"])
                self.assertEqual(dashboard.get_language(), "en")

    def test_onboarding_endpoint_persists_complete_state(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(dashboard, "LANGUAGE_FILE", Path(directory) / "settings.json"):
                status, _, body = self.request("/api/onboarding", {"complete": True})
                self.assertEqual(status, 200)
                self.assertTrue(json.loads(body)["ok"])
                self.assertTrue(dashboard.get_onboarding_complete())

    def test_token_required_for_api(self):
        status, _, _ = self.request("/api/state", headers={})
        self.assertEqual(status, 403)

    def test_findings_are_returned_in_small_pages(self):
        findings = [{"sev": "low", "kind": "ไฟล์", "target": f"sample-{i}.exe", "why": "test"}
                    for i in range(45)]
        with mock.patch.object(lg, "LAST_SCAN", {"findings": findings}):
            headers = {"X-Luna-Token": dashboard.TOKEN}
            status, _, body = self.request("/api/findings?offset=0", headers=headers)
            self.assertEqual(status, 200)
            first = json.loads(body)
            self.assertEqual(first["total"], 45)
            self.assertEqual(len(first["findings"]), dashboard.FINDING_PAGE_SIZE)
            status, _, body = self.request("/api/findings?offset=20", headers=headers)
            self.assertEqual(status, 200)
            second = json.loads(body)
            self.assertEqual(len(second["findings"]), dashboard.FINDING_PAGE_SIZE)
            self.assertEqual(second["findings"][0]["target"], "sample-20.exe")
            status, _, _ = self.request("/api/findings?offset=3", headers=headers)
            self.assertEqual(status, 400)

    def test_cross_origin_is_rejected(self):
        status, _, _ = self.request("/api/state", headers={
            "X-Luna-Token": dashboard.TOKEN,
            "Origin": "http://attacker.invalid",
        })
        self.assertEqual(status, 403)

    def test_dashboard_has_request_scoped_nonce_and_no_inline_handlers(self):
        status, headers, body = self.request("/")
        self.assertEqual(status, 200)
        page = body.decode("utf-8")
        policy = headers.get("Content-Security-Policy", "")
        match = __import__("re").search(r"script-src 'self' 'nonce-([^']+)'", policy)
        self.assertIsNotNone(match)
        self.assertIn(f'<script nonce="{match.group(1)}">', page)
        self.assertNotIn("'unsafe-inline'", policy.split("script-src", 1)[1].split(";", 1)[0])
        self.assertNotRegex(page, r"\bon(?:click|change|input)=")
        self.assertIn('data-quarantine-action="restore" data-id="${esc(q.id)}"', page)

    def test_untrusted_severity_is_not_used_as_a_css_class(self):
        html = (Path(__file__).resolve().parent / "dashboard.html").read_text(encoding="utf-8")
        self.assertIn("severity=['high','medium','low'].includes(f.sev)?f.sev:'low'", html)

    def test_bounded_server_refuses_connections_after_worker_limit(self):
        class OneWorkerServer(dashboard.BoundedThreadingHTTPServer):
            max_workers = 1

        server = OneWorkerServer(("127.0.0.1", 0), dashboard.H)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.assertTrue(server._request_slots.acquire(blocking=False))
        try:
            with self.assertRaises(HTTPError) as error:
                urlopen(f"http://127.0.0.1:{server.server_address[1]}/", timeout=5)
            self.assertEqual(error.exception.code, 503)
            error.exception.close()
        finally:
            server._request_slots.release()
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_unsupported_http_method_is_405(self):
        status, headers, _ = self.request("/api/state", headers={"X-Luna-Token": dashboard.TOKEN}, method="PUT")
        self.assertEqual(status, 405)
        self.assertEqual(headers.get("Allow"), "GET, POST")

    def test_oversized_request_body_is_rejected_before_read(self):
        status, _, _ = self.request("/api/language", {"language": "en"},
                                     {"Content-Type": "application/json",
                                      "X-Luna-Token": dashboard.TOKEN,
                                      "Content-Length": str(dashboard.MAX_API_BODY_BYTES + 1)})
        self.assertEqual(status, 413)

    def test_application_log_is_bounded_and_secrets_are_redacted(self):
        old_log, old_base, old_cap = dashboard.S["log"], dashboard.S["log_base"], dashboard.MAX_APP_LOG_LINES
        dashboard.S["log"], dashboard.S["log_base"], dashboard.MAX_APP_LOG_LINES = [], 0, 2
        try:
            with mock.patch.object(lg, "get_key", return_value="secret-api-key"):
                dashboard.log(f"token={dashboard.TOKEN} https://example.invalid/?api_key=secret-api-key")
                dashboard.log("second")
                dashboard.log("third")
            snapshot = dashboard.log_since(0)
            self.assertTrue(snapshot["dropped"])
            self.assertEqual(snapshot["next"], 3)
            self.assertEqual(len(snapshot["lines"]), 2)
            self.assertNotIn(dashboard.TOKEN, " ".join(item["m"] for item in dashboard.S["log"]))
            self.assertNotIn("secret-api-key", " ".join(item["m"] for item in dashboard.S["log"]))
        finally:
            dashboard.S["log"], dashboard.S["log_base"], dashboard.MAX_APP_LOG_LINES = old_log, old_base, old_cap

    def test_onboarding_can_be_skipped_and_preserves_language_setting(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(dashboard, "LANGUAGE_FILE", Path(directory) / "settings.json"):
                dashboard.set_language("zh-CN")
                self.assertFalse(dashboard.get_onboarding_complete())
                dashboard.set_onboarding_complete(True)
                self.assertTrue(dashboard.get_onboarding_complete())
                self.assertEqual(json.loads(dashboard.LANGUAGE_FILE.read_text(encoding="utf-8")),
                                 {"language": "zh-CN", "onboarding_complete": True})

    def test_onboarding_modal_has_skip_and_accessible_dialog_labels(self):
        html = (Path(__file__).resolve().parent / "dashboard.html").read_text(encoding="utf-8")
        self.assertIn('<dialog class="onboarding" id="welcomeDialog" aria-labelledby="onboardingTitle"', html)
        self.assertIn('data-i18n="onboarding.skip"', html)
        self.assertIn("event.preventDefault();skipOnboarding()", html)

    def test_state_reports_counts_by_threat_feed_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.object(lg, "APP_DIR", root), mock.patch.object(lg, "DB_PATH", root / "feed.sqlite"), \
                    mock.patch.object(lg, "HISTORY", root / "history.json"):
                con = lg.db()
                con.execute("INSERT INTO hashes VALUES(?,?,?)", ("a" * 64, "TestFamily", "MalwareBazaar recent detections"))
                lg.record_ioc(con, "feed.example", "domain", "TestFamily", "ThreatFox")
                con.commit()
                con.close()
                state = dashboard.state()
                self.assertEqual(state["feed_sources"]["hashes"]["MalwareBazaar recent detections"], 1)
                self.assertEqual(state["feed_sources"]["iocs"]["ThreatFox"], 1)

    def test_detection_layout_keeps_badges_whole_and_uses_mobile_cards(self):
        html = (Path(__file__).resolve().parent / "dashboard.html").read_text(encoding="utf-8")
        self.assertIn("white-space:nowrap;min-width:74px", html)
        self.assertIn("@media(max-width:620px){", html)
        self.assertIn('id="det-cards" class="finding-cards"', html)
        self.assertIn("background-repeat:no-repeat", html)


if __name__ == "__main__":
    unittest.main()
