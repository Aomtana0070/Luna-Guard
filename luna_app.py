#!/usr/bin/env python3
"""Luna Guard desktop app. The dashboard is hosted inside a pywebview window."""
import ctypes
import os
import sys
import threading
from http.server import ThreadingHTTPServer

import luna_dashboard as d


def load_webview():
    try:
        import webview
    except ImportError:
        return None
    return webview


def show_dependency_error():
    message = "ไม่พบ pywebview จึงไม่สามารถเปิดแอป Luna Guard ได้\n\nติดตั้งด้วยคำสั่ง:\npython -m pip install pywebview"
    print(message, file=sys.stderr)
    if os.name == "nt":
        ctypes.windll.user32.MessageBoxW(None, message, "Luna Guard", 0x10)


def serve():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), d.H)  # พอร์ตสุ่ม ฟังเฉพาะในเครื่อง
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/?t={d.TOKEN}"


def main():
    webview = load_webview()
    if webview is None:
        show_dependency_error()
        return 1

    srv, url = serve()
    try:
        webview.create_window("Luna Guard", url, width=1280, height=820, min_size=(980, 640), background_color="#070b12")
        webview.start()
    finally:
        srv.shutdown()
        srv.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
