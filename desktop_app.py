import os
import sys
import time
import socket
import threading
import webbrowser
import urllib.request
import uvicorn
import webview
import pystray
from PIL import Image, ImageDraw

if getattr(sys, "frozen", False):
    os.chdir(os.path.dirname(sys.executable))
else:
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

if os.path.exists(".env"):
    with open(".env", encoding="utf-8") as f:
        for line in f:
            if "=" in line and not line.startswith("#"):
                k, v = line.strip().split("=", 1)
                os.environ[k] = v

def find_available_port(preferred: int = 8000) -> int:
    for port in [preferred, 8088, 8888, 9000, 0]:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return s.getsockname()[1]
            except OSError:
                continue
    return 8000

ACTIVE_PORT = find_available_port(int(os.getenv("APP_PORT", "8000")))
os.environ["ACTIVE_APP_PORT"] = str(ACTIVE_PORT)

from main import app

def run_backend():
    uvicorn.run(app, host="0.0.0.0", port=ACTIVE_PORT, log_level="warning")

def wait_for_server(url: str, timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1.0) as resp:
                if resp.status == 204:
                    return True
        except Exception:
            time.sleep(0.2)
    return False

def create_tray_icon():
    img = Image.new("RGB", (64, 64), color=(15, 23, 42))
    draw = ImageDraw.Draw(img)
    draw.rectangle([10, 10, 54, 54], outline=(6, 182, 212), width=4)
    draw.ellipse([22, 22, 42, 42], fill=(6, 182, 212))
    return img

def start_tray():
    target_path = "soc/dashboard" if os.getenv("SETUP_COMPLETED", "false").lower() == "true" else "setup"
    url = f"http://127.0.0.1:{ACTIVE_PORT}/{target_path}"

    def on_open(icon, item):
        webbrowser.open(url)

    def on_exit(icon, item):
        icon.stop()
        os._exit(0)

    menu = pystray.Menu(
        pystray.MenuItem(f"AdHDF SOC Panelini Aç (Port {ACTIVE_PORT})", on_open, default=True),
        pystray.MenuItem("Korumayı Durdur ve Çık", on_exit)
    )
    tray = pystray.Icon("AdHDF_Enterprise", create_tray_icon(), f"AdHDF Enterprise Active (:{ACTIVE_PORT})", menu)
    tray.run()

if __name__ == "__main__":
    threading.Thread(target=run_backend, daemon=True).start()
    wait_for_server(f"http://127.0.0.1:{ACTIVE_PORT}/health_check")
    threading.Thread(target=start_tray, daemon=True).start()

    initial_route = "soc/dashboard" if os.getenv("SETUP_COMPLETED", "false").lower() == "true" else "setup"
    window = webview.create_window(
        f"AdHDF Enterprise v2.0 — Cyber Deception & SOC Console (Port {ACTIVE_PORT})",
        f"http://127.0.0.1:{ACTIVE_PORT}/{initial_route}",
        width=1380,
        height=880,
        min_size=(1024, 680)
    )
    webview.start()
