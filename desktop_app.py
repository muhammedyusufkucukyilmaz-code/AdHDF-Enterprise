import os
import sys
import time
import threading
import urllib.request
import importlib.util
import uvicorn
import webview

if getattr(sys, 'frozen', False):
    base_dir = sys._MEIPASS
    sys.path.insert(0, base_dir)
    os.chdir(os.path.dirname(sys.executable))
else:
    base_dir = os.path.abspath(".")

if os.path.exists(".env"):
    with open(".env", encoding="utf-8") as f:
        for line in f:
            if "=" in line and not line.startswith("#"):
                k, v = line.strip().split("=", 1)
                os.environ[k] = v

main_file = os.path.join(base_dir, "main.py")
spec = importlib.util.spec_from_file_location("main", main_file)
main_mod = importlib.util.module_from_spec(spec)
sys.modules["main"] = main_mod
spec.loader.exec_module(main_mod)
app = main_mod.app

HOST = "127.0.0.1"
PORT = 8000

def start_backend():
    uvicorn.run(app, host=HOST, port=PORT, log_level="warning")

def wait_for_server(timeout=15):
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            urllib.request.urlopen(f"http://{HOST}:{PORT}/health_check", timeout=1)
            return True
        except urllib.error.HTTPError:
            return True
        except Exception:
            time.sleep(0.3)
    return False

if __name__ == "__main__":
    server_thread = threading.Thread(target=start_backend, daemon=True)
    server_thread.start()
    wait_for_server()

    user = os.getenv("SOC_USERNAME", "admin")
    pwd = os.getenv("SOC_PASSWORD", "AdHDF_Soc2026!")
    dashboard_url = f"http://{user}:{pwd}@{HOST}:{PORT}/soc/dashboard"

    webview.create_window(
        title="AdHDF Enterprise — AI Active Deception & SOC Console",
        url=dashboard_url,
        width=1380,
        height=880,
        min_size=(1024, 700),
        background_color="#090d16"
    )
    webview.start()
