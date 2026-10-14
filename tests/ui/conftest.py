import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.request

import pytest

pytest.importorskip("playwright")
from playwright.sync_api import sync_playwright  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TOKEN = "ui-test-admin-token-0123456789"
VIEWER = "ui-test-viewer-token-0123456789"
CHROME = os.environ.get("CHROME_PATH") or shutil.which("google-chrome") or shutil.which("chromium") or shutil.which("chromium-browser")


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Server:
    def __init__(self, tmp, **env):
        self.port = free_port()
        self.tmp = tmp
        self.env = {**os.environ, "PORT": str(self.port), "BLOCKAUDIT_ADMIN_TOKEN": TOKEN, "BLOCKAUDIT_VIEWER_TOKEN": VIEWER, "CHAIN_FILE": str(tmp / "chain.json"),
                    "DATA_DIR": str(tmp), "SIM_SCENARIO_INTERVAL": "0", "PYTHONUNBUFFERED": "1", **env}
        self.proc = None

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def start(self):
        self.proc = subprocess.Popen([sys.executable, "enhanced_network_app.py"], cwd=ROOT, env=self.env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                if urllib.request.urlopen(f"{self.url}/healthz", timeout=1).status == 200:
                    return self
            except OSError:
                time.sleep(0.2)
        raise RuntimeError("server did not start")

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    def api(self, path, method="GET"):
        req = urllib.request.Request(f"{self.url}{path}", method=method, headers={"Authorization": f"Bearer {TOKEN}"})
        import json
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read() or b"{}")

    def seed(self):
        for name in ("port_scan", "brute_force"):
            self.api(f"/api/simulate/{name}", "POST")
        for _ in range(60):
            if self.api("/api/alerts")["total"] >= 2:
                return
            time.sleep(0.25)
        raise RuntimeError("alerts were not produced")


@pytest.fixture(scope="session")
def browser():
    if not CHROME:
        pytest.skip("no chrome or chromium found; set CHROME_PATH")
    with sync_playwright() as p:
        b = p.chromium.launch(executable_path=CHROME, headless=True, args=["--no-sandbox"])
        yield b
        b.close()


@pytest.fixture(scope="session")
def sim_server(tmp_path_factory):
    s = Server(tmp_path_factory.mktemp("ui-sim"), ENABLE_SIMULATION_MODE="1").start()
    s.seed()
    yield s
    s.stop()


@pytest.fixture
def make_page(browser, sim_server):
    contexts = []

    def make(width=1440, height=900, server=None, theme="dark", signed_in=True, **kw):
        srv = server or sim_server
        ctx = browser.new_context(viewport={"width": width, "height": height}, **kw)
        if signed_in:
            ctx.add_init_script(f"if(!sessionStorage.getItem('blockaudit.token')) sessionStorage.setItem('blockaudit.token','{TOKEN}');"
                                f"if(!localStorage.getItem('blockaudit.theme')) localStorage.setItem('blockaudit.theme', JSON.stringify('{theme}'));")
        page = ctx.new_page()
        page.problems = []
        page.on("console", lambda m: page.problems.append(f"{m.type}: {m.text}") if m.type in ("error", "warning") else None)
        page.on("pageerror", lambda e: page.problems.append(f"pageerror: {e}"))
        page.base = srv.url
        contexts.append(ctx)
        return page

    yield make
    for c in contexts:
        c.close()
