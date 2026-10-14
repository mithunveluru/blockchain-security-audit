import time

from blockaudit.app import create_app
from blockaudit.config import Settings

ADMIN, ANALYST, VIEWER = "admin-token-0123456789", "analyst-token-0123456789", "viewer-token-0123456789"


def make_env(tmp_path, **extra):
    env = {"BLOCKAUDIT_ENV": "test", "CHAIN_FILE": str(tmp_path / "chain.json"), "DATA_DIR": str(tmp_path),
           "BLOCKAUDIT_ADMIN_TOKEN": ADMIN, "BLOCKAUDIT_ANALYST_TOKEN": ANALYST, "BLOCKAUDIT_VIEWER_TOKEN": VIEWER,
           "ALERT_DEDUP_SECONDS": "0"}
    env.update({k: str(v) for k, v in extra.items()})
    return env


def make_app(tmp_path, **extra):
    settings = Settings.from_env(make_env(tmp_path, **extra))
    app, sio, svc = create_app(settings, start=False)
    return app, sio, svc


def hdr(token):
    return {"Authorization": f"Bearer {token}"}


def pkt(src, dst, dport, sport=40000, proto="TCP", flags="S", size=60, ts=None):
    return {"ts": ts if ts is not None else time.time(), "src_ip": src, "dst_ip": dst, "src_port": sport,
            "dst_port": dport, "protocol": proto, "size": size, "flags": flags}


def port_scan(svc, src="203.0.113.50", dst="192.168.1.100", n=30, base=None):
    base = base or time.time()
    out = []
    for i in range(n):
        out += svc.analyzer.process_packet(pkt(src, dst, 1000 + i, sport=40000 + i, ts=base + i * 0.05))
    return out
