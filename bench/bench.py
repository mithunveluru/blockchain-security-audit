"""reproducible micro-benchmarks. usage: python bench/bench.py [--legacy DIR]

--legacy points at a checkout of the original modules (git show HEAD:file) so the same workload
can be run against both implementations. numbers depend on the machine; always report the environment
"""
import argparse
import json
import os
import platform
import random
import statistics
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def workload(n, seed=1):
    r = random.Random(seed)
    t0 = time.time()
    pk = []
    for i in range(n):
        proto = r.choice(["TCP", "TCP", "UDP"])
        pk.append({"ts": t0 + i * 0.001, "timestamp": None, "src_ip": f"192.168.1.{r.randint(10, 250)}",
                   "dst_ip": f"10.0.{r.randint(0, 3)}.{r.randint(1, 250)}", "src_port": r.randint(20000, 65000),
                   "dst_port": r.choice([80, 443, 443, 53, 8080]), "protocol": proto, "size": r.randint(60, 1500),
                   "flags": "A" if proto == "TCP" else ""})
    return pk


def bench_new(n):
    sys.path.insert(0, ROOT)
    from blockaudit.config import Settings
    from blockaudit.service import SecurityService
    d = tempfile.mkdtemp()
    s = Settings.from_env({"BLOCKAUDIT_ENV": "test", "CHAIN_FILE": f"{d}/c.json", "DATA_DIR": d,
                           "BLOCKAUDIT_ADMIN_TOKEN": "x" * 20})
    svc = SecurityService(s)
    pk = workload(n)
    t = time.perf_counter()
    for p in pk:
        svc.analyzer.process_packet(p)
    el = time.perf_counter() - t
    svc.close()
    return n / el


def bench_legacy(n, legacy):
    sys.path.insert(0, legacy)
    os.environ["ENABLE_SIMULATION_MODE"] = "1"
    from ml_anomaly_detector import MLAnomalyDetector
    from network_packet_analyzer import NetworkPacketAnalyzer
    a = NetworkPacketAnalyzer(interface="lo", ml_detector=MLAnomalyDetector())
    pk = workload(n)
    for p in pk:
        p["timestamp"] = "2026-01-01T12:00:00"
        p["payload_hash"] = "x"
    import io
    import contextlib
    t = time.perf_counter()
    with contextlib.redirect_stdout(io.StringIO()):
        for p in pk:
            a.process_packet(p)
    return n / (time.perf_counter() - t)


def bench_ledger_new(n):
    sys.path.insert(0, ROOT)
    from blockaudit.ledger import Ledger
    d = tempfile.mkdtemp()
    out = {}
    for fsync in (True, False):
        lg = Ledger(f"{d}/c{fsync}.json", fsync=fsync)
        lat = []
        for i in range(n):
            t = time.perf_counter()
            lg.append({"event_type": "ALERT", "i": i, "pad": "x" * 400})
            lat.append((time.perf_counter() - t) * 1000)
        out["fsync" if fsync else "no_fsync"] = lat
        lg.close()
    return out


def bench_ledger_legacy(n, legacy):
    sys.path.insert(0, legacy)
    d = tempfile.mkdtemp()
    import hashlib
    chain = [{"index": 0, "timestamp": "t", "data": "g", "previous_hash": "0", "hash": "0" * 64}]
    lat = []
    for i in range(n):
        t = time.perf_counter()
        prev = chain[-1]
        b = {"index": len(chain), "timestamp": "t", "data": json.dumps({"i": i, "pad": "x" * 400}), "previous_hash": prev["hash"], "hash": ""}
        b["hash"] = hashlib.sha256(json.dumps({k: b[k] for k in ("index", "timestamp", "data", "previous_hash")}, sort_keys=True).encode()).hexdigest()
        chain.append(b)
        with open(f"{d}/c.json", "w") as f:
            json.dump(chain, f, indent=2)
        lat.append((time.perf_counter() - t) * 1000)
    return lat


def pct(v, p):
    s = sorted(v)
    return s[min(len(s) - 1, int(len(s) * p))]


def bench_api(alerts):
    sys.path.insert(0, ROOT)
    sys.path.insert(0, os.path.join(ROOT, "tests"))
    from blockaudit.app import create_app
    from blockaudit.config import Settings
    d = tempfile.mkdtemp()
    tok = "bench-token-0123456789"
    s = Settings.from_env({"BLOCKAUDIT_ENV": "test", "CHAIN_FILE": f"{d}/c.json", "DATA_DIR": d, "BLOCKAUDIT_ADMIN_TOKEN": tok,
                           "ALERT_DEDUP_SECONDS": "0", "ALERT_RETENTION": str(alerts), "RATE_LIMIT_PER_MIN": "1000000"})
    app, _, svc = create_app(s, start=False)
    svc.alerts.max_ledger_per_min = 10**9
    for i in range(alerts):
        svc.alerts.submit({"type": "PORT_SCAN", "severity": "HIGH", "source": f"203.0.113.{i % 250}", "destination": "192.168.1.1",
                           "ts": time.time() - i, "evidence": {"observed": {"distinct_ports": 25}}})
    c = app.test_client()
    h = {"Authorization": f"Bearer {tok}"}
    res = {}
    for name, url in (("alerts_page", "/api/alerts?page_size=25"), ("alerts_filtered", "/api/alerts?severity=HIGH&q=203.0.113.7&page_size=25"),
                      ("overview", "/api/overview?range=24h"), ("ledger_blocks", "/api/ledger/blocks?page_size=25"),
                      ("ledger_status", "/api/ledger/status")):
        lat = []
        for _ in range(30):
            t = time.perf_counter()
            assert c.get(url, headers=h).status_code == 200
            lat.append((time.perf_counter() - t) * 1000)
        res[name] = (statistics.median(lat), pct(lat, .95))
    svc.close()
    return res


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--legacy")
    ap.add_argument("--packets", type=int, default=50000)
    ap.add_argument("--appends", type=int, default=300)
    ap.add_argument("--alerts", type=int, default=5000)
    a = ap.parse_args()
    print(f"python {platform.python_version()} on {platform.platform()} cpu_count={os.cpu_count()}")
    print(f"packet pipeline, {a.packets} packets: new {bench_new(a.packets):,.0f} pkt/s", end="")
    if a.legacy:
        print(f"  legacy {bench_legacy(a.packets, a.legacy):,.0f} pkt/s", end="")
    print()
    for k, lat in bench_ledger_new(a.appends).items():
        print(f"ledger append ({k}), {a.appends} appends: median {statistics.median(lat):.2f} ms  p95 {pct(lat, .95):.2f} ms")
    if a.legacy:
        lat = bench_ledger_legacy(a.appends, a.legacy)
        print(f"ledger append (legacy full-file rewrite, no fsync), {a.appends} appends: median {statistics.median(lat):.2f} ms  p95 {pct(lat, .95):.2f} ms  last10 median {statistics.median(lat[-10:]):.2f} ms")
    for k, (m, p) in bench_api(a.alerts).items():
        print(f"api {k} with {a.alerts} alerts: median {m:.1f} ms  p95 {p:.1f} ms")
