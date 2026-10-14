import json
import time

import pytest

from tests.helpers import ADMIN, ANALYST, VIEWER, hdr, make_app, make_env, pkt, port_scan
from blockaudit.app import create_app
from blockaudit.config import Settings


def replace_file(path, text):
    import os
    os.write(os.open(path + ".x", os.O_CREAT | os.O_WRONLY | os.O_TRUNC), text.encode())
    os.replace(path + ".x", path)


def wait_for(cond, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        v = cond()
        if v:
            return v
        time.sleep(0.1)
    return None


def test_full_investigation_workflow_in_process(tmp_path):
    app, sio, svc = make_app(tmp_path)
    c = app.test_client()
    # 1-4: a known suspicious sequence is processed, detected, persisted and linked
    alerts = port_scan(svc, src="203.0.113.50", dst="192.168.1.100", n=30)
    assert len(alerts) == 1
    a = c.get("/api/alerts?type=PORT_SCAN", headers=hdr(VIEWER)).get_json()["items"][0]
    assert a["provenance"] == "synthetic_test" and a["ledger_index"] is not None
    block = svc.ledger.get(a["ledger_index"])
    assert json.loads(block["data"])["alert"]["id"] == a["id"] and block["hash"] == a["ledger_hash"]
    # 5-6: ledger verifies
    assert c.post("/api/ledger/verify", headers=hdr(ANALYST)).get_json()["valid"] is True
    # 7-8: dashboard summary shows it; detail exposes evidence and ledger record
    ov = c.get("/api/overview?range=1h", headers=hdr(VIEWER)).get_json()
    assert ov["alerts"]["total"] == 1 and ov["recent_high_priority"][0]["id"] == a["id"]
    d = c.get(f"/api/alerts/{a['id']}", headers=hdr(VIEWER)).get_json()
    assert d["alert"]["evidence"]["observed"]["distinct_ports"] >= 20
    assert d["alert"]["evidence"]["sample_packets"] and d["ledger_block"]["hash"] == block["hash"]
    # 9: copilot references resolve to real records
    r = c.post("/api/copilot/ask", json={"question": "why was this alert raised?", "alert_id": a["id"]}, headers=hdr(VIEWER)).get_json()
    for s in r["sources"]:
        if s["kind"] == "alert":
            assert c.get(f"/api/alerts/{s['id']}", headers=hdr(VIEWER)).status_code == 200
        if s["kind"] == "ledger_block":
            assert c.get(f"/api/ledger/blocks/{s['id'].split('-')[1]}", headers=hdr(VIEWER)).status_code == 200
    # 10: incident report
    md = c.get(f"/api/alerts/{a['id']}/report?format=md", headers=hdr(VIEWER))
    text = md.get_data(as_text=True)
    assert md.status_code == 200 and a["id"] in text and block["hash"] in text and "SYNTHETIC" in text
    assert "203.0.113.50" in text and "passed" in text
    rj = c.get(f"/api/alerts/{a['id']}/report", headers=hdr(VIEWER)).get_json()
    assert rj["ledger"]["verification"]["valid"] and rj["alert"]["status"] == "new"
    # 11: tamper with the ledger and confirm verification fails with precise detail
    lines = open(svc.ledger.path).read().splitlines()
    b = json.loads(lines[a["ledger_index"]])
    b["data"] = b["data"].replace("203.0.113.50", "203.0.113.51")
    lines[a["ledger_index"]] = json.dumps(b, sort_keys=True)
    open(svc.ledger.path, "w").write("\n".join(lines) + "\n")
    res = c.post("/api/ledger/verify", headers=hdr(ANALYST)).get_json()
    assert res["valid"] is False and res["first_failure_index"] == a["ledger_index"]
    assert any(f["check"] == "hash_mismatch" and f["index"] == a["ledger_index"] for f in res["failures"])
    h = c.get("/api/health", headers=hdr(VIEWER)).get_json()
    assert h["status"] == "critical"
    assert any(x["type"] == "INTEGRITY" for x in c.get("/api/alerts", headers=hdr(VIEWER)).get_json()["items"])
    svc.close()


def test_threaded_simulation_mode_end_to_end(tmp_path, monkeypatch):
    monkeypatch.setenv("SIM_SCENARIO_INTERVAL", "0")
    settings = Settings.from_env(make_env(tmp_path, ENABLE_SIMULATION_MODE=1, EXFIL_BYTES=200000))
    app, sio, svc = create_app(settings, start=True)
    c = app.test_client()
    try:
        assert wait_for(lambda: svc.analyzer.counters["packets"] > 5)
        health = c.get("/api/health", headers=hdr(VIEWER)).get_json()
        cap = next(x for x in health["components"] if x["name"] == "packet_capture")
        assert cap["state"] == "healthy" and cap["mode"] == "simulation" and health["data_mode"] == "simulation"
        # benign synthetic traffic alone raises no rule alerts
        assert svc.alerts.query()[1] == 0
        for name in ("port_scan", "brute_force", "ddos", "exfiltration"):
            assert c.post(f"/api/simulate/{name}", headers=hdr(ADMIN)).status_code == 200
        types = lambda: {a["type"] for a in svc.alerts.query(page_size=100)[0]}
        assert wait_for(lambda: {"PORT_SCAN", "BRUTE_FORCE", "DDOS", "DATA_EXFILTRATION"} <= types()), types()
        items = svc.alerts.query(page_size=100)[0]
        assert all(a["provenance"] == "simulation" for a in items)
        assert c.get("/api/simulate/nonsense", headers=hdr(ADMIN)).status_code == 405
        assert c.post("/api/simulate/nonsense", headers=hdr(ADMIN)).status_code == 400
        net = c.get("/api/network?range=15m", headers=hdr(VIEWER)).get_json()
        assert net["packets"] > 100 and net["data_mode"] == "simulation" and net["top_ports"]
        assert wait_for(lambda: svc.ledger.last_verification and svc.ledger.last_verification["valid"])
    finally:
        svc.close()
    assert not svc.analyzer.running and not svc.integrity.alive()


def test_integrity_monitor_detects_live_tampering_and_recovery(tmp_path):
    app, sio, svc = make_app(tmp_path, INTEGRITY_CHECK_INTERVAL=1)
    port_scan(svc)
    svc.integrity.poll_interval = 0.1
    svc.integrity.start()
    try:
        good = open(svc.ledger.path).read()
        lines = good.splitlines()
        b = json.loads(lines[1])
        b["data"] = '{"forged":1}'
        lines[1] = json.dumps(b, sort_keys=True)
        replace_file(svc.ledger.path, "\n".join(lines) + "\n")
        assert wait_for(lambda: svc.integrity.tampering_detected, 10)
        crit = [a for a in svc.integrity.alerts if a["type"] == "LEDGER_TAMPERED"]
        assert crit and any(a["forensics"]["first_failure_index"] == 1 for a in crit)
        # the monitor's own alert block was appended meanwhile, so a restore must include it
        replace_file(svc.ledger.path, svc.ledger._encode(svc.ledger.all_blocks()).decode())
        assert wait_for(lambda: not svc.integrity.tampering_detected, 10)
    finally:
        svc.integrity.stop()
        svc.close()


def test_deleted_ledger_file_is_reported(tmp_path):
    import os
    app, sio, svc = make_app(tmp_path)
    port_scan(svc)
    os.remove(svc.ledger.path)
    res = svc.integrity.check_now()
    assert res["valid"] is False and any(f["check"] == "unreadable" for f in res["failures"])
    svc.close()


def test_health_reports_unavailable_capture_not_healthy(tmp_path, monkeypatch):
    import network_packet_analyzer as npa
    monkeypatch.setattr(npa, "get_permissions_info", lambda: {"can_capture": False, "is_root": False, "cap_net_raw": False, "cap_net_admin": False, "raw_socket": False})
    monkeypatch.setattr(npa, "get_available_interfaces", lambda: ["eth0"])
    settings = Settings.from_env(make_env(tmp_path, NETWORK_INTERFACE="eth0"))
    app, sio, svc = create_app(settings, start=True)
    try:
        h = app.test_client().get("/api/health", headers=hdr(VIEWER)).get_json()
        cap = next(c for c in h["components"] if c["name"] == "packet_capture")
        assert cap["state"] == "unavailable" and "permission" in cap["detail"] and cap["fix"]
        assert h["status"] in ("degraded", "critical") and h["status"] != "ok"
    finally:
        svc.close()


def test_missing_interface_is_unavailable(tmp_path, monkeypatch):
    import network_packet_analyzer as npa
    monkeypatch.setattr(npa, "get_available_interfaces", lambda: ["eth0"])
    settings = Settings.from_env(make_env(tmp_path, NETWORK_INTERFACE="nope0"))
    app, sio, svc = create_app(settings, start=True)
    try:
        cap = next(c for c in svc.components() if c["name"] == "packet_capture")
        assert cap["state"] == "unavailable" and "nope0" in cap["detail"]
    finally:
        svc.close()


def test_queue_backpressure_counts_drops(tmp_path):
    app, sio, svc = make_app(tmp_path, PACKET_QUEUE=100)
    for i in range(500):
        svc.analyzer.enqueue(pkt("10.0.0.1", "10.0.0.2", 80, ts=100 + i))
    st = svc.analyzer.get_capture_status()
    assert st["dropped_packets"] == 400 and st["queue_depth"] == 100
    svc.close()


def test_invalid_packets_counted_not_fatal(tmp_path):
    app, sio, svc = make_app(tmp_path)
    for bad in (None, {"ts": 1, "size": "big"}, {"ts": 1, "src_port": -5}, "junk"):
        assert svc.analyzer.process_packet(bad) == []
    assert svc.analyzer.counters["invalid"] == 4
    svc.close()


def test_second_instance_cannot_share_ledger(tmp_path):
    from blockaudit.ledger import LedgerLocked
    app, sio, svc = make_app(tmp_path)
    with pytest.raises(LedgerLocked):
        make_app(tmp_path)
    svc.close()
    make_app(tmp_path)[2].close()


def test_dedup_merges_repeats_and_alerts_survive_restart(tmp_path):
    app, sio, svc = make_app(tmp_path, ALERT_DEDUP_SECONDS=60)
    port_scan(svc, base=time.time())
    first = svc.alerts.query()[0][0]
    svc.alerts.submit({"type": "PORT_SCAN", "severity": "HIGH", "source": "203.0.113.50", "destination": "192.168.1.100"})
    assert svc.alerts.query()[1] == 1 and svc.alerts.get(first["id"])["occurrences"] == 2
    svc.close()
    app2, _, svc2 = make_app(tmp_path)
    again = svc2.alerts.get(first["id"])
    assert again and again["evidence"]["observed"]["distinct_ports"] >= 20 and again["ledger_hash"] == first["ledger_hash"]
    svc2.close()


def test_legacy_threat_blocks_become_historical_alerts(tmp_path):
    from blockaudit.ledger import Ledger
    p = tmp_path / "chain.json"
    lg = Ledger(str(p), str(tmp_path / "chain.json.checkpoint"))
    lg.append({"event_type": "SECURITY_THREAT", "timestamp": "2026-06-02T09:46:50.262528", "threat_level": "CRITICAL",
               "threats": [{"type": "DDOS_ATTACK", "severity": "CRITICAL", "target": "162.159.198.2:443", "packet_rate": 100,
                            "description": "legacy", "timestamp": "2026-06-02T09:46:50.262528"}]})
    lg.close()
    app, sio, svc = make_app(tmp_path)
    a = svc.alerts.query()[0][0]
    assert a["type"] == "DDOS" and a["provenance"] == "historical" and a["destination"] == "162.159.198.2" and a["dst_port"] == 443
    assert a["evidence"]["legacy"] and a["timestamp"].endswith("Z")
    svc.close()
