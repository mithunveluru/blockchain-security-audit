import json

import pytest

from tests.helpers import ADMIN, ANALYST, VIEWER, hdr, make_app, port_scan


@pytest.fixture
def ctx(tmp_path):
    app, sio, svc = make_app(tmp_path)
    port_scan(svc)
    yield app.test_client(), svc, sio, app
    svc.close()


def test_every_api_route_requires_auth(ctx):
    c, *_ = ctx
    for path in ("/api/me", "/api/overview", "/api/alerts", "/api/network", "/api/ledger/status", "/api/health",
                 "/api/whitelist", "/api/stats", "/api/integrity/status", "/api/blockchain/verify"):
        assert c.get(path).status_code == 401, path
        assert c.get(path, headers=hdr("wrong-token-xxxxxxxxxx")).status_code == 401, path
    assert c.post("/api/copilot/ask", json={"question": "x"}).status_code == 401
    assert c.post("/api/start").status_code == 401


def test_health_probes_are_open_and_minimal(ctx):
    c, *_ = ctx
    assert c.get("/healthz").get_json() == {"status": "ok"}
    r = c.get("/readyz")
    assert set(r.get_json()) == {"ready"}


def test_role_enforcement(ctx):
    c, svc, *_ = ctx
    aid = c.get("/api/alerts", headers=hdr(VIEWER)).get_json()["items"][0]["id"]
    assert c.patch(f"/api/alerts/{aid}", json={"status": "resolved"}, headers=hdr(VIEWER)).status_code == 403
    assert c.patch(f"/api/alerts/{aid}", json={"status": "resolved"}, headers=hdr(ANALYST)).status_code == 200
    assert c.post("/api/whitelist/add", json={"ip": "8.8.8.8"}, headers=hdr(ANALYST)).status_code == 403
    assert c.post("/api/whitelist/add", json={"ip": "8.8.8.8"}, headers=hdr(ADMIN)).status_code == 200
    assert c.post("/api/start", headers=hdr(ANALYST)).status_code == 403
    assert c.post("/api/ledger/verify", headers=hdr(VIEWER)).status_code == 403
    assert c.post("/api/ledger/verify", headers=hdr(ANALYST)).status_code == 200


def test_query_validation(ctx):
    c, *_ = ctx
    h = hdr(VIEWER)
    for q in ("severity=BOGUS", "page=0", "page=x", "page_size=1000", "sort=evil", "order=up", "status=nope",
              "source=not-an-ip", "since=yesterday", "range=forever", "provenance=magic"):
        r = c.get(f"/api/alerts?{q}", headers=h)
        assert r.status_code == 400, q
        assert "Traceback" not in r.get_data(as_text=True)


def test_filters_sort_and_pagination(ctx):
    c, svc, *_ = ctx
    h = hdr(VIEWER)
    port_scan(svc, src="203.0.113.77", dst="192.168.1.200")
    assert c.get("/api/alerts?source=203.0.113.77", headers=h).get_json()["total"] == 1
    assert c.get("/api/alerts?q=203.0.113.50", headers=h).get_json()["total"] == 1
    assert c.get("/api/alerts?severity=CRITICAL", headers=h).get_json()["total"] == 0
    r = c.get("/api/alerts?page_size=1&page=2&sort=time&order=asc", headers=h).get_json()
    assert r["total"] == 2 and len(r["items"]) == 1 and r["items"][0]["source"] == "203.0.113.77"


def test_error_responses_do_not_leak_internals(ctx, monkeypatch):
    c, svc, *_ = ctx
    monkeypatch.setattr(svc, "overview", lambda r: (_ for _ in ()).throw(RuntimeError("secret path /home/x/key.pem")))
    app = ctx[3]
    app.testing = False
    app.config["PROPAGATE_EXCEPTIONS"] = False
    r = c.get("/api/overview", headers=hdr(VIEWER))
    assert r.status_code == 500
    body = r.get_data(as_text=True)
    assert "secret path" not in body and "key.pem" not in body and "request_id" in body


def test_oversized_body_rejected(ctx):
    c, *_ = ctx
    r = c.post("/api/whitelist/add", data=b"{" + b"a" * 200_000, content_type="application/json", headers=hdr(ADMIN))
    assert r.status_code == 413


def test_bad_json_bodies(ctx):
    c, *_ = ctx
    for data in ("not json", "[1,2]", "null"):
        r = c.post("/api/whitelist/add", data=data, content_type="application/json", headers=hdr(ADMIN))
        assert r.status_code == 400
    assert c.post("/api/whitelist/add", json={"ip": "999.1.1.1; rm -rf /"}, headers=hdr(ADMIN)).status_code == 400
    assert c.post("/api/whitelist/remove", json={"ip": "9.9.9.9"}, headers=hdr(ADMIN)).status_code == 404


def test_security_headers_and_no_wildcard_cors(ctx):
    c, *_ = ctx
    r = c.get("/api/me", headers={**hdr(VIEWER), "Origin": "https://evil.example"})
    assert "Access-Control-Allow-Origin" not in r.headers
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]
    assert r.headers["X-Frame-Options"] == "DENY" and r.headers["Cache-Control"] == "no-store"


def test_cors_allows_only_listed_origin(tmp_path):
    app, sio, svc = make_app(tmp_path, CORS_ORIGINS="https://soc.example")
    c = app.test_client()
    ok = c.get("/api/me", headers={**hdr(VIEWER), "Origin": "https://soc.example"})
    bad = c.get("/api/me", headers={**hdr(VIEWER), "Origin": "https://evil.example"})
    assert ok.headers["Access-Control-Allow-Origin"] == "https://soc.example"
    assert "Access-Control-Allow-Origin" not in bad.headers
    svc.close()


def test_rate_limit(tmp_path):
    app, sio, svc = make_app(tmp_path, RATE_LIMIT_PER_MIN=5)
    c = app.test_client()
    codes = [c.get("/api/me", headers=hdr(VIEWER)).status_code for _ in range(8)]
    assert codes[:5] == [200] * 5 and codes[5] == 429
    svc.close()


def test_path_traversal_in_static_is_blocked(ctx):
    c, *_ = ctx
    for p in ("/static/../config.py", "/static/..%2fAGENTS.md", "/static/%2e%2e/enhanced_network_app.py"):
        assert c.get(p).status_code in (400, 404)


def test_websocket_requires_token(ctx):
    _, svc, sio, app = ctx
    assert not sio.test_client(app).is_connected()
    assert not sio.test_client(app, auth={"token": "bad-token-xxxxxxxxxxxx"}).is_connected()
    ok = sio.test_client(app, auth={"token": VIEWER})
    assert ok.is_connected()
    assert ok.get_received()[0]["name"] == "snapshot"
    ok.disconnect()
    assert svc.clients == 0


def test_websocket_receives_alert_pushes(ctx):
    _, svc, sio, app = ctx
    cl = sio.test_client(app, auth={"token": VIEWER})
    cl.get_received()
    port_scan(svc, src="203.0.113.99", dst="192.168.1.9")
    names = [m["name"] for m in cl.get_received()]
    assert "alert" in names


def test_operator_actions_are_audited_in_ledger(ctx):
    c, svc, *_ = ctx
    before = len(svc.ledger)
    c.post("/api/whitelist/add", json={"ip": "10.9.9.0/24"}, headers=hdr(ADMIN))
    blk = svc.ledger.get(before)
    d = json.loads(blk["data"])
    assert d["event_type"] == "OPERATOR_ACTION" and d["action"] == "whitelist_added" and d["actor"].startswith("admin:")
    assert ADMIN not in blk["data"]


def test_whitelist_suppresses_and_persists(tmp_path):
    app, sio, svc = make_app(tmp_path)
    c = app.test_client()
    c.post("/api/whitelist/add", json={"ip": "203.0.113.0/24"}, headers=hdr(ADMIN))
    assert port_scan(svc) and svc.alerts.query()[1] == 0 and svc.alerts.stats["whitelisted"] == 1
    svc.close()
    app2, _, svc2 = make_app(tmp_path)
    assert "203.0.113.0/24" in svc2.whitelist.entries()
    svc2.close()


def test_simulation_injection_disabled_outside_simulation(ctx):
    c, *_ = ctx
    r = c.post("/api/simulate/port_scan", headers=hdr(ADMIN))
    assert r.status_code == 409


def test_alert_notes_validation(ctx):
    c, *_ = ctx
    aid = c.get("/api/alerts", headers=hdr(VIEWER)).get_json()["items"][0]["id"]
    assert c.post(f"/api/alerts/{aid}/notes", json={"text": ""}, headers=hdr(ANALYST)).status_code == 400
    assert c.post(f"/api/alerts/{aid}/notes", json={"text": "x" * 5000}, headers=hdr(ANALYST)).status_code == 400
    assert c.post(f"/api/alerts/{aid}/notes", json={"text": "checked with owner"}, headers=hdr(ANALYST)).status_code == 201
    d = c.get(f"/api/alerts/{aid}", headers=hdr(VIEWER)).get_json()
    assert d["investigation"]["notes"][0]["text"] == "checked with owner"
    assert c.get("/api/alerts/alr-doesnotexist", headers=hdr(VIEWER)).status_code == 404
