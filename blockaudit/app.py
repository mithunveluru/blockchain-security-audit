import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, Response, g, jsonify, request, send_from_directory
from flask_socketio import SocketIO

from .alerts import RANGES, range_seconds
from .auth import Authenticator, RateLimiter, bearer_token
from .config import Settings
from .copilot import Copilot, make_provider, MAX_QUESTION
from .events import SEVERITIES, STATUSES, PROVENANCE, RULES, parse_time, valid_ip
from .reports import build_report, to_markdown
from .service import SecurityService
from .simulator import SCENARIOS

log = logging.getLogger("blockaudit.api")
STATIC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")

CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self' ws: wss:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


class ApiError(Exception):
    def __init__(self, status, message, **extra):
        self.status, self.message, self.extra = status, message, extra


def create_app(settings=None, service=None, start=True):
    settings = settings or Settings.from_env()
    app = Flask(__name__, static_folder=None)
    app.config["MAX_CONTENT_LENGTH"] = settings.max_request_bytes
    app.config["JSON_SORT_KEYS"] = False
    origins = settings.cors_origins or None
    sio = SocketIO(app, cors_allowed_origins=origins, async_mode="threading", logger=False, engineio_logger=False,
                   max_http_buffer_size=16 * 1024)
    svc = service or SecurityService(settings, emit=lambda ev, data: sio.emit(ev, data))
    copilot = Copilot(svc, make_provider(settings), settings.copilot_timeout_s)
    auth = Authenticator(settings.tokens)
    limiter = RateLimiter()
    app.extensions["blockaudit"] = {"svc": svc, "settings": settings, "copilot": copilot, "socketio": sio,
                                    "limiter": limiter}

    # ---- helpers -------------------------------------------------------------------------------
    def require(role="viewer", bucket="read"):
        def deco(fn):
            @wraps(fn)
            def wrapper(*a, **kw):
                p = auth.check(bearer_token(request.headers))
                if p is None:
                    return jsonify(error="authentication required"), 401
                if not p.allows(role):
                    return jsonify(error=f"{role} role required"), 403
                limit = {"read": settings.rate_limit_per_min, "write": settings.rate_limit_write_per_min,
                         "copilot": settings.rate_limit_copilot_per_min}[bucket]
                ok, retry = limiter.allow((p.id, bucket), limit)
                if not ok:
                    r = jsonify(error="rate limit exceeded", retry_after_seconds=retry)
                    r.status_code = 429
                    r.headers["Retry-After"] = str(retry)
                    return r
                g.principal = p
                return fn(*a, **kw)
            return wrapper
        return deco

    def body():
        if request.content_length and request.content_length > settings.max_request_bytes:
            raise ApiError(413, "request body too large")
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            raise ApiError(400, "a json object body is required")
        return data

    def int_arg(name, default, lo, hi):
        raw = request.args.get(name)
        if raw in (None, ""):
            return default
        try:
            v = int(raw)
        except ValueError:
            raise ApiError(400, f"{name} must be an integer")
        if not lo <= v <= hi:
            raise ApiError(400, f"{name} must be between {lo} and {hi}")
        return v

    def range_arg():
        r = request.args.get("range", "1h")
        if r not in RANGES:
            raise ApiError(400, f"range must be one of {', '.join(RANGES)}")
        return r

    def time_arg(name):
        raw = request.args.get(name)
        if not raw:
            return None
        t = parse_time(raw)
        if t is None:
            raise ApiError(400, f"{name} must be an ISO 8601 time")
        return t

    def csv_arg(name, allowed):
        raw = request.args.get(name, "")
        vals = [v.strip().upper() if allowed is SEVERITIES else v.strip() for v in raw.split(",") if v.strip()]
        bad = [v for v in vals if v not in allowed]
        if bad:
            raise ApiError(400, f"invalid {name}: {', '.join(b[:20] for b in bad)}")
        return vals or None

    def ip_arg(name):
        raw = request.args.get(name, "").strip()
        if not raw:
            return None
        ip = valid_ip(raw)
        if ip is None:
            raise ApiError(400, f"{name} must be an ip address")
        return ip

    # ---- hooks ---------------------------------------------------------------------------------
    @app.before_request
    def _start():
        g.rid = uuid.uuid4().hex[:12]
        g.t0 = time.monotonic()

    @app.after_request
    def _headers(resp):
        resp.headers.setdefault("Content-Security-Policy", CSP)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        resp.headers["X-Request-Id"] = getattr(g, "rid", "-")
        if request.path.startswith("/api/") or request.path in ("/healthz", "/readyz"):
            resp.headers["Cache-Control"] = "no-store"
        if settings.production and request.is_secure:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000"
        origin = request.headers.get("Origin")
        if origin and origin in settings.cors_origins and request.path.startswith("/api/"):
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Vary"] = "Origin"
            resp.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
            resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PATCH, DELETE, OPTIONS"
        return resp

    @app.errorhandler(ApiError)
    def _api_error(e):
        return jsonify(error=e.message, **e.extra), e.status

    @app.errorhandler(404)
    def _404(e):
        return jsonify(error="not found"), 404

    @app.errorhandler(405)
    def _405(e):
        return jsonify(error="method not allowed"), 405

    @app.errorhandler(413)
    def _413(e):
        return jsonify(error="request body too large"), 413

    @app.errorhandler(Exception)
    def _500(e):
        if hasattr(e, "code") and isinstance(e.code, int) and e.code < 500:
            return jsonify(error=getattr(e, "description", "bad request")), e.code
        log.exception("unhandled error", extra={"fields": {"request_id": getattr(g, "rid", "-"), "path": request.path}})
        return jsonify(error="internal error", request_id=getattr(g, "rid", "-")), 500

    # ---- static ui -----------------------------------------------------------------------------
    @app.route("/")
    def index():
        return send_from_directory(STATIC, "index.html")

    @app.route("/static/<path:path>")
    def static_files(path):
        return send_from_directory(STATIC, path)

    @app.route("/soc")
    def legacy_soc():
        return Response(status=302, headers={"Location": "/"})

    # ---- health --------------------------------------------------------------------------------
    @app.route("/healthz")
    def healthz():
        return jsonify(status="ok")

    @app.route("/readyz")
    def readyz():
        comps = {c["name"]: c["state"] for c in svc.components()}
        ready = svc.running and comps.get("ledger") != "unavailable" and comps.get("background_workers") != "unavailable"
        return jsonify(ready=ready), (200 if ready else 503)

    @app.route("/api/me")
    @require("viewer")
    def me():
        return jsonify(role=g.principal.role, auth_enabled=settings.auth_enabled, data_mode=svc.provenance,
                       simulation=settings.simulation, rules=RULES, severities=list(SEVERITIES),
                       statuses=list(STATUSES), provenance=list(PROVENANCE), ranges=list(RANGES),
                       scenarios=list(SCENARIOS) if settings.simulation else [], copilot=copilot.status(),
                       warnings=settings.warnings())

    @app.route("/api/health")
    @require("viewer")
    def health():
        return jsonify(svc.health())

    @app.route("/api/overview")
    @require("viewer")
    def overview():
        return jsonify(svc.overview(range_arg()))

    @app.route("/api/stats")
    @require("viewer")
    def stats():
        s = svc.snapshot()
        return jsonify({**s, "packets_analyzed": s["packets"], "flows_tracked": s["active_flows"],
                        "threats_detected": svc.alerts.stats["raised"], "blockchain_blocks": s["ledger_blocks"]})

    # ---- alerts --------------------------------------------------------------------------------
    @app.route("/api/alerts")
    @require("viewer")
    def list_alerts():
        sort = request.args.get("sort", "time")
        if sort not in ("time", "severity", "score"):
            raise ApiError(400, "sort must be time, severity or score")
        order = request.args.get("order", "desc")
        if order not in ("asc", "desc"):
            raise ApiError(400, "order must be asc or desc")
        status = request.args.get("status") or None
        if status and status not in STATUSES:
            raise ApiError(400, f"status must be one of {', '.join(STATUSES)}")
        prov = request.args.get("provenance") or None
        if prov and prov not in PROVENANCE:
            raise ApiError(400, "invalid provenance")
        since, until = time_arg("since"), time_arg("until")
        if since is None and request.args.get("range"):
            since = datetime.fromtimestamp(time.time() - range_seconds(range_arg()), timezone.utc)
        items, total = svc.alerts.query(
            q=request.args.get("q", "")[:100], severities=csv_arg("severity", SEVERITIES),
            types=[t.upper() for t in request.args.get("type", "").split(",") if t] or None,
            source=ip_arg("source"), destination=ip_arg("destination"), status=status, provenance=prov,
            since=since, until=until, sort=sort, order=order, page=int_arg("page", 1, 1, 100000),
            page_size=int_arg("page_size", 25, 1, 100))
        return jsonify(items=items, total=total, page=int_arg("page", 1, 1, 100000), page_size=int_arg("page_size", 25, 1, 100))

    def alert_or_404(aid):
        a = svc.alerts.get(aid)
        if a is None:
            raise ApiError(404, "alert not found")
        return a

    def detail(a):
        block = svc.ledger.get(a["ledger_index"]) if a.get("ledger_index") is not None else None
        ev = a.get("evidence") or {}
        packets = ev.get("sample_packets") or []
        from .reports import missing_evidence
        return {"alert": a, "related": svc.alerts.related(a), "ledger_block": block,
                "investigation": svc.investigations.get(a["id"]), "rule": RULES.get(a["type"], {}),
                "missing_evidence": missing_evidence(a, block, packets)}

    @app.route("/api/alerts/<aid>")
    @require("viewer")
    def get_alert(aid):
        return jsonify(detail(alert_or_404(aid)))

    @app.route("/api/alerts/<aid>", methods=["PATCH"])
    @require("analyst", "write")
    def patch_alert(aid):
        a = alert_or_404(aid)
        data = body()
        try:
            svc.investigations.set_status(aid, data.get("status"))
        except ValueError as e:
            raise ApiError(400, str(e))
        svc.audit(g.principal.id, "alert_status_changed", {"alert_id": aid, "status": data["status"]})
        return jsonify(detail(svc.alerts.get(a["id"])))

    @app.route("/api/alerts/<aid>/notes", methods=["POST"])
    @require("analyst", "write")
    def add_note(aid):
        alert_or_404(aid)
        try:
            note = svc.investigations.add_note(aid, body().get("text"), g.principal.id)
        except ValueError as e:
            raise ApiError(400, str(e))
        svc.audit(g.principal.id, "alert_note_added", {"alert_id": aid, "note_id": note["id"]})
        return jsonify(note), 201

    @app.route("/api/alerts/<aid>/report")
    @require("viewer")
    def alert_report(aid):
        a = alert_or_404(aid)
        fmt = request.args.get("format", "json")
        if fmt not in ("json", "md"):
            raise ApiError(400, "format must be json or md")
        d = detail(a)
        check = svc.ledger.verify_memory()
        rep = build_report(a, d["related"], d["ledger_block"],
                           {"valid": check["valid"], "message": check["message"], "block_count": check["block_count"]},
                           d["investigation"], svc.health()["status"])
        if fmt == "md":
            return Response(to_markdown(rep), mimetype="text/markdown",
                            headers={"Content-Disposition": f'attachment; filename="{a["id"]}.md"'})
        return Response(json.dumps(rep, indent=2), mimetype="application/json",
                        headers={"Content-Disposition": f'attachment; filename="{a["id"]}.json"'})

    # ---- network -------------------------------------------------------------------------------
    @app.route("/api/network")
    @require("viewer")
    def network():
        return jsonify(svc.network(range_arg()))

    @app.route("/api/network/flows")
    @require("viewer")
    def flows():
        port = int_arg("port", 0, 0, 65535)
        return jsonify(items=svc.flows.snapshot(int_arg("limit", 100, 1, 500), ip_arg("src"), ip_arg("dst"), port or None),
                       data_mode=svc.provenance)

    # ---- ledger --------------------------------------------------------------------------------
    def summarize(b):
        try:
            d = json.loads(b["data"])
        except ValueError:
            d = None
        kind, text, ids = "RAW", b["data"][:80], []
        if isinstance(d, dict):
            kind = d.get("event_type", "RAW")
            if kind == "ALERT":
                a = d.get("alert", {})
                text, ids = f"{a.get('severity')} {a.get('type')} {a.get('source') or ''}".strip(), [a.get("id")]
            elif kind == "SECURITY_THREAT":
                text = f"{len(d.get('threats', []))} legacy threat(s), level {d.get('threat_level')}"
                ids = [f"alr-L{b['index']}-{n}" for n in range(len(d.get("threats", [])))]
            elif kind == "OPERATOR_ACTION":
                text = f"{d.get('action')} by {d.get('actor')}"
            elif kind == "LEDGER_RESTART":
                text = d.get("reason", "ledger restart")
        elif b["index"] == 0:
            kind, text = "GENESIS", b["data"]
        return {"index": b["index"], "timestamp": b["timestamp"], "hash": b["hash"], "previous_hash": b["previous_hash"],
                "kind": kind, "summary": text, "alert_ids": [i for i in ids if i]}

    @app.route("/api/ledger/status")
    @require("viewer")
    def ledger_status():
        s = svc.ledger.status()
        s["history"] = list(svc.ledger.history)[-20:]
        s["integrity"] = svc.integrity.get_status()
        return jsonify(s)

    @app.route("/api/ledger/blocks")
    @require("viewer")
    def ledger_blocks():
        q = request.args.get("q", "").strip().lower()[:100]
        kind = request.args.get("kind", "").strip().upper()[:30]
        page, size = int_arg("page", 1, 1, 100000), int_arg("page_size", 25, 1, 100)

        def pred(b):
            if not q and not kind:
                return True
            s = summarize(b)
            if kind and s["kind"] != kind:
                return False
            return not q or q in (s["summary"] + s["hash"] + str(s["index"]) + " ".join(s["alert_ids"])).lower()
        blocks, total = svc.ledger.search(pred, (page - 1) * size, size)
        return jsonify(items=[summarize(b) for b in blocks], total=total, page=page, page_size=size)

    @app.route("/api/ledger/blocks/<int:index>")
    @require("viewer")
    def ledger_block(index):
        b = svc.ledger.get(index)
        if b is None:
            raise ApiError(404, "block not found")
        from .ledger import block_hash
        prev = svc.ledger.get(index - 1) if index else None
        checks = {"hash_matches_contents": block_hash(b) == b["hash"],
                  "links_to_previous": (b["previous_hash"] == "0") if index == 0 else (prev is not None and prev["hash"] == b["previous_hash"])}
        try:
            parsed = json.loads(b["data"])
        except ValueError:
            parsed = None
        return jsonify(block=b, summary=summarize(b), event=parsed, checks=checks, merkle=svc.ledger.merkle_proof(index),
                       next_hash=(svc.ledger.get(index + 1) or {}).get("hash"))

    @app.route("/api/ledger/verify", methods=["GET", "POST"])
    @require("viewer")
    def ledger_verify():
        if request.method == "GET":
            return jsonify(svc.ledger.last_verification or svc.ledger.verify_memory())
        p = auth.check(bearer_token(request.headers))
        if not p.allows("analyst"):
            raise ApiError(403, "analyst role required")
        ok, retry = limiter.allow((p.id, "verify"), 6)
        if not ok:
            raise ApiError(429, "verification is limited to 6 per minute", retry_after_seconds=retry)
        res = svc.integrity.check_now()
        return jsonify(res)

    @app.route("/api/ledger/checkpoint")
    @require("viewer")
    def ledger_checkpoint():
        t = svc.ledger.tip()
        return jsonify(count=len(svc.ledger), tip_hash=t["hash"], merkle_root=svc.ledger.merkle_root(),
                       exported_at=datetime.now(timezone.utc).isoformat(),
                       note="store this outside the host that runs BlockAudit to detect a full-ledger rewrite")

    # legacy aliases
    @app.route("/api/blockchain/verify")
    @require("viewer")
    def legacy_verify():
        r = svc.ledger.last_verification or svc.ledger.verify_memory()
        return jsonify(valid=r["valid"], message=r["message"], block_count=r["block_count"])

    @app.route("/api/integrity/status")
    @require("viewer")
    def integrity_status():
        return jsonify(svc.integrity.get_status())

    @app.route("/api/integrity/alerts")
    @require("viewer")
    def integrity_alerts():
        return jsonify(list(svc.integrity.alerts))

    # ---- control + whitelist ---------------------------------------------------------------------
    @app.route("/api/start", methods=["POST"])
    @require("admin", "write")
    def start_monitoring():
        svc.start()
        svc.audit(g.principal.id, "monitoring_started")
        return jsonify(status="started")

    @app.route("/api/stop", methods=["POST"])
    @require("admin", "write")
    def stop_monitoring():
        svc.stop()
        svc.audit(g.principal.id, "monitoring_stopped")
        return jsonify(status="stopped")

    @app.route("/api/whitelist")
    @require("viewer")
    def get_whitelist():
        e = svc.whitelist.entries()
        return jsonify(whitelist=e, enabled=svc.whitelist.enabled, count=len(e),
                       suppressed=svc.alerts.stats["whitelisted"])

    @app.route("/api/whitelist/add", methods=["POST"])
    @require("admin", "write")
    def whitelist_add():
        try:
            v = svc.whitelist.add(body().get("ip"))
        except ValueError as e:
            raise ApiError(400, str(e))
        svc.audit(g.principal.id, "whitelist_added", {"entry": v})
        return jsonify(status="added", ip=v)

    @app.route("/api/whitelist/remove", methods=["POST"])
    @require("admin", "write")
    def whitelist_remove():
        v = str(body().get("ip") or "")[:64]
        if not svc.whitelist.remove(v):
            raise ApiError(404, "entry not found")
        svc.audit(g.principal.id, "whitelist_removed", {"entry": v})
        return jsonify(status="removed", ip=v)

    @app.route("/api/whitelist/toggle", methods=["POST"])
    @require("admin", "write")
    def whitelist_toggle():
        enabled = svc.whitelist.toggle()
        svc.audit(g.principal.id, "whitelist_toggled", {"enabled": enabled})
        return jsonify(enabled=enabled)

    @app.route("/api/simulate/<name>", methods=["POST"])
    @require("admin", "write")
    def simulate(name):
        try:
            svc.inject_scenario(name)
        except PermissionError as e:
            raise ApiError(409, str(e))
        except ValueError as e:
            raise ApiError(400, str(e))
        svc.audit(g.principal.id, "simulation_scenario_injected", {"scenario": name})
        return jsonify(status="injected", scenario=name, provenance="simulation")

    # ---- copilot -------------------------------------------------------------------------------
    @app.route("/api/copilot/ask", methods=["POST"])
    @require("viewer", "copilot")
    def copilot_ask():
        data = body()
        q = data.get("question")
        if not isinstance(q, str) or not q.strip():
            raise ApiError(400, "question is required")
        if len(q) > MAX_QUESTION:
            raise ApiError(400, f"question is limited to {MAX_QUESTION} characters")
        aid = data.get("alert_id")
        if aid is not None and (not isinstance(aid, str) or len(aid) > 40):
            raise ApiError(400, "alert_id is invalid")
        rng = data.get("range", "1h")
        if rng not in RANGES:
            raise ApiError(400, "range is invalid")
        return jsonify(copilot.ask(q, aid, rng))

    # ---- websocket -----------------------------------------------------------------------------
    @sio.on("connect")
    def ws_connect(auth_data=None):
        token = (auth_data or {}).get("token") if isinstance(auth_data, dict) else None
        p = auth.check(token if isinstance(token, str) else None)
        if p is None:
            return False
        svc.clients += 1
        sio.emit("snapshot", svc.snapshot(), to=request.sid)

    @sio.on("disconnect")
    def ws_disconnect(*_):
        svc.clients = max(0, svc.clients - 1)

    if start:
        svc.start()
    return app, sio, svc
