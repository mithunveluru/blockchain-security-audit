import ipaddress
import json
import re
import uuid
from datetime import datetime, timezone

SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
PROVENANCE = ("live_capture", "simulation", "synthetic_test", "historical", "integrity_monitor", "operator")
STATUSES = ("new", "investigating", "resolved", "false_positive")
PROTOCOLS = {"TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS", "OTHER"}

TYPE_ALIASES = {"DDOS_ATTACK": "DDOS", "DOS": "DOS_FLOOD", "DATA_EXFIL": "DATA_EXFILTRATION"}

RULES = {
    "PORT_SCAN": {
        "title": "Port scan",
        "rule": "port_scan.v2",
        "explains": "one source contacted many distinct ports on one destination inside a short window. "
                    "the threshold and window are shown in the evidence",
        "false_positives": "vulnerability scanners, service discovery tools and some peer-to-peer clients",
        "next_steps": [
            "identify the owner of the source address and whether a scan was authorised",
            "check which of the contacted ports are open on the destination",
            "look for follow-up connections from the same source to those ports",
        ],
    },
    "DDOS": {
        "title": "Distributed denial of service pattern",
        "rule": "dos_flood.v2",
        "explains": "a destination service received a sustained packet rate from many distinct sources, "
                    "or a high share of connection-opening packets without completion",
        "false_positives": "flash crowds, load tests and large legitimate downloads",
        "next_steps": [
            "confirm service latency or error rates on the destination",
            "compare the source addresses with expected clients",
            "ask the upstream provider about rate limiting if the load is confirmed",
        ],
    },
    "DOS_FLOOD": {
        "title": "Single-source flood",
        "rule": "dos_flood.v2",
        "explains": "a destination service received a sustained rate of mostly connection-opening packets from "
                    "few sources",
        "false_positives": "misbehaving clients with aggressive retry loops, load tests",
        "next_steps": [
            "identify the source and stop or rate-limit the offending client if it is not authorised",
            "confirm service health on the destination",
        ],
    },
    "BRUTE_FORCE": {
        "title": "Repeated connection attempts to an authentication service",
        "rule": "brute_force.v2",
        "explains": "one source opened many new connections to a login-style service in a short window. "
                    "this sees connection attempts only, not whether credentials were guessed",
        "false_positives": "automation that reconnects frequently, monitoring probes, connection pooling bugs",
        "next_steps": [
            "review the service authentication logs for failed logins from this source",
            "check whether any login from this source succeeded",
            "consider rate limiting or key-only authentication on the service",
        ],
    },
    "DATA_EXFILTRATION": {
        "title": "Large outbound transfer",
        "rule": "exfil.v2",
        "explains": "a flow from a private address to a public address moved more bytes than the configured "
                    "threshold in a short time. payload content is not inspected",
        "false_positives": "backups, software updates, video calls and legitimate uploads",
        "next_steps": [
            "identify the process and user on the source host",
            "check whether the destination is a known service",
            "compare against the host's normal transfer volume",
        ],
    },
    "ANOMALY": {
        "title": "Statistical anomaly",
        "rule": "isolation_forest.v1",
        "explains": "a source's behaviour in a short window deviated from the traffic baseline learned by this "
                    "process. the score is an uncalibrated anomaly score, not a probability of malice",
        "false_positives": "new but legitimate behaviour, baselines learned while attacks were already present",
        "next_steps": [
            "read the contributing features to see what deviated",
            "check whether the source is a new host or application",
            "correlate with rule-based alerts for the same source",
        ],
    },
    "INTEGRITY": {
        "title": "Ledger integrity event",
        "rule": "integrity_monitor.v2",
        "explains": "the integrity monitor re-verified the ledger file and compared it with the copy held in memory",
        "false_positives": "none expected; a failure is always worth investigating",
        "next_steps": [
            "inspect the failing block indices in the audit ledger view",
            "restore the ledger from a trusted backup and compare the checkpoint",
            "review who has write access to the data directory",
        ],
    },
}

_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def clean_text(value, limit=300):
    if value is None:
        return None
    return _CTRL.sub("", str(value))[:limit]


def utc_iso(ts=None):
    if ts is None:
        dt = datetime.now(timezone.utc)
    elif isinstance(ts, (int, float)):
        dt = datetime.fromtimestamp(ts, timezone.utc)
    else:
        dt = parse_time(ts) or datetime.now(timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_time(value):
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.astimezone()
    return dt.astimezone(timezone.utc)


def normalize_severity(value, default="MEDIUM"):
    v = str(value or "").strip().upper()
    if v in ("NORMAL", "NONE"):
        return "INFO"
    if v in ("WARN", "WARNING"):
        return "MEDIUM"
    if v in ("ERROR",):
        return "HIGH"
    return v if v in SEV_RANK else default


def normalize_type(value):
    v = str(value or "ANOMALY").strip().upper()
    return TYPE_ALIASES.get(v, v)


def valid_ip(value):
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def normalize_packet(raw, now=None):
    """returns a validated packet dict or None. ts is epoch seconds"""
    if not isinstance(raw, dict):
        return None
    ts = raw.get("ts")
    if not isinstance(ts, (int, float)):
        parsed = parse_time(raw.get("timestamp")) if raw.get("timestamp") else None
        ts = parsed.timestamp() if parsed else now
    if ts is None:
        return None
    proto = str(raw.get("protocol") or "OTHER").upper()
    try:
        size = max(0, int(raw.get("size") or 0))
        sport = int(raw.get("src_port") or 0)
        dport = int(raw.get("dst_port") or 0)
    except (TypeError, ValueError):
        return None
    if not (0 <= sport <= 65535 and 0 <= dport <= 65535):
        return None
    flags = str(raw.get("flags") or "").upper()
    if flags == "SYN":
        flags = "S"
    return {
        "ts": float(ts),
        "src_ip": raw.get("src_ip") or "",
        "dst_ip": raw.get("dst_ip") or "",
        "src_port": sport,
        "dst_port": dport,
        "protocol": proto if proto in PROTOCOLS else "OTHER",
        "size": size,
        "flags": flags[:8],
    }


def packet_summary(p):
    return {"time": utc_iso(p["ts"]), "src": p["src_ip"], "dst": p["dst_ip"], "sport": p["src_port"],
            "dport": p["dst_port"], "proto": p["protocol"], "size": p["size"], "flags": p["flags"]}


def build_alert(raw, provenance, now=None):
    """normalise a detector result into the alert contract"""
    ev = raw.get("evidence") or {}
    atype = normalize_type(raw.get("type"))
    meta = RULES.get(atype, {})
    score = raw.get("score")
    return {
        "id": raw.get("id") or "alr-" + uuid.uuid4().hex[:12],
        "timestamp": utc_iso(raw.get("ts", now)),
        "type": atype,
        "severity": normalize_severity(raw.get("severity")),
        "source": clean_text(raw.get("source"), 64) or None,
        "destination": clean_text(raw.get("destination"), 64) or None,
        "dst_port": raw.get("dst_port") if isinstance(raw.get("dst_port"), int) else None,
        "protocol": clean_text(raw.get("protocol"), 16) or None,
        "rule": raw.get("rule") or meta.get("rule"),
        "score": round(float(score), 3) if isinstance(score, (int, float)) else None,
        "score_kind": raw.get("score_kind") if score is not None else None,
        "description": clean_text(raw.get("description"), 400) or meta.get("title", atype),
        "evidence": ev,
        "provenance": provenance if provenance in PROVENANCE else "synthetic_test",
        "occurrences": 1,
        "last_seen": utc_iso(raw.get("ts", now)),
        "ledger_index": None,
        "ledger_hash": None,
    }


def alert_event(alert):
    persisted = {k: v for k, v in alert.items() if k not in ("occurrences", "last_seen", "ledger_index", "ledger_hash")}
    return {"schema": 2, "event_type": "ALERT", "alert": persisted}


def alerts_from_block(block):
    """rebuild alerts from a ledger block. understands schema 2 and the original SECURITY_THREAT format"""
    try:
        data = json.loads(block["data"])
    except (ValueError, TypeError, KeyError):
        return []
    if not isinstance(data, dict):
        return []
    idx, bh = block.get("index"), block.get("hash")
    out = []
    if data.get("event_type") == "ALERT" and isinstance(data.get("alert"), dict):
        a = dict(data["alert"])
        a.update(occurrences=1, last_seen=a.get("timestamp"), ledger_index=idx, ledger_hash=bh)
        a["severity"] = normalize_severity(a.get("severity"))
        a["type"] = normalize_type(a.get("type"))
        a.setdefault("evidence", {})
        out.append(a)
    elif data.get("event_type") == "SECURITY_THREAT":
        for n, t in enumerate(data.get("threats") or []):
            if not isinstance(t, dict):
                continue
            target = str(t.get("target") or t.get("dest_ip") or "")
            host, _, port = target.partition(":") if target.count(":") == 1 else (target, "", "")
            ev = {"observed": {k: v for k, v in t.items() if k in (
                "port_count", "packet_rate", "attempt_count", "ports_scanned", "bytes_transferred", "attempts")},
                "legacy": True, "note": "recorded by an earlier version; packet samples and thresholds were not kept"}
            atype = normalize_type(t.get("type"))
            out.append({
                "id": f"alr-L{idx}-{n}", "timestamp": utc_iso(t.get("timestamp") or data.get("timestamp")),
                "type": atype, "severity": normalize_severity(t.get("severity") or data.get("threat_level")),
                "source": clean_text(t.get("source") or t.get("source_ip"), 64) or None,
                "destination": clean_text(host, 64) or None,
                "dst_port": int(port) if port.isdigit() else None, "protocol": None,
                "rule": "legacy", "score": t.get("score") if isinstance(t.get("score"), (int, float)) else None,
                "score_kind": "anomaly_score" if t.get("score") is not None else None,
                "description": clean_text(t.get("description"), 400) or atype, "evidence": ev,
                "provenance": "historical", "occurrences": 1, "last_seen": utc_iso(t.get("timestamp")),
                "ledger_index": idx, "ledger_hash": bh,
            })
    return out
