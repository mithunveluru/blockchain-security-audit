import ipaddress
import json
import os
import threading
import time
from collections import OrderedDict

from .events import (SEV_RANK, STATUSES, alert_event, alerts_from_block, build_alert, clean_text, parse_time, utc_iso)
from .ledger import LedgerError, atomic_write

RANGES = {"5m": 300, "15m": 900, "1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800}
MAX_NOTES, MAX_NOTE_LEN, MAX_INVESTIGATIONS = 50, 2000, 20000


class Whitelist:
    """addresses and networks whose alerts are suppressed. persisted so it survives restarts"""

    def __init__(self, path=None, defaults=("127.0.0.1", "::1")):
        self.path = path
        self.enabled = True
        self._nets = {}
        self._lock = threading.Lock()
        loaded = self._load()
        for entry in (loaded if loaded is not None else defaults):
            self._nets[entry] = ipaddress.ip_network(entry, strict=False)

    @staticmethod
    def parse(value):
        v = str(value or "").strip()
        if not v or len(v) > 64:
            raise ValueError("an ip address or cidr is required")
        try:
            return v, ipaddress.ip_network(v, strict=False)
        except ValueError:
            raise ValueError(f"invalid ip address or cidr: {clean_text(v, 40)}")

    def _load(self):
        if not self.path or not os.path.exists(self.path):
            return None
        try:
            with open(self.path) as f:
                data = json.load(f)
            self.enabled = bool(data.get("enabled", True))
            return [self.parse(e)[0] for e in data.get("entries", [])]
        except (OSError, ValueError):
            return None

    def _save(self):
        if self.path:
            body = {"enabled": self.enabled, "entries": sorted(self._nets)}
            atomic_write(self.path, json.dumps(body).encode())

    def add(self, value):
        key, net = self.parse(value)
        with self._lock:
            if len(self._nets) >= 1000:
                raise ValueError("whitelist is full")
            self._nets[key] = net
            self._save()
        return key

    def remove(self, value):
        with self._lock:
            if value not in self._nets:
                return False
            del self._nets[value]
            self._save()
            return True

    def toggle(self):
        with self._lock:
            self.enabled = not self.enabled
            self._save()
            return self.enabled

    def entries(self):
        with self._lock:
            return sorted(self._nets)

    def matches(self, ip):
        if not self.enabled or not ip:
            return False
        try:
            a = ipaddress.ip_address(ip.split(":")[0] if ip.count(":") == 1 else ip)
        except ValueError:
            return False
        with self._lock:
            return any(a in net for net in self._nets.values() if net.version == a.version)


class Investigations:
    def __init__(self, path=None):
        self.path = path
        self._lock = threading.Lock()
        self._data = {}
        if path and os.path.exists(path):
            try:
                with open(path) as f:
                    self._data = json.load(f)
            except (OSError, ValueError):
                self._data = {}

    def get(self, alert_id):
        with self._lock:
            rec = self._data.get(alert_id)
            return json.loads(json.dumps(rec)) if rec else {"status": "new", "notes": [], "updated": None}

    def status(self, alert_id):
        with self._lock:
            return self._data.get(alert_id, {}).get("status", "new")

    def _rec(self, alert_id):
        if alert_id not in self._data:
            if len(self._data) >= MAX_INVESTIGATIONS:
                raise ValueError("investigation store is full")
            self._data[alert_id] = {"status": "new", "notes": [], "updated": None}
        return self._data[alert_id]

    def set_status(self, alert_id, status):
        if status not in STATUSES:
            raise ValueError(f"status must be one of {', '.join(STATUSES)}")
        with self._lock:
            rec = self._rec(alert_id)
            rec["status"], rec["updated"] = status, utc_iso()
            self._save()

    def add_note(self, alert_id, text, actor):
        text = (text or "").strip()
        if not text:
            raise ValueError("note text is required")
        if len(text) > MAX_NOTE_LEN:
            raise ValueError(f"note is limited to {MAX_NOTE_LEN} characters")
        with self._lock:
            rec = self._rec(alert_id)
            if len(rec["notes"]) >= MAX_NOTES:
                raise ValueError("note limit reached for this alert")
            note = {"id": len(rec["notes"]) + 1, "at": utc_iso(), "by": actor, "text": clean_text(text, MAX_NOTE_LEN)}
            rec["notes"].append(note)
            rec["updated"] = note["at"]
            self._save()
            return note

    def _save(self):
        if self.path:
            atomic_write(self.path, json.dumps(self._data).encode())


def range_seconds(name, default="1h"):
    return RANGES.get(name, RANGES[default])


class AlertManager:
    """dedup, whitelist, persist to the ledger and keep a bounded searchable history"""

    def __init__(self, ledger, whitelist, investigations, provenance, telemetry, retention=5000, dedup_s=30,
                 max_ledger_per_min=120, emit=None, clock=time.time):
        self.ledger = ledger
        self.whitelist = whitelist
        self.investigations = investigations
        self.provenance = provenance
        self.telemetry = telemetry
        self.retention = retention
        self.dedup_s = dedup_s
        self.max_ledger_per_min = max_ledger_per_min
        self.emit = emit
        self.clock = clock
        self._alerts = OrderedDict()
        self._recent = {}
        self._ledger_times = []
        self._lock = threading.RLock()
        self.stats = {"raised": 0, "deduplicated": 0, "whitelisted": 0, "not_recorded": 0, "ledger_errors": 0}

    def load_from_ledger(self):
        with self._lock:
            for block in self.ledger.all_blocks():
                for a in alerts_from_block(block):
                    self._insert(a)

    def _insert(self, alert):
        self._alerts[alert["id"]] = alert
        while len(self._alerts) > self.retention:
            self._alerts.popitem(last=False)

    def submit(self, raw, provenance=None):
        alert = build_alert(raw, provenance or self.provenance, now=self.clock())
        if self.whitelist.matches(alert["source"]) or (alert["type"] != "INTEGRITY" and self.whitelist.matches(alert["destination"])):
            with self._lock:
                self.stats["whitelisted"] += 1
            return None
        key = (alert["type"], alert["source"], alert["destination"], alert["dst_port"])
        with self._lock:
            prior = self._recent.get(key)
            now = self.clock()
            if prior and now - prior[0] < self.dedup_s and prior[1] in self._alerts:
                existing = self._alerts[prior[1]]
                existing["occurrences"] += 1
                existing["last_seen"] = alert["timestamp"]
                self.stats["deduplicated"] += 1
                return None
            self._recent[key] = (now, alert["id"])
            if len(self._recent) > 5000:
                cutoff = now - self.dedup_s
                self._recent = {k: v for k, v in self._recent.items() if v[0] >= cutoff}
            self._record(alert, now)
            self._insert(alert)
            self.stats["raised"] += 1
        self.telemetry.record_alert(self.clock())
        if self.emit:
            self.emit("alert", self.public(alert))
        return alert

    def _record(self, alert, now):
        self._ledger_times = [t for t in self._ledger_times if now - t < 60]
        if len(self._ledger_times) >= self.max_ledger_per_min:
            self.stats["not_recorded"] += 1
            alert["evidence"]["ledger_note"] = "not recorded in the ledger: write rate cap reached"
            return
        try:
            block = self.ledger.append(alert_event(alert))
            alert["ledger_index"], alert["ledger_hash"] = block["index"], block["hash"]
            self._ledger_times.append(now)
        except LedgerError:
            self.stats["ledger_errors"] += 1
            alert["evidence"]["ledger_note"] = "not recorded in the ledger: write failed"

    def public(self, alert):
        out = dict(alert)
        out["status"] = self.investigations.status(alert["id"])
        return out

    def get(self, alert_id):
        with self._lock:
            a = self._alerts.get(alert_id)
            return self.public(a) if a else None

    def _select(self, q=None, severities=None, types=None, source=None, destination=None, status=None,
                provenance=None, since=None, until=None):
        ql = (q or "").strip().lower()
        with self._lock:
            items = list(self._alerts.values())
        out = []
        for a in items:
            if severities and a["severity"] not in severities:
                continue
            if types and a["type"] not in types:
                continue
            if source and a["source"] != source:
                continue
            if destination and a["destination"] != destination:
                continue
            if provenance and a["provenance"] != provenance:
                continue
            ts = parse_time(a["timestamp"])
            if ts is None:
                continue
            if since and ts < since or until and ts > until:
                continue
            if ql and ql not in " ".join(str(x or "") for x in (
                    a["id"], a["type"], a["source"], a["destination"], a["description"], a["rule"])).lower():
                continue
            pub = self.public(a)
            if status and pub["status"] != status:
                continue
            out.append(pub)
        return out

    def query(self, sort="time", order="desc", page=1, page_size=25, **filters):
        out = self._select(**filters)
        keyf = {"severity": lambda a: (SEV_RANK[a["severity"]], a["timestamp"]),
                "score": lambda a: (a["score"] is not None, a["score"] or 0, a["timestamp"])}.get(
            sort, lambda a: a["timestamp"])
        out.sort(key=keyf, reverse=(order != "asc"))
        total = len(out)
        page_size = max(1, min(int(page_size), 100))
        start = (max(1, int(page)) - 1) * page_size
        return out[start:start + page_size], total

    def facets(self, **filters):
        """counts for the filter bar: each facet ignores its own selection so options stay visible"""
        def count(key, skip, getter):
            f = {k: v for k, v in filters.items() if k != skip}
            c = {}
            for a in self._select(**f):
                k = getter(a)
                c[k] = c.get(k, 0) + 1
            return c
        return {"severity": count("severity", "severities", lambda a: a["severity"]),
                "type": count("type", "types", lambda a: a["type"]),
                "status": count("status", "status", lambda a: a["status"]),
                "provenance": count("provenance", "provenance", lambda a: a["provenance"])}

    def counts(self, since=None):
        sev, typ, status = {}, {}, {}
        total = 0
        with self._lock:
            items = list(self._alerts.values())
        for a in items:
            ts = parse_time(a["timestamp"])
            if since and (ts is None or ts < since):
                continue
            total += 1
            sev[a["severity"]] = sev.get(a["severity"], 0) + 1
            typ[a["type"]] = typ.get(a["type"], 0) + 1
            st = self.investigations.status(a["id"])
            status[st] = status.get(st, 0) + 1
        return {"total": total, "by_severity": sev, "by_type": typ, "by_status": status}

    def timeline(self, since, bucket_s):
        with self._lock:
            items = list(self._alerts.values())
        buckets = {}
        for a in items:
            ts = parse_time(a["timestamp"])
            if ts is None or ts < since:
                continue
            b = int(ts.timestamp() // bucket_s) * bucket_s
            row = buckets.setdefault(b, {"t": utc_iso(b), "total": 0, "high": 0, "sev": {}, "types": {}})
            row["total"] += 1
            row["sev"][a["severity"]] = row["sev"].get(a["severity"], 0) + 1
            row["types"][a["type"]] = row["types"].get(a["type"], 0) + 1
            row["high"] += SEV_RANK[a["severity"]] >= SEV_RANK["HIGH"]
        return [buckets[k] for k in sorted(buckets)]

    def related(self, alert, window_s=900, limit=25):
        base = parse_time(alert["timestamp"])
        with self._lock:
            items = list(self._alerts.values())
        out = []
        for a in items:
            if a["id"] == alert["id"]:
                continue
            same_src = alert["source"] and a["source"] == alert["source"]
            same_dst = alert["destination"] and a["destination"] == alert["destination"]
            if not (same_src or same_dst):
                continue
            ts = parse_time(a["timestamp"])
            if base and ts and abs((ts - base).total_seconds()) <= window_s:
                out.append({**self.public(a), "relation": "same source" if same_src else "same destination"})
        out.sort(key=lambda a: a["timestamp"])
        return out[:limit]

    def all_ids(self):
        with self._lock:
            return set(self._alerts)
