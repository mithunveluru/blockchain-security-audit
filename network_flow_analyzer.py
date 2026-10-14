#!/usr/bin/env python3
import ipaddress
import threading
from collections import OrderedDict

from blockaudit.events import utc_iso


# python flags documentation ranges as private, so internal space is listed explicitly
INTERNAL = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "::1/128", "fe80::/10")]


def _private(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in INTERNAL if n.version == a.version)


class NetworkFlowAnalyzer:
    """bidirectional flow table with bounded size and a large-outbound-transfer rule"""

    rule = "exfil.v2"

    def __init__(self, flow_timeout=300, max_flows=20000, exfil_bytes=10 * 1024 * 1024, exfil_max_age=120):
        self.flow_timeout = flow_timeout
        self.max_flows = max_flows
        self.exfil_bytes = exfil_bytes
        self.exfil_max_age = exfil_max_age
        self.flows = OrderedDict()
        self._lock = threading.Lock()
        self.stats = {"total_flows": 0, "completed_flows": 0, "evicted_flows": 0, "exfil_flags": 0}

    @staticmethod
    def flow_key(p):
        a, b = (p["src_ip"], p["src_port"]), (p["dst_ip"], p["dst_port"])
        lo, hi = (a, b) if a <= b else (b, a)
        return f"{lo[0]}:{lo[1]}-{hi[0]}:{hi[1]}-{p['protocol']}"

    def update(self, p):
        """account one packet; returns an alert dict when a flow first crosses the exfiltration rule"""
        if not p["src_ip"] or not p["dst_ip"]:
            return None
        key = self.flow_key(p)
        now = p["ts"]
        with self._lock:
            f = self.flows.get(key)
            if f is None:
                f = self.flows[key] = {
                    "key": key, "initiator": p["src_ip"], "src_ip": p["src_ip"], "src_port": p["src_port"],
                    "dst_ip": p["dst_ip"], "dst_port": p["dst_port"], "protocol": p["protocol"],
                    "start": now, "last_seen": now, "packets": 0, "bytes": 0, "fwd_bytes": 0, "rev_bytes": 0,
                    "flags": set(), "flagged": False}
                self.stats["total_flows"] += 1
                while len(self.flows) > self.max_flows:
                    self.flows.popitem(last=False)
                    self.stats["evicted_flows"] += 1
            else:
                self.flows.move_to_end(key)
            f["packets"] += 1
            f["bytes"] += p["size"]
            f["last_seen"] = now
            if p["src_ip"] == f["initiator"]:
                f["fwd_bytes"] += p["size"]
            else:
                f["rev_bytes"] += p["size"]
            if p["flags"]:
                f["flags"].add(p["flags"])
            return self._exfil(f)

    def _exfil(self, f):
        if f["flagged"] or f["fwd_bytes"] < self.exfil_bytes:
            return None
        age = f["last_seen"] - f["start"]
        if age > self.exfil_max_age or not (_private(f["initiator"]) and not _private(f["dst_ip"])):
            return None
        f["flagged"] = True
        self.stats["exfil_flags"] += 1
        mb = f["fwd_bytes"] / 1024 / 1024
        return {
            "type": "DATA_EXFILTRATION", "severity": "HIGH", "source": f["initiator"], "destination": f["dst_ip"],
            "dst_port": f["dst_port"], "protocol": f["protocol"], "rule": self.rule, "ts": f["last_seen"],
            "description": f"{mb:.1f} MB sent from {f['initiator']} to {f['dst_ip']}:{f['dst_port']} in {age:.0f}s",
            "evidence": {"observed": {"outbound_bytes": f["fwd_bytes"], "inbound_bytes": f["rev_bytes"],
                                      "flow_age_seconds": round(age, 1), "packets": f["packets"],
                                      "flow_key": f["key"], "flow_started": utc_iso(f["start"])},
                         "thresholds": {"outbound_bytes": self.exfil_bytes, "max_flow_age_seconds": self.exfil_max_age},
                         "window_seconds": self.exfil_max_age},
        }

    def cleanup_expired_flows(self, now):
        with self._lock:
            dead = [k for k, f in self.flows.items() if now - f["last_seen"] > self.flow_timeout]
            for k in dead:
                del self.flows[k]
            self.stats["completed_flows"] += len(dead)

    def snapshot(self, limit=100, src=None, dst=None, port=None):
        with self._lock:
            rows = []
            for f in reversed(self.flows.values()):
                if src and src not in (f["src_ip"], f["dst_ip"]):
                    continue
                if dst and dst not in (f["src_ip"], f["dst_ip"]):
                    continue
                if port and port not in (f["src_port"], f["dst_port"]):
                    continue
                rows.append({"key": f["key"], "initiator": f["initiator"], "src_ip": f["src_ip"],
                             "src_port": f["src_port"], "dst_ip": f["dst_ip"], "dst_port": f["dst_port"],
                             "protocol": f["protocol"], "packets": f["packets"], "bytes": f["bytes"],
                             "outbound_bytes": f["fwd_bytes"], "inbound_bytes": f["rev_bytes"],
                             "started": utc_iso(f["start"]), "last_seen": utc_iso(f["last_seen"]),
                             "flags": sorted(f["flags"])[:6]})
                if len(rows) >= limit:
                    break
            return rows

    def get_network_intelligence(self):
        with self._lock:
            return {**self.stats, "active_flows": len(self.flows), "max_flows": self.max_flows}
