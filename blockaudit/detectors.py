import ipaddress
from collections import Counter, OrderedDict, deque
from functools import lru_cache

from .events import packet_summary

SENSITIVE_PORTS = {21: "ftp", 22: "ssh", 23: "telnet", 445: "smb", 1433: "mssql", 3306: "mysql", 3389: "rdp",
                   5432: "postgres", 5900: "vnc"}
NOISE_PORTS = {5353, 1900, 137, 138, 67, 68}


@lru_cache(maxsize=65536)
def ignorable(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return a.is_multicast or a.is_unspecified or a.is_link_local or ip == "255.255.255.255" or ip.endswith(".255")


def is_syn_only(p):
    return p["protocol"] == "TCP" and p["flags"] in ("S", "SYN")


class _Lru(OrderedDict):
    def __init__(self, cap):
        super().__init__()
        self.cap = cap

    def touch(self, key, factory):
        if key in self:
            self.move_to_end(key)
            return self[key]
        val = self[key] = factory()
        while len(self) > self.cap:
            self.popitem(last=False)
        return val


class PortScanDetector:
    rule = "port_scan.v2"

    def __init__(self, threshold=20, time_window=10, max_pairs=5000):
        self.threshold = threshold
        self.time_window = time_window
        self.cooldown = time_window * 3
        self.pairs = _Lru(max_pairs)
        self.alerted = _Lru(max_pairs)

    def describe(self):
        return {"distinct_ports": self.threshold, "window_seconds": self.time_window}

    def analyze(self, p):
        if p["protocol"] not in ("TCP", "UDP") or not p["src_ip"] or not p["dst_ip"]:
            return None
        if p["protocol"] == "TCP" and not is_syn_only(p):
            return None
        if ignorable(p["src_ip"]) or ignorable(p["dst_ip"]) or p["dst_port"] in NOISE_PORTS:
            return None
        now, key = p["ts"], (p["src_ip"], p["dst_ip"])
        ports = self.pairs.touch(key, dict)
        ports[p["dst_port"]] = now
        if len(ports) > self.threshold:
            for port in [k for k, t in ports.items() if now - t > self.time_window]:
                del ports[port]
        live = {k: t for k, t in ports.items() if now - t <= self.time_window}
        if len(live) < self.threshold:
            return None
        last = self.alerted.get(key)
        if last is not None and now - last < self.cooldown:
            return None
        self.alerted.touch(key, lambda: now)
        self.alerted[key] = now
        sample = sorted(live)[:25]
        return {
            "type": "PORT_SCAN", "severity": "HIGH", "source": p["src_ip"], "destination": p["dst_ip"],
            "protocol": p["protocol"], "rule": self.rule, "ts": now,
            "description": f"{p['src_ip']} contacted {len(live)} distinct ports on {p['dst_ip']} within "
                           f"{self.time_window}s",
            "evidence": {"observed": {"distinct_ports": len(live), "sample_ports": sample},
                         "thresholds": self.describe(), "window_seconds": self.time_window},
        }


class _Window:
    __slots__ = ("q", "sources", "syn", "horizon")

    def __init__(self):
        self.q = deque()
        self.sources = Counter()
        self.syn = 0
        self.horizon = 0

    def add(self, now, src, syn, cap):
        self.q.append((now, src, syn))
        self.sources[src] += 1
        self.syn += syn
        while self.q and (now - self.q[0][0] > self.horizon or len(self.q) > cap):
            self._drop()

    def _drop(self):
        _, src, syn = self.q.popleft()
        self.sources[src] -= 1
        if not self.sources[src]:
            del self.sources[src]
        self.syn -= syn


class DoSDetector:
    rule = "dos_flood.v2"

    def __init__(self, pps=200, time_window=5, min_sources=20, max_targets=2000, max_samples=20000):
        self.pps = pps
        self.time_window = time_window
        self.min_sources = min_sources
        self.max_samples = max_samples
        self.targets = _Lru(max_targets)
        self.alerted = _Lru(max_targets)
        self.cooldown = time_window * 6

    def describe(self):
        return {"packets_per_second": self.pps, "window_seconds": self.time_window,
                "min_sources_for_ddos": self.min_sources, "syn_ratio": 0.7}

    def analyze(self, p):
        dst = p["dst_ip"]
        if not dst or ignorable(dst) or p["dst_port"] in NOISE_PORTS or dst == "0.0.0.0":
            return None
        now, key = p["ts"], f"{dst}:{p['dst_port']}"
        w = self.targets.touch(key, _Window)
        w.horizon = self.time_window
        w.add(now, p["src_ip"], is_syn_only(p), self.max_samples)
        n = len(w.q)
        if n < self.pps * self.time_window:
            return None
        last = self.alerted.get(key)
        if last is not None and now - last < self.cooldown:
            return None
        syn_ratio = w.syn / n
        nsrc = len(w.sources)
        if not (syn_ratio >= 0.7 or nsrc >= self.min_sources):
            return None
        self.alerted.touch(key, lambda: now)
        self.alerted[key] = now
        distributed = nsrc >= self.min_sources
        rate = n / self.time_window
        top = [s for s, _ in w.sources.most_common(10)]
        return {
            "type": "DDOS" if distributed else "DOS_FLOOD", "severity": "CRITICAL" if distributed else "HIGH",
            "source": None if distributed else top[0], "destination": dst, "dst_port": p["dst_port"],
            "protocol": p["protocol"], "rule": self.rule, "ts": now,
            "description": f"{dst}:{p['dst_port']} received {rate:.0f} packets/s from {nsrc} source(s)",
            "evidence": {"observed": {"packets_per_second": round(rate, 1), "unique_sources": nsrc,
                                      "syn_only_ratio": round(syn_ratio, 3), "top_sources": top},
                         "thresholds": self.describe(), "window_seconds": self.time_window},
        }


class BruteForceDetector:
    rule = "brute_force.v2"

    def __init__(self, threshold=10, time_window=60, max_keys=5000):
        self.threshold = threshold
        self.time_window = time_window
        self.cooldown = time_window
        self.attempts = _Lru(max_keys)
        self.alerted = _Lru(max_keys)

    def describe(self):
        return {"connection_attempts": self.threshold, "window_seconds": self.time_window,
                "services": sorted(SENSITIVE_PORTS)}

    def analyze(self, p):
        if p["dst_port"] not in SENSITIVE_PORTS or not is_syn_only(p) or not p["src_ip"] or not p["dst_ip"]:
            return None
        if ignorable(p["src_ip"]) or ignorable(p["dst_ip"]):
            return None
        now, key = p["ts"], (p["src_ip"], p["dst_ip"], p["dst_port"])
        q = self.attempts.touch(key, lambda: deque(maxlen=max(self.threshold * 4, 64)))
        q.append((now, p["src_port"]))
        while q and now - q[0][0] > self.time_window:
            q.popleft()
        if len(q) < self.threshold:
            return None
        last = self.alerted.get(key)
        if last is not None and now - last < self.cooldown:
            return None
        self.alerted.touch(key, lambda: now)
        self.alerted[key] = now
        svc = SENSITIVE_PORTS[p["dst_port"]]
        return {
            "type": "BRUTE_FORCE", "severity": "HIGH", "source": p["src_ip"], "destination": p["dst_ip"],
            "dst_port": p["dst_port"], "protocol": "TCP", "rule": self.rule, "ts": now,
            "description": f"{len(q)} connection attempts from {p['src_ip']} to {svc} on {p['dst_ip']}:{p['dst_port']} "
                           f"within {self.time_window}s",
            "evidence": {"observed": {"connection_attempts": len(q), "service": svc,
                                      "distinct_source_ports": len({sp for _, sp in q}),
                                      "first_attempt": q[0][0], "last_attempt": q[-1][0]},
                         "thresholds": self.describe(), "window_seconds": self.time_window},
        }


def sample_packets(ring, match, limit=10):
    out = []
    for p in reversed(ring):
        if match(p):
            out.append(packet_summary(p))
            if len(out) >= limit:
                break
    out.reverse()
    return out
