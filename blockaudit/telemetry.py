import threading
from collections import Counter, deque

from .events import utc_iso

BUCKET_S = 5
KEY_CAP = 200


class Telemetry:
    """fixed-width time buckets of traffic counters, bounded by retention and per-bucket key caps"""

    def __init__(self, retention_s=3600):
        self.buckets = deque(maxlen=max(1, retention_s // BUCKET_S))
        self._lock = threading.Lock()
        self.totals = Counter()

    def _bucket(self, ts):
        start = int(ts // BUCKET_S) * BUCKET_S
        if not self.buckets or self.buckets[-1]["t"] < start:
            self.buckets.append({"t": start, "packets": 0, "bytes": 0, "alerts": 0, "proto": Counter(),
                                 "src": Counter(), "dst": Counter(), "port": Counter()})
        b = self.buckets[-1]
        if b["t"] != start:
            for old in reversed(self.buckets):
                if old["t"] == start:
                    return old
                if old["t"] < start:
                    break
            return None
        return b

    @staticmethod
    def _add(counter, key, n):
        if key in counter or len(counter) < KEY_CAP:
            counter[key] += n
        else:
            counter["(other)"] += n

    def record_packet(self, p):
        with self._lock:
            b = self._bucket(p["ts"])
            self.totals["packets"] += 1
            self.totals["bytes"] += p["size"]
            if b is None:
                return
            b["packets"] += 1
            b["bytes"] += p["size"]
            b["proto"][p["protocol"]] += 1
            if p["src_ip"]:
                self._add(b["src"], p["src_ip"], 1)
            if p["dst_ip"]:
                self._add(b["dst"], p["dst_ip"], 1)
            if p["dst_port"]:
                self._add(b["port"], p["dst_port"], 1)

    def record_alert(self, ts):
        with self._lock:
            b = self._bucket(ts)
            if b is not None:
                b["alerts"] += 1

    def query(self, since_ts, until_ts=None, top=10):
        with self._lock:
            rows = [b for b in self.buckets if b["t"] + BUCKET_S > since_ts and (until_ts is None or b["t"] <= until_ts)]
            proto, src, dst, port = Counter(), Counter(), Counter(), Counter()
            series, packets, byt = [], 0, 0
            for b in rows:
                proto.update(b["proto"])
                src.update(b["src"])
                dst.update(b["dst"])
                port.update(b["port"])
                packets += b["packets"]
                byt += b["bytes"]
                series.append({"t": utc_iso(b["t"]), "packets": b["packets"], "bytes": b["bytes"], "alerts": b["alerts"]})
            for c in (src, dst, port):
                c.pop("(other)", None)
            return {
                "packets": packets, "bytes": byt, "bucket_seconds": BUCKET_S, "series": series,
                "protocols": dict(proto.most_common()),
                "top_sources": [{"ip": k, "packets": v} for k, v in src.most_common(top)],
                "top_destinations": [{"ip": k, "packets": v} for k, v in dst.most_common(top)],
                "top_ports": [{"port": k, "packets": v} for k, v in port.most_common(top)],
            }

    def last_packet_time(self):
        with self._lock:
            for b in reversed(self.buckets):
                if b["packets"]:
                    return b["t"]
        return None
