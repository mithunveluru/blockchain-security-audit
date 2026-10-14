"""per-source behavioural anomaly detection using scikit-learn's IsolationForest.

the model learns a baseline from traffic this process has observed, so a baseline learned while an
attack is already present will treat that behaviour as normal. scores are anomaly scores, not probabilities
"""
import threading
from collections import deque

import numpy as np

try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

FEATURES = ["packets_per_s", "bytes_per_s", "mean_packet_size", "distinct_dst_ips", "distinct_dst_ports", "syn_ratio"]
MIN_PACKETS = 10
MAX_SOURCES = 2000
RETRAIN_EVERY = 500


class MLAnomalyDetector:
    def __init__(self, window_s=10, min_train=200, threshold=0.65, seed=0):
        self.window_s = window_s
        self.min_train = min_train
        self.threshold = threshold
        self.seed = seed
        self._win_start = None
        self._acc = {}
        self._lock = threading.Lock()
        self.train = deque(maxlen=5000)
        self.model = None
        self._since_fit = 0
        self.median = None
        self.mad = None
        self.stats = {"windows": 0, "scored": 0, "anomalies": 0, "fits": 0}

    @property
    def state(self):
        if not SKLEARN_AVAILABLE:
            return "unavailable"
        return "ready" if self.model is not None else "learning"

    def status(self):
        return {"state": self.state, "samples": len(self.train), "samples_needed": self.min_train,
                "window_seconds": self.window_s, "threshold": self.threshold, "features": FEATURES,
                "score_meaning": "uncalibrated isolation-forest anomaly score, 0 to 1; higher is more unusual",
                **self.stats}

    def observe(self, p):
        """add a packet; returns anomalies from a window that just closed, if any"""
        with self._lock:
            out = []
            if self._win_start is None:
                self._win_start = p["ts"]
            elif p["ts"] - self._win_start >= self.window_s:
                out = self._close(p["ts"])
                self._win_start = p["ts"]
            if not p["src_ip"]:
                return out
            a = self._acc.get(p["src_ip"])
            if a is None:
                if len(self._acc) >= MAX_SOURCES:
                    return out
                a = self._acc[p["src_ip"]] = {"n": 0, "bytes": 0, "dst": set(), "ports": set(), "syn": 0}
            a["n"] += 1
            a["bytes"] += p["size"]
            if len(a["dst"]) < 512:
                a["dst"].add(p["dst_ip"])
            if len(a["ports"]) < 1024:
                a["ports"].add(p["dst_port"])
            a["syn"] += p["flags"] == "S"
            return out

    def flush(self, now):
        with self._lock:
            if self._win_start is not None and now - self._win_start >= self.window_s:
                out = self._close(now)
                self._win_start = now
                return out
        return []

    def _close(self, now):
        span = max(now - self._win_start, 1.0)
        rows, srcs = [], []
        for src, a in self._acc.items():
            if a["n"] < MIN_PACKETS:
                continue
            rows.append([a["n"] / span, a["bytes"] / span, a["bytes"] / a["n"], len(a["dst"]), len(a["ports"]),
                         a["syn"] / a["n"]])
            srcs.append(src)
        self._acc = {}
        self.stats["windows"] += 1
        if not rows or not SKLEARN_AVAILABLE:
            return []
        X = np.array(rows, dtype=float)
        anomalies = []
        if self.model is not None:
            raw = -self.model.score_samples(np.log1p(X))
            for i, score in enumerate(raw):
                self.stats["scored"] += 1
                if score >= self.threshold:
                    self.stats["anomalies"] += 1
                    anomalies.append(self._explain(srcs[i], X[i], float(score), span))
        flagged = {a["source"] for a in anomalies}
        for i, src in enumerate(srcs):
            if src not in flagged:
                self.train.append(X[i])
                self._since_fit += 1
        if len(self.train) >= self.min_train and (self.model is None or self._since_fit >= RETRAIN_EVERY):
            self._fit()
        return anomalies

    def _fit(self):
        data = np.log1p(np.array(self.train))
        self.model = IsolationForest(n_estimators=100, contamination="auto", random_state=self.seed).fit(data)
        self.median = np.median(data, axis=0)
        self.mad = np.median(np.abs(data - self.median), axis=0) + 1e-6
        self._since_fit = 0
        self.stats["fits"] += 1

    def _explain(self, src, row, score, span):
        z = np.abs((np.log1p(row) - self.median) / (1.4826 * self.mad))
        order = np.argsort(-z)[:3]
        return {
            "source": src, "score": score, "window_seconds": round(span, 1),
            "features": {n: round(float(v), 3) for n, v in zip(FEATURES, row)},
            "contributors": [{"feature": FEATURES[i], "value": round(float(row[i]), 3),
                              "baseline_median": round(float(np.expm1(self.median[i])), 3),
                              "robust_z": round(float(z[i]), 1)} for i in order],
        }
