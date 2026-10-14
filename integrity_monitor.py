#!/usr/bin/env python3
"""re-verifies the on-disk ledger against the copy held in memory and the independent checkpoint"""
import os
import threading
import time
from collections import deque

from blockaudit.ledger import utcnow


class IntegrityMonitor:
    def __init__(self, ledger, alert_callback=None, check_interval=30, poll_interval=1.0):
        self.ledger = ledger
        self.alert_callback = alert_callback
        self.check_interval = check_interval
        self.poll_interval = poll_interval
        self.alerts = deque(maxlen=200)
        self.tampering_detected = False
        self.last_check_time = None
        self.last_ok_time = None
        self.last_error = None
        self.checks = 0
        self.running = False
        self._thread = None
        self._stop = threading.Event()
        self._signature = None
        self._seen_stat = None

    def start(self):
        if self.running:
            return
        self._stop.clear()
        self.running = True
        self._seen_stat = self._stat()
        self._thread = threading.Thread(target=self._loop, name="integrity-monitor", daemon=True)
        self._thread.start()

    def stop(self):
        self.running = False
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def alive(self):
        return bool(self._thread and self._thread.is_alive())

    def _stat(self):
        try:
            st = os.stat(self.ledger.path)
            return (st.st_size, st.st_mtime_ns)
        except OSError:
            return None

    def _loop(self):
        next_full = 0.0
        while not self._stop.is_set():
            try:
                now = time.monotonic()
                changed = self._stat() != self.ledger.expected_stat() and self._stat() != self._seen_stat
                if changed or now >= next_full:
                    self.check_now()
                    next_full = time.monotonic() + self.check_interval
            except Exception as e:
                self.last_error = f"{type(e).__name__}: {e}"
            self._stop.wait(self.poll_interval)

    def check_now(self):
        result = self.ledger.verify_disk()
        self._seen_stat = self._stat()
        self.checks += 1
        self.last_check_time = utcnow()
        if result["valid"]:
            self.last_ok_time = self.last_check_time
            if self.tampering_detected:
                self.tampering_detected = False
                self._signature = None
                self._raise("INFO", "LEDGER_RESTORED", "ledger verification passes again", result)
        else:
            sig = tuple((f["index"], f["check"]) for f in result["failures"][:20])
            if not self.tampering_detected or sig != self._signature:
                self._raise("CRITICAL", "LEDGER_TAMPERED", self._describe(result), result)
            self.tampering_detected = True
            self._signature = sig
        return result

    @staticmethod
    def _describe(result):
        lines = [result["message"]]
        for f in result["failures"][:5]:
            where = f"block {f['index']}" if f["index"] is not None else "ledger"
            lines.append(f"{where}: {f['check']} - {f['detail']}")
        if result["failure_count"] > 5:
            lines.append(f"and {result['failure_count'] - 5} more failure(s)")
        return "\n".join(lines)

    def _raise(self, severity, kind, message, result):
        alert = {"timestamp": utcnow(), "severity": severity, "type": kind, "message": message,
                 "forensics": {"failures": result["failures"][:20], "failure_count": result["failure_count"],
                               "block_count": result["block_count"], "checks": result["checks"],
                               "first_failure_index": result["first_failure_index"]}}
        self.alerts.append(alert)
        if self.alert_callback:
            self.alert_callback(alert)

    def get_status(self):
        return {"running": self.running, "last_check": self.last_check_time, "last_ok": self.last_ok_time,
                "tampering_detected": self.tampering_detected, "checks": self.checks,
                "total_alerts": len(self.alerts), "recent_alerts": list(self.alerts)[-10:],
                "check_interval_seconds": self.check_interval, "last_error": self.last_error}
