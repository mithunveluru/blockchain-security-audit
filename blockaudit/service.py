import os
import threading
import time
from datetime import datetime, timezone

from integrity_monitor import IntegrityMonitor
from ml_anomaly_detector import MLAnomalyDetector
from network_flow_analyzer import NetworkFlowAnalyzer
from network_packet_analyzer import NetworkPacketAnalyzer, CAPTURE_RUNNING, CAPTURE_SIMULATION, CAPTURE_IDLE, CAPTURE_STOPPED

from .alerts import AlertManager, Investigations, Whitelist, range_seconds
from .events import SEVERITIES, utc_iso
from .ledger import Ledger, LedgerError
from .simulator import TrafficSimulator
from .telemetry import Telemetry

HEALTHY, DEGRADED, UNAVAILABLE, DISABLED = "healthy", "degraded", "unavailable", "disabled"


def _comp(name, state, detail, **extra):
    return {"name": name, "state": state, "detail": detail, **extra}


class SecurityService:
    def __init__(self, settings, emit=None, analyzer_kwargs=None):
        self.settings = settings
        self._emit = emit
        self.emit_failures = 0
        self.started_at = time.time()
        self.running = False
        self.provenance = "simulation" if settings.simulation else ("synthetic_test" if settings.env == "test" else "live_capture")
        os.makedirs(settings.data_dir, exist_ok=True)

        self.ledger = Ledger(settings.chain_file, settings.checkpoint_file)
        self.telemetry = Telemetry(settings.telemetry_retention_s)
        self.whitelist = Whitelist(os.path.join(settings.data_dir, "whitelist.json"))
        self.investigations = Investigations(os.path.join(settings.data_dir, "investigations.json"))
        self.alerts = AlertManager(self.ledger, self.whitelist, self.investigations, self.provenance, self.telemetry,
                                   retention=settings.alert_retention, dedup_s=settings.alert_dedup_s,
                                   max_ledger_per_min=settings.ledger_max_alerts_per_min, emit=self._safe_emit)
        self.alerts.load_from_ledger()
        self.flows = NetworkFlowAnalyzer(exfil_bytes=settings.exfil_bytes, exfil_max_age=settings.exfil_max_age_s)
        self.ml = MLAnomalyDetector(settings.ml_window_s, settings.ml_min_train, settings.ml_threshold)

        factory = None
        if settings.simulation:
            interval = int(os.environ.get("SIM_SCENARIO_INTERVAL", "120"))
            factory = lambda emit: TrafficSimulator(emit, scenario_interval=interval, exfil_bytes=settings.exfil_bytes)
        kwargs = dict(
            interface=settings.network_interface, ml_detector=self.ml, flow_analyzer=self.flows,
            telemetry=self.telemetry, simulator_factory=factory, provenance=self.provenance,
            on_alert=self.alerts.submit, queue_size=settings.packet_queue, ring=settings.packet_ring,
            thresholds={k: getattr(settings, k) for k in (
                "portscan_ports", "portscan_window", "dos_pps", "dos_window", "dos_min_sources", "brute_attempts",
                "brute_window")})
        kwargs.update(analyzer_kwargs or {})
        self.analyzer = NetworkPacketAnalyzer(**kwargs)
        self.integrity = IntegrityMonitor(self.ledger, self._integrity_alert, settings.integrity_check_interval)
        self._ticker = None
        self._stop = threading.Event()
        self.ticker_heartbeat = None
        self.ticker_errors = 0
        self.last_ticker_error = None
        self.clients = 0

    def audit(self, actor, action, detail=None):
        try:
            return self.ledger.append({"schema": 2, "event_type": "OPERATOR_ACTION", "time": utc_iso(), "actor": actor,
                                       "action": action, "detail": detail or {}})
        except LedgerError:
            return None

    def _safe_emit(self, event, payload):
        if self._emit is None:
            return
        try:
            self._emit(event, payload)
        except Exception:
            self.emit_failures += 1

    def _integrity_alert(self, ia):
        self._safe_emit("integrity_alert", ia)
        sev = ia["severity"]
        self.alerts.submit({
            "type": "INTEGRITY", "severity": sev, "rule": "integrity_monitor.v2",
            "description": ia["message"].splitlines()[0],
            "evidence": {"observed": ia["forensics"], "thresholds": {}, "window_seconds": None,
                         "alert_kind": ia["type"]}}, provenance="integrity_monitor")

    def start(self):
        if self.running:
            return
        self.running = True
        self._stop.clear()
        self.analyzer.start_capture()
        self.integrity.start()
        self._ticker = threading.Thread(target=self._tick_loop, name="ticker", daemon=True)
        self._ticker.start()

    def stop(self):
        self.running = False
        self._stop.set()
        self.analyzer.stop_capture()
        self.integrity.stop()
        if self._ticker:
            self._ticker.join(timeout=5)

    def close(self):
        self.stop()
        self.ledger.close()

    def _tick_loop(self):
        while not self._stop.is_set():
            try:
                self.analyzer.tick()
                self._safe_emit("snapshot", self.snapshot())
                self.ticker_heartbeat = time.time()
            except Exception as e:
                self.ticker_errors += 1
                self.last_ticker_error = f"{type(e).__name__}: {e}"
            self._stop.wait(1.0)

    def inject_scenario(self, name):
        if not self.settings.simulation or self.analyzer.simulator is None:
            raise PermissionError("scenario injection is only available in simulation mode")
        self.analyzer.simulator.inject(name)

    def snapshot(self):
        c = self.alerts.counts(since=datetime.fromtimestamp(time.time() - 3600, timezone.utc))
        return {
            "time": utc_iso(), "data_mode": self.provenance, "running": self.running,
            "packets": self.analyzer.counters["packets"], "bytes": self.analyzer.counters["bytes"],
            "dropped_packets": self.analyzer.counters["dropped"],
            "active_flows": self.flows.get_network_intelligence()["active_flows"],
            "alerts_last_hour": c["total"], "by_severity": c["by_severity"],
            "ledger_blocks": len(self.ledger), "ledger_valid": (self.ledger.last_verification or {}).get("valid"),
            "tampering_detected": self.integrity.tampering_detected,
        }

    def components(self):
        cap = self.analyzer.get_capture_status()
        st = cap["status"]
        comps = []
        if st in (CAPTURE_RUNNING, CAPTURE_SIMULATION):
            lag = time.time() - cap["last_packet_at"] if cap["last_packet_at"] else None
            stale = lag is not None and lag > 30 or (lag is None and time.time() - self.started_at > 30)
            detail = ("synthetic traffic generator" if st == CAPTURE_SIMULATION else f"capturing on {cap['interface']}")
            comps.append(_comp("packet_capture", DEGRADED if stale else HEALTHY,
                               detail + ("; no packets seen in the last 30s" if stale else ""),
                               mode=cap["mode"], last_packet_at=cap["last_packet_at"], dropped=cap["dropped_packets"],
                               queue_depth=cap["queue_depth"]))
        elif st in (CAPTURE_IDLE, CAPTURE_STOPPED):
            comps.append(_comp("packet_capture", DISABLED, "monitoring is stopped", mode=cap["mode"]))
        else:
            comps.append(_comp("packet_capture", UNAVAILABLE, cap["error"] or st, fix=cap["fix"], mode=cap["mode"]))
        comps.append(_comp("flow_analyzer", HEALTHY if self.running else DISABLED,
                           f"{self.flows.get_network_intelligence()['active_flows']} active flows"))
        ms = self.ml.status()
        comps.append(_comp("ml_detector", {"ready": HEALTHY, "learning": HEALTHY, "unavailable": UNAVAILABLE}[ms["state"]],
                           {"ready": "baseline model active", "learning": f"learning baseline: {ms['samples']}/{ms['samples_needed']} samples; no anomaly alerts yet",
                            "unavailable": "scikit-learn is not installed"}[ms["state"]], phase=ms["state"], **{k: ms[k] for k in ("samples", "fits")}))
        im = self.integrity.get_status()
        if not self.running:
            comps.append(_comp("integrity_monitor", DISABLED, "monitoring is stopped"))
        elif not self.integrity.alive():
            comps.append(_comp("integrity_monitor", UNAVAILABLE, "monitor thread is not running"))
        elif im["tampering_detected"]:
            comps.append(_comp("integrity_monitor", DEGRADED, "tampering detected; see the audit ledger", last_check=im["last_check"]))
        else:
            comps.append(_comp("integrity_monitor", HEALTHY, f"{im['checks']} checks; last ok {im['last_ok']}", last_check=im["last_check"]))
        ls = self.ledger.status()
        lv = ls["last_verification"]
        if ls["last_write_error"]:
            comps.append(_comp("ledger", UNAVAILABLE, "last write failed: " + ls["last_write_error"]["error"]))
        elif lv and not lv["valid"]:
            comps.append(_comp("ledger", DEGRADED, lv["message"], blocks=ls["block_count"]))
        elif ls["recovery"] and ls["recovery"]["kind"] not in ("migrated_legacy_json",):
            comps.append(_comp("ledger", DEGRADED, f"recovered at startup: {ls['recovery']['kind']}", blocks=ls["block_count"]))
        else:
            comps.append(_comp("ledger", HEALTHY, "verified" if lv else "not yet verified this session", blocks=ls["block_count"],
                               durability=ls["durability"], checkpoint_error=ls["checkpoint_error"]))
        worker_alive = self.analyzer._worker is not None and self.analyzer._worker.is_alive()
        beat = self.ticker_heartbeat
        if not self.running:
            comps.append(_comp("background_workers", DISABLED, "monitoring is stopped"))
        elif not worker_alive or not (self._ticker and self._ticker.is_alive()) or (beat and time.time() - beat > 10):
            comps.append(_comp("background_workers", UNAVAILABLE, "a worker thread stopped or stalled",
                               ticker_errors=self.ticker_errors, last_error=self.last_ticker_error))
        elif self.ticker_errors or self.analyzer.last_error:
            comps.append(_comp("background_workers", DEGRADED, self.last_ticker_error or self.analyzer.last_error,
                               ticker_errors=self.ticker_errors))
        else:
            comps.append(_comp("background_workers", HEALTHY, "packet worker, ticker and monitor running"))
        comps.append(_comp("websocket", DEGRADED if self.emit_failures else HEALTHY,
                           f"{self.clients} client(s) connected" + (f"; {self.emit_failures} failed emits" if self.emit_failures else ""),
                           clients=self.clients, emit_failures=self.emit_failures))
        return comps

    def health(self):
        comps = self.components()
        states = {c["state"] for c in comps}
        critical = {"ledger", "background_workers"}
        if any(c["state"] == UNAVAILABLE and c["name"] in critical for c in comps) or self.integrity.tampering_detected:
            overall = "critical"
        elif states & {DEGRADED, UNAVAILABLE}:
            overall = "degraded"
        else:
            overall = "ok"
        return {"status": overall, "components": comps, "data_mode": self.provenance, "time": utc_iso(),
                "uptime_seconds": round(time.time() - self.started_at), "running": self.running}

    def overview(self, range_name="1h"):
        secs = range_seconds(range_name)
        since = datetime.fromtimestamp(time.time() - secs, timezone.utc)
        tele = self.telemetry.query(time.time() - secs)
        counts = self.alerts.counts(since)
        high, _ = self.alerts.query(severities=["HIGH", "CRITICAL"], since=since, page_size=5)
        bucket = max(60, secs // 60)
        return {
            "range": range_name, "since": utc_iso(since.timestamp()), "data_mode": self.provenance,
            "alerts": counts, "alert_timeline": self.alerts.timeline(since, bucket),
            "traffic": {"packets": tele["packets"], "bytes": tele["bytes"], "series": tele["series"],
                        "bucket_seconds": tele["bucket_seconds"], "protocols": tele["protocols"]},
            "recent_high_priority": high,
            "ledger": self._ledger_summary(), "health": self.health(),
            "severities": list(SEVERITIES),
            "alert_stats": dict(self.alerts.stats),
        }

    def _ledger_summary(self):
        ls = self.ledger.status()
        lv = ls["last_verification"]
        return {"blocks": ls["block_count"], "tip_hash": ls["tip_hash"], "merkle_root": ls["merkle_root"],
                "verified": None if lv is None else lv["valid"], "verified_at": lv and lv["checked_at"],
                "verification_message": lv and lv["message"], "recovery": ls["recovery"],
                "tampering_detected": self.integrity.tampering_detected}

    def network(self, range_name="1h"):
        secs = range_seconds(range_name)
        t = self.telemetry.query(time.time() - secs, top=15)
        t["range"] = range_name
        t["data_mode"] = self.provenance
        t["flows"] = self.flows.get_network_intelligence()
        t["alert_timeline"] = self.alerts.timeline(datetime.fromtimestamp(time.time() - secs, timezone.utc), max(60, secs // 60))
        return t

