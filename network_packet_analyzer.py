#!/usr/bin/env python3
"""packet intake: live capture through scapy or simulation, then validation and detection"""
import os
import queue
import socket
import sys
import threading
import time
from collections import deque

from blockaudit.detectors import BruteForceDetector, DoSDetector, PortScanDetector, sample_packets
from blockaudit.events import normalize_packet
from blockaudit.telemetry import Telemetry

CAPTURE_IDLE = "idle"
CAPTURE_STARTING = "starting"
CAPTURE_RUNNING = "capture_running"
CAPTURE_SIMULATION = "simulation"
CAPTURE_STOPPED = "capture_stopped"
CAPTURE_PERM_DENIED = "permission_denied"
CAPTURE_IFACE_MISSING = "interface_missing"
CAPTURE_SCAPY_MISSING = "scapy_missing"
CAPTURE_FAILED = "capture_failed"

try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
    _SCAPY_VERSION = getattr(scapy, "VERSION", "unknown")
except ImportError:
    scapy = None
    SCAPY_AVAILABLE = False
    _SCAPY_VERSION = None


def _cap_bit(bit):
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("CapEff:"):
                    return bool(int(line.split()[1], 16) & (1 << bit))
    except (OSError, ValueError):
        pass
    return False


def _check_raw_socket():
    try:
        socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0).close()
        return True
    except (OSError, AttributeError):
        return False


def get_permissions_info():
    is_root = os.geteuid() == 0
    raw = _check_raw_socket()
    cap_raw = _cap_bit(13)
    return {"is_root": is_root, "cap_net_raw": cap_raw, "cap_net_admin": _cap_bit(12), "raw_socket": raw,
            "can_capture": is_root or cap_raw or raw}


def get_available_interfaces():
    if SCAPY_AVAILABLE:
        try:
            return list(scapy.get_if_list())
        except Exception:
            pass
    try:
        return [n for _, n in socket.if_nameindex()]
    except OSError:
        return []


def default_interface():
    if SCAPY_AVAILABLE:
        try:
            return str(scapy.conf.iface)
        except Exception:
            pass
    names = [n for n in get_available_interfaces() if n != "lo"]
    return names[0] if names else ""


class NetworkPacketAnalyzer:
    def __init__(self, interface="", ml_detector=None, flow_analyzer=None, telemetry=None, simulator_factory=None,
                 provenance="live_capture", on_alert=None, queue_size=10000, ring=5000, thresholds=None):
        t = thresholds or {}
        self.interface = interface or default_interface()
        self.ml_detector = ml_detector
        self.flow_analyzer = flow_analyzer
        self.telemetry = telemetry or Telemetry()
        self.simulator_factory = simulator_factory
        self.provenance = provenance
        self.on_alert = on_alert
        self.simulator = None

        self.detectors = [
            PortScanDetector(t.get("portscan_ports", 20), t.get("portscan_window", 10)),
            DoSDetector(t.get("dos_pps", 200), t.get("dos_window", 5), t.get("dos_min_sources", 20)),
            BruteForceDetector(t.get("brute_attempts", 10), t.get("brute_window", 60)),
        ]
        self.ring = deque(maxlen=ring)
        self._lock = threading.RLock()
        self._q = queue.Queue(maxsize=queue_size)
        self._stop = threading.Event()
        self._worker = None
        self._sniffer = None

        self.counters = {"packets": 0, "bytes": 0, "invalid": 0, "dropped": 0, "alerts": 0}
        self.last_packet_at = None
        self.last_error = None
        self._status = CAPTURE_IDLE
        self._error = None
        self._fix = None

    @property
    def running(self):
        return self._worker is not None and self._worker.is_alive() and not self._stop.is_set()

    def _set_status(self, status, error=None, fix=None):
        self._status, self._error, self._fix = status, error, fix

    def get_capture_status(self):
        if self._status in (CAPTURE_RUNNING, CAPTURE_SIMULATION) and not self.running:
            self._set_status(CAPTURE_FAILED, "worker thread is not running")
        elif self._status == CAPTURE_RUNNING and self._sniffer is not None:
            exc = getattr(self._sniffer, "exception", None)
            if exc is not None or not getattr(self._sniffer, "running", True):
                self._set_status(CAPTURE_FAILED, f"capture thread stopped: {exc}" if exc else "capture thread stopped")
        return {"status": self._status, "mode": "simulation" if self.provenance == "simulation" else "live",
                "interface": self.interface, "scapy_available": SCAPY_AVAILABLE, "scapy_version": _SCAPY_VERSION,
                "error": self._error, "fix": self._fix, "queue_depth": self._q.qsize(),
                "queue_capacity": self._q.maxsize, "dropped_packets": self.counters["dropped"],
                "last_packet_at": self.last_packet_at}

    def _preflight(self):
        if not SCAPY_AVAILABLE:
            return CAPTURE_SCAPY_MISSING, "scapy is not installed", "pip install scapy, or set ENABLE_SIMULATION_MODE=1"
        ifaces = get_available_interfaces()
        if self.interface not in ifaces:
            return (CAPTURE_IFACE_MISSING, f"interface {self.interface!r} not found; available: {', '.join(ifaces) or 'none'}",
                    "set NETWORK_INTERFACE to one of the available interfaces")
        if not get_permissions_info()["can_capture"]:
            return (CAPTURE_PERM_DENIED, "no permission for raw packet capture",
                    f"sudo setcap cap_net_raw,cap_net_admin=eip {os.path.realpath(sys.executable)}, or use simulation mode")
        return None

    def start_capture(self):
        if self.running:
            return
        self._stop.clear()
        if self.provenance != "simulation" and self.simulator_factory is None:
            self._set_status(CAPTURE_STARTING)
            failure = self._preflight()
            if failure:
                self._set_status(*failure)
                return
        self._worker = threading.Thread(target=self._work, name="packet-worker", daemon=True)
        self._worker.start()
        if self.simulator_factory is not None:
            self.simulator = self.simulator_factory(self.enqueue)
            self.simulator.start()
            self._set_status(CAPTURE_SIMULATION)
        else:
            try:
                self._sniffer = scapy.AsyncSniffer(iface=self.interface, prn=self._on_scapy_packet, store=False)
                self._sniffer.start()
                self._set_status(CAPTURE_RUNNING)
            except PermissionError as e:
                self._set_status(CAPTURE_PERM_DENIED, str(e))
            except Exception as e:
                self._set_status(CAPTURE_FAILED, f"{type(e).__name__}: {e}")

    def stop_capture(self):
        self._stop.set()
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None
        if self.simulator is not None:
            self.simulator.stop()
            self.simulator = None
        if self._worker is not None:
            self._worker.join(timeout=5)
        self._set_status(CAPTURE_STOPPED)

    def _on_scapy_packet(self, pkt):
        try:
            ip = pkt.getlayer(scapy.IP) or pkt.getlayer(scapy.IPv6)
            tcp, udp = pkt.getlayer(scapy.TCP), pkt.getlayer(scapy.UDP)
            layer = tcp or udp
            proto = "TCP" if tcp else "UDP" if udp else "ICMP" if pkt.haslayer(scapy.ICMP) else "OTHER"
            self.enqueue({
                "ts": float(pkt.time), "src_ip": ip.src if ip else "", "dst_ip": ip.dst if ip else "",
                "src_port": layer.sport if layer else 0, "dst_port": layer.dport if layer else 0,
                "protocol": proto, "size": len(pkt), "flags": pkt.sprintf("%TCP.flags%") if tcp else ""})
        except Exception as e:
            self.last_error = f"{type(e).__name__}: {e}"
            self.counters["invalid"] += 1

    def enqueue(self, raw):
        try:
            self._q.put_nowait(raw)
            return True
        except queue.Full:
            self.counters["dropped"] += 1
            return False

    def _work(self):
        while not self._stop.is_set():
            try:
                raw = self._q.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self.process_packet(raw)
            except Exception as e:
                self.last_error = f"{type(e).__name__}: {e}"

    def process_packet(self, raw):
        """validate, account, detect. returns the alerts raised so tests can call this directly"""
        p = normalize_packet(raw, now=time.time())
        if p is None:
            self.counters["invalid"] += 1
            return []
        alerts = []
        with self._lock:
            self.counters["packets"] += 1
            self.counters["bytes"] += p["size"]
            self.last_packet_at = p["ts"]
            self.ring.append(p)
            self.telemetry.record_packet(p)
            for det in self.detectors:
                a = det.analyze(p)
                if a:
                    alerts.append(a)
            if self.flow_analyzer is not None:
                a = self.flow_analyzer.update(p)
                if a:
                    alerts.append(a)
            if self.ml_detector is not None:
                alerts.extend(self._ml_alerts(self.ml_detector.observe(p)))
            for a in alerts:
                self._attach_samples(a)
        for a in alerts:
            self.counters["alerts"] += 1
            if self.on_alert:
                self.on_alert(a)
        return alerts

    def tick(self, now=None):
        """periodic housekeeping: close the ml window and expire flows"""
        now = now or time.time()
        if self.flow_analyzer is not None:
            self.flow_analyzer.cleanup_expired_flows(now)
        if self.ml_detector is not None:
            for a in self._ml_alerts(self.ml_detector.flush(now)):
                self.counters["alerts"] += 1
                if self.on_alert:
                    self.on_alert(a)

    @staticmethod
    def _ml_alerts(anomalies):
        return [{
            "type": "ANOMALY", "severity": "HIGH" if a["score"] >= 0.75 else "MEDIUM", "source": a["source"],
            "score": a["score"], "score_kind": "anomaly_score", "rule": "isolation_forest.v1", "ts": time.time(),
            "description": f"{a['source']} deviated from the learned traffic baseline "
                           f"({', '.join(c['feature'] for c in a['contributors'])})",
            "evidence": {"observed": {"features": a["features"], "contributors": a["contributors"]},
                         "thresholds": {"anomaly_score": None}, "window_seconds": a["window_seconds"]},
        } for a in anomalies]

    def _attach_samples(self, alert):
        src, dst, port = alert.get("source"), alert.get("destination"), alert.get("dst_port")
        if alert["type"] == "ANOMALY":
            match = lambda p: p["src_ip"] == src
        elif alert["type"] in ("DDOS",):
            match = lambda p: p["dst_ip"] == dst and (not port or p["dst_port"] == port)
        else:
            match = lambda p: (not src or p["src_ip"] == src) and (not dst or p["dst_ip"] == dst) and (
                not port or p["dst_port"] == port or alert["type"] == "PORT_SCAN")
        alert.setdefault("evidence", {})["sample_packets"] = sample_packets(self.ring, match)

    def recent_packets(self, src=None, dst=None, since=None, until=None, limit=50):
        with self._lock:
            out = []
            for p in reversed(self.ring):
                if until is not None and p["ts"] > until:
                    continue
                if since is not None and p["ts"] < since:
                    break
                if src and p["src_ip"] != src and p["dst_ip"] != src:
                    continue
                if dst and p["dst_ip"] != dst and p["src_ip"] != dst:
                    continue
                out.append(p)
                if len(out) >= limit:
                    break
            out.reverse()
            return out

    def get_statistics(self):
        return {"packet_count": self.counters["packets"], "byte_count": self.counters["bytes"],
                "dropped_packets": self.counters["dropped"], "invalid_packets": self.counters["invalid"],
                "active_flows": self.flow_analyzer.get_network_intelligence()["active_flows"] if self.flow_analyzer else 0}
