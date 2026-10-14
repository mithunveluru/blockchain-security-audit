import random
import threading
import time

SCENARIOS = ("port_scan", "brute_force", "ddos", "exfiltration")
# rfc 5737 documentation ranges: these addresses never route on the internet
SCANNER, BRUTER, EXFIL_DST = "203.0.113.50", "198.51.100.23", "203.0.113.9"


class TrafficSimulator:
    """synthetic traffic for demos and tests. every packet is labelled simulation downstream"""

    def __init__(self, emit, seed=None, scenario_interval=0, exfil_bytes=10 * 1024 * 1024):
        self.emit = emit
        self.rng = random.Random(seed)
        self.scenario_interval = scenario_interval
        self.exfil_bytes = exfil_bytes
        self._stop = threading.Event()
        self._thread = None
        self.injected = []

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="simulator", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)

    def alive(self):
        return bool(self._thread and self._thread.is_alive())

    def _pkt(self, src, dst, sport, dport, proto="TCP", size=None, flags=""):
        return {"ts": time.time(), "src_ip": src, "dst_ip": dst, "src_port": sport, "dst_port": dport,
                "protocol": proto, "size": size or self.rng.randint(64, 1500), "flags": flags}

    def _run(self):
        next_scn = time.monotonic() + min(20, self.scenario_interval) if self.scenario_interval else None
        while not self._stop.is_set():
            self.emit(self._benign())
            if next_scn is not None and time.monotonic() >= next_scn:
                self.inject(self.rng.choice(SCENARIOS))
                next_scn = time.monotonic() + self.scenario_interval
            self._stop.wait(self.rng.uniform(0.03, 0.2))

    def _benign(self):
        r = self.rng
        proto = r.choice(["TCP", "TCP", "TCP", "UDP"])
        port = r.choice([80, 443, 443, 53, 25, 3306, 22]) if proto == "TCP" else 53
        flags = "S" if proto == "TCP" and r.random() < 0.15 else ("A" if proto == "TCP" else "")
        return self._pkt(f"192.168.1.{r.randint(10, 250)}", f"192.168.1.{r.randint(10, 250)}",
                         r.randint(20000, 65000), port, proto, flags=flags)

    def inject(self, name):
        if name not in SCENARIOS:
            raise ValueError(f"unknown scenario {name!r}; choose one of {', '.join(SCENARIOS)}")
        r = self.rng
        self.injected.append((name, time.time()))
        if name == "port_scan":
            for port in r.sample(range(1, 1025), 40):
                self.emit(self._pkt(SCANNER, "192.168.1.100", r.randint(40000, 60000), port, flags="S", size=60))
        elif name == "brute_force":
            for _ in range(18):
                self.emit(self._pkt(BRUTER, "192.168.1.10", r.randint(40000, 60000), 22, flags="S", size=60))
        elif name == "ddos":
            for _ in range(1500):
                src = f"198.18.{r.randint(0, 255)}.{r.randint(1, 254)}"
                self.emit(self._pkt(src, "192.168.1.50", r.randint(10000, 65000), 80, flags="S", size=60))
        else:
            sport = r.randint(40000, 60000)
            for _ in range(self.exfil_bytes // 1400 + 50):
                self.emit(self._pkt("192.168.1.77", EXFIL_DST, sport, 443, size=1400, flags="PA"))
