
from blockaudit.detectors import BruteForceDetector, DoSDetector, PortScanDetector
from blockaudit.events import normalize_packet
from network_flow_analyzer import NetworkFlowAnalyzer
from ml_anomaly_detector import MLAnomalyDetector
from tests.helpers import pkt


def norm(**kw):
    return normalize_packet(pkt(**kw))


def feed(det, packets):
    return [a for p in packets if (a := det.analyze(normalize_packet(p)))]


def test_port_scan_fires_once_with_evidence():
    d = PortScanDetector(threshold=20, time_window=10)
    alerts = feed(d, [pkt("203.0.113.5", "10.0.0.9", 1000 + i, ts=100 + i * 0.1) for i in range(40)])
    assert len(alerts) == 1
    ev = alerts[0]["evidence"]
    assert ev["observed"]["distinct_ports"] >= 20 and ev["thresholds"]["distinct_ports"] == 20
    assert alerts[0]["source"] == "203.0.113.5" and alerts[0]["destination"] == "10.0.0.9"


def test_normal_browsing_is_not_a_port_scan():
    d = PortScanDetector()
    pk = [pkt("192.168.1.5", "93.184.216.34", p, ts=100 + i) for i, p in enumerate([80, 443, 443, 80, 53, 443])]
    assert feed(d, pk) == []


def test_slow_scan_outside_window_is_not_flagged():
    d = PortScanDetector(threshold=20, time_window=10)
    assert feed(d, [pkt("203.0.113.5", "10.0.0.9", 1000 + i, ts=100 + i * 5) for i in range(40)]) == []


def test_established_traffic_to_many_ports_is_ignored():
    d = PortScanDetector(threshold=5)
    assert feed(d, [pkt("1.2.3.4", "10.0.0.9", 1000 + i, flags="A", ts=100 + i * 0.1) for i in range(40)]) == []


def test_scan_state_is_bounded():
    d = PortScanDetector(threshold=20, max_pairs=100)
    feed(d, [pkt(f"198.51.100.{i % 250}", f"10.1.{i // 250}.{i % 250}", 80, ts=100 + i * 0.001) for i in range(3000)])
    assert len(d.pairs) <= 100


def test_ddos_requires_rate_and_distribution():
    d = DoSDetector(pps=100, time_window=5, min_sources=20)
    flood = [pkt(f"198.18.{i % 200}.{i % 250 + 1}", "10.0.0.5", 80, ts=100 + i * 0.002) for i in range(700)]
    alerts = feed(d, flood)
    assert len(alerts) == 1 and alerts[0]["type"] == "DDOS" and alerts[0]["severity"] == "CRITICAL"
    assert alerts[0]["evidence"]["observed"]["unique_sources"] >= 20


def test_single_source_syn_flood_is_dos_flood_not_ddos():
    d = DoSDetector(pps=100, time_window=5)
    alerts = feed(d, [pkt("198.51.100.9", "10.0.0.5", 80, ts=100 + i * 0.002) for i in range(700)])
    assert [a["type"] for a in alerts] == ["DOS_FLOOD"]


def test_large_legitimate_download_is_not_a_flood():
    d = DoSDetector(pps=100, time_window=5, min_sources=20)
    dl = [pkt("93.184.216.34", "192.168.1.5", 50000, sport=443, flags="A", size=1400, ts=100 + i * 0.002) for i in range(1500)]
    assert feed(d, dl) == []


def test_flood_below_rate_is_ignored():
    d = DoSDetector(pps=200, time_window=5)
    assert feed(d, [pkt(f"198.18.0.{i % 250 + 1}", "10.0.0.5", 80, ts=100 + i * 0.05) for i in range(300)]) == []


def test_brute_force_counts_connection_attempts_not_packets():
    d = BruteForceDetector(threshold=10, time_window=60)
    ssh_session = [pkt("10.0.0.2", "10.0.0.9", 22, flags="PA", ts=100 + i) for i in range(200)]
    assert feed(d, ssh_session) == []
    attempts = [pkt("203.0.113.7", "10.0.0.9", 22, sport=40000 + i, ts=100 + i) for i in range(15)]
    alerts = feed(d, attempts)
    assert len(alerts) == 1 and alerts[0]["evidence"]["observed"]["service"] == "ssh"


def test_brute_force_window_expires():
    d = BruteForceDetector(threshold=10, time_window=60)
    assert feed(d, [pkt("203.0.113.7", "10.0.0.9", 22, sport=40000 + i, ts=100 + i * 20) for i in range(15)]) == []


def test_malformed_packets_are_rejected_not_crashing():
    for bad in (None, "x", {}, {"ts": "bad"}, {"ts": 1, "src_port": 70000}, {"ts": 1, "size": "big"}):
        assert normalize_packet(bad) is None
    p = normalize_packet({"ts": 1, "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "protocol": "weird", "flags": "SYN"})
    assert p["protocol"] == "OTHER" and p["flags"] == "S"


def test_exfil_flags_large_private_to_public_transfer_once():
    f = NetworkFlowAnalyzer(exfil_bytes=100_000)
    hits = [a for i in range(100) if (a := f.update(normalize_packet(pkt("192.168.1.7", "203.0.113.9", 443, size=1400, flags="PA", ts=100 + i * 0.1))))]
    assert len(hits) == 1 and hits[0]["evidence"]["observed"]["outbound_bytes"] >= 100_000


def test_exfil_ignores_inbound_and_internal_transfers():
    f = NetworkFlowAnalyzer(exfil_bytes=100_000)
    inbound = [f.update(normalize_packet(pkt("203.0.113.9", "192.168.1.7", 50000, sport=443, size=1400, ts=100 + i * 0.1))) for i in range(200)]
    internal = [f.update(normalize_packet(pkt("192.168.1.7", "192.168.1.8", 445, size=1400, ts=100 + i * 0.1))) for i in range(200)]
    assert not any(inbound) and not any(internal)


def test_flow_table_is_bounded():
    f = NetworkFlowAnalyzer(max_flows=50)
    for i in range(500):
        f.update(normalize_packet(pkt("10.0.0.1", f"10.0.{i // 250}.{i % 250 + 1}", 80, ts=100 + i)))
    assert len(f.flows) == 50 and f.stats["evicted_flows"] == 450


def test_ml_learns_then_flags_outlier_and_explains():
    ml = MLAnomalyDetector(window_s=10, min_train=60, threshold=0.6)
    t = 1000.0
    import random
    rnd = random.Random(1)
    for w in range(12):
        for s in range(8):
            for i in range(rnd.randint(15, 25)):
                ml.observe(normalize_packet(pkt(f"192.168.1.{s + 10}", "192.168.1.1", 443, flags="A", size=rnd.randint(500, 900), ts=t + i * 0.3)))
        t += 10.5
    ml.flush(t + 20)
    assert ml.state == "ready"
    found = []
    for i in range(400):
        found += ml.observe(normalize_packet(pkt("203.0.113.66", f"192.168.1.{i % 200 + 2}", 1000 + i, flags="S", size=60, ts=t + 30 + i * 0.02)))
    found += ml.flush(t + 60)
    assert found, "an obvious scanner-like outlier should score as anomalous"
    a = found[0]
    assert a["source"] == "203.0.113.66" and 0 <= a["score"] <= 1.5 and len(a["contributors"]) == 3


def test_ml_does_not_alert_while_learning():
    ml = MLAnomalyDetector(window_s=10, min_train=500)
    out = []
    for i in range(300):
        out += ml.observe(normalize_packet(pkt("1.2.3.4", "5.6.7.8", 80, ts=100 + i * 0.1)))
    out += ml.flush(500)
    assert out == [] and ml.state == "learning"
