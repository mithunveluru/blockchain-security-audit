#!/usr/bin/env python3

import socket
import struct
import time
import json
from datetime import datetime
from collections import defaultdict, deque
from typing import Dict, List, Tuple, Any
import threading
import hashlib

try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[Warning] Scapy not available. Using simulated packet capture.")


class NetworkPacketAnalyzer:
    def __init__(self, interface='wlp0s20f3', ml_detector=None):
        self.interface = interface
        self.ml_detector = ml_detector

        self.packet_count = 0
        self.byte_count = 0
        self.protocol_stats = defaultdict(int)
        self.ip_stats = defaultdict(lambda: {'packets': 0, 'bytes': 0})
        self.port_stats = defaultdict(int)

        self.active_flows = {}
        self.flow_timeout = 300

        self.port_scan_detector = PortScanDetector(threshold=3, time_window=10)
        self.ddos_detector = DDoSDetector(threshold=100, time_window=5)
        self.brute_force_detector = BruteForceDetector(threshold=5, time_window=60)

        self.recent_alerts = deque(maxlen=100)
        self.alert_lock = threading.Lock()

        self.recent_packets = deque(maxlen=10000)

        self.running = False
        self.capture_thread = None

        print(f"[Network Analyzer] Initialized on interface: {interface}")
        print(f"[Network Analyzer] ML Detector: {'Enabled' if ml_detector else 'Disabled'}")

    def start_capture(self):
        if self.running:
            print("[Warning] Capture already running")
            return

        self.running = True
        self.capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.capture_thread.start()
        print(f"[Network Analyzer] Started packet capture on {self.interface}")

    def stop_capture(self):
        self.running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        print("[Network Analyzer] Stopped packet capture")

    def _capture_loop(self):
        if SCAPY_AVAILABLE:
            self._capture_with_scapy()
        else:
            self._capture_simulated()

    def _capture_simulated(self):
        import random

        print("[Network Analyzer] Running in SIMULATION mode")
        print("[Network Analyzer] Install scapy for real packet capture")

        protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS']
        attack_types = ['normal', 'port_scan', 'ddos', 'brute_force']

        while self.running:
            attack_type = random.choices(
                attack_types, 
                weights=[85, 5, 5, 5]
            )[0]

            if attack_type == 'port_scan':
                src_ip = '203.45.67.89'
                dst_ip = '192.168.1.100'
                dst_port = random.randint(1, 65535)
                src_port = random.randint(10000, 65000)
                protocol = 'TCP'

            elif attack_type == 'ddos':
                src_ip = f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}'
                dst_ip = '192.168.1.50'
                dst_port = 80
                src_port = random.randint(10000, 65000)
                protocol = 'TCP'

            elif attack_type == 'brute_force':
                src_ip = '10.0.0.25'
                dst_ip = '192.168.1.10'
                dst_port = 22
                src_port = random.randint(10000, 65000)
                protocol = 'TCP'

            else:
                src_ip = f'192.168.1.{random.randint(10, 250)}'
                dst_ip = f'192.168.1.{random.randint(10, 250)}'
                dst_port = random.choice([80, 443, 22, 53, 25, 3306])
                src_port = random.randint(10000, 65000)
                protocol = random.choice(protocols)

            packet_data = {
                'timestamp': datetime.now().isoformat(),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': protocol,
                'size': random.randint(64, 1500),
                'flags': 'SYN' if protocol == 'TCP' else '',
                'payload_hash': hashlib.md5(f'{time.time()}'.encode()).hexdigest()[:16]
            }

            self.process_packet(packet_data)

            if attack_type == 'ddos':
                time.sleep(0.001)
            elif attack_type == 'port_scan':
                time.sleep(0.01)
            else:
                time.sleep(random.uniform(0.05, 0.5))

    def _capture_with_scapy(self):
        print("[Network Analyzer] Running in LIVE capture mode (Scapy)")

        def pkt_callback(pkt):
            try:
                packet_data = {
                    "timestamp": datetime.now().isoformat(),
                    "src_ip": pkt[scapy.IP].src if pkt.haslayer(scapy.IP) else "",
                    "dst_ip": pkt[scapy.IP].dst if pkt.haslayer(scapy.IP) else "",
                    "src_port": pkt[scapy.TCP].sport if pkt.haslayer(scapy.TCP) else (pkt[scapy.UDP].sport if pkt.haslayer(scapy.UDP) else 0),
                    "dst_port": pkt[scapy.TCP].dport if pkt.haslayer(scapy.TCP) else (pkt[scapy.UDP].dport if pkt.haslayer(scapy.UDP) else 0),
                    "protocol": "TCP" if pkt.haslayer(scapy.TCP) else ("UDP" if pkt.haslayer(scapy.UDP) else "OTHER"),
                    "size": len(pkt),
                    "flags": pkt.sprintf('%TCP.flags%') if pkt.haslayer(scapy.TCP) else "",
                    "payload_hash": hashlib.md5(bytes(pkt)).hexdigest()[:16]
                }
                self.process_packet(packet_data)
            except Exception as e:
                pass

        scapy.sniff(iface=self.interface, prn=pkt_callback, store=0)

    def process_packet(self, packet_data: Dict[str, Any]) -> Dict[str, Any]:
        self.packet_count += 1
        self.byte_count += packet_data.get('size', 0)

        protocol = packet_data.get('protocol', 'Unknown')
        self.protocol_stats[protocol] += 1

        src_ip = packet_data.get('src_ip')
        dst_ip = packet_data.get('dst_ip')

        self.ip_stats[src_ip]['packets'] += 1
        self.ip_stats[src_ip]['bytes'] += packet_data.get('size', 0)

        dst_port = packet_data.get('dst_port', 0)
        self.port_stats[dst_port] += 1

        self.recent_packets.append(packet_data)

        flow_key = self._get_flow_key(packet_data)
        if flow_key in self.active_flows:
            self.active_flows[flow_key]['packet_count'] += 1
            self.active_flows[flow_key]['byte_count'] += packet_data.get('size', 0)
            self.active_flows[flow_key]['last_seen'] = time.time()
        else:
            self.active_flows[flow_key] = {
                'first_seen': time.time(),
                'last_seen': time.time(),
                'packet_count': 1,
                'byte_count': packet_data.get('size', 0)
            }

        threats = []

        scan_alert = self.port_scan_detector.analyze(packet_data)
        if scan_alert:
            threats.append(scan_alert)
            self._add_alert(scan_alert)

        ddos_alert = self.ddos_detector.analyze(packet_data)
        if ddos_alert:
            threats.append(ddos_alert)
            self._add_alert(ddos_alert)

        brute_alert = self.brute_force_detector.analyze(packet_data)
        if brute_alert:
            threats.append(brute_alert)
            self._add_alert(brute_alert)

        if self.ml_detector and threats == []:
            ml_result = self.ml_detector.detect_anomaly(packet_data)
            if ml_result['is_anomaly']:
                ml_alert = {
                    'type': 'ANOMALY',
                    'severity': ml_result['threat_level'],
                    'score': ml_result['threat_score'],
                    'source': src_ip,
                    'target': dst_ip,
                    'description': f'ML detected anomaly: {ml_result["anomaly_type"]}',
                    'timestamp': packet_data['timestamp']
                }
                threats.append(ml_alert)
                self._add_alert(ml_alert)

        return {
            'packet_id': self.packet_count,
            'timestamp': packet_data['timestamp'],
            'packet_data': packet_data,
            'threats_detected': threats,
            'is_malicious': len(threats) > 0
        }

    def _add_alert(self, alert: Dict):
        with self.alert_lock:
            self.recent_alerts.append(alert)

    def get_recent_alerts(self) -> List[Dict]:
        with self.alert_lock:
            alerts = list(self.recent_alerts)
            self.recent_alerts.clear()
            return alerts

    def _get_flow_key(self, packet_data: Dict) -> Tuple:
        return (
            packet_data.get('src_ip'),
            packet_data.get('dst_ip'),
            packet_data.get('src_port', 0),
            packet_data.get('dst_port', 0),
            packet_data.get('protocol')
        )

    def get_statistics(self) -> Dict[str, Any]:
        current_time = time.time()
        expired_flows = [
            k for k, v in self.active_flows.items()
            if current_time - v['last_seen'] > self.flow_timeout
        ]
        for k in expired_flows:
            del self.active_flows[k]

        return {
            'packet_count': self.packet_count,
            'byte_count': self.byte_count,
            'bytes_mb': round(self.byte_count / 1024 / 1024, 2),
            'active_flows': len(self.active_flows),
            'unique_ips': len(self.ip_stats),
            'protocol_distribution': dict(self.protocol_stats),
            'top_talkers': sorted(
                [(ip, stats['packets']) for ip, stats in self.ip_stats.items()],
                key=lambda x: x[1],
                reverse=True
            )[:10],
            'top_ports': sorted(
                [(port, count) for port, count in self.port_stats.items()],
                key=lambda x: x[1],
                reverse=True
            )[:10]
        }

    def get_network_summary(self) -> str:
        stats = self.get_statistics()

        summary = f"""
╔══════════════════════════════════════════════════════════════╗
║           NETWORK TRAFFIC ANALYSIS SUMMARY                   ║
╚══════════════════════════════════════════════════════════════╝

Overall Statistics:
   • Total Packets:    {stats['packet_count']:,}
   • Total Data:       {stats['bytes_mb']} MB
   • Active Flows:     {stats['active_flows']}
   • Unique IPs:       {stats['unique_ips']}

Protocol Distribution:
"""
        for proto, count in sorted(stats['protocol_distribution'].items(), 
                                   key=lambda x: x[1], reverse=True):
            percentage = (count / stats['packet_count'] * 100) if stats['packet_count'] > 0 else 0
            summary += f"   • {proto:8s}: {count:6,} packets ({percentage:5.1f}%)\n"

        summary += "\nTop Talkers (by packet count):\n"
        for i, (ip, count) in enumerate(stats['top_talkers'][:5], 1):
            summary += f"   {i}. {ip:15s}: {count:6,} packets\n"

        summary += "\nTop Destination Ports:\n"
        port_names = {
            80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 53: 'DNS',
            25: 'SMTP', 3306: 'MySQL', 3389: 'RDP', 21: 'FTP'
        }
        for i, (port, count) in enumerate(stats['top_ports'][:5], 1):
            port_name = port_names.get(port, 'Unknown')
            summary += f"   {i}. Port {port:5d} ({port_name:6s}): {count:6,} packets\n"

        return summary


class PortScanDetector:
    def __init__(self, threshold=3, time_window=60):
        self.threshold = threshold
        self.time_window = time_window
        self.scan_data = defaultdict(lambda: defaultdict(set))
        self.scan_attempts = {}
        self.alerted = set()

    def analyze(self, packet_data: Dict) -> Dict:
        src_ip = packet_data.get('src_ip')
        dst_ip = packet_data.get('dst_ip')
        dst_port = packet_data.get('dst_port')
        protocol = packet_data.get('protocol')

        if protocol not in ['TCP', 'UDP']:
            return None

        if not src_ip or not dst_ip or src_ip == '' or dst_ip == '':
            return None
        if src_ip.startswith('224.') or dst_ip.startswith('224.'):
            return None
        if src_ip.startswith('169.254.') or dst_ip.startswith('169.254.'):
            return None
        if src_ip.startswith('255.') or dst_ip.startswith('255.'):
            return None

        self.scan_data[src_ip][dst_ip].add(dst_port)
        unique_ports = len(self.scan_data[src_ip][dst_ip])

        self.scan_attempts[src_ip] = {
            'port_count': unique_ports,
            'target': dst_ip,
            'timestamp': datetime.now().isoformat()
        }

        if unique_ports >= self.threshold:
            alert_key = f"{src_ip}->{dst_ip}"
            if alert_key not in self.alerted:
                self.alerted.add(alert_key)
                print(f"[ALERT] Port scan detected: {src_ip} → {dst_ip} ({unique_ports} ports)")

                return {
                    'type': 'PORT_SCAN',
                    'severity': 'HIGH',
                    'source': src_ip,
                    'target': dst_ip,
                    'port_count': unique_ports,
                    'description': f"Port scan: {src_ip} contacted {unique_ports} ports on {dst_ip}",
                    'timestamp': packet_data['timestamp']
                }

        return None


class DDoSDetector:
    def __init__(self, threshold=200, time_window=10):
        self.threshold = threshold
        self.time_window = time_window
        self.traffic_buffer = defaultdict(deque)
        self.traffic_counts = {}
        self.alerted = set()

    def analyze(self, packet_data: Dict) -> Dict:
        dst_ip = packet_data.get('dst_ip')
        dst_port = packet_data.get('dst_port')
        current_time = time.time()

        if not dst_ip or dst_ip == '':
            return None
        if dst_ip.startswith('224.') or dst_ip.startswith('255.') or dst_ip == '0.0.0.0':
            return None
        if dst_ip.startswith('169.254.'):
            return None
        if dst_port in [5353, 1900, 137, 138, 67, 68]:
            return None

        target = f"{dst_ip}:{dst_port}"
        self.traffic_buffer[target].append(current_time)

        while (self.traffic_buffer[target] and 
               current_time - self.traffic_buffer[target][0] > self.time_window):
            self.traffic_buffer[target].popleft()

        packet_rate = len(self.traffic_buffer[target])

        self.traffic_counts[target] = {
            'count': packet_rate,
            'timestamp': datetime.now().isoformat()
        }

        if packet_rate >= self.threshold:
            if target not in self.alerted:
                self.alerted.add(target)
                print(f"[ALERT] DDoS attack detected: {target} ({packet_rate} packets in {self.time_window}s)")

                return {
                    'type': 'DDOS_ATTACK',
                    'severity': 'CRITICAL',
                    'target': target,
                    'packet_rate': packet_rate,
                    'description': f"DDoS attack targeting {target} ({packet_rate} packets in {self.time_window}s)",
                    'timestamp': packet_data['timestamp']
                }
        else:
            self.alerted.discard(target)

        return None


class BruteForceDetector:
    def __init__(self, threshold=5, time_window=60):
        self.threshold = threshold
        self.time_window = time_window
        self.attempts = defaultdict(deque)
        self.attempt_counts = {}
        self.alerted = set()
        self.sensitive_ports = [21, 22, 23, 3389, 445, 3306, 5432]

    def analyze(self, packet_data: Dict) -> Dict:
        dst_ip = packet_data.get('dst_ip')
        dst_port = packet_data.get('dst_port')
        src_ip = packet_data.get('src_ip')
        protocol = packet_data.get('protocol')

        if dst_port not in self.sensitive_ports or protocol != 'TCP':
            return None

        if not src_ip or not dst_ip or src_ip == '' or dst_ip == '':
            return None

        current_time = time.time()
        target = f"{src_ip}->{dst_ip}:{dst_port}"

        self.attempts[target].append(current_time)

        while (self.attempts[target] and 
               current_time - self.attempts[target][0] > self.time_window):
            self.attempts[target].popleft()

        attempt_count = len(self.attempts[target])

        self.attempt_counts[target] = {
            'count': attempt_count,
            'timestamp': datetime.now().isoformat()
        }

        if attempt_count >= self.threshold:
            if target not in self.alerted:
                self.alerted.add(target)
                print(f"[ALERT] Brute force detected: {target} ({attempt_count} attempts in {self.time_window}s)")

                return {
                    'type': 'BRUTE_FORCE',
                    'severity': 'HIGH',
                    'source': src_ip,
                    'target': f"{dst_ip}:{dst_port}",
                    'attempt_count': attempt_count,
                    'description': f"Brute force: {attempt_count} attempts from {src_ip} to {dst_ip}:{dst_port}",
                    'timestamp': packet_data['timestamp']
                }

        return None


if __name__ == "__main__":
    print("="*70)
    print("NETWORK PACKET ANALYZER - DEMONSTRATION")
    print("="*70)

    analyzer = NetworkPacketAnalyzer(interface='wlp0s20f3')

    print("\n[1] Starting packet capture...")
    analyzer.start_capture()

    print("[2] Capturing packets for 30 seconds...")
    print("    Monitoring for security threats...")
    print()

    try:
        time.sleep(30)
    except KeyboardInterrupt:
        print("\n[Interrupted by user]")

    print("\n[3] Stopping packet capture...")
    analyzer.stop_capture()

    print("\n[4] Network Analysis Results:")
    print(analyzer.get_network_summary())

    print("\n[5] Recent Alerts:")
    alerts = analyzer.get_recent_alerts()
    if alerts:
        for alert in alerts:
            print(f"   • {alert['type']}: {alert['description']}")
    else:
        print("   No alerts detected")

    print("\n" + "="*70)
    print("Network packet analysis demonstration complete!")
    print("="*70)
