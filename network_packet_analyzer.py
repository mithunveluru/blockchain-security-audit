#!/usr/bin/env python3
"""
network_packet_analyzer.py

NETWORK PACKET ANALYZER WITH ML-BASED THREAT DETECTION
========================================================
Captures and analyzes network packets in real-time for security threats.
Integrates with blockchain audit system for immutable logging.

Features:
- Real-time packet capture and deep packet inspection
- ML-based anomaly detection for network traffic
- Protocol analysis (TCP, UDP, ICMP, HTTP, HTTPS, DNS)
- Attack pattern detection (DDoS, Port Scan, Brute Force)
- Network flow analysis with statistics
- Integration with blockchain for audit trail
"""

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
    # For actual packet capture (requires root/admin)
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[Warning] Scapy not available. Using simulated packet capture.")


class NetworkPacketAnalyzer:
    """
    Real-time network packet analyzer with ML threat detection
    Focused on network security monitoring and intrusion detection
    """
    
    def __init__(self, interface='wlp0s20f3', ml_detector=None):
        self.interface = interface
        self.ml_detector = ml_detector
        
        # Network statistics
        self.packet_count = 0
        self.byte_count = 0
        self.protocol_stats = defaultdict(int)
        self.ip_stats = defaultdict(lambda: {'packets': 0, 'bytes': 0})
        self.port_stats = defaultdict(int)
        
        # Flow tracking (5-tuple: src_ip, dst_ip, src_port, dst_port, protocol)
        self.active_flows = {}
        self.flow_timeout = 300  # 5 minutes
        
        # Attack detection
        self.port_scan_detector = PortScanDetector()
        self.ddos_detector = DDoSDetector()
        self.brute_force_detector = BruteForceDetector()
        
        # Circular buffer for recent packets (for analysis)
        self.recent_packets = deque(maxlen=10000)
        
        # Thread control
        self.running = False
        self.capture_thread = None
        
        print(f"[Network Analyzer] Initialized on interface: {interface}")
        print(f"[Network Analyzer] ML Detector: {'Enabled' if ml_detector else 'Disabled'}")
    
    def start_capture(self):
        """
        Start packet capture in background thread
        """
        if self.running:
            print("[Warning] Capture already running")
            return
        
        self.running = True
        self.capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.capture_thread.start()
        print(f"[Network Analyzer] Started packet capture on {self.interface}")
    
    def stop_capture(self):
        """
        Stop packet capture
        """
        self.running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        print("[Network Analyzer] Stopped packet capture")
    
    def _capture_loop(self):
        """
        Main packet capture loop
        """
        if SCAPY_AVAILABLE:
            self._capture_with_scapy()
        else:
            self._capture_simulated()
    
    def _capture_simulated(self):
        """
        Simulated packet capture for demonstration
        """
        import random
        
        print("[Network Analyzer] Running in SIMULATION mode")
        print("[Network Analyzer] Install scapy for real packet capture")
        
        # Simulate network traffic patterns
        protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS']
        attack_types = ['normal', 'port_scan', 'ddos', 'brute_force']
        
        while self.running:
            # Generate simulated packet
            attack_type = random.choices(
                attack_types, 
                weights=[85, 5, 5, 5]  # 85% normal, 5% each attack
            )[0]
            
            if attack_type == 'port_scan':
                # Simulate port scan: same src, many dst ports
                src_ip = '203.45.67.89'
                dst_ip = '192.168.1.100'
                dst_port = random.randint(1, 65535)
                src_port = random.randint(10000, 65000)
                protocol = 'TCP'
            
            elif attack_type == 'ddos':
                # Simulate DDoS: many sources to one target
                src_ip = f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}'
                dst_ip = '192.168.1.50'  # Target server
                dst_port = 80  # Web server
                src_port = random.randint(10000, 65000)
                protocol = 'TCP'
            
            elif attack_type == 'brute_force':
                # Simulate brute force: same dst, many attempts
                src_ip = '10.0.0.25'
                dst_ip = '192.168.1.10'
                dst_port = 22  # SSH
                src_port = random.randint(10000, 65000)
                protocol = 'TCP'
            
            else:  # normal traffic
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
            
            # Simulate packet inter-arrival time
            if attack_type == 'ddos':
                time.sleep(0.001)  # Very fast for DDoS
            elif attack_type == 'port_scan':
                time.sleep(0.01)   # Fast for port scan
            else:
                time.sleep(random.uniform(0.05, 0.5))  # Normal traffic
    
    def process_packet(self, packet_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process captured packet and detect threats
        Returns threat assessment
        """
        self.packet_count += 1
        self.byte_count += packet_data.get('size', 0)
        
        # Update statistics
        protocol = packet_data.get('protocol', 'Unknown')
        self.protocol_stats[protocol] += 1
        
        src_ip = packet_data.get('src_ip')
        dst_ip = packet_data.get('dst_ip')
        
        self.ip_stats[src_ip]['packets'] += 1
        self.ip_stats[src_ip]['bytes'] += packet_data.get('size', 0)
        
        dst_port = packet_data.get('dst_port', 0)
        self.port_stats[dst_port] += 1
        
        # Store in recent packets buffer
        self.recent_packets.append(packet_data)
        
        # Update flow tracking
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
        
        # Attack detection
        threats = []
        
        # Port scan detection
        if self.port_scan_detector.analyze(packet_data):
            threats.append({
                'type': 'PORT_SCAN',
                'severity': 'HIGH',
                'source': src_ip,
                'description': f'Port scan detected from {src_ip}'
            })
        
        # DDoS detection
        if self.ddos_detector.analyze(packet_data):
            threats.append({
                'type': 'DDOS_ATTACK',
                'severity': 'CRITICAL',
                'target': dst_ip,
                'description': f'DDoS attack targeting {dst_ip}'
            })
        
        # Brute force detection
        if self.brute_force_detector.analyze(packet_data):
            threats.append({
                'type': 'BRUTE_FORCE',
                'severity': 'HIGH',
                'target': f'{dst_ip}:{dst_port}',
                'description': f'Brute force attack on {dst_ip}:{dst_port}'
            })
        
        # ML-based anomaly detection (FIXED - use detect_anomaly method)
        if self.ml_detector and threats == []:
            ml_result = self.ml_detector.detect_anomaly(packet_data)
            if ml_result['is_anomaly']:
                threats.append({
                    'type': 'ANOMALY',
                    'severity': ml_result['threat_level'],
                    'score': ml_result['threat_score'],
                    'description': f'ML detected anomaly: {ml_result["anomaly_type"]}'
                })
        
        # Return threat assessment
        return {
            'packet_id': self.packet_count,
            'timestamp': packet_data['timestamp'],
            'packet_data': packet_data,
            'threats_detected': threats,
            'is_malicious': len(threats) > 0
        }
    
    def _get_flow_key(self, packet_data: Dict) -> Tuple:
        """
        Generate flow key from packet
        """
        return (
            packet_data.get('src_ip'),
            packet_data.get('dst_ip'),
            packet_data.get('src_port', 0),
            packet_data.get('dst_port', 0),
            packet_data.get('protocol')
        )
        
        
    def _capture_with_scapy(self):
        print("[Network Analyzer] Running in LIVE capture mode (Scapy)")
        def pkt_callback(pkt):
            print("GOT PACKET", pkt.summary())  # ADD THIS LINE
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
                print(f"[Scapy Callback Error] {e}")
        scapy.sniff(iface=self.interface, prn=pkt_callback, store=0)


    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get current network statistics
        """
        # Clean up old flows
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
        """
        Get human-readable network summary
        """
        stats = self.get_statistics()
        
        summary = f"""
╔══════════════════════════════════════════════════════════════╗
║           NETWORK TRAFFIC ANALYSIS SUMMARY                   ║
╚══════════════════════════════════════════════════════════════╝

📊 Overall Statistics:
   • Total Packets:    {stats['packet_count']:,}
   • Total Data:       {stats['bytes_mb']} MB
   • Active Flows:     {stats['active_flows']}
   • Unique IPs:       {stats['unique_ips']}

📡 Protocol Distribution:
"""
        for proto, count in sorted(stats['protocol_distribution'].items(), 
                                   key=lambda x: x[1], reverse=True):
            percentage = (count / stats['packet_count'] * 100) if stats['packet_count'] > 0 else 0
            summary += f"   • {proto:8s}: {count:6,} packets ({percentage:5.1f}%)\n"
        
        summary += "\n🔝 Top Talkers (by packet count):\n"
        for i, (ip, count) in enumerate(stats['top_talkers'][:5], 1):
            summary += f"   {i}. {ip:15s}: {count:6,} packets\n"
        
        summary += "\n🔌 Top Destination Ports:\n"
        port_names = {
            80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 53: 'DNS',
            25: 'SMTP', 3306: 'MySQL', 3389: 'RDP', 21: 'FTP'
        }
        for i, (port, count) in enumerate(stats['top_ports'][:5], 1):
            port_name = port_names.get(port, 'Unknown')
            summary += f"   {i}. Port {port:5d} ({port_name:6s}): {count:6,} packets\n"
        
        return summary


class PortScanDetector:
    """Detects port scanning attacks"""
    
    def __init__(self, threshold=20, time_window=60):
        self.threshold = threshold  # ports per time window
        self.time_window = time_window  # seconds
        self.scan_data = defaultdict(lambda: defaultdict(set))
        self.alerts = set()
    
    def analyze(self, packet_data: Dict) -> bool:
        """Returns True if port scan detected"""
        src_ip = packet_data.get('src_ip')
        dst_ip = packet_data.get('dst_ip')
        dst_port = packet_data.get('dst_port')
        protocol = packet_data.get('protocol')
        
        if protocol not in ['TCP', 'UDP']:
            return False
        
        # Track ports accessed by this source IP
        current_time = time.time()
        self.scan_data[src_ip][dst_ip].add(dst_port)
        
        # Check if threshold exceeded
        unique_ports = len(self.scan_data[src_ip][dst_ip])
        
        if unique_ports >= self.threshold:
            alert_key = f"{src_ip}->{dst_ip}"
            if alert_key not in self.alerts:
                self.alerts.add(alert_key)
                print(f"[ALERT] Port scan detected: {src_ip} → {dst_ip} ({unique_ports} ports)")
                return True
        
        return False


class DDoSDetector:
    """Detects DDoS attacks"""
    
    def __init__(self, threshold=100, time_window=10):
        self.threshold = threshold  # packets per time window
        self.time_window = time_window  # seconds
        self.traffic_buffer = defaultdict(deque)
        self.alerts = set()
    
    def analyze(self, packet_data: Dict) -> bool:
        """Returns True if DDoS detected"""
        dst_ip = packet_data.get('dst_ip')
        dst_port = packet_data.get('dst_port')
        current_time = time.time()
        
        # Track packets to this destination
        target = f"{dst_ip}:{dst_port}"
        self.traffic_buffer[target].append(current_time)
        
        # Remove old entries
        while (self.traffic_buffer[target] and 
               current_time - self.traffic_buffer[target][0] > self.time_window):
            self.traffic_buffer[target].popleft()
        
        # Check if threshold exceeded
        packet_rate = len(self.traffic_buffer[target])
        
        if packet_rate >= self.threshold:
            if target not in self.alerts:
                self.alerts.add(target)
                print(f"[ALERT] Possible DDoS attack: {target} ({packet_rate} packets in {self.time_window}s)")
                return True
        else:
            self.alerts.discard(target)
        
        return False


class BruteForceDetector:
    """Detects brute force attacks"""
    
    def __init__(self, threshold=2, time_window=60):
        self.threshold = threshold
        self.time_window = time_window
        self.attempts = defaultdict(deque)
        self.alerts = set()
        self.sensitive_ports = [21, 22, 23, 3389, 445, 3306, 5432]  # FTP, SSH, Telnet, RDP, SMB, MySQL, PostgreSQL
    
    def analyze(self, packet_data: Dict) -> bool:
        """Returns True if brute force detected"""
        dst_ip = packet_data.get('dst_ip')
        dst_port = packet_data.get('dst_port')
        src_ip = packet_data.get('src_ip')
        protocol = packet_data.get('protocol')
        
        # Only monitor sensitive ports
        if dst_port not in self.sensitive_ports or protocol != 'TCP':
            return False
        
        current_time = time.time()
        target = f"{src_ip}->{dst_ip}:{dst_port}"
        
        # Track connection attempts
        self.attempts[target].append(current_time)
        
        # Remove old entries
        while (self.attempts[target] and 
               current_time - self.attempts[target][0] > self.time_window):
            self.attempts[target].popleft()
        
        # Check if threshold exceeded
        attempt_count = len(self.attempts[target])
        
        if attempt_count >= self.threshold:
            if target not in self.alerts:
                self.alerts.add(target)
                print(f"[ALERT] Possible brute force: {target} ({attempt_count} attempts in {self.time_window}s)")
                return True
        
        return False


# Example usage and testing
if __name__ == "__main__":
    print("="*70)
    print("NETWORK PACKET ANALYZER - DEMONSTRATION")
    print("="*70)
    
    # Initialize analyzer
    analyzer = NetworkPacketAnalyzer(interface='wlp0s20f3')
    
    # Start capture
    print("\n[1] Starting packet capture (simulation mode)...")
    analyzer.start_capture()
    
    # Run for 30 seconds
    print("[2] Capturing packets for 30 seconds...")
    print("    This will simulate various network traffic patterns:")
    print("    • Normal traffic (85%)")
    print("    • Port scans (5%)")
    print("    • DDoS attacks (5%)")
    print("    • Brute force attempts (5%)")
    print()
    
    try:
        time.sleep(30)
    except KeyboardInterrupt:
        print("\n[Interrupted by user]")
    
    # Stop capture
    print("\n[3] Stopping packet capture...")
    analyzer.stop_capture()
    
    # Display statistics
    print("\n[4] Network Analysis Results:")
    print(analyzer.get_network_summary())
    
    print("\n" + "="*70)
    print("✓ Network packet analysis demonstration complete!")
    print("="*70)
    print("\nNOTE: This is simulation mode for demonstration.")
    print("For real packet capture:")
    print("  1. Install scapy: pip install scapy")
    print("  2. Run with root/admin privileges")
    print("  3. Specify correct network interface")

