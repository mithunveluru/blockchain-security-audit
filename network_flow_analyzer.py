#!/usr/bin/env python3

import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, List, Any, Tuple, Optional


class NetworkFlowAnalyzer:
    def __init__(self, ml_detector=None, flow_timeout=300):
        self.ml_detector = ml_detector
        self.flow_timeout = flow_timeout

        self.flows = {}

        self.ddos_threshold = 100
        self.port_scan_threshold = 10
        self.data_exfil_threshold = 10 * 1024 * 1024

        self.stats = {
            'total_flows': 0,
            'active_flows': 0,
            'completed_flows': 0,
            'malicious_flows': 0
        }

        self.port_scan_tracker = defaultdict(set)
        self.ddos_tracker = defaultdict(lambda: deque(maxlen=1000))

        print("[Network Flow Analyzer] Initialized")
        if ml_detector:
            print("[Network Flow Analyzer] ML Detector: Enabled")

    def create_flow(self, packet_data: Dict[str, Any]) -> Optional[str]:
        try:
            src_ip = packet_data.get('src_ip', '0.0.0.0')
            dst_ip = packet_data.get('dst_ip', '0.0.0.0')
            src_port = packet_data.get('src_port', 0)
            dst_port = packet_data.get('dst_port', 0)
            protocol = packet_data.get('protocol', 'UNKNOWN')

            flow_key = self._create_flow_key(src_ip, dst_ip, src_port, dst_port, protocol)

            if flow_key not in self.flows:
                self.flows[flow_key] = {
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'protocol': protocol,
                    'start_time': time.time(),
                    'last_seen': time.time(),
                    'packet_count': 0,
                    'byte_count': 0,
                    'flags': set(),
                    'threat_indicators': []
                }
                self.stats['total_flows'] += 1

            flow = self.flows[flow_key]
            flow['packet_count'] += 1
            flow['byte_count'] += packet_data.get('size', 0)
            flow['last_seen'] = time.time()

            if 'flags' in packet_data:
                flow['flags'].update(packet_data['flags'])

            self.stats['active_flows'] = len(self.flows)

            self._track_for_attacks(src_ip, dst_ip, dst_port)

            return flow_key

        except Exception as e:
            print(f"[Warning] Flow creation error: {e}")
            return None

    def _create_flow_key(self, src_ip: str, dst_ip: str, 
                        src_port: int, dst_port: int, protocol: str) -> str:
        if src_ip < dst_ip or (src_ip == dst_ip and src_port < dst_port):
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        else:
            return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"

    def _track_for_attacks(self, src_ip: str, dst_ip: str, dst_port: int):
        self.port_scan_tracker[src_ip].add(dst_port)

        ddos_key = f"{dst_ip}:{dst_port}"
        self.ddos_tracker[ddos_key].append(time.time())

    def analyze_flow(self, flow_key: str) -> Dict[str, Any]:
        if flow_key not in self.flows:
            return {'error': 'Flow not found'}

        flow = self.flows[flow_key]

        duration = flow['last_seen'] - flow['start_time']
        packet_rate = flow['packet_count'] / duration if duration > 0 else 0
        byte_rate = flow['byte_count'] / duration if duration > 0 else 0

        threats_detected = []
        threat_level = 'NORMAL'
        is_malicious = False

        port_scan_threat = self._detect_port_scan(flow['src_ip'])
        if port_scan_threat:
            threats_detected.append(port_scan_threat)
            is_malicious = True
            threat_level = 'HIGH'

        ddos_threat = self._detect_ddos(flow['dst_ip'], flow['dst_port'])
        if ddos_threat:
            threats_detected.append(ddos_threat)
            is_malicious = True
            threat_level = 'CRITICAL'

        exfil_threat = self._detect_data_exfiltration(flow)
        if exfil_threat:
            threats_detected.append(exfil_threat)
            is_malicious = True
            if threat_level != 'CRITICAL':
                threat_level = 'HIGH'

        brute_force_threat = self._detect_brute_force(flow)
        if brute_force_threat:
            threats_detected.append(brute_force_threat)
            is_malicious = True
            if threat_level == 'NORMAL':
                threat_level = 'MEDIUM'

        anomaly_score = 0
        if self.ml_detector and is_malicious:
            log_entry = {
                'timestamp': datetime.fromtimestamp(flow['start_time']).isoformat(),
                'source_ip': flow['src_ip'],
                'dest_ip': flow['dst_ip'],
                'dest_port': flow['dst_port'],
                'protocol': flow['protocol'],
                'level': 'ALERT' if is_malicious else 'INFO',
                'message': f"Flow analysis: {len(threats_detected)} threats detected"
            }

            ml_result = self.ml_detector.detect_anomaly(log_entry)
            anomaly_score = ml_result.get('threat_score', 0)

            if ml_result.get('is_anomaly'):
                if threat_level == 'NORMAL':
                    threat_level = ml_result.get('threat_level', 'MEDIUM')

        if is_malicious:
            self.stats['malicious_flows'] += 1

        return {
            'flow_key': flow_key,
            'flow_data': {
                'src_ip': flow['src_ip'],
                'dst_ip': flow['dst_ip'],
                'src_port': flow['src_port'],
                'dst_port': flow['dst_port'],
                'protocol': flow['protocol'],
                'duration': round(duration, 2),
                'packets': flow['packet_count'],
                'bytes': flow['byte_count'],
                'packet_rate': round(packet_rate, 2),
                'byte_rate': round(byte_rate, 2)
            },
            'is_malicious': is_malicious,
            'threat_level': threat_level,
            'threats_detected': threats_detected,
            'anomaly_score': anomaly_score
        }

    def _detect_port_scan(self, src_ip: str) -> Optional[Dict[str, Any]]:
        ports_contacted = len(self.port_scan_tracker[src_ip])

        if ports_contacted >= self.port_scan_threshold:
            return {
                'type': 'PORT_SCAN',
                'severity': 'HIGH',
                'description': f"Port scan detected: {src_ip} contacted {ports_contacted} ports",
                'source_ip': src_ip,
                'ports_scanned': ports_contacted
            }

        return None

    def _detect_ddos(self, dst_ip: str, dst_port: int) -> Optional[Dict[str, Any]]:
        ddos_key = f"{dst_ip}:{dst_port}"
        timestamps = self.ddos_tracker[ddos_key]

        if len(timestamps) < 10:
            return None

        current_time = time.time()
        recent_packets = sum(1 for ts in timestamps if current_time - ts <= 10)
        packet_rate = recent_packets / 10.0

        if packet_rate >= self.ddos_threshold:
            return {
                'type': 'DDOS',
                'severity': 'CRITICAL',
                'description': f"Possible DDoS attack: {dst_ip}:{dst_port} receiving {packet_rate:.1f} pkt/s",
                'target': f"{dst_ip}:{dst_port}",
                'packet_rate': round(packet_rate, 2)
            }

        return None

    def _detect_data_exfiltration(self, flow: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if flow['byte_count'] > self.data_exfil_threshold:
            duration = flow['last_seen'] - flow['start_time']
            if duration < 60:
                return {
                    'type': 'DATA_EXFILTRATION',
                    'severity': 'HIGH',
                    'description': f"Potential data exfiltration: {flow['byte_count']} bytes in {duration:.1f}s",
                    'source_ip': flow['src_ip'],
                    'dest_ip': flow['dst_ip'],
                    'bytes_transferred': flow['byte_count']
                }

        return None

    def _detect_brute_force(self, flow: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        auth_ports = {22, 23, 3389, 21, 25, 110, 143}

        if flow['dst_port'] in auth_ports and flow['packet_count'] > 50:
            duration = flow['last_seen'] - flow['start_time']
            connection_rate = flow['packet_count'] / duration if duration > 0 else 0

            if connection_rate > 5:
                return {
                    'type': 'BRUTE_FORCE',
                    'severity': 'MEDIUM',
                    'description': f"Brute force attempt on port {flow['dst_port']}",
                    'source_ip': flow['src_ip'],
                    'target_port': flow['dst_port'],
                    'attempts': flow['packet_count']
                }

        return None

    def cleanup_expired_flows(self):
        current_time = time.time()
        expired_keys = []

        for flow_key, flow in self.flows.items():
            if current_time - flow['last_seen'] > self.flow_timeout:
                expired_keys.append(flow_key)

        for key in expired_keys:
            del self.flows[key]
            self.stats['completed_flows'] += 1

        self.stats['active_flows'] = len(self.flows)

    def get_network_intelligence(self) -> Dict[str, Any]:
        return {
            'total_flows': self.stats['total_flows'],
            'active_flows': self.stats['active_flows'],
            'completed_flows': self.stats['completed_flows'],
            'malicious_flows': self.stats['malicious_flows'],
            'malicious_rate': round(
                self.stats['malicious_flows'] / self.stats['total_flows'] * 100, 2
            ) if self.stats['total_flows'] > 0 else 0,
            'port_scan_sources': len(self.port_scan_tracker),
            'ddos_targets': len(self.ddos_tracker)
        }


if __name__ == "__main__":
    print("="*70)
    print("NETWORK FLOW ANALYZER - DEMONSTRATION")
    print("="*70)

    analyzer = NetworkFlowAnalyzer()

    print("\n1. Normal traffic flow...")
    for i in range(20):
        packet = {
            'src_ip': '192.168.1.100',
            'dst_ip': '8.8.8.8',
            'src_port': 50000 + i,
            'dst_port': 443,
            'protocol': 'TCP',
            'size': 1500
        }
        flow_key = analyzer.create_flow(packet)
        time.sleep(0.1)

    print("\n2. Simulating port scan...")
    for port in range(20, 50):
        packet = {
            'src_ip': '203.45.67.89',
            'dst_ip': '192.168.1.100',
            'src_port': 60000,
            'dst_port': port,
            'protocol': 'TCP',
            'size': 64
        }
        flow_key = analyzer.create_flow(packet)

    print("\n3. Analyzing flows...")
    for flow_key in list(analyzer.flows.keys())[:3]:
        analysis = analyzer.analyze_flow(flow_key)
        print(f"\nFlow: {flow_key}")
        print(f"  Malicious: {analysis['is_malicious']}")
        print(f"  Threat Level: {analysis['threat_level']}")
        print(f"  Threats: {len(analysis['threats_detected'])}")
        for threat in analysis['threats_detected']:
            print(f"    - {threat['type']}: {threat['description']}")

    intel = analyzer.get_network_intelligence()
    print("\n" + "="*70)
    print("NETWORK INTELLIGENCE:")
    for key, value in intel.items():
        print(f"  {key}: {value}")
    print("="*70)
