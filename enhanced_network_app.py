#!/usr/bin/env python3

import os
import time
import json
import hashlib
import threading
import ipaddress
from datetime import datetime
from collections import deque
from flask import Flask, render_template_string, jsonify, request, send_from_directory
from flask_socketio import SocketIO, emit
from integrity_monitor import IntegrityMonitor

try:
    from adaptive_merkle_tree import AdaptiveMerkleTree
    from ml_anomaly_detector import MLAnomalyDetector
    from network_packet_analyzer import NetworkPacketAnalyzer
    from network_flow_analyzer import NetworkFlowAnalyzer
    MODULES_AVAILABLE = True
except ImportError:
    print("[Warning] Some modules not found. Using simplified mode.")
    MODULES_AVAILABLE = False

CHAIN_FILE = "network_blockchain.json"
MONITOR_INTERVAL = 0.01

app = Flask(__name__)
app.config['SECRET_KEY'] = 'network-security-blockchain-2025'
socketio = SocketIO(app, cors_allowed_origins="*")


class NetworkBlockchain:
    def __init__(self, chain_file=CHAIN_FILE):
        self.chain_file = chain_file
        self.chain = []
        self.merkle_tree = AdaptiveMerkleTree() if MODULES_AVAILABLE else None

        if os.path.exists(chain_file):
            self.load_chain()
        else:
            self.create_genesis_block()

    def create_genesis_block(self):
        genesis = {
            'index': 0,
            'timestamp': datetime.now().isoformat(),
            'data': 'Genesis Block - Network Security Audit System',
            'previous_hash': '0',
            'hash': '0' * 64
        }
        genesis['hash'] = self.calculate_hash(genesis)
        self.chain.append(genesis)
        self.save_chain()
        print("[Blockchain] Genesis block created")

    def calculate_hash(self, block):
        block_string = json.dumps({
            'index': block['index'],
            'timestamp': block['timestamp'],
            'data': block['data'],
            'previous_hash': block['previous_hash']
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

    def add_network_event(self, event_data):
        previous_block = self.chain[-1]

        new_block = {
            'index': len(self.chain),
            'timestamp': datetime.now().isoformat(),
            'data': json.dumps(event_data),
            'previous_hash': previous_block['hash'],
            'hash': ''
        }

        new_block['hash'] = self.calculate_hash(new_block)
        self.chain.append(new_block)

        if self.merkle_tree:
            self.merkle_tree.add_leaf(new_block['hash'], do_hash=False)
            self.merkle_tree.make_tree()

        if len(self.chain) % 10 == 0:
            self.save_chain()

        return new_block

    def verify_chain(self):
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i-1]

            if current['hash'] != self.calculate_hash(current):
                return False, f"Block {i} hash mismatch"

            if current['previous_hash'] != previous['hash']:
                return False, f"Block {i} link broken"

        return True, "Blockchain verified"

    def save_chain(self):
        with open(self.chain_file, 'w') as f:
            json.dump(self.chain, f, indent=2)

    def load_chain(self):
        with open(self.chain_file, 'r') as f:
            self.chain = json.load(f)
        print(f"[Blockchain] Loaded {len(self.chain)} blocks")


class NetworkSecuritySystem:
    def __init__(self):
        self.blockchain = NetworkBlockchain()

        self.integrity_monitor = IntegrityMonitor(
            blockchain_file=CHAIN_FILE,
            alert_callback=self._handle_integrity_alert,
            check_interval=30
        )

        if MODULES_AVAILABLE:
            self.ml_detector = MLAnomalyDetector(learning_window_days=7)
            self.packet_analyzer = NetworkPacketAnalyzer(
                interface='wlp0s20f3',
                ml_detector=self.ml_detector
            )
            self.flow_analyzer = NetworkFlowAnalyzer(ml_detector=self.ml_detector)
        else:
            self.ml_detector = None
            self.packet_analyzer = None
            self.flow_analyzer = None

        self.stats = {
            'packets_analyzed': 0,
            'flows_tracked': 0,
            'threats_detected': 0,
            'blockchain_blocks': len(self.blockchain.chain),
            'system_uptime': time.time()
        }

        self.recent_events = deque(maxlen=100)
        self.recent_threats = deque(maxlen=50)
        self.running = False
        self.monitor_thread = None

        self.last_logged_alerts = {}
        self.alert_dedup_timeout = 5

        self.whitelist = {
            '13.107.0.0/16', '13.104.0.0/14', '52.217.0.0/16', '52.84.0.0/15',
            '34.107.0.0/16', '34.64.0.0/10', '104.18.0.0/15', '1.1.1.1',
            '1.0.0.1', '8.8.8.8', '8.8.4.4', '127.0.0.1', '::1'
        }

        self.whitelist_enabled = True

        print("[Network Security System] Initialized")
        print(f"[Whitelist] Enabled with {len(self.whitelist)} entries")

    def _is_whitelisted(self, ip):
        if not self.whitelist_enabled or not ip:
            return False

        try:
            ip_obj = ipaddress.ip_address(ip)

            for entry in self.whitelist:
                try:
                    if '/' in entry:
                        if ip_obj in ipaddress.ip_network(entry, strict=False):
                            return True
                    elif ip == entry:
                        return True
                except Exception:
                    pass
        except Exception:
            pass

        return False

    def start(self):
        if self.running:
            return

        self.running = True

        if self.packet_analyzer:
            self.packet_analyzer.start_capture()

        self.integrity_monitor.start()

        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()

        print("[Network Security System] Started monitoring")

    def stop(self):
        self.running = False
        if self.packet_analyzer:
            self.packet_analyzer.stop_capture()

        self.integrity_monitor.stop()

        print("[Network Security System] Stopped")

    def _handle_integrity_alert(self, alert):
        try:
            socketio.emit('integrity_alert', alert)

            self.recent_events.append({
                'block_index': 'INTEGRITY',
                'timestamp': alert['timestamp'],
                'threat_level': alert['severity'],
                'summary': f"INTEGRITY: {alert['message']}"
            })

            if alert['severity'] == 'CRITICAL':
                self.stats['threats_detected'] += 1

        except Exception as e:
            print(f"[Error] Failed to broadcast integrity alert: {e}")

    def _monitor_loop(self):
        while self.running:
            try:
                if self.packet_analyzer:
                    recent_alerts = self.packet_analyzer.get_recent_alerts()

                    if recent_alerts:
                        for alert in recent_alerts:
                            source_ip = alert.get('source', '')
                            target_ip = alert.get('target', '')

                            if self._is_whitelisted(source_ip) or self._is_whitelisted(target_ip):
                                print(f"[Whitelist] Ignoring {alert['type']} from {source_ip} or {target_ip} (whitelisted)")
                                continue

                            alert_key = f"{alert['type']}_{source_ip}"
                            current_time = time.time()

                            if alert_key in self.last_logged_alerts:
                                elapsed = current_time - self.last_logged_alerts[alert_key]
                                if elapsed < self.alert_dedup_timeout:
                                    print(f"[Dedup] Skipping duplicate {alert['type']}")
                                    continue

                            event_data = {
                                'event_type': 'SECURITY_THREAT',
                                'timestamp': alert.get('timestamp', datetime.now().isoformat()),
                                'threat_level': alert.get('severity', 'MEDIUM'),
                                'threats_detected': [alert],
                                'flow_data': {},
                                'anomaly_score': 0
                            }

                            self._log_security_event(event_data)
                            self.last_logged_alerts[alert_key] = current_time
                            print(f"[Dashboard] Logged {alert['type']} to blockchain")

                self._update_statistics()
                self._emit_dashboard_update()
                time.sleep(MONITOR_INTERVAL)

            except Exception as e:
                print(f"[Error] Monitor loop: {e}")
                import traceback
                traceback.print_exc()
                time.sleep(5)

    def _log_security_event(self, event_data):
        log_entry = {
            'event_type': 'SECURITY_THREAT',
            'timestamp': datetime.now().isoformat(),
            'threat_level': event_data.get('threat_level', 'MEDIUM'),
            'threats': event_data.get('threats_detected', []),
            'flow_data': event_data.get('flow_data', {}),
            'anomaly_score': event_data.get('anomaly_score', 0)
        }

        block = self.blockchain.add_network_event(log_entry)
        self.stats['threats_detected'] += 1
        self.stats['blockchain_blocks'] = len(self.blockchain.chain)

        self.recent_events.append({
            'block_index': block['index'],
            'timestamp': log_entry['timestamp'],
            'threat_level': log_entry['threat_level'],
            'summary': f"{len(log_entry['threats'])} threat(s) detected"
        })

        self.recent_threats.append(log_entry)
        print(f"[Security Event] Block #{block['index']} - {log_entry['threat_level']} threat logged")

    def _update_statistics(self):
        if self.packet_analyzer:
            pkt_stats = self.packet_analyzer.get_statistics()
            self.stats['packets_analyzed'] = pkt_stats['packet_count']
            self.stats['flows_tracked'] = pkt_stats.get('active_flows', 0)

        self.stats['blockchain_blocks'] = len(self.blockchain.chain)
        self.stats['uptime_hours'] = (time.time() - self.stats['system_uptime']) / 3600

    def _emit_dashboard_update(self):
        try:
            update_data = {
                'stats': self.stats,
                'recent_events': list(self.recent_events)[-10:],
                'recent_threats': list(self.recent_threats)[-5:],
                'timestamp': datetime.now().isoformat()
            }

            socketio.emit('dashboard_update', update_data)
        except Exception as e:
            pass


network_system = NetworkSecuritySystem()
DASHBOARD_FILE = 'dashboard.html'


@app.route('/')
def index():
    if os.path.exists(DASHBOARD_FILE):
        with open(DASHBOARD_FILE, 'r') as f:
            return f.read()
    else:
        return "<h1>Dashboard file not found. Run setup script first.</h1>"


@app.route('/api/stats')
def get_stats():
    return jsonify(network_system.stats)


@app.route('/api/blockchain/verify')
def verify_blockchain():
    is_valid, message = network_system.blockchain.verify_chain()
    return jsonify({
        'valid': is_valid,
        'message': message,
        'block_count': len(network_system.blockchain.chain)
    })


@app.route('/api/integrity/status')
def get_integrity_status():
    return jsonify(network_system.integrity_monitor.get_status())


@app.route('/api/integrity/alerts')
def get_integrity_alerts():
    return jsonify(network_system.integrity_monitor.alerts)


@app.route('/api/start', methods=['POST'])
def start_monitoring():
    network_system.start()
    return jsonify({'status': 'started'})


@app.route('/api/stop', methods=['POST'])
def stop_monitoring():
    network_system.stop()
    return jsonify({'status': 'stopped'})


@app.route('/api/whitelist', methods=['GET'])
def get_whitelist():
    return jsonify({
        'whitelist': list(network_system.whitelist),
        'enabled': network_system.whitelist_enabled,
        'count': len(network_system.whitelist)
    })


@app.route('/api/whitelist/add', methods=['POST'])
def add_to_whitelist():
    data = request.json
    ip_or_cidr = data.get('ip')

    if ip_or_cidr:
        network_system.whitelist.add(ip_or_cidr)
        print(f"[Whitelist] Added {ip_or_cidr}")
        return jsonify({'status': 'added', 'ip': ip_or_cidr})

    return jsonify({'error': 'Invalid IP'}), 400


@app.route('/api/whitelist/remove', methods=['POST'])
def remove_from_whitelist():
    data = request.json
    ip_or_cidr = data.get('ip')

    if ip_or_cidr in network_system.whitelist:
        network_system.whitelist.remove(ip_or_cidr)
        print(f"[Whitelist] Removed {ip_or_cidr}")
        return jsonify({'status': 'removed', 'ip': ip_or_cidr})

    return jsonify({'error': 'IP not found'}), 404


@app.route('/api/whitelist/toggle', methods=['POST'])
def toggle_whitelist():
    network_system.whitelist_enabled = not network_system.whitelist_enabled
    print(f"[Whitelist] Toggled to {network_system.whitelist_enabled}")
    return jsonify({'enabled': network_system.whitelist_enabled})


@app.route('/soc')
def soc_dashboard():
    dashboard_file = os.path.join('soc_dashboard', 'index.html')
    if os.path.exists(dashboard_file):
        with open(dashboard_file, 'r') as f:
            return f.read()
    return "<h1>SOC Dashboard not found at soc_dashboard/index.html</h1>"


@app.route('/soc/assets/css/<filename>')
def soc_css(filename):
    return send_from_directory(os.path.join('soc_dashboard', 'assets', 'css'), filename)


@app.route('/soc/assets/js/<filename>')
def soc_js(filename):
    return send_from_directory(os.path.join('soc_dashboard', 'assets', 'js'), filename)


@app.route('/soc/assets/<path:path>')
def soc_assets(path):
    return send_from_directory(os.path.join('soc_dashboard', 'assets'), path)


if __name__ == '__main__':
    print("="*70)
    print("NETWORK SECURITY BLOCKCHAIN AUDIT SYSTEM")
    print("="*70)
    print("\nStarting system components...\n")

    network_system.start()

    print("\nSystem ready!\n")
    print("\nDashboards:")
    print("   • http://localhost:5000/          - Original Dashboard")
    print("   • http://localhost:5000/soc       - Professional SOC Dashboard")
    print("\nAPI Endpoints:")
    print("   • GET  /api/stats                 - Get statistics")
    print("   • GET  /api/blockchain/verify     - Verify blockchain")
    print("   • GET  /api/integrity/status      - Integrity monitor status")
    print("   • GET  /api/integrity/alerts      - All integrity alerts")
    print("   • POST /api/start                 - Start monitoring")
    print("   • POST /api/stop                  - Stop monitoring")
    print("\nWhitelist Management:")
    print("   • GET  /api/whitelist             - Get whitelist entries")
    print("   • POST /api/whitelist/add         - Add IP to whitelist")
    print("   • POST /api/whitelist/remove      - Remove IP from whitelist")
    print("   • POST /api/whitelist/toggle      - Enable/disable whitelist")
    print("\n" + "="*70)

    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
