#!/usr/bin/env python3
'''
enhanced_network_app.py

BLOCKCHAIN-BASED NETWORK SECURITY AUDIT SYSTEM
===============================================
Enterprise-grade network security monitoring with blockchain immutability.

NETWORK-FOCUSED FEATURES:
- Real-time network packet capture and analysis
- Network flow monitoring (NetFlow/IPFIX style)
- ML-based anomaly detection for network traffic
- Attack detection: DDoS, Port Scan, Brute Force, Data Exfiltration
- Blockchain audit trail for all network events
- Adaptive Merkle tree for efficient verification
- Real-time tamper detection and alerts
- Real-time dashboard with network visualizations
'''

import os
import time
import json
import hashlib
import threading
from datetime import datetime
from collections import deque
from flask import Flask, render_template_string, jsonify, request
from flask_socketio import SocketIO, emit
from integrity_monitor import IntegrityMonitor

# Import our enhanced modules
try:
    from adaptive_merkle_tree import AdaptiveMerkleTree
    from ml_anomaly_detector import MLAnomalyDetector
    from network_packet_analyzer import NetworkPacketAnalyzer
    from network_flow_analyzer import NetworkFlowAnalyzer
    MODULES_AVAILABLE = True
except ImportError:
    print("[Warning] Some modules not found. Using simplified mode.")
    MODULES_AVAILABLE = False

# Configuration
CHAIN_FILE = "network_blockchain.json"
MONITOR_INTERVAL = 0.1 # seconds

# Flask app setup
app = Flask(__name__)
app.config['SECRET_KEY'] = 'network-security-blockchain-2025'
socketio = SocketIO(app, cors_allowed_origins="*")


class NetworkBlockchain:
    '''
    Blockchain for network security audit logs
    Each block contains network events (packets, flows, threats)
    '''
    
    def __init__(self, chain_file=CHAIN_FILE):
        self.chain_file = chain_file
        self.chain = []
        self.merkle_tree = AdaptiveMerkleTree() if MODULES_AVAILABLE else None
        
        # Load existing chain or create genesis
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
    '''Main network security monitoring system'''
    
    def __init__(self):
        self.blockchain = NetworkBlockchain()
        
        # Initialize integrity monitor with callback
        self.integrity_monitor = IntegrityMonitor(
            blockchain_file=CHAIN_FILE,
            alert_callback=self._handle_integrity_alert,
            check_interval=30  # Check every 30 seconds
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
        
        print("[Network Security System] Initialized")
    
    def start(self):
        if self.running:
            return
        
        self.running = True
        
        if self.packet_analyzer:
            self.packet_analyzer.start_capture()
        
        # Start integrity monitor
        self.integrity_monitor.start()
        
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        print("[Network Security System] Started monitoring")
    
    def stop(self):
        self.running = False
        if self.packet_analyzer:
            self.packet_analyzer.stop_capture()
        
        # Stop integrity monitor
        self.integrity_monitor.stop()
        
        print("[Network Security System] Stopped")
    
    def _handle_integrity_alert(self, alert):
        """Handle integrity violation alerts"""
        # Broadcast to dashboard via WebSocket
        try:
            socketio.emit('integrity_alert', alert)
            
            # Also log to recent events
            self.recent_events.append({
                'block_index': 'INTEGRITY',
                'timestamp': alert['timestamp'],
                'threat_level': alert['severity'],
                'summary': f"🚨 INTEGRITY: {alert['message']}"
            })
            
            # Increment threat counter for critical alerts
            if alert['severity'] == 'CRITICAL':
                self.stats['threats_detected'] += 1
                
        except Exception as e:
            print(f"[Error] Failed to broadcast integrity alert: {e}")
    
    def _monitor_loop(self):
        while self.running:
            try:
                # Check packet analyzer for direct threat detections
                if self.packet_analyzer:
                    # Get alerts from detectors
                    recent_alerts = self.packet_analyzer.get_recent_alerts()
                    
                    if recent_alerts:
                        # Log each alert to blockchain
                        for alert in recent_alerts:
                            # Create event data for blockchain
                            event_data = {
                                'event_type': 'SECURITY_THREAT',
                                'timestamp': alert.get('timestamp', datetime.now().isoformat()),
                                'threat_level': alert.get('severity', 'MEDIUM'),
                                'threats_detected': [alert],
                                'flow_data': {},
                                'anomaly_score': 0
                            }
                            
                            # Log to blockchain
                            self._log_security_event(event_data)
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
            
            # FIX: Use packet analyzer's active_flows count instead
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


# Global system instance
network_system = NetworkSecuritySystem()

# Dashboard HTML saved as separate file - see dashboard.html
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


if __name__ == '__main__':
    print("="*70)
    print("NETWORK SECURITY BLOCKCHAIN AUDIT SYSTEM")
    print("="*70)
    print("\n🚀 Starting system components...\n")
    
    network_system.start()
    
    print("\n✓ System ready!\n")
    print("\n📊 Dashboard: http://localhost:5000")
    print("📡 API Endpoints:")
    print("   • GET  /api/stats - Get statistics")
    print("   • GET  /api/blockchain/verify - Verify blockchain")
    print("   • GET  /api/integrity/status - Integrity monitor status")
    print("   • GET  /api/integrity/alerts - All integrity alerts")
    print("   • POST /api/start - Start monitoring")
    print("   • POST /api/stop - Stop monitoring")
    print("\n" + "="*70)
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)

