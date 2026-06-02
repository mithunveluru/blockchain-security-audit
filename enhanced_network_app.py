#!/usr/bin/env python3

import os
import sys
import time
import json
import hashlib
import threading
import ipaddress
from datetime import datetime
from collections import deque
from flask import Flask, render_template_string, jsonify, request, send_from_directory
from flask_socketio import SocketIO, emit
from config import config
from integrity_monitor import IntegrityMonitor
from health.dependency_check import run_all as _run_dep_checks, print_report as _print_dep_report

try:
    from adaptive_merkle_tree import AdaptiveMerkleTree
    from ml_anomaly_detector import MLAnomalyDetector
    from network_packet_analyzer import NetworkPacketAnalyzer
    from network_flow_analyzer import NetworkFlowAnalyzer
    MODULES_AVAILABLE = True
except ImportError as _module_err:
    print(f"\n[FATAL] Failed to import required module: {_module_err}", file=sys.stderr)
    print("  Hint: run the dependency check — python health/dependency_check.py", file=sys.stderr)
    print("  Or enable simulation mode: ENABLE_SIMULATION_MODE=1 python enhanced_network_app.py\n", file=sys.stderr)
    MODULES_AVAILABLE = False
    if not config.ENABLE_SIMULATION_MODE:
        sys.exit(1)

CHAIN_FILE = config.CHAIN_FILE
MONITOR_INTERVAL = 0.01

app = Flask(__name__)
app.config['SECRET_KEY'] = config.SECRET_KEY
socketio = SocketIO(app, cors_allowed_origins=config.CORS_ORIGINS)


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
            self.merkle_tree.add_leaf(new_block['hash'], hashed=False)
            self.merkle_tree.build()

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
        valid, msg = self.verify_chain()
        if not valid:
            print(f"[Blockchain] WARNING: Loaded chain failed integrity check: {msg}")


class NetworkSecuritySystem:
    def __init__(self):
        self.blockchain = NetworkBlockchain()

        self.integrity_monitor = IntegrityMonitor(
            blockchain_file=CHAIN_FILE,
            alert_callback=self._handle_integrity_alert,
            check_interval=30
        )

        if MODULES_AVAILABLE:
            self.ml_detector = MLAnomalyDetector(learning_window_days=config.ML_LEARNING_WINDOW_DAYS)
            self.packet_analyzer = NetworkPacketAnalyzer(
                interface=config.NETWORK_INTERFACE,
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
            network_stats = {}
            if self.packet_analyzer:
                pkt_stats = self.packet_analyzer.get_statistics()
                network_stats = {
                    'protocol_distribution': pkt_stats.get('protocol_distribution', {}),
                    'top_ports': pkt_stats.get('top_ports', []),
                    'top_talkers': pkt_stats.get('top_talkers', []),
                }

            update_data = {
                'stats': self.stats,
                'recent_events': list(self.recent_events)[-10:],
                'recent_threats': list(self.recent_threats)[-5:],
                'network_stats': network_stats,
                'capture_status': self.packet_analyzer.get_capture_status() if self.packet_analyzer else {'status': 'unavailable'},
                'timestamp': datetime.now().isoformat()
            }

            socketio.emit('dashboard_update', update_data)
        except Exception as e:
            print(f"[Error] Dashboard emit failed: {e}")


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


@app.route('/api/health')
def get_health():
    from health.dependency_check import get_environment_info
    from network_packet_analyzer import get_permissions_info, SCAPY_AVAILABLE, _SCAPY_VERSION

    capture_status = (
        network_system.packet_analyzer.get_capture_status()
        if network_system.packet_analyzer else {
            'status': 'scapy_missing', 'mode': 'none', 'interface': config.NETWORK_INTERFACE,
            'scapy_available': False, 'scapy_version': None, 'error': 'Modules not loaded', 'fix': None,
        }
    )

    perms = get_permissions_info()
    env   = get_environment_info()
    bc_valid, bc_msg = network_system.blockchain.verify_chain()

    python_real = os.path.realpath(sys.executable)
    setcap_cmd  = f"sudo /usr/sbin/setcap cap_net_raw,cap_net_admin=eip {python_real}"
    sudo_cmd    = f"sudo {python_real} enhanced_network_app.py"

    overall = 'ok'
    if capture_status.get('status') in ('permission_denied', 'interface_missing', 'scapy_missing', 'capture_failed'):
        overall = 'degraded'
    if not bc_valid:
        overall = 'critical'

    return jsonify({
        'status': overall,
        'capture': capture_status,
        'blockchain': {
            'blocks': len(network_system.blockchain.chain),
            'valid': bc_valid,
            'message': bc_msg,
        },
        'dependencies': {
            'flask':        True,
            'scapy':        SCAPY_AVAILABLE,
            'scapy_version': _SCAPY_VERSION,
            'numpy':        _dep_ok('numpy'),
            'watchdog':     _dep_ok('watchdog'),
            'flask_socketio': _dep_ok('flask_socketio'),
        },
        'permissions': perms,
        'environment': {
            'python':           env['python_executable'],
            'python_real':      env['python_real_path'],
            'python_version':   env['python_version'],
            'env_type':         env['env_type'],
            'env_name':         env['env_name'],
            'conda_env':        env['conda_env'],
            'virtual_env':      env['virtual_env'],
            'user':             env['user'],
            'uid':              env['uid'],
            'working_dir':      env['working_dir'],
            'interface':        config.NETWORK_INTERFACE,
            'simulation_mode':  config.ENABLE_SIMULATION_MODE,
        },
        'system': {
            'running':          network_system.running,
            'uptime_hours':     round(network_system.stats.get('uptime_hours', 0), 3),
            'threats_detected': network_system.stats.get('threats_detected', 0),
            'blockchain_blocks': len(network_system.blockchain.chain),
        },
        'fix_commands': {
            'setcap':   setcap_cmd,
            'sudo_run': sudo_cmd,
            'sim_mode': 'ENABLE_SIMULATION_MODE=true python enhanced_network_app.py',
            'run_sh':   './run.sh',
        },
    })


def _dep_ok(module: str) -> bool:
    try:
        __import__(module)
        return True
    except ImportError:
        return False


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
    data = request.json or {}
    ip_or_cidr = data.get('ip', '').strip()

    if not ip_or_cidr:
        return jsonify({'error': 'ip field required'}), 400

    try:
        if '/' in ip_or_cidr:
            ipaddress.ip_network(ip_or_cidr, strict=False)
        else:
            ipaddress.ip_address(ip_or_cidr)
    except ValueError:
        return jsonify({'error': f'Invalid IP address or CIDR: {ip_or_cidr}'}), 400

    network_system.whitelist.add(ip_or_cidr)
    print(f"[Whitelist] Added {ip_or_cidr}")
    return jsonify({'status': 'added', 'ip': ip_or_cidr})


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
    dep_results = _run_dep_checks(
        interface=config.NETWORK_INTERFACE,
        chain_file=config.CHAIN_FILE,
    )
    all_ok = _print_dep_report(dep_results, fail_on_errors=False)

    if not all_ok and not config.ENABLE_SIMULATION_MODE:
        # Raw socket failure is non-fatal — user can still start, but capture will fail
        # Only hard-fail if scapy itself is missing
        scapy_result = next((r for r in dep_results if r.name == "scapy"), None)
        if scapy_result and not scapy_result.ok:
            print("[FATAL] Scapy not available. Cannot start packet capture.", file=sys.stderr)
            print("  Set ENABLE_SIMULATION_MODE=1 to run in simulation mode.", file=sys.stderr)
            sys.exit(1)

    for warning in config.validate():
        print(f"[Config Warning] {warning}")

    if config.ENABLE_SIMULATION_MODE:
        print("[Network] Running in SIMULATION MODE (ENABLE_SIMULATION_MODE=1)")
    else:
        raw_socket_result = next((r for r in dep_results if r.name == "raw_socket_permission"), None)
        if raw_socket_result and not raw_socket_result.ok:
            print("\n[WARNING] Raw socket permission denied. Packet capture will fail.")
            print("  Run with:  sudo python enhanced_network_app.py")
            print(f"  Or grant:  sudo setcap cap_net_raw+eip {sys.executable}\n")

    print("\nEnvironment & capture diagnostics:")
    try:
        from network_packet_analyzer import get_permissions_info, get_available_interfaces, SCAPY_AVAILABLE, _SCAPY_VERSION
        from health.dependency_check import get_environment_info
        _env   = get_environment_info()
        _perms = get_permissions_info()
        _ifaces = get_available_interfaces()
        _iface = config.NETWORK_INTERFACE
        _iface_exists = _iface in _ifaces
        _python_real = os.path.realpath(sys.executable)

        print(f"  Python     : {_env['python_executable']}")
        print(f"  Real path  : {_python_real}")
        print(f"  Version    : {_env['python_version']}")
        print(f"  Environment: {_env['env_type']} / {_env['env_name']}")
        if _env['conda_env']:
            print(f"  Conda env  : {_env['conda_env']}")
        if _env['virtual_env']:
            print(f"  Venv       : {_env['virtual_env']}")
        print(f"  User       : {_env['user']} (uid={_env['uid']})")
        print(f"  Work dir   : {_env['working_dir']}")
        print()
        print(f"  Interface  : {_iface} ({'FOUND' if _iface_exists else 'NOT FOUND'})")
        if not _iface_exists:
            print(f"    Available : {', '.join(_ifaces) or 'none'}")
            print(f"    Fix       : NETWORK_INTERFACE=<name> ./run.sh")
        print(f"  Scapy      : {'available (' + _SCAPY_VERSION + ')' if SCAPY_AVAILABLE else 'NOT AVAILABLE'}")
        if not SCAPY_AVAILABLE:
            print(f"    Fix: {_python_real} -m pip install scapy")
        print()
        print(f"  is_root    : {_perms['is_root']}")
        print(f"  cap_net_raw: {_perms['cap_net_raw']}")
        print(f"  cap_net_adm: {_perms['cap_net_admin']}")
        print(f"  raw_socket : {_perms['raw_socket']}")
        print(f"  can_capture: {_perms['can_capture']}")

        if not _perms['can_capture'] and not config.ENABLE_SIMULATION_MODE:
            print()
            print("  [ACTION REQUIRED] No raw socket permission. Choose one:")
            print()
            print(f"  Option 1 — setcap (recommended, run once):")
            print(f"    sudo /usr/sbin/setcap cap_net_raw,cap_net_admin=eip {_python_real}")
            print(f"    Then: python {sys.argv[0]}")
            print()
            print(f"  Option 2 — sudo with correct interpreter:")
            print(f"    sudo {_python_real} {sys.argv[0]}")
            print()
            print(f"  Option 3 — auto-handled launcher:")
            print(f"    ./run.sh")
            print()
            print(f"  Option 4 — simulation mode (no real capture):")
            print(f"    ENABLE_SIMULATION_MODE=true python {sys.argv[0]}")
        elif config.ENABLE_SIMULATION_MODE:
            print()
            print("  [SIMULATION MODE] Real packet capture is disabled.")
            print("  To enable live capture, remove ENABLE_SIMULATION_MODE and run:")
            print(f"    sudo /usr/sbin/setcap cap_net_raw,cap_net_admin=eip {_python_real}")
            print(f"    python {sys.argv[0]}")
    except Exception as _diag_err:
        print(f"  [diagnostics unavailable: {_diag_err}]")

    print()
    network_system.start()

    sim = config.ENABLE_SIMULATION_MODE
    print(f"Listening on http://{config.HOST}:{config.PORT}")
    print(f"  interface={config.NETWORK_INTERFACE}  chain={config.CHAIN_FILE}  sim={'yes' if sim else 'no'}")
    print()

    socketio.run(app, host=config.HOST, port=config.PORT, debug=config.DEBUG)
