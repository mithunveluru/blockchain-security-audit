# Blockchain-Based Network Security Audit System

An end-to-end, SOC-ready platform that combines real-time network threat detection with a blockchain-backed, tamper-evident audit ledger to provide forensic-grade integrity and intelligent detection for modern networks.


## 1. Overview

Traditional SIEM and IDS/IPS stacks struggle with: log tampering, noisy and low-context alerts, and lack of cryptographic assurance over historical data.
This project addresses those gaps by unifying packet/flow analytics, ML-based anomaly detection, and a blockchain-style audit chain with continuous integrity monitoring and forensic reporting. 


## 2. Core Features

### Network and Threat Analytics

- Real-time packet capture (live via Scapy where available, or simulation mode for labs).
- NetFlow-style 5‑tuple flow tracking (src/dst IP, src/dst port, protocol) with per-flow statistics.  
- Detection of port scans, DDoS patterns, brute-force activity on sensitive services, and high-volume data exfiltration flows. 

### ML-Driven Anomaly Detection

- Feature extraction from logs/flows: time, level, IP characteristics, message properties, and behavioral signals.   
- Unsupervised anomaly scoring (Isolation-Forest–style) combined with heuristics and temporal context into a single 0–100 threat score with NORMAL/LOW/MEDIUM/HIGH/CRITICAL levels.   
- Threat classification into categories such as port_scan, brute_force, data_exfil, privilege_escalation, unusual_access, and resource_exhaustion. 

### Blockchain Audit Ledger and Integrity

- Append-only blockchain structure for all security events, each block containing index, timestamp, payload, previous hash, and block hash.   
- Optional adaptive Merkle tree for efficient proof-of-inclusion and state verification.   
- Continuous integrity monitoring with baseline snapshots, detection of deleted/modified blocks, hash mismatches, and broken links, with full forensic reports on tampering. 

### Operations and SOC Integration

- Flask + Socket.IO backend providing REST APIs and real-time WebSocket updates to SOC dashboards.   
- Whitelist management endpoints (add/remove/toggle) to suppress noise from known-good IP ranges and services.   

---

## 3. Architecture

The system is composed of modular, production-oriented components designed to be understandable and extensible by engineers. 

- **NetworkPacketAnalyzer**:  
  - Captures packets (live or simulated), maintains protocol/IP/port statistics, tracks flows, and runs PortScan, DDoS, and BruteForce detectors.  
  - Optionally passes events to the ML anomaly detector and exposes recent alerts for dashboards and blockchain logging. 

- **NetworkFlowAnalyzer**:  
  - Maintains 5‑tuple flows, computes duration/packet/byte rates, and detects DDoS, port scans, brute-force attempts, and data exfiltration at the flow level. 

- **MLAnomalyDetector**:  
  - Trains on historical logs, scores new events, and returns threat_score, threat_level, anomaly_type, component breakdown, and derived statistics. 

- **NetworkBlockchain**:  
  - Minimal blockchain engine specialized for audit events, supporting block append, chain verification, and Merkle-tree updates. 

- **IntegrityMonitor**:  
  - Watches the blockchain file, runs periodic and event-driven validation, compares against the last known-good chain, and emits structured integrity alerts. 

- **Flask / Socket.IO App**:  
  - Hosts REST endpoints (`/api/stats`, `/api/blockchain/verify`, `/api/integrity/status`, whitelist APIs) and serves the dashboards (`/` and `/soc`). 

---

## 4. Why It Matters (Security Impact)

- **Prove, not just trust, your logs**: Every event is chained and continuously verified, turning the audit trail into cryptographic evidence for incident response and compliance.   
- **Prioritize by risk, not noise**: ML scoring, flow context, and enriched alert metadata make it easier for analysts to focus on the highest-impact events first.   
- **Forensic-grade transparency**: Integrity violations are themselves first-class incidents, with detailed forensics on what changed and where, instead of silent log manipulation. 

---

## 5. Getting Started

### 5.1 Prerequisites

- Python 3.13 (or 3.11+ with compatible dependencies).   
- Linux environment recommended for live packet capture and traffic simulation.   
- Optional external tools (for full functionality and lab testing): `scapy`, `nmap`, `hping3`. 

### 5.2 Installation

```bash
git clone <your-repo-url>.git
cd <your-repo-folder>

python -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```


### 5.3 Configuration
Key configuration points before first run: 

Capture interface

Set your NIC in the packet analyzer, for example:
NetworkPacketAnalyzer(interface="wlp0s20f3", ml_detector=...).

Detection thresholds

Tune thresholds for DDoS, port scan, brute force, and data exfiltration in the packet and flow analyzer classes to match your environment’s normal behavior. 

Whitelist

Manage trusted IPs/ranges via:

GET /api/whitelist

POST /api/whitelist/add

POST /api/whitelist/remove

POST /api/whitelist/toggle
to filter noise from known-good services.

ML training window

Configure MLAnomalyDetector(learning_window_days=7) (or another value) to define how much historical data forms the baseline.


## 6. Running the System
Start the main application:

bash
python enhanced_network_app.py

Access:
Main dashboard: http://localhost:5000/

SOC dashboard: http://localhost:5000/soc

Useful APIs:

GET /api/stats – overall statistics and live metrics.

GET /api/blockchain/verify – blockchain integrity verification.

GET /api/integrity/status – integrity monitor runtime state.

GET /api/integrity/alerts – recent integrity alerts.

## 7. Optional: Threat Simulation (Lab Use Only)
To validate detections end-to-end in a controlled lab, you can use the threat simulation script to generate port-scan and DDoS patterns against your own host. 

bash
chmod +x threat_simulation.sh
./threat_simulation.sh
Use this only in an authorized, isolated environment.

## 8. Intended Use and Extension
This codebase is intended as a research- and education-grade reference implementation for: security engineering, network forensics, and blockchain-for-security experimentation. 
It serves as a blueprint for integrating network analytics, ML, and cryptographic integrity guarantees into future SIEM/SOC architectures and can be extended with new detectors, data sources, and dashboards. 
