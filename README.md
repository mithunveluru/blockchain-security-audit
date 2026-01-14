# Blockchain-Based Network Security Audit System

An end-to-end, SOC-ready platform that combines real-time network threat detection with a blockchain-backed, tamper-evident audit ledger to provide forensic-grade integrity and intelligent detection for modern networks. [conversation_history:1]

---

## 1. Overview

Traditional SIEM and IDS/IPS stacks struggle with: log tampering, noisy and low-context alerts, and lack of cryptographic assurance over historical data. [conversation_history:1]  
This project addresses those gaps by unifying packet/flow analytics, ML-based anomaly detection, and a blockchain-style audit chain with continuous integrity monitoring and forensic reporting. [conversation_history:1]

---

## 2. Core Features

### Network and Threat Analytics

- Real-time packet capture (live via Scapy where available, or simulation mode for labs). [conversation_history:1]  
- NetFlow-style 5‑tuple flow tracking (src/dst IP, src/dst port, protocol) with per-flow statistics. [conversation_history:1]  
- Detection of port scans, DDoS patterns, brute-force activity on sensitive services, and high-volume data exfiltration flows. [conversation_history:1]

### ML-Driven Anomaly Detection

- Feature extraction from logs/flows: time, level, IP characteristics, message properties, and behavioral signals. [conversation_history:1]  
- Unsupervised anomaly scoring (Isolation-Forest–style) combined with heuristics and temporal context into a single 0–100 threat score with NORMAL/LOW/MEDIUM/HIGH/CRITICAL levels. [conversation_history:1]  
- Threat classification into categories such as port_scan, brute_force, data_exfil, privilege_escalation, unusual_access, and resource_exhaustion. [conversation_history:1]

### Blockchain Audit Ledger and Integrity

- Append-only blockchain structure for all security events, each block containing index, timestamp, payload, previous hash, and block hash. [conversation_history:1]  
- Optional adaptive Merkle tree for efficient proof-of-inclusion and state verification. [conversation_history:1]  
- Continuous integrity monitoring with baseline snapshots, detection of deleted/modified blocks, hash mismatches, and broken links, with full forensic reports on tampering. [conversation_history:1]

### Operations and SOC Integration

- Flask + Socket.IO backend providing REST APIs and real-time WebSocket updates to SOC dashboards. [conversation_history:1]  
- Whitelist management endpoints (add/remove/toggle) to suppress noise from known-good IP ranges and services. [conversation_history:1]  

---

## 3. Architecture

The system is composed of modular, production-oriented components designed to be understandable and extensible by engineers. [conversation_history:1]

- **NetworkPacketAnalyzer**:  
  - Captures packets (live or simulated), maintains protocol/IP/port statistics, tracks flows, and runs PortScan, DDoS, and BruteForce detectors.  
  - Optionally passes events to the ML anomaly detector and exposes recent alerts for dashboards and blockchain logging. [conversation_history:1]

- **NetworkFlowAnalyzer**:  
  - Maintains 5‑tuple flows, computes duration/packet/byte rates, and detects DDoS, port scans, brute-force attempts, and data exfiltration at the flow level. [conversation_history:1]

- **MLAnomalyDetector**:  
  - Trains on historical logs, scores new events, and returns threat_score, threat_level, anomaly_type, component breakdown, and derived statistics. [conversation_history:1]

- **NetworkBlockchain**:  
  - Minimal blockchain engine specialized for audit events, supporting block append, chain verification, and Merkle-tree updates. [conversation_history:1]

- **IntegrityMonitor**:  
  - Watches the blockchain file, runs periodic and event-driven validation, compares against the last known-good chain, and emits structured integrity alerts. [conversation_history:1]

- **Flask / Socket.IO App**:  
  - Hosts REST endpoints (`/api/stats`, `/api/blockchain/verify`, `/api/integrity/status`, whitelist APIs) and serves the dashboards (`/` and `/soc`). [conversation_history:1]

---

## 4. Why It Matters (Security Impact)

- **Prove, not just trust, your logs**: Every event is chained and continuously verified, turning the audit trail into cryptographic evidence for incident response and compliance. [conversation_history:1]  
- **Prioritize by risk, not noise**: ML scoring, flow context, and enriched alert metadata make it easier for analysts to focus on the highest-impact events first. [conversation_history:1]  
- **Forensic-grade transparency**: Integrity violations are themselves first-class incidents, with detailed forensics on what changed and where, instead of silent log manipulation. [conversation_history:1]

---

## 5. Getting Started

### 5.1 Prerequisites

- Python 3.13 (or 3.11+ with compatible dependencies). [conversation_history:1]  
- Linux environment recommended for live packet capture and traffic simulation. [conversation_history:1]  
- Optional external tools (for full functionality and lab testing): `scapy`, `nmap`, `hping3`. [conversation_history:1]

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
To validate detections end-to-end in a controlled lab, you can use the threat simulation script to generate port-scan and DDoS patterns against your own host. [conversation_history:1]

bash
chmod +x threat_simulation.sh
./threat_simulation.sh
Use this only in an authorized, isolated environment.

## 8. Intended Use and Extension
This codebase is intended as a research- and education-grade reference implementation for: security engineering, network forensics, and blockchain-for-security experimentation. 
It serves as a blueprint for integrating network analytics, ML, and cryptographic integrity guarantees into future SIEM/SOC architectures and can be extended with new detectors, data sources, and dashboards. 
