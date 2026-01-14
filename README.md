# BLOCKCHAIN-BASED NETWORK SECURITY AUDIT SYSTEM

An end-to-end, SOC-ready platform that combines real-time network threat detection with blockchain-backed, tamper-evident audit logging. This project is designed to bring **forensic-grade** integrity and intelligent detection into everyday network monitoring. [conversation_history:1]

---

## Why This Project Exists

Modern networks generate massive volumes of security-relevant data, but traditional SIEMs and IDS/IPS solutions suffer from three critical gaps: [conversation_history:1]

- Tampering risk: Logs can be deleted, modified, or forged after an incident, weakening forensics and compliance. [conversation_history:1]  
- Alert overload: Signature-only systems generate noisy, low-context alerts that overwhelm analysts. [conversation_history:1]  
- Lack of end-to-end assurance: Even when threats are detected, there is no cryptographic proof that historical data was not altered. [conversation_history:1]

This project directly addresses these problems by: [conversation_history:1]

- Using a blockchain-style append-only ledger for all security events, making manipulation immediately detectable. [conversation_history:1]  
- Applying ML-based anomaly detection and flow-level analytics so that alerts are prioritized by real risk, not just rules. [conversation_history:1]  
- Providing integrity monitoring with forensic analysis so that any tampering attempt becomes an incident in itself. [conversation_history:1]

The result is a system that turns your network into its own cryptographically verifiable evidence source, suitable for incident response, audits, and regulatory reporting. [conversation_history:1]

---

## Key Capabilities

### 1. Network Packet & Flow Intelligence

- Real-time packet capture (live via Scapy or simulation mode). [conversation_history:1]  
- 5-tuple flow tracking (src/dst IP, src/dst port, protocol) with statistics. [conversation_history:1]  
- Detection of:
  - Port scanning  
  - DDoS patterns  
  - Brute-force activity on sensitive services  
  - High-volume data exfiltration flows  [conversation_history:1]

This provides both packet-level and flow-level visibility into attack behavior. [conversation_history:1]

### 2. ML-Driven Anomaly Detection

- Feature-based log analysis (time, level, IP properties, message semantics). [conversation_history:1]  
- Isolation-Forest–style anomaly scoring plus heuristic and temporal rules. [conversation_history:1]  
- Composite threat score (0–100) with levels: NORMAL, LOW, MEDIUM, HIGH, CRITICAL. [conversation_history:1]  
- Threat categorization (port scan, brute force, data exfiltration, privilege escalation, unusual access, resource exhaustion). [conversation_history:1]

This moves beyond static signatures and lets the system adapt to your environment. [conversation_history:1]

### 3. Blockchain Security Audit Ledger

- Each security event is appended as a block with index, timestamp, payload, previous hash, and block hash. [conversation_history:1]  
- Optional Adaptive Merkle Tree support for efficient verification. [conversation_history:1]  
- Chain verification ensures hash consistency and unbroken links. [conversation_history:1]

This turns the audit trail into a cryptographic evidence chain. [conversation_history:1]

### 4. Integrity Monitoring & Forensics

- Continuous monitoring of the blockchain file via filesystem watching. [conversation_history:1]  
- Baseline snapshots and deep comparison against the last known-good chain. [conversation_history:1]  
- Forensic reporting of deleted blocks, modified fields, hash mismatches, and broken links. [conversation_history:1]

Log tampering becomes a first-class, high-severity alert instead of a silent failure. [conversation_history:1]

---

## Architecture Overview

Core components: [conversation_history:1]

- **NetworkPacketAnalyzer**  
  - Live or simulated capture.  
  - Threat detectors: PortScanDetector, DDoSDetector, BruteForceDetector.  
  - Optional integration with the ML anomaly engine.  
  - Exposes recent alerts for dashboards and blockchain logging. [conversation_history:1]

- **NetworkFlowAnalyzer**  
  - NetFlow-style flow tracking and analysis.  
  - Flow-based detection of DDoS, port scans, brute force, and exfiltration.  
  - Produces flow-level threat events. [conversation_history:1]

- **MLAnomalyDetector**  
  - Feature extraction from logs and flow summaries.  
  - Unsupervised learning plus heuristics and temporal scoring.  
  - Returns threat score, level, type, and score components. [conversation_history:1]

- **NetworkBlockchain**  
  - Minimal blockchain tailored for audit events.  
  - Optional Merkle tree for efficient verification.  
  - Chain persistence and verification API. [conversation_history:1]

- **IntegrityMonitor**  
  - Watches blockchain storage for changes.  
  - Runs forensic analysis and raises structured alerts. [conversation_history:1]

- **Flask + Socket.IO Application**  
  - REST API for stats, verification, whitelist management, and control.  
  - SOC dashboard endpoints with real-time WebSocket updates. [conversation_history:1]

---

## How It Revolutionizes Security

1. **From “trust the logs” to “prove the logs”**  
   Cryptographically links and verifies audit records, so integrity can be demonstrated, not assumed. [conversation_history:1]

2. **From alert floods to risk-ranked intelligence**  
   Alerts carry a scored risk, type, and context so analysts can triage by impact, not just volume. [conversation_history:1]

3. **From black-box detection to forensic transparency**  
   Detections, blocks, and integrity findings are all traceable and explainable for post-incident review. [conversation_history:1]

4. **From siloed tools to a unified evidence pipeline**  
   Packet capture, flow analysis, ML detection, and blockchain logging form a cohesive chain of evidence. [conversation_history:1]

---

## Getting Started

### Prerequisites

- Python 3.13 (or compatible 3.11+ environment). [conversation_history:1]  
- Linux environment recommended for live capture and simulations. [conversation_history:1]  
- Optional tools: `scapy`, `nmap`, `hping3` for full functionality. [conversation_history:1]

### Installation

```bash
git clone <your-repo-url>.git
cd <your-repo-folder>

python -m venv venv
source venv/bin/activate

pip install -r requirements.txt


```
### Configuration Highlights
Capture interface via NetworkPacketAnalyzer(interface='wlp0s20f3', ...). [conversation_history:1]

Detection thresholds tunable for DDoS, port scan, brute force, and exfiltration in the analyzer/flow modules. [conversation_history:1]

Whitelist control via /api/whitelist/add, /remove, and /toggle. [conversation_history:1]

ML learning window via MLAnomalyDetector(learning_window_days=7). [conversation_history:1]



### Intended Use & Scope
This project is intended as a research- and education-grade platform for: [conversation_history:1]

Security engineering

Network forensics

Blockchain-for-security experimentation

It serves as a blueprint for next-generation systems that blend network analytics, ML, and cryptographic integrity guarantees in one stack. [conversation_history:1]
