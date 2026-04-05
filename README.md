# BlockAudit — Blockchain-Based Network Security Audit Platform

> A production-oriented, SOC-ready platform unifying real-time network threat
> detection with a cryptographically verifiable, blockchain-backed audit ledger.
> Designed for forensic-grade incident response, compliance evidence, and
> intelligent analyst workflows.

---

## Table of Contents

1. [Problem Statement](#1-problem-statement)
2. [System Architecture](#2-system-architecture)
3. [Feature Surface](#3-feature-surface)
4. [Component Reference](#4-component-reference)
5. [Getting Started](#5-getting-started)
6. [Configuration](#6-configuration)
7. [API Reference](#7-api-reference)
8. [Threat Simulation (Lab Only)](#8-threat-simulation-lab-only)
9. [Design Decisions](#9-design-decisions)
10. [Extension Points](#10-extension-points)

---

## 1. Problem Statement

Modern SIEM and IDS/IPS deployments share three structural weaknesses:

| Gap | Consequence |
|---|---|
| No cryptographic assurance on stored logs | Silent log tampering goes undetected |
| Low-context, high-volume alerts | Analyst fatigue; critical signals buried in noise |
| Reactive integrity checks | Tampering is discovered post-incident, not in real time |

**BlockAudit** addresses all three by combining packet/flow-level analytics,
ML-driven anomaly scoring, and an append-only blockchain audit chain with
continuous integrity monitoring — producing a system where every event is
*provably unmodified* and every alert carries enough context to act on.

---

## 2. System Architecture
```plaintext
┌──────────────────────────────────────────────────────────────────┐
│                        Ingestion Layer                           │
│                                                                  │
│   NetworkPacketAnalyzer  ──►  NetworkFlowAnalyzer                │
│   (live Scapy / sim mode)     (5-tuple flows, rate analytics)    │
└────────────────────────────────┬─────────────────────────────────┘
                                 │  normalized events
                                 ▼
┌──────────────────────────────────────────────────────────────────┐
│                       Intelligence Layer                         │
│                                                                  │
│   MLAnomalyDetector  (0–100 threat score, 6 threat classes)      │
└────────────────────────────────┬─────────────────────────────────┘
                                 │  scored + classified events
                                 ▼
┌──────────────────────────────────────────────────────────────────┐
│                          Ledger Layer                            │
│                                                                  │
│   NetworkBlockchain  ──►  IntegrityMonitor                       │
│   (append-only chain)     (continuous hash verification)         │
└────────────────────────────────┬─────────────────────────────────┘
                                 │  REST + WebSocket
                                 ▼
┌──────────────────────────────────────────────────────────────────┐
│                      Presentation Layer                          │
│                                                                  │
│   Flask + Socket.IO  →  Main Dashboard  /  SOC Dashboard         │
└──────────────────────────────────────────────────────────────────┘
```

Each layer is independently testable and replaceable. The ingestion layer can
be swapped from Scapy to a NetFlow collector or a PCAP replay engine without
touching the ledger or presentation layers.

---

## 3. Feature Surface

### 3.1 Network & Threat Analytics
- **Dual-mode capture** — live packet capture via Scapy (requires root) or
  deterministic simulation mode for CI and lab environments.
- **5-tuple flow tracking** — `(src_ip, dst_ip, src_port, dst_port, proto)`
  with per-flow byte/packet rates, duration, and connection state.
- **Rule-based detectors** — port scan, DDoS amplification, brute-force on
  sensitive services (SSH/RDP/FTP), and high-volume data exfiltration flows.

### 3.2 ML-Driven Anomaly Detection
- **Feature set** — time-of-day, log level, IP reputation signals, message
  entropy, behavioral deltas, and flow-level statistics (17 features total).
- **Scoring model** — Isolation Forest baseline combined with temporal
  heuristics, producing a `0–100` threat score mapped to five severity bands:
  `NORMAL / LOW / MEDIUM / HIGH / CRITICAL`.
- **Threat taxonomy** — `port_scan`, `brute_force`, `data_exfil`,
  `privilege_escalation`, `unusual_access`, `resource_exhaustion`.

### 3.3 Blockchain Audit Ledger
- **Append-only chain** — each block stores `index`, `timestamp`, `payload`,
  `prev_hash`, and `block_hash`; no block can be silently modified.
- **Merkle tree (optional)** — adaptive Merkle tree for efficient
  proof-of-inclusion and partial-chain verification without full replay.
- **Continuous integrity monitoring** — `IntegrityMonitor` maintains a
  known-good baseline snapshot; any deletion, modification, hash mismatch, or
  broken chain link triggers a structured integrity alert with full forensic
  diff output.

### 3.4 SOC Operations
- **Real-time push** — Socket.IO WebSocket stream delivers live alert feeds to
  the SOC dashboard without polling.
- **Whitelist management** — REST endpoints to add, remove, and toggle trusted
  IP ranges, suppressing known-good noise without restarting the process.

---

## 4. Component Reference

| Component | Responsibility |
|---|---|
| `NetworkPacketAnalyzer` | Packet capture, protocol/IP stats, per-packet detector pipeline, ML handoff |
| `NetworkFlowAnalyzer` | 5-tuple flow state machine, flow-level detectors, exfil heuristics |
| `MLAnomalyDetector` | Feature extraction, Isolation Forest scoring, threat classification |
| `NetworkBlockchain` | Block append, chain verification, Merkle tree maintenance |
| `IntegrityMonitor` | Blockchain file watch, periodic + event-driven validation, forensic diffs |
| `Flask / Socket.IO App` | REST API host, WebSocket event broker, dashboard server |

---

## 5. Getting Started

### Prerequisites

- Python **3.11+** (3.13 recommended)
- Linux host recommended for live capture and traffic simulation
- Optional system tools for full lab coverage: `scapy`, `nmap`, `hping3`

### Installation

```bash
git clone https://github.com/mithunveluru/blockchain-security-audit.git
cd blockchain-security-audit

python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt
```

### Run

```bash
python enhanced_network_app.py
```

| Endpoint | URL |
|---|---|
| Main dashboard | `http://localhost:5000/` |
| SOC dashboard | `http://localhost:5000/soc` |

---

## 6. Configuration

All tunable parameters are co-located in the component constructors for
explicit, traceable configuration — no hidden environment magic.

**Capture interface**
```python
# Set your NIC before starting the analyzer
analyzer = NetworkPacketAnalyzer(interface="eth0", ml_detector=detector)
```

**ML training window**
```python
# Days of historical logs used to build the anomaly baseline
detector = MLAnomalyDetector(learning_window_days=7)
```

**Detection thresholds** — Tune DDoS packet-rate, port-scan connection-rate,
brute-force attempt-count, and exfil byte-rate thresholds inside
`NetworkPacketAnalyzer` and `NetworkFlowAnalyzer` to match your environment's
normal baseline before going live.

**Whitelist** — Managed at runtime via API (see §7); no restart required.

---

## 7. API Reference

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/stats` | Live metrics: packet rates, flow counts, alert totals |
| `GET` | `/api/blockchain/verify` | Full chain integrity verification result |
| `GET` | `/api/integrity/status` | IntegrityMonitor runtime state |
| `GET` | `/api/integrity/alerts` | Recent integrity violation events |
| `GET` | `/api/whitelist` | Current whitelist entries |
| `POST` | `/api/whitelist/add` | Add IP or CIDR range |
| `POST` | `/api/whitelist/remove` | Remove entry |
| `POST` | `/api/whitelist/toggle` | Enable / disable entry without deletion |

All responses are `application/json`. Integrity and blockchain endpoints return
a `verified: bool` field alongside detailed diff output on failure.

---

## 8. Threat Simulation (Lab Only)

A bundled simulation script generates synthetic port-scan and DDoS traffic
patterns against `localhost` for end-to-end detector validation.

```bash
chmod +x threat_simulation.sh
./threat_simulation.sh
```

> ⚠️ **Run only in an authorized, isolated lab environment.**
> This script generates traffic patterns that will trigger IDS/IPS rules on
> any production or shared network.

---

## 9. Design Decisions

**Why a custom blockchain instead of a DB with checksums?**
A traditional append-only DB with row-level hashes can be bypassed by an
attacker with DB write access. The chained-hash structure means any
modification invalidates every subsequent block, making silent tampering
computationally infeasible without full chain reconstruction.

**Why Isolation Forest over a supervised classifier?**
Network baselines shift with topology changes, new services, and traffic
seasonality. An unsupervised scorer adapts to the local normal without
requiring labelled attack data, which is rarely available in real SOC
environments.

**Why Flask + Socket.IO over a heavier framework?**
The presentation layer is deliberately thin. The intelligence and ledger layers
carry the system's value; keeping the API surface minimal reduces attack area
and makes the codebase easier to audit.

---

## 10. Extension Points

| Area | How to Extend |
|---|---|
| New detectors | Implement the detector interface in `NetworkPacketAnalyzer`; detectors are composable and independently testable |
| Alternative data sources | Swap `NetworkPacketAnalyzer` for a NetFlow or PCAP-replay adapter; downstream components are source-agnostic |
| Supervised ML | Replace or augment `MLAnomalyDetector` with a labelled-data classifier; the threat score contract (`0–100`, 5 levels) is stable |
| Persistent ledger | Swap the file-backed blockchain store for a distributed key-value store to support multi-node deployments |
| SIEM export | Add a Syslog/CEF/STIX emitter consuming `IntegrityMonitor` alerts for integration with Splunk, Elastic, or Chronicle |

---

## License

MIT — see [LICENSE](LICENSE).
