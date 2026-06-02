# BlockAudit — Blockchain-Based Network Security Audit

Real-time packet capture and threat detection backed by an append-only
blockchain audit log with continuous integrity monitoring.

---

## Table of Contents

1. [System Architecture](#1-system-architecture)
2. [Components](#2-components)
3. [Getting Started](#3-getting-started)
4. [Configuration](#4-configuration)
5. [API Reference](#5-api-reference)
6. [Threat Simulation (Lab Only)](#6-threat-simulation-lab-only)
7. [Design Decisions](#7-design-decisions)
8. [Extension Points](#8-extension-points)

---

## 1. System Architecture
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

## 2. Components

| Component | Responsibility |
|---|---|
| `NetworkPacketAnalyzer` | Packet capture, protocol/IP stats, per-packet detector pipeline, ML handoff |
| `NetworkFlowAnalyzer` | 5-tuple flow state machine, flow-level detectors, exfil heuristics |
| `MLAnomalyDetector` | Feature extraction, Isolation Forest scoring, threat classification |
| `NetworkBlockchain` | Block append, chain verification, Merkle tree maintenance |
| `IntegrityMonitor` | Blockchain file watch, periodic + event-driven validation, forensic diffs |
| `Flask / Socket.IO App` | REST API host, WebSocket event broker, dashboard server |

---

## 3. Getting Started

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

## 4. Configuration

All settings are read from environment variables (see `.env.example`). The main ones:

| Variable | Default | Notes |
|---|---|---|
| `NETWORK_INTERFACE` | `wlp0s20f3` | NIC for live capture |
| `ENABLE_SIMULATION_MODE` | unset | Set to `1` to skip Scapy |
| `SECRET_KEY` | generated | Required in production |
| `CORS_ORIGINS` | `*` | Restrict in production |
| `CHAIN_FILE` | `network_blockchain.json` | Blockchain storage path |

Detection thresholds (DDoS rate, port-scan window, brute-force count) are set in the constructor arguments of `NetworkPacketAnalyzer` and `NetworkFlowAnalyzer`.

Whitelist entries are managed at runtime via the API — no restart required.

---

## 5. API Reference

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

All responses are `application/json`.

---

## 6. Threat Simulation (Lab Only)

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

## 7. Design Decisions

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

## 8. Extension Points

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
