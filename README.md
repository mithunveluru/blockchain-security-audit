# BlockAudit

A network security investigation tool. It watches traffic (live capture or a built-in simulator), raises explainable alerts, preserves each alert in a hash-linked audit ledger, and gives analysts a dashboard and a read-only copilot to investigate with.

The journey it is built around: see the current posture, pick a suspicious alert, inspect the evidence behind it, verify the ledger record, decide what to do, export a report.

## What it does

| Area | Capability |
| --- | --- |
| Overview | health of every component, alerts by severity, traffic and alert timelines, ledger status |
| Alerts | search, filter, sort, paginate; per-alert evidence, thresholds vs observed values, related alerts, status and analyst notes, Markdown/JSON incident report |
| Network activity | protocol, port, source and destination breakdowns, packet-rate timeline, active-flow table with click-to-filter |
| Audit ledger | records, block detail, Merkle proof, verification with per-block failure detail, verification history, checkpoint export |
| System health | healthy, degraded, unavailable or disabled per component, with fix hints |
| Copilot | questions answered from retrieved alerts, flows, ledger records and health; cites record ids; optional model wording |

Not collected: packet payloads, application-layer content, geolocation. Only headers are analysed.

## Quick start (no privileges, no real traffic)

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
./run.sh --sim
```

Open http://127.0.0.1:5000. With no tokens configured, a one-time admin token is printed in the terminal; paste it into the sign-in page. Simulation mode generates benign synthetic traffic and injects attack scenarios every two minutes (`SIM_SCENARIO_INTERVAL`, seconds, `0` disables). Everything it produces is labelled `simulation` in the UI, API and reports.

Live capture needs raw-socket permission: `./run.sh --setcap` once (grants `cap_net_raw,cap_net_admin` to the Python interpreter), then `NETWORK_INTERFACE=eth0 ./run.sh`. If permission or the interface is missing, System health shows packet capture as unavailable with the fix; it is never reported healthy.

## Architecture

```
capture (scapy) or simulator
        │ bounded queue (drops are counted, never silent)
        ▼
packet worker ─► validate ─► rule detectors ─► flow table ─► ML windows
                                   │               │             │
                                   └──────► alert manager ◄───────┘
                              dedup · whitelist · evidence samples
                                   │
              ┌────────────────────┼─────────────────────┐
              ▼                    ▼                     ▼
         audit ledger        alert history         Socket.IO push
      (fsync, checkpoint)   (rebuilt from ledger)   (authenticated)
              ▲
      integrity monitor (re-reads the file, compares with memory + checkpoint)
```

| Path | Responsibility |
| --- | --- |
| `blockaudit/config.py` | environment parsing and validation; refuses unsafe production settings |
| `blockaudit/auth.py` | token roles, constant-time comparison, rate limiter |
| `blockaudit/app.py` | Flask routes, security headers, error handling, Socket.IO auth |
| `blockaudit/service.py` | wires workers; health model; overview and network queries |
| `blockaudit/ledger.py` | append-only ledger, verification, recovery, checkpoint, Merkle proofs |
| `blockaudit/detectors.py`, `network_flow_analyzer.py`, `ml_anomaly_detector.py` | detection rules, flow table, anomaly model |
| `network_packet_analyzer.py` | capture, simulation intake, normalisation, evidence samples |
| `integrity_monitor.py` | continuous ledger verification |
| `blockaudit/alerts.py` | alert history, whitelist, investigation status and notes |
| `blockaudit/copilot.py`, `blockaudit/reports.py` | copilot tools and validation; incident reports |
| `static/` | dashboard (vanilla JS modules, no build step, no CDN) |

## Configuration

Set via environment variables; see `.env.example`.

| Variable | Default | Meaning |
| --- | --- | --- |
| `BLOCKAUDIT_ENV` | `development` | `production` enforces the checks below |
| `BLOCKAUDIT_ADMIN_TOKEN`, `_ANALYST_TOKEN`, `_VIEWER_TOKEN` | unset | access tokens, 16+ characters. Production requires the admin token |
| `HOST`, `PORT` | `127.0.0.1`, `5000` | bind address. Without tokens a non-loopback bind is refused |
| `CORS_ORIGINS` | empty | comma-separated trusted origins; empty means same-origin only; `*` is refused in production |
| `ENABLE_SIMULATION_MODE` | off | synthetic traffic instead of capture |
| `NETWORK_INTERFACE` | auto | capture interface |
| `DATA_DIR`, `CHAIN_FILE`, `CHECKPOINT_FILE` | `data`, `network_blockchain.json`, `<chain>.checkpoint` | persistence |
| `INTEGRITY_CHECK_INTERVAL` | `30` | seconds between full ledger checks (a file change triggers one immediately) |
| `PORTSCAN_PORTS`, `DOS_PPS`, `DOS_MIN_SOURCES`, `BRUTE_ATTEMPTS`, `EXFIL_BYTES`, `ALERT_DEDUP_SECONDS`, `ML_MIN_TRAIN_SAMPLES`, `ML_THRESHOLD` | see `.env.example` | detection tuning |
| `MAX_REQUEST_BYTES`, `RATE_LIMIT_PER_MIN`, `RATE_LIMIT_WRITE_PER_MIN`, `RATE_LIMIT_COPILOT_PER_MIN` | 64 KiB, 600, 60, 20 | request limits, per token |
| `COPILOT_PROVIDER`, `COPILOT_MODEL`, `ANTHROPIC_API_KEY`, `COPILOT_TIMEOUT_SECONDS` | `auto`, `claude-sonnet-5-5`, unset, 20 | optional model |

Invalid values stop startup with a message naming the variable.

## Authentication and authorization

Bearer tokens in three roles: `viewer` (read everything, ask the copilot), `analyst` (also set alert status, add notes, run verification), `admin` (also start/stop monitoring, whitelist, simulation scenarios). Every `/api/*` route and every Socket.IO connection requires a token; only `/healthz`, `/readyz` and the static UI are open. The browser keeps the token in `sessionStorage` and sends it in the `Authorization` header, so there are no cookies and no CSRF surface. Sensitive actions (whitelist changes, status changes, start/stop, scenario injection) are written to the ledger with a short token fingerprint, never the token.

This is a shared-secret model. There is no identity provider integration. For per-user identity put BlockAudit behind your SSO-aware reverse proxy and issue tokens per team. Terminate TLS at the proxy.

Responses carry a strict Content-Security-Policy (`default-src 'self'`), `X-Frame-Options: DENY`, `nosniff` and `no-store` on API calls. The UI builds DOM with `textContent` only and applies inline styles through the CSSOM, so no `unsafe-inline` is needed.

## Detection

| Rule | Fires when | Default |
| --- | --- | --- |
| `port_scan.v2` | one source sends SYN/UDP to many distinct ports of one host within a window | 20 ports / 10 s |
| `dos_flood.v2` | a destination service receives a sustained packet rate and either most packets are bare SYNs or many distinct sources are involved (`DDOS` vs `DOS_FLOOD`) | 200 pkt/s over 5 s, 20 sources |
| `brute_force.v2` | one source opens many new connections to ssh/ftp/telnet/smb/rdp/database ports | 10 attempts / 60 s |
| `exfil.v2` | a flow from internal to non-internal space exceeds a byte threshold quickly | 10 MiB in 120 s |
| `isolation_forest.v1` | a source's per-window behaviour is unusual against a baseline this process learned (scikit-learn IsolationForest on rate, size, fan-out and SYN-share features) | score ≥ 0.65 |

Every alert stores the observed values, the thresholds, the window and up to 10 packet header summaries. Known limits:

- Brute-force sees connection attempts, not failed logins.
- The anomaly score is uncalibrated and is never presented as probability of malice. The model learns from this process's own traffic, so a baseline learned during an attack treats it as normal; it stays silent while learning (shown in System health).
- All state is bounded (LRU caps, windows), so very distributed scans can evade per-pair tracking.
- Rule defaults suit a small network; tune them for yours. They were not validated against a labelled dataset.

Data provenance travels with every alert: `live_capture`, `simulation`, `synthetic_test`, `historical` (alerts from the earlier ledger format) or `integrity_monitor`.

## Audit ledger: guarantees and limits

Format: one JSON block per line, `{index, timestamp, data, previous_hash, hash}`; `hash` is SHA-256 over the canonical JSON of the other four fields (the same rule as earlier versions, so existing ledgers still verify). An earlier JSON-array ledger is migrated automatically on first start and a `.legacy.bak` copy is kept.

- **Durability:** each append is written and `fsync`ed before it is acknowledged; a failed write is surfaced and not added to memory. A checkpoint file (`count`, `tip hash`) is rewritten atomically after each append. At most the append in flight is lost on power failure.
- **Concurrency:** one in-process lock plus an exclusive file lock; a second process pointed at the same ledger refuses to start (this is also why gunicorn runs one worker).
- **Recovery:** an incomplete last line is quarantined to `*.recovered-<time>` and the chain continues. An unreadable record in the middle quarantines the file to `*.corrupt-<time>` and starts a new chain that records the old tip. Both show in System health.
- **Verification:** recomputes every hash, links, indices and uniqueness for all blocks, compares the file block-by-block with the copy held in memory, and compares against the checkpoint. It reports each failure with block index and check name. Detected in tests: altered payloads, changed hashes, broken links, reordered, missing or truncated records, and a full rewrite with recomputed hashes (caught by the checkpoint and the memory copy).
- **Limits:** this is a local hash chain, not a decentralized or consensus-backed blockchain. Anyone who can rewrite both the ledger and the checkpoint while the service is stopped can produce a consistent forgery. Export the checkpoint (`GET /api/ledger/checkpoint`, or the button on the ledger page) to a separate system on a schedule, and set `CHECKPOINT_FILE` to a different disk. The Merkle root changes with every append, so a proof only holds against a root you saved earlier.
- **Retention:** the ledger is never pruned. Alert history in memory is capped by `ALERT_RETENTION` and rebuilt from the ledger on start. Traffic statistics are kept for one hour in memory. Packet payloads are never stored.

## API

All routes need a bearer token unless stated. JSON errors look like `{"error": "..."}`.

| Route | Role | Purpose |
| --- | --- | --- |
| `GET /healthz`, `GET /readyz` | none | liveness, readiness (`ready` only) |
| `GET /api/me` | viewer | role, mode, rule catalogue, copilot status |
| `GET /api/overview?range=` | viewer | summary for 5m, 15m, 1h, 6h, 24h, 7d |
| `GET /api/alerts` | viewer | `q, severity, type, source, destination, status, provenance, range` or `since`/`until`, `sort, order, page, page_size` |
| `GET /api/alerts/<id>`, `GET .../report?format=md` or `json` | viewer | detail with evidence, related alerts, ledger record; incident report |
| `PATCH /api/alerts/<id>`, `POST .../notes` | analyst | investigation status, notes |
| `GET /api/network`, `GET /api/network/flows` | viewer | traffic breakdowns, active flows |
| `GET /api/ledger/status`, `/blocks`, `/blocks/<n>`, `/checkpoint`, `GET` or `POST /api/ledger/verify` | viewer (POST: analyst) | ledger views, verification |
| `GET /api/health` | viewer | component states |
| `POST /api/copilot/ask` | viewer | `{question, alert_id?, range?}` |
| `GET /api/whitelist`; `POST /api/whitelist/add`, `remove`, `toggle` | viewer / admin | alert suppression |
| `POST /api/start`, `/api/stop`, `/api/simulate/<scenario>` | admin | control (scenarios only in simulation mode) |
| `GET /api/stats`, `/api/blockchain/verify`, `/api/integrity/status`, `/api/integrity/alerts` | viewer | kept from earlier versions |

Socket.IO: connect with `auth: {token}`. Events pushed: `snapshot` (about once a second), `alert`, `integrity_alert`.

Breaking changes from earlier versions: every API route now needs a token; `/soc` redirects to `/`; the two earlier dashboards were replaced by the single UI in `static/`; whitelist mutations need admin; ledger files are JSON lines; `config.py`, `requirements_network.txt` and the eventlet and watchdog dependencies are gone.

## Investigation copilot

Read-only. For each question it runs fixed tools (search alerts, get alert, related alerts, ledger block, verify ledger, health), collects the records, and builds an answer split into observed, interpretation, suggested steps and missing evidence, each item citing record ids that link to the UI. It cannot change configuration, block addresses or run commands, and records are treated as untrusted data.

Without a model it answers deterministically from the records (tested). With `ANTHROPIC_API_KEY` set, the same records are sent to the Messages API to phrase the answer; the reply is then validated: unknown record ids are dropped, items citing nothing are demoted from "observed", and any address or hash not present in the records removes the item. If the provider fails, times out or returns unusable text, the deterministic answer is shown. Records leave the host when a model is configured; do not enable it if that is not acceptable. The provider code is covered by mocked tests only; it has not been run against the live API here.

## Development and testing

```bash
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/pytest                      # unit, security, reliability, end-to-end
.venv/bin/ruff check .                # lint and security rules
node scripts/check_ui_imports.mjs     # every frontend import resolves
.venv/bin/pip-audit -r requirements.txt
.venv/bin/python bench/bench.py --legacy <dir with the old modules>
```

Tests cover ledger integrity and recovery, detector positives and negatives, API validation, authentication, rate limits, CORS, oversized bodies, error disclosure, WebSocket auth, the investigation workflow end to end, threaded simulation mode, degraded health, queue overflow, copilot grounding and prompt-injection handling, and repository hygiene (no key material, no secrets). Live packet capture is not covered by automated tests (it needs privileges). The browser UI was exercised manually in Chrome (desktop width, and a narrow-width emulation); there are no automated browser tests.

### Measured performance

Python 3.12.3, Linux 7.0, 8 logical CPUs, single process, synthetic benign workload.

| Workload | Before | After |
| --- | --- | --- |
| packet pipeline (validate, 3 rules, flow table, telemetry, ML windows) | 62,000 pkt/s (rules only; its flow analyzer and "ML" never ran on packets) | 53,000 pkt/s |
| ledger append, 300 blocks | 0.83 ms median, not durable | 2.7 ms median with `fsync` |
| ledger append, 5,000 blocks | 16 ms median, 30 ms at the tail, grows with chain size | 2.9 ms median, constant |
| `GET /api/alerts` page, 5,000 alerts | n/a | 7 ms median |
| `GET /api/overview`, 5,000 alerts | n/a | 31 ms median |

The packet path is about 15% slower than before because it now does more work; durable appends cost about 2 ms each. Reproduce with `bench/bench.py`. The earlier dashboard was pushed about 100 times a second; it now receives one snapshot per second.

## Production deployment

```bash
export BLOCKAUDIT_ENV=production BLOCKAUDIT_ADMIN_TOKEN=... BLOCKAUDIT_ANALYST_TOKEN=... BLOCKAUDIT_VIEWER_TOKEN=...
gunicorn -c gunicorn.conf.py wsgi:app
```

- One worker with many threads; Flask-SocketIO runs on simple-websocket under `gthread` (verified with a WebSocket connection through gunicorn). Do not raise `workers`; the ledger lock would reject the extra worker.
- Put nginx, Caddy or a cloud load balancer in front for TLS and forward `Upgrade` and `Connection` headers for `/socket.io/`.
- Docker: `docker build -t blockaudit .`, run with `-v blockaudit-data:/data -p 5000:5000 -e BLOCKAUDIT_ADMIN_TOKEN=...`. The image runs as a non-root user and has a health check against `/readyz`. If the build cannot reach PyPI (restrictive DNS or VPN), use `docker build --network host`. Live capture in a container needs `--network host --cap-add NET_RAW --cap-add NET_ADMIN`.
- Probes: `/healthz` for liveness, `/readyz` for readiness (not ready if monitoring is stopped or the ledger or workers are down).
- Logs are JSON on stderr with tokens, API keys and private keys redacted.
- Backups: copy the data directory (ledger, checkpoint, whitelist, investigations) while the service is stopped, or copy the ledger and checkpoint together. Keep exported checkpoints on a different system.
- Restore: stop the service, restore the files together, start, then run Verify on the ledger page.
- Upgrade: take a backup, deploy, check `/readyz`. Roll back by redeploying the previous version with the same data directory; the `.legacy.bak` file is the pre-migration copy of an old ledger.
- Shutdown: SIGTERM stops workers and releases the ledger lock; gunicorn waits up to 10 s for open connections.

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `configuration error: ...` | the named variable is invalid or a production requirement is missing |
| `another process already owns ledger` | a second instance uses the same `CHAIN_FILE`; stop it, or gunicorn workers were set above 1 |
| Packet capture shows unavailable | follow the `fix` text in System health: `./run.sh --setcap`, run as root, or use `--sim` |
| Sign-in rejects the token | development tokens are generated per run; each restart prints a new one. Set `BLOCKAUDIT_ADMIN_TOKEN` for a stable one |
| Ledger "recovered at startup" | an interrupted write or corrupt record was quarantined; the side file next to the ledger holds the original bytes |
| ML shows "learning" | it needs `ML_MIN_TRAIN_SAMPLES` (default 200) source windows of traffic before it can alert |

## Security notes and required operator actions

See `SECURITY.md`. In short:

- A private key file (`device_priv.pem`) was committed to this repository's history. It was unused by the application. It is removed from the current tree, but it remains in git history and in any clone or fork made before. Treat it as compromised; it protects nothing in BlockAudit today. History has not been rewritten and nothing was rotated by this change.
- Set strong tokens, terminate TLS in front of the service, and export ledger checkpoints off-host.
- The simulator's `203.0.113.0/24`, `198.51.100.0/24` and `198.18.0.0/16` addresses are reserved documentation and benchmarking ranges.
- `threat_demo.sh` sends real scan and flood traffic to this host and requires `I_OWN_THIS_NETWORK=yes`. Prefer simulation mode.
- `log_generator_signed.py` is an old test-data helper; its `signature` field is a plain SHA-256 digest, not a cryptographic signature.

## Known limitations

Single node and single worker; shared-secret tokens instead of per-user identity; fixed rule thresholds validated only against synthetic and unit-test traffic; no application-layer visibility; the optional model provider is untested against the live service; live capture is untested in automation.
