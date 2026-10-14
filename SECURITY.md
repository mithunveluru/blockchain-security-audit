# Security

## Exposed private key (action required by the repository owner)

`device_priv.pem`, a genuine 2048-bit RSA private key whose public half was `device_pub.pem`, was committed in the first commit (`e2e72e5`, 2025-10-30) and again in `47f93df`. The repository is publicly reachable, so the key must be treated as exposed.

What was checked:

- The key parses and matches the tracked public key.
- Nothing in BlockAudit loads, signs with or verifies against either file. `create_device_keys.py` only generated them. Compromise of this key therefore does not weaken BlockAudit's ledger or authentication.
- If you reused this keypair anywhere else (SSH, TLS, signing, another service), rotate it there and revoke the old public key.

What this change did:

- Removed both files from the current tree and added key patterns to `.gitignore`.
- Replaced `create_device_keys.py` with a script that writes keys with mode 0600 outside the repository and refuses to overwrite.
- Added tests that fail if key material, `.env` files, caches or the runtime ledger are tracked.

What it did not do, and what is still required:

- Removing a file from the latest commit does not remove it from history, clones or forks. History was not rewritten and nothing was force-pushed.
- Nothing has been rotated or revoked. Do that wherever the key may have been used.
- If you want the key gone from history, rewrite it deliberately (for example with `git filter-repo --path device_priv.pem --invert-paths`), coordinate with every clone and fork, and still assume the key was copied while it was public.
- To provision a new device key: `python create_device_keys.py` (writes to `~/.config/blockaudit/keys` or `BLOCKAUDIT_KEY_DIR`).

## Other findings fixed

| Finding | Fix |
| --- | --- |
| no authentication on any route, including start/stop and whitelist changes | bearer-token roles on every API route and Socket.IO connection |
| CORS and Socket.IO origins defaulted to `*`; bind `0.0.0.0` | same-origin by default, explicit allow-list, loopback bind; wildcard refused in production |
| Werkzeug dev server, optional debug mode, tracebacks printed to clients | gunicorn deployment, debug refused in production, JSON errors without internals |
| `/api/health` returned usernames, paths and interpreter details | removed |
| alert whitelist pre-filled with large cloud-provider ranges, silently hiding attacks from them | defaults reduced to loopback; changes require admin, are persisted and are written to the ledger |
| ledger rewritten non-atomically on every append, no locking, no fsync | append-only, fsync, file lock, checkpoint, recovery |
| integrity monitor could not distinguish its own writes from tampering and read half-written files | compares disk with memory copy and checkpoint |
| Merkle proofs failed on levels with an odd node; `optimize()` dropped leaves | fixed, tested |
| detectors: unbounded state, thresholds that fire on normal browsing, brute force counting every packet | bounded state, windows, connection-attempt counting, negative tests |
| "Isolation Forest" and "LSTM" were stand-ins and the ML received fields it could not read | real scikit-learn model on per-source window features |
| dashboards loaded scripts, fonts and charts from CDNs and assigned `innerHTML` in 28 places (not individually assessed for exploitability) | self-hosted assets, DOM built without `innerHTML`, strict CSP |
| `threat_demo.sh` ran flooding tools without confirmation | requires `I_OWN_THIS_NETWORK=yes` |
| tracked `__pycache__`, runtime ledger with real addresses | untracked and ignored (the local files were left in place) |

## Trust model

- Anyone holding the admin token controls the service. Tokens are shared secrets; rotate them by changing the environment and restarting.
- The ledger resists casual or partial tampering and reports it precisely. It does not resist an attacker who controls the host, can stop the service and rewrite both the ledger and its checkpoint. Keep exported checkpoints elsewhere.
- Traffic analysed by the sensor is untrusted. Free-text fields are length-limited and stripped of control characters, the UI never renders them as HTML, and the copilot treats them as data.
- When a model provider is configured, alert and ledger records for the question are sent to it. Leave `ANTHROPIC_API_KEY` unset to keep everything local.

## Reporting a vulnerability

Open a private security advisory on the repository, or contact the maintainer directly. Please do not file public issues for undisclosed vulnerabilities.
