# Chirify Execution Pod (`chirify-openalgo`)

> **GNU AGPL-3.0 Section 13 Notice:** This repository (`chiranjeevich2808-spec/chirify-openalgo`) is the public **GNU AGPL-3.0** execution-plane fork of [marketcalls/openalgo](https://github.com/marketcalls/openalgo) used by Chirify managed trading pods and `BYO-VPS` self-hosted deployments. Every running pod publicly exposes its exact corresponding source repository URL and EU AI Act Article 50 white-box transparency notice prior to login at `GET /api/v1/chirify/status`.
>
> All proprietary control-plane billing, Firebase identity, Kubernetes `TenantWorkspace` reconciliation, and ephemeral Qlib ML orchestration reside strictly in the separate repository [`chirify-platform`](https://github.com/chiranjeevich2808-spec/chirify-platform) and communicate exclusively across HTTP/API boundaries.

---

## 1. Execution Pod Architecture & Chirify Capabilities

Each Chirify tenant runs in an isolated, single-replica execution pod (`Strategy: Recreate`, `runAsNonRoot`, UID/GID `1000`, `readOnlyRootFilesystem: true`, `cap_drop: [ALL]`, `256Mi` `/dev/shm`, `TZ=UTC`) with zero shared broker sessions or databases.

| Capability | Primary Module(s) | Purpose |
| :--- | :--- | :--- |
| **Headless Managed Pod Bootstrap** | `services/chirify_bootstrap_service.py`, `start.sh` | Eliminates the first-boot `/setup` admin-claim race when `CHIRIFY_MANAGED_POD=true`; idempotently provisions the tenant admin owner, initializes Analyzer (Sandbox) Mode, locks `/setup` with `403`, and logs a WORM bootstrap record. |
| **Single-Use 60s HS256 SSO Handoff** | `blueprints/chirify_sso.py` | Exchanges short-lived HS256 SSO tickets (`POST/GET /auth/chirify/sso`) minted by `chirify-control` for a browser session cookie without ever transmitting a password. Enforces `iss == "chirify-control-plane"`, `aud == tenant_id`, `typ == "CHIRIFY-SSO"`, hard `<= 120s` TTL ceiling (default `60s`), `<= 5s` clock-skew tolerance, and atomic single-use `jti` replay protection. |
| **Cohort-A Live Gate & DORA Kill-Switch** | `services/chirify_live_gate.py`, `blueprints/internal_ops.py` | When `CHIRIFY_ENFORCE_LIVE_GATE=true`, blocks switching `analyze_mode` from `True` (Sandbox) to `False` (Live) unless an HMAC-SHA256 signed entitlement token verifies `>= 5` sandbox trades, `0` unhandled RMS breaches, positive `max_daily_loss` & `max_order_notional`, SEBI static IP + `exchange_algo_id` (hosted India) or `<10 OPS` family attestation (`india_byo_vps`), and disengaged kill-switch. |
| **Three-Gate Prompt-Blind Copilot Guard** | `services/chirify_agent_guard.py`, `services/chirify_openrouter.py` | Enforces Gate 1 (surface exclusion on `/trading` chart), Gate 2 (HITL confirmation), and Gate 3 (`PromptBlindOrderGuard` ignoring prompt text completely and halting immediately if kill-switch is engaged). Routes LLM traffic strictly to region-pinned OpenRouter endpoints (`openrouter.ai`, `us.openrouter.ai`, `eu.openrouter.ai`) with workspace key isolation. |
| **42 Native Brokers (39 Upstream + 3 Global)** | `broker/alpaca/`, `broker/ibkr/`, `broker/ccxt/`, `utils/broker_setup_guide.py`, `.sample.env` | Preserves all 39 upstream Indian brokers unchanged and appends native `alpaca` (US Equities/Options/Crypto), `ibkr` (Global Multi-Asset via headless TWS/IB Gateway `127.0.0.1:4002` + OAuth 2.0 Web API with 45 msg/sec pacing governor & `reqCurrentTime()` `CLOSE_WAIT` readiness probe), and `ccxt` (103+ spot, perp & options crypto venues with per-key nonce lock). |
| **DuckDB Warm Anchor Cursor Pool & Parquet Export** | `database/historify_db.py`, `services/qlib_snapshot_service.py` | `acquire_duckdb_cursor()` maintains a warm per-file DuckDB anchor connection preventing C++ `DBInstanceCache` refcount `0 <-> 1` oscillation and `pandas_scan` conflicts under concurrent `gthread` workers. Exports atomic Parquet snapshots (`POST /internal/v1/historify/export-parquet`) for ephemeral Qlib jobs. |
| **5-Year Hash-Chained UTC WORM Audit Trail** | `subscribers/worm_audit_subscriber.py` | Writes strictly monotonic (`seq_no`), UTC ISO-8601 (`...Z`), recursively credential-redacted JSONL events chained via `prev_hash -> record_hash = sha256(canonical_json)` to `CHIRIFY_WORM_LOG_PATH` (default `/app/log/worm_audit.jsonl`), archived to S3 Object Lock (`COMPLIANCE`, `1826d`). |
| **Startup Security Invariants** | `utils/startup_invariants.py`, `start.sh` | Refuses boot if `ZMQ_HOST` is non-loopback (`not in {"127.0.0.1", "localhost"}`), if `FLASK_DEBUG` is truthy in cluster mode or on non-loopback bind, if secrets use placeholder/compromised defaults, or if `CHIRIFY_REQUIRE_STATIC_EGRESS=true` lacks a fresh verified SNAT VIP file from `egress-ip-guard`. |
| **K8s Probes, Prometheus `/metrics` & Public Status** | `blueprints/chirify_status.py`, `app.py` | Exposes unauthenticated, CSRF-exempt, pre-login endpoints `GET /healthz`, `GET /readyz`, `GET /metrics` (Prometheus 0.0.4), and `GET /api/v1/chirify/status`. |

---

## 2. Supported Brokers (42 Native) & Global Exchanges

All **39 upstream Indian brokers** remain intact in `.sample.env` (`VALID_BROKERS`), with **3 native global/crypto adapters** appended:

- **Upstream 39 Indian Brokers:** `fivepaisa`, `fivepaisaxts`, `aliceblue`, `angel`, `arrow`, `compositedge`, `dhan`, `dhan_sandbox`, `definedge`, `deltaexchange`, `firstock`, `flattrade`, `fyers`, `groww`, `hdfcsecurities`, `hdfcsky`, `ibulls`, `iifl`, `iiflcapital`, `indmoney`, `jainamxts`, `kotak`, `motilal`, `mstock`, `nubra`, `nuvama`, `paytm`, `pocketful`, `rmoney`, `rupeezy`, `sahi`, `samco`, `shoonya`, `tradejini`, `tradesmart`, `upstox`, `wisdom`, `zebu`, `zerodha`.
- **Appended 3 Global/Crypto Brokers:**
  1. **`alpaca`** (`US_multi`): `US_EQUITY`, `US_OPTIONS`, `CRYPTO` — paper (`PK*`) and live (`AK*`) keys, 200 req/min rate limit.
  2. **`ibkr`** (`GLOBAL_multi`): `US_EQUITY`, `US_OPTIONS`, `EU_EQUITY`, `FUTURES`, `FOREX` — OAuth 2.0 Web API + headless `ibg-controller` (`127.0.0.1:4002` paper / `:4001` live), 45 msg/sec sliding pacing governor, active `reqCurrentTime()` `CLOSE_WAIT` probe, Sunday `00:45 ET` 2FA notification scheduler.
  3. **`ccxt`** (`crypto`): `CRYPTO`, `CRYPTO_SWAP`, `CRYPTO_OPTIONS` — 103+ exchanges (`exchange_id[:testnet]` + optional passphrase), fractional order quantities, per-API-key monotonic nonce lock registry.

**Global Exchange Venues Added:** `US_EQUITY`, `US_OPTIONS`, `EU_EQUITY`, `FUTURES`, `FOREX`, `CRYPTO_SWAP`, `CRYPTO_OPTIONS` (alongside upstream `NSE`, `BSE`, `NFO`, `BFO`, `MCX`, `CDS`, `CRYPTO`).

---

## 3. Environment Flags Reference

| Variable | Default | Description |
| :--- | :--- | :--- |
| `CHIRIFY_MANAGED_POD` | `false` | Enables headless first-boot tenant admin provisioning and locks `/setup` (`403`). |
| `CHIRIFY_CLUSTER_MODE` | `false` | Enforces production startup invariants (forbids `FLASK_DEBUG=true`, placeholder or leaked `APP_KEY`/`API_KEY_PEPPER`/`FERNET_SALT`). |
| `CHIRIFY_TENANT_ID` | *(none)* | Tenant UUID/identifier bound to SSO ticket `aud`, entitlement claims, and WORM records. |
| `CHIRIFY_TENANT_ADMIN_EMAIL` | *(none)* | Required when `CHIRIFY_MANAGED_POD=true`; provisions the single admin owner. |
| `CHIRIFY_TENANT_ADMIN_USERNAME` | *(derived)* | Optional explicit OpenAlgo username (defaults to sanitized email local-part). |
| `CHIRIFY_TENANT_BOOTSTRAP_PASSWORD` | *(random 256-bit)* | Optional bootstrap password; if omitted, a random 256-bit hex secret is generated and never logged. |
| `CHIRIFY_SSO_SECRET` | *(fallback: entitlement secret)* | HS256 HMAC secret verifying single-use `/auth/chirify/sso` launch tickets (`<= 120s` TTL, default `60s`). |
| `CHIRIFY_ENTITLEMENT_SECRET` | *(none)* | HMAC-SHA256 secret verifying signed `CHIRIFY_ENTITLEMENT_TOKEN` claims from `chirify-control`. |
| `CHIRIFY_ENTITLEMENT_TOKEN` | *(none)* | Signed entitlement token synchronized via `POST /internal/v1/entitlements/sync`. |
| `CHIRIFY_ENFORCE_LIVE_GATE` | `false` (`true` in managed pods) | Enables Cohort-A Sandbox + Risk Guard + SEBI Live Mode transition enforcement. |
| `CHIRIFY_EMERGENCY_KILL_SWITCH` | `false` | When `true`, forces Analyzer Sandbox Mode and blocks live transitions and agent orders unconditionally (EU DORA Art. 30). |
| `CHIRIFY_INTERNAL_OPS_TOKEN` | *(none)* | Constant-time bearer / `X-Chirify-Internal-Token` authenticating private-network `/internal/v1/*` requests. |
| `CHIRIFY_REQUIRE_STATIC_EGRESS` | `false` | Requires fresh verified static SNAT VIP artifact from `egress-ip-guard` (`EXPECTED_EGRESS_IPV4` / `EXPECTED_SECONDARY_IPV4`). |
| `CHIRIFY_EGRESS_STATE_PATH` | `/app/tmp/egress_verified.json` | JSON file written by `egress-ip-guard` containing `observed_ip` and verification epoch. |
| `CHIRIFY_OPENROUTER_REGION` | `GLOBAL` | Data residency pinning for `/agent`: `EU` (`eu.openrouter.ai`), `US` (`us.openrouter.ai`), or `IN`/`GLOBAL` (`openrouter.ai`). |
| `CHIRIFY_WORM_AUDIT_ENABLED` | `false` | Enables append-only hash-chained UTC WORM JSONL audit logging. |
| `CHIRIFY_WORM_LOG_PATH` | `/app/log/worm_audit.jsonl` | Destination file for hash-chained WORM JSONL events. |
| `CHIRIFY_SOURCE_REPO_URL` | `https://github.com/chiranjeevich2808-spec/chirify-openalgo` | AGPL-3.0 Section 13 source link returned by `GET /api/v1/chirify/status`. |
| `CHIRIFY_IB_GATEWAY_READY` | `true` | Optional readiness override (`true`/`false`) reflected in `chirify_ib_gateway_api_readiness_probe_success`. |
| `ZMQ_HOST` / `ZMQ_PORT` | `127.0.0.1` / `5555` | Strictly loopback-only ZeroMQ tick bus (non-loopback fails startup invariants and `/readyz`). |
| `HISTORIFY_DATABASE_PATH` | `db/historify.duckdb` | DuckDB file path backing the warm anchor cursor pool (`acquire_duckdb_cursor`). |

---

## 4. Operational Endpoints & Probes

### Unauthenticated Kubernetes Probes, Prometheus Metrics & Public Status
All endpoints below are registered in `app.py` with CSRF exemption and pre-login / DB-wait bypasses (`Cache-Control: no-store`):

- **`GET /healthz`** — Kubernetes liveness probe. Immediately returns `200 OK` `{"status": "ok", "service": "chirify-openalgo", "tz": "UTC"}` without blocking on DB init.
- **`GET /readyz`** — Kubernetes readiness probe. Verifies `app.db_ready`, loopback `ZMQ_HOST` (`127.0.0.1` / `localhost`), and static egress IP verification (when `CHIRIFY_REQUIRE_STATIC_EGRESS=true`). Returns `200 OK` `{"status": "ready", "analyze_mode": ..., "kill_switch_engaged": ...}` or `503 Service Unavailable` with diagnostic `reasons`.
- **`GET /metrics`** — Prometheus OpenMetrics (`text/plain; version=0.0.4; charset=utf-8`) aligned with `infra/helm/worm-observability/prometheus-slo-rules.yaml`:
  - `chirify_pod_analyze_mode`
  - `chirify_pod_kill_switch_engaged`
  - `chirify_eventbus_worm_events_published_total`
  - `chirify_tenant_static_egress_ip_mismatch_total`
  - `chirify_ib_gateway_api_readiness_probe_success`
- **`GET /api/v1/chirify/status`** — Public AGPL-3.0 Section 13 source link, EU AI Act Art. 50 disclosure, live-gate verdict, static egress status, OpenRouter region, and WORM chain head hash (attaches non-secret tenant/broker telemetry when signed in or called with `CHIRIFY_INTERNAL_OPS_TOKEN` over a private IP).

### Cluster-Private Internal Ops Endpoints (`/internal/v1/*`)
Restricted strictly to loopback/RFC1918/pod-CGNAT `request.remote_addr` + constant-time `CHIRIFY_INTERNAL_OPS_TOKEN`:
- `GET  /internal/v1/health/egress`
- `POST /internal/v1/failover-reconcile` (triggered within `<15s` by Cilium failover watcher)
- `POST /internal/v1/historify/export-parquet` (atomic DuckDB -> Parquet snapshot for Qlib)
- `POST /internal/v1/entitlements/sync` (pushes signed entitlement token from `chirify-control`)
- `POST /internal/v1/compliance/kill-switch` (engages/clears EU DORA Art. 30 kill-switch and records WORM event)

---

## 5. Running the Chirify Verification Suite

```bash
# Run all Chirify execution-pod PRR tests (brokers, SSO, live-gate, WORM, DuckDB, Three-Gate redteam, probes & metrics)
pytest test/chirify/ -v

# Or using the pre-provisioned virtual environment:
/tmp/chirify-oa-venv/bin/pytest test/chirify/ -v
```

Test modules under `test/chirify/`:
- `test_agent_three_gate_redteam.py` — Prompt-injection red-team & Three-Gate deterministic risk guard tests
- `test_broker_ui_and_compliance.py` — 42-broker catalog/setup UI, AGPL-3.0/EU AI Act `/api/v1/chirify/status`, DORA kill-switch, and `/healthz`, `/readyz`, `/metrics` probes
- `test_global_brokers.py` — `alpaca`, `ibkr` (45 msg/s pacing + `CLOSE_WAIT` probe + Sunday 2FA), and `ccxt` (nonce lock + precision)
- `test_historify_parquet_concurrency.py` — DuckDB warm anchor cursor concurrency & atomic Parquet export
- `test_pod_bootstrap_and_sso.py` — Headless first-boot bootstrap, `/setup` lockdown, and 60s single-use HS256 SSO ticket handoff
- `test_sandbox_live_gate.py` — Cohort-A Sandbox-to-Live entitlement gate & SEBI compliance checks
- `test_startup_invariants.py` — `ZMQ_HOST`, `FLASK_DEBUG`, secret hygiene & static egress startup gates
- `test_worm_audit_and_failover.py` — SHA-256 WORM hash-chain tamper detection & Cilium failover reconciliation
