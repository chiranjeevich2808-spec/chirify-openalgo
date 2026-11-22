#!/usr/bin/env bash
# Chirify live Execution Pod launcher (Analyzer Sandbox, managed mode).
#
#   scripts/chirify_live_pod.sh start   -> detached daemon (setsid/nohup), logs in $RUNTIME/logs
#   scripts/chirify_live_pod.sh stop
#   scripts/chirify_live_pod.sh status
#   scripts/chirify_live_pod.sh foreground   (used internally by `start`)
#
# All mutable runtime state (SQLite DBs, Historify DuckDB, WORM audit log, generated
# secrets) lives under CHIRIFY_RUNTIME_DIR (default /tmp/chirify_openalgo_runtime)
# so the git working tree stays clean.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME="${CHIRIFY_RUNTIME_DIR:-/tmp/chirify_openalgo_runtime}"
PY="${CHIRIFY_PYTHON:-/home/antigravity/.venvs/chirify-openalgo/bin/python}"
PIDFILE="$RUNTIME/pod.pid"
LOGDIR="$RUNTIME/logs"
SECRETS="$RUNTIME/secrets.env"

mkdir -p "$RUNTIME" "$LOGDIR" "$RUNTIME/worm"
chmod 700 "$RUNTIME"

gen_secret() { "$PY" -c "import secrets; print(secrets.token_hex(32))"; }

if [ ! -s "$SECRETS" ]; then
    umask 077
    {
        echo "APP_KEY=$(gen_secret)"
        echo "API_KEY_PEPPER=$(gen_secret)"
        echo "FERNET_SALT=$(gen_secret)"
        echo "CHIRIFY_TENANT_BOOTSTRAP_PASSWORD=Cx$(gen_secret | cut -c1-24)!9a"
    } > "$SECRETS"
fi
set -a
# shellcheck disable=SC1090
. "$SECRETS"
set +a

# Loopback traffic must never traverse the VM's egress proxy; the IPv6 NO_PROXY literal
# also breaks httpx URL parsing, so normalise it for the pod process.
export NO_PROXY="127.0.0.1,localhost" no_proxy="127.0.0.1,localhost"

export CHIRIFY_MANAGED_POD=true
export CHIRIFY_TENANT_ID="${CHIRIFY_TENANT_ID:-tenant-live-001}"
export CHIRIFY_TENANT_ADMIN_USERNAME="${CHIRIFY_TENANT_ADMIN_USERNAME:-chirify_admin}"
export CHIRIFY_TENANT_ADMIN_EMAIL="${CHIRIFY_TENANT_ADMIN_EMAIL:-admin@chirify.io}"
export CHIRIFY_INTERNAL_OPS_TOKEN="${CHIRIFY_INTERNAL_OPS_TOKEN:-chirify-internal-ops-sync-token-2026}"
export CHIRIFY_ENTITLEMENT_SECRET="${CHIRIFY_ENTITLEMENT_SECRET:-chirify-prod-entitlement-hmac-secret-2026}"
export CHIRIFY_SSO_SECRET="${CHIRIFY_SSO_SECRET:-chirify-prod-pod-sso-hmac-secret-2026}"
export CHIRIFY_WORM_LOG_PATH="${CHIRIFY_WORM_LOG_PATH:-$RUNTIME/worm/chirify_worm_audit.jsonl}"
export CHIRIFY_SANDBOX_24X7="${CHIRIFY_SANDBOX_24X7:-true}"

export HISTORIFY_DATABASE_PATH="${HISTORIFY_DATABASE_PATH:-$RUNTIME/historify.duckdb}"
export DATABASE_URL="${DATABASE_URL:-sqlite:///$RUNTIME/openalgo.db}"
export SANDBOX_DATABASE_URL="${SANDBOX_DATABASE_URL:-sqlite:///$RUNTIME/sandbox.db}"
export LATENCY_DATABASE_URL="${LATENCY_DATABASE_URL:-sqlite:///$RUNTIME/latency.db}"
export LOGS_DATABASE_URL="${LOGS_DATABASE_URL:-sqlite:///$RUNTIME/logs.db}"
export HEALTH_DATABASE_URL="${HEALTH_DATABASE_URL:-sqlite:///$RUNTIME/health.db}"

export HOST_SERVER="http://127.0.0.1:5000"
export FLASK_HOST_IP="127.0.0.1" FLASK_PORT="5000" FLASK_DEBUG="False" FLASK_ENV="production"
export WEBSOCKET_HOST="127.0.0.1" WEBSOCKET_PORT="8765" WEBSOCKET_URL="ws://127.0.0.1:8765"
export WEBSOCKET_PROXY_MODE="${WEBSOCKET_PROXY_MODE:-thread}"
export ZMQ_HOST="127.0.0.1" ZMQ_PORT="5555"
export WS_PING_INTERVAL=20 WS_PING_TIMEOUT=20
export LOG_DIR="$RUNTIME/logs" LOG_TO_FILE=False LOG_COLORS=False
export CORS_ALLOWED_ORIGINS="http://127.0.0.1:5000,http://127.0.0.1:5173"
export VALID_BROKERS="${VALID_BROKERS:-fivepaisa,fivepaisaxts,aliceblue,angel,arrow,compositedge,dhan,dhan_sandbox,definedge,deltaexchange,firstock,flattrade,fyers,groww,hdfcsecurities,hdfcsky,ibulls,iifl,iiflcapital,indmoney,jainamxts,kotak,motilal,mstock,nubra,nuvama,paytm,pocketful,rmoney,rupeezy,sahi,samco,shoonya,tradejini,tradesmart,upstox,wisdom,zebu,zerodha,alpaca,ibkr,ccxt}"
export MCP_HTTP_ENABLED="${MCP_HTTP_ENABLED:-False}"
export PYTHONUNBUFFERED=1 PYTHONPATH="$REPO_DIR"

cmd="${1:-start}"

case "$cmd" in
    bootstrap)
        cd "$REPO_DIR"
        "$PY" -m utils.startup_invariants
        "$PY" -m services.chirify_bootstrap_service
        ;;
    foreground)
        cd "$REPO_DIR"
        "$PY" -m utils.startup_invariants
        "$PY" -m services.chirify_bootstrap_service
        exec "$PY" app.py
        ;;
    start)
        if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
            echo "pod already running (pid $(cat "$PIDFILE"))"
            exit 0
        fi
        cd "$REPO_DIR"
        setsid nohup "$0" foreground > "$LOGDIR/pod.out.log" 2>&1 < /dev/null &
        echo $! > "$PIDFILE"
        echo "pod starting (pid $(cat "$PIDFILE")); logs: $LOGDIR/pod.out.log"
        ;;
    stop)
        if [ -f "$PIDFILE" ]; then
            pid="$(cat "$PIDFILE")"
            pkill -TERM -P "$pid" 2>/dev/null || true
            kill -TERM "$pid" 2>/dev/null || true
            rm -f "$PIDFILE"
        fi
        ;;
    status)
        if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
            echo "running pid $(cat "$PIDFILE")"
        else
            echo "stopped"; exit 1
        fi
        ;;
    *) echo "usage: $0 {start|stop|status|foreground}" >&2; exit 2 ;;
esac
