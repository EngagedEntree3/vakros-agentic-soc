#!/bin/bash
# Vakros Full Stack Launcher
# Starts: webhook ingest server + optional triage batch + hunt runner

set -e
cd "$(dirname "$0")"

# Load .env
[ -f .env ] && export $(grep -v '^#' .env | xargs)

# Validate
: "${SUPABASE_URL:?Need SUPABASE_URL in .env}"
: "${SUPABASE_SERVICE_KEY:?Need SUPABASE_SERVICE_KEY in .env}"
: "${ANTHROPIC_API_KEY:?Need ANTHROPIC_API_KEY in .env}"

WORKERS=${WORKER_CONCURRENCY:-4}
THRESHOLD=${AUTO_TRIAGE_THRESHOLD:-7}

echo "╔══════════════════════════════════════╗"
echo "║     VAKROS AGENTIC SOC  v1.0         ║"
echo "╚══════════════════════════════════════╝"
echo ""
echo "  Webhook server   → http://0.0.0.0:8001"
echo "  Auto-triage sev  ≥ $THRESHOLD"
echo "  Worker threads   : $WORKERS"
echo ""

case "${1:-ingest}" in
  ingest)
    echo "Starting webhook ingest server..."
    python webhook_server.py
    ;;
  triage)
    echo "Running tiered triage batch (SOC1 → SOC2)..."
    python tiered_runner.py --limit "${2:-20}"
    ;;
  hunt)
    echo "Running all threat hunt hypotheses..."
    python hunt_runner.py --all --hours "${2:-24}"
    ;;
  mcp)
    echo "Starting MCP server (stdio)..."
    python mcp_server.py
    ;;
  all)
    # Run ingest server in background, then hunt on a schedule
    echo "Starting full stack..."
    python webhook_server.py &
    INGEST_PID=$!
    echo "  Ingest server PID: $INGEST_PID"

    # Run initial triage pass
    sleep 2
    echo "  Running initial triage pass..."
    python tiered_runner.py --limit 50 &

    # Run hunt every hour
    echo "  Hunt scheduler running (every 60min)..."
    while true; do
      sleep 3600
      echo "[$(date)] Running scheduled threat hunt..."
      python hunt_runner.py --all --hours 2 &
    done
    ;;
  *)
    echo "Usage: ./start.sh [ingest|triage|hunt|mcp|all]"
    echo "  ingest  — Start webhook server (default)"
    echo "  triage  — Run one triage batch"
    echo "  hunt    — Run all hunt hypotheses"
    echo "  mcp     — Start MCP server for Claude Desktop"
    echo "  all     — Start everything"
    ;;
esac
