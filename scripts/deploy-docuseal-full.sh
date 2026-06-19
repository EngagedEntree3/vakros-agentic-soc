#!/usr/bin/env bash
# =============================================================================
# deploy-docuseal-full.sh — One-shot DocuSeal + Vakros Backend Deploy
# =============================================================================
# Runs in order:
#   1. Create & deploy DocuSeal on Fly.io (vakros-docuseal)
#   2. Open browser for admin setup → collect API key
#   3. Push all secrets (DOCUSEAL_API_KEY, DOCUSEAL_BASE_URL, DOCUSEAL_WEBHOOK_SECRET)
#   4. fly deploy vakros-backend-long-rain-1451
#
# Usage:
#   chmod +x scripts/deploy-docuseal-full.sh
#   ./scripts/deploy-docuseal-full.sh
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DOCUSEAL_APP="vakros-docuseal"
BACKEND_APP="vakros-backend-long-rain-1451"
DOCUSEAL_FLY_URL="https://${DOCUSEAL_APP}.fly.dev"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║        VAKROS — DocuSeal Full Deploy & Configure             ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  DocuSeal app  : $DOCUSEAL_APP"
echo "║  Backend app   : $BACKEND_APP"
echo "║  DocuSeal URL  : $DOCUSEAL_FLY_URL"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ── Prerequisites ─────────────────────────────────────────────────────────────
echo "▶ [1/8] Checking prerequisites..."
command -v fly     >/dev/null 2>&1 || { echo "❌  fly CLI not found — install from https://fly.io/docs/hands-on/install-flyctl/"; exit 1; }
command -v curl    >/dev/null 2>&1 || { echo "❌  curl not found"; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "❌  openssl not found"; exit 1; }
echo "   ✅ Prerequisites OK"

# ── Create Fly.io app ─────────────────────────────────────────────────────────
echo ""
echo "▶ [2/8] Creating Fly.io app: $DOCUSEAL_APP ..."
if fly apps list 2>/dev/null | grep -q "^$DOCUSEAL_APP"; then
  echo "   ℹ️  App already exists — skipping create"
else
  fly apps create "$DOCUSEAL_APP" --org personal 2>/dev/null \
    || fly apps create "$DOCUSEAL_APP" 2>/dev/null \
    || echo "   ⚠️  App may already exist — continuing"
  echo "   ✅ App created"
fi

# ── Create persistent volume ──────────────────────────────────────────────────
echo ""
echo "▶ [3/8] Creating persistent volume (docuseal_data, 5GB)..."
if fly volumes list -a "$DOCUSEAL_APP" 2>/dev/null | grep -q "docuseal_data"; then
  echo "   ℹ️  Volume already exists — skipping"
else
  fly volumes create docuseal_data \
    --size 5 \
    -a "$DOCUSEAL_APP" \
    -r iad \
    --yes 2>/dev/null || echo "   ⚠️  Volume may already exist — continuing"
  echo "   ✅ Volume created"
fi

# ── Set required secrets ──────────────────────────────────────────────────────
echo ""
echo "▶ [4/8] Setting DocuSeal secrets on Fly.io..."
SECRET_KEY=$(openssl rand -hex 64)
fly secrets set \
  SECRET_KEY_BASE="$SECRET_KEY" \
  FORCE_SSL="true" \
  -a "$DOCUSEAL_APP"
echo "   ✅ Secrets set"

# ── Deploy DocuSeal ───────────────────────────────────────────────────────────
echo ""
echo "▶ [5/8] Deploying DocuSeal (docuseal/docuseal:latest)..."
echo "   This pulls ~400MB Docker image — may take 2-3 minutes..."
cd "$SCRIPT_DIR/vakros-docuseal"
fly deploy \
  --image docuseal/docuseal:latest \
  -a "$DOCUSEAL_APP" \
  --wait-timeout 180 \
  --strategy immediate
echo "   ✅ DocuSeal deployed at $DOCUSEAL_FLY_URL"

# ── Wait for DocuSeal to be ready ─────────────────────────────────────────────
echo ""
echo "▶ [6/8] Waiting for DocuSeal to be ready..."
MAX_WAIT=60
COUNT=0
until curl -sf -o /dev/null "$DOCUSEAL_FLY_URL/health" 2>/dev/null \
   || curl -sf -o /dev/null "$DOCUSEAL_FLY_URL" 2>/dev/null; do
  sleep 3
  COUNT=$((COUNT + 3))
  echo "   ⏳ Waiting... ($COUNT/${MAX_WAIT}s)"
  if [[ $COUNT -ge $MAX_WAIT ]]; then
    echo "   ⚠️  DocuSeal taking longer than expected — open $DOCUSEAL_FLY_URL manually"
    break
  fi
done
echo "   ✅ DocuSeal is up!"

# ── Admin setup + API key ─────────────────────────────────────────────────────
echo ""
echo "▶ [7/8] DocuSeal Admin Setup"
echo ""
echo "   Opening DocuSeal admin in your browser..."
echo "   URL: $DOCUSEAL_FLY_URL"
echo ""
open "$DOCUSEAL_FLY_URL" 2>/dev/null || xdg-open "$DOCUSEAL_FLY_URL" 2>/dev/null || true
echo "   ┌──────────────────────────────────────────────────────────┐"
echo "   │  In the browser:                                          │"
echo "   │  1. Complete admin registration (email + password)        │"
echo "   │  2. Go to Settings → API → Create API Token               │"
echo "   │  3. Copy the token                                        │"
echo "   └──────────────────────────────────────────────────────────┘"
echo ""
read -rsp "   Paste your DocuSeal API key here: " DOCUSEAL_API_KEY
echo ""

if [[ -z "$DOCUSEAL_API_KEY" ]]; then
  echo "   ❌ No API key provided. Exiting."
  exit 1
fi

# Validate the API key
echo ""
echo "   Validating API key..."
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "X-Auth-Token: $DOCUSEAL_API_KEY" \
  "${DOCUSEAL_FLY_URL}/api/templates")

if [[ "$HTTP_STATUS" == "200" ]]; then
  echo "   ✅ API key valid"
else
  echo "   ⚠️  Unexpected status $HTTP_STATUS (key may still work — continuing)"
fi

# Generate webhook secret
DOCUSEAL_WEBHOOK_SECRET=$(openssl rand -hex 32)
echo "   ✅ Webhook secret generated"

# Push all secrets to backend
echo ""
echo "   Pushing secrets to $BACKEND_APP..."
fly secrets set \
  DOCUSEAL_API_KEY="$DOCUSEAL_API_KEY" \
  DOCUSEAL_BASE_URL="${DOCUSEAL_FLY_URL}/api" \
  DOCUSEAL_WEBHOOK_SECRET="$DOCUSEAL_WEBHOOK_SECRET" \
  -a "$BACKEND_APP"
echo "   ✅ Secrets pushed to backend"

# ── Deploy Vakros backend ─────────────────────────────────────────────────────
echo ""
echo "▶ [8/8] Deploying Vakros backend with new DocuSeal routes..."
cd "$SCRIPT_DIR/vakros-agent"
fly deploy -a "$BACKEND_APP" --wait-timeout 120 2>/dev/null \
  || (cd "$SCRIPT_DIR" && fly deploy -a "$BACKEND_APP" --wait-timeout 120)
echo "   ✅ Backend deployed"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    ✅  ALL DONE                              ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  DocuSeal admin   : $DOCUSEAL_FLY_URL"
echo "║  Backend API      : https://$BACKEND_APP.fly.dev"
echo "║  DocuSeal routes  : https://$BACKEND_APP.fly.dev/api/docuseal/"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  NEXT — Add webhook in DocuSeal admin:                       ║"
echo "║  Settings → Webhooks → Add endpoint:                         ║"
echo "║    URL    : https://n8n.vakros.com/webhook/docuseal           ║"
echo "║    Secret : (shown below)                                    ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "  Webhook secret (paste into DocuSeal + n8n):"
echo "  $DOCUSEAL_WEBHOOK_SECRET"
echo ""
echo "  Import n8n workflow:"
echo "  n8n-manifests/docuseal-webhook-listener.json"
echo ""
