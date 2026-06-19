#!/usr/bin/env bash
# =============================================================================
# docuseal-configure.sh — Vakros DocuSeal Integration Setup
# =============================================================================
# Verifies environment, generates secrets, and pushes them to Fly.io.
# Run once after deploying the DocuSeal Fly.io instance.
#
# Usage:
#   chmod +x scripts/docuseal-configure.sh
#   ./scripts/docuseal-configure.sh
# =============================================================================

set -euo pipefail

VAKROS_APP="vakros-backend-long-rain-1451"
DOCUSEAL_APP="vakros-docuseal"
DOCUSEAL_HOST="${DOCUSEAL_HOST:-https://signing.vakros.com}"

echo ""
echo "============================================================"
echo " Vakros DocuSeal Configuration Script"
echo " Target backend app : $VAKROS_APP"
echo " DocuSeal host      : $DOCUSEAL_HOST"
echo "============================================================"
echo ""

# ── 1. Check prerequisites ────────────────────────────────────────────────────
echo "► Checking prerequisites..."

command -v fly  >/dev/null 2>&1 || { echo "❌ Fly CLI not installed. Install: https://fly.io/docs/hands-on/install-flyctl/"; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "❌ curl not found"; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "❌ openssl not found"; exit 1; }

echo "  ✅ Prerequisites OK"

# ── 2. Prompt for DocuSeal API key ────────────────────────────────────────────
echo ""
echo "► DocuSeal API Key"
echo "  Get this from: ${DOCUSEAL_HOST}/settings/api"
echo ""
read -rsp "  Paste your DocuSeal API key: " DOCUSEAL_API_KEY
echo ""

if [[ -z "$DOCUSEAL_API_KEY" ]]; then
  echo "❌ No API key provided. Exiting."
  exit 1
fi

# ── 3. Validate API key against DocuSeal ─────────────────────────────────────
echo ""
echo "► Validating API key against DocuSeal..."
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "X-Auth-Token: $DOCUSEAL_API_KEY" \
  "${DOCUSEAL_HOST}/api/templates")

if [[ "$HTTP_STATUS" == "200" ]]; then
  echo "  ✅ API key is valid"
elif [[ "$HTTP_STATUS" == "401" ]]; then
  echo "  ❌ API key rejected (401 Unauthorized)"
  exit 1
else
  echo "  ⚠️  Unexpected status $HTTP_STATUS — check that DocuSeal is running at ${DOCUSEAL_HOST}"
  read -rp "  Continue anyway? (y/N): " CONTINUE
  [[ "$CONTINUE" == "y" ]] || exit 1
fi

# ── 4. Generate webhook secret ────────────────────────────────────────────────
echo ""
echo "► Generating webhook HMAC secret..."
DOCUSEAL_WEBHOOK_SECRET=$(openssl rand -hex 32)
echo "  ✅ Generated: ${DOCUSEAL_WEBHOOK_SECRET:0:8}...${DOCUSEAL_WEBHOOK_SECRET: -8}"
echo ""
echo "  ⚠️  IMPORTANT: Add this to DocuSeal admin:"
echo "  ${DOCUSEAL_HOST}/settings/webhooks"
echo "  Webhook URL    : https://n8n.vakros.com/webhook/docuseal"
echo "  Webhook Secret : $DOCUSEAL_WEBHOOK_SECRET"
echo ""
read -rp "  Press Enter once you've added the webhook in DocuSeal admin..."

# ── 5. Push secrets to Fly.io ─────────────────────────────────────────────────
echo ""
echo "► Pushing secrets to Fly.io app: $VAKROS_APP"

fly secrets set \
  DOCUSEAL_API_KEY="$DOCUSEAL_API_KEY" \
  DOCUSEAL_BASE_URL="${DOCUSEAL_HOST}/api" \
  DOCUSEAL_WEBHOOK_SECRET="$DOCUSEAL_WEBHOOK_SECRET" \
  -a "$VAKROS_APP"

echo "  ✅ Secrets pushed"

# ── 6. Prompt for template IDs ────────────────────────────────────────────────
echo ""
echo "► DocuSeal Template IDs"
echo "  Get these from: ${DOCUSEAL_HOST}/templates"
echo ""
read -rp "  MSA template ID  (or press Enter to skip): " TEMPLATE_MSA
read -rp "  NDA template ID  (or press Enter to skip): " TEMPLATE_NDA
read -rp "  SOW template ID  (or press Enter to skip): " TEMPLATE_SOW

if [[ -n "$TEMPLATE_MSA" || -n "$TEMPLATE_NDA" || -n "$TEMPLATE_SOW" ]]; then
  TEMPLATE_SECRETS=""
  [[ -n "$TEMPLATE_MSA" ]] && TEMPLATE_SECRETS+="DOCUSEAL_TEMPLATE_MSA=$TEMPLATE_MSA "
  [[ -n "$TEMPLATE_NDA" ]] && TEMPLATE_SECRETS+="DOCUSEAL_TEMPLATE_NDA=$TEMPLATE_NDA "
  [[ -n "$TEMPLATE_SOW" ]] && TEMPLATE_SECRETS+="DOCUSEAL_TEMPLATE_SOW=$TEMPLATE_SOW "

  # shellcheck disable=SC2086
  fly secrets set $TEMPLATE_SECRETS -a "$VAKROS_APP"
  echo "  ✅ Template IDs saved"
fi

# ── 7. Verify final secret list ───────────────────────────────────────────────
echo ""
echo "► Current secrets on $VAKROS_APP:"
fly secrets list -a "$VAKROS_APP" | grep -E "DOCUSEAL|FLY_INTERNAL"

# ── 8. Quick smoke test ───────────────────────────────────────────────────────
echo ""
echo "► Running smoke test against Vakros backend..."
BACKEND_URL="https://${VAKROS_APP}.fly.dev"

HTTP=$(curl -s -o /dev/null -w "%{http_code}" "${BACKEND_URL}/health")
if [[ "$HTTP" == "200" ]]; then
  echo "  ✅ Backend health: OK"
else
  echo "  ⚠️  Backend health returned $HTTP — check Fly.io logs"
fi

TEMPLATES_HTTP=$(curl -s -o /dev/null -w "%{http_code}" "${BACKEND_URL}/api/docuseal/templates")
if [[ "$TEMPLATES_HTTP" == "200" ]]; then
  echo "  ✅ /api/docuseal/templates: OK"
else
  echo "  ⚠️  /api/docuseal/templates returned $TEMPLATES_HTTP"
fi

echo ""
echo "============================================================"
echo " DocuSeal integration configured successfully."
echo " Next step: Run the Supabase migration:"
echo "   vakros-agent/integrations/docuseal/migrations/001_signing_submissions.sql"
echo "============================================================"
echo ""
