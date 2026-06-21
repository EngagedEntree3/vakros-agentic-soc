#!/bin/bash
# ============================================================
# VAKROS SOC APPS — ONE-SHOT DEPLOY SCRIPT
# Deploys vakros-soc-dashboard and vakros-soc-portal to Vercel
# Run from: ~/Documents/Claude/Projects/Vakros First Billionaire Camel Firm/
# ============================================================

set -e

WORKDIR="$(cd "$(dirname "$0")" && pwd)"
GH_TOKEN="${GH_TOKEN:?Set GH_TOKEN env var before running}"
GH_USER="EngagedEntree3"

# Supabase public config
SUPABASE_URL="https://etmshueaqaqxpyzuvkqi.supabase.co"
SUPABASE_ANON_KEY="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImV0bXNodWVhcWFxeHB5enV2a3FpIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzY4MTk5NDgsImV4cCI6MjA5MjM5NTk0OH0.Io9u5GW1guGQ1cETb-RGzAsnAWXzkOp6UWHZlCMsmAk"

echo "=========================================="
echo " VAKROS SOC APPS DEPLOY"
echo "=========================================="

# ── 1. Check prereqs ─────────────────────────────────────────
echo ""
echo "[1/6] Checking prerequisites..."
command -v git >/dev/null 2>&1 || { echo "❌ git not found"; exit 1; }
command -v node >/dev/null 2>&1 || { echo "❌ node not found"; exit 1; }
command -v npx >/dev/null 2>&1 || { echo "❌ npx not found"; exit 1; }

# Check Vercel CLI
if ! command -v vercel >/dev/null 2>&1; then
  echo "Installing Vercel CLI..."
  npm install -g vercel
fi
echo "✅ Prerequisites OK"

# ── 2. Create GitHub repos ────────────────────────────────────
echo ""
echo "[2/6] Creating GitHub repos..."

create_repo() {
  local name=$1
  local desc=$2
  local response
  response=$(curl -s -w "%{http_code}" -X POST https://api.github.com/user/repos \
    -H "Authorization: Bearer $GH_TOKEN" \
    -H "Accept: application/vnd.github+json" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"$name\",\"private\":true,\"description\":\"$desc\"}")
  local http_code="${response: -3}"
  if [ "$http_code" == "201" ]; then
    echo "  ✅ Created $GH_USER/$name"
  elif [ "$http_code" == "422" ]; then
    echo "  ℹ️  $GH_USER/$name already exists"
  else
    echo "  ⚠️  $GH_USER/$name: HTTP $http_code"
  fi
}

create_repo "vakros-soc-dashboard" "Vakros Agentic SOC Operator Dashboard"
create_repo "vakros-soc-portal" "Vakros Multi-tenant Customer Portal"

# ── 3. Push vakros-soc-dashboard ─────────────────────────────
echo ""
echo "[3/6] Pushing vakros-soc-dashboard to GitHub..."
cd "$WORKDIR/vakros-dashboard"

# Create .gitignore if missing
cat > .gitignore << 'EOF'
node_modules/
.next/
.env.local
.env
*.env
.DS_Store
EOF

# Create .env.local for local dev (not committed)
cat > .env.local << ENVEOF
NEXT_PUBLIC_SUPABASE_URL=$SUPABASE_URL
NEXT_PUBLIC_SUPABASE_ANON_KEY=$SUPABASE_ANON_KEY
# Add these manually in Vercel dashboard → Settings → Environment Variables:
# SUPABASE_SERVICE_ROLE_KEY=<your-service-role-key>
# ANTHROPIC_API_KEY=<your-anthropic-key>
ENVEOF

if [ ! -d .git ]; then
  git init
  git branch -M main
fi
git remote remove origin 2>/dev/null || true
git remote add origin "https://$GH_TOKEN@github.com/$GH_USER/vakros-soc-dashboard.git"
git add -A
git commit -m "feat: Vakros Agentic SOC dashboard — live alerts, AI triage, metrics" 2>/dev/null || echo "  (nothing new to commit)"
git push -u origin main --force
echo "  ✅ Dashboard pushed"

# ── 4. Push vakros-soc-portal ────────────────────────────────
echo ""
echo "[4/6] Pushing vakros-soc-portal to GitHub..."
cd "$WORKDIR/vakros-portal"

cat > .gitignore << 'EOF'
node_modules/
.next/
.env.local
.env
*.env
.DS_Store
EOF

cat > .env.local << ENVEOF
NEXT_PUBLIC_SUPABASE_URL=$SUPABASE_URL
NEXT_PUBLIC_SUPABASE_ANON_KEY=$SUPABASE_ANON_KEY
ENVEOF

if [ ! -d .git ]; then
  git init
  git branch -M main
fi
git remote remove origin 2>/dev/null || true
git remote add origin "https://$GH_TOKEN@github.com/$GH_USER/vakros-soc-portal.git"
git add -A
git commit -m "feat: Vakros multi-tenant SOC portal — Supabase auth, RLS, per-tenant dashboards" 2>/dev/null || echo "  (nothing new to commit)"
git push -u origin main --force
echo "  ✅ Portal pushed"

# ── 5. Deploy to Vercel ──────────────────────────────────────
echo ""
echo "[5/6] Deploying to Vercel..."
echo "  Note: You'll need to be logged into Vercel CLI."
echo "  If prompted, run: vercel login"
echo ""

deploy_to_vercel() {
  local dir=$1
  local name=$2
  cd "$WORKDIR/$dir"
  echo "  Deploying $name..."

  # Set Vercel env vars and deploy
  vercel env add NEXT_PUBLIC_SUPABASE_URL production <<< "$SUPABASE_URL" 2>/dev/null || true
  vercel env add NEXT_PUBLIC_SUPABASE_ANON_KEY production <<< "$SUPABASE_ANON_KEY" 2>/dev/null || true

  vercel --prod --yes --name "$name" 2>&1 | tail -5
  echo "  ✅ $name deployed"
}

deploy_to_vercel "vakros-dashboard" "vakros-soc-dashboard"
deploy_to_vercel "vakros-portal" "vakros-soc-portal"

# ── 6. Set Fly.io Slack bot token if available ───────────────
echo ""
echo "[6/6] Checking Fly.io..."
if command -v fly >/dev/null 2>&1; then
  echo "  Fly.io CLI found. Add secrets when you have them:"
  echo ""
  echo "  fly secrets set \\"
  echo "    SLACK_WEBHOOK_URL=https://hooks.slack.com/services/... \\"
  echo "    SLACK_WEBHOOK_ALERTS=https://hooks.slack.com/services/... \\"
  echo "    SLACK_WEBHOOK_OPS=https://hooks.slack.com/services/... \\"
  echo "    ABUSEIPDB_API_KEY=<your-key> \\"
  echo "    -a vakros-backend-long-rain-1451"
else
  echo "  ⚠️  Fly CLI not found. Install from: https://fly.io/docs/hands-on/install-flyctl/"
fi

echo ""
echo "=========================================="
echo " ✅ DEPLOY COMPLETE"
echo "=========================================="
echo ""
echo "After deploy:"
echo "  1. Add to Vercel dashboard → vakros-soc-dashboard → Settings → Env Vars:"
echo "     SUPABASE_SERVICE_ROLE_KEY = <from Supabase dashboard>"
echo "     ANTHROPIC_API_KEY         = <your Anthropic key>"
echo ""
echo "  2. Configure Supabase Auth:"
echo "     Supabase → Authentication → URL Configuration"
echo "     Site URL: https://vakros-soc-portal.vercel.app"
echo "     Redirect URLs: https://vakros-soc-portal.vercel.app/auth/callback"
echo ""
echo "  3. For Slack webhooks: sign into vakroksoperations.slack.com"
echo "     → Apps → Incoming WebHooks → Add to Slack"
echo "     Create webhooks for #vakroks-alerts and #vakroks-ops"
echo ""
