#!/bin/bash
cd "/Users/aro/Documents/Claude/Projects/Vakros First Billionaire Camel Firm"

echo "🔓 Removing git lock files..."
rm -fv .git/index.lock .git/HEAD.lock .git/refs/heads/*.lock 2>/dev/null || true

echo "⚙️  Configuring git..."
git config user.email "anwarkhalfaqir@gmail.com"
git config user.name "Anwar Khalfaqir"

echo "📦 Staging SOC code..."
git add .gitignore \
  vakros-soc/agent/ \
  vakros-dashboard/ \
  vakros-portal/ \
  vakroks-mvp/ \
  vakros-chrome-extension/ \
  vakros-platform/ \
  Vakros_Agentic_SOC_Architecture_Analysis.docx \
  vakros-agentic-soc.html \
  vakros-platform-system-design.md \
  Vakros_GRC_Platform_Product_Spec.md

echo ""
echo "🔍 Checking for env files in staging area..."
ENV_FILES=$(git diff --cached --name-only | grep -i "\.env" || true)
if [ -n "$ENV_FILES" ]; then
  echo "❌ ABORT — .env file staged: $ENV_FILES"
  exit 1
fi
echo "✅ No .env files staged"

echo ""
echo "💾 Committing..."
git commit -m "feat: Vakros Agentic SOC — full platform push

- vakros-soc/agent/: SOC1/SOC2 triage agents, threat hunt agent, MITRE seeder, Wazuh webhook, MCP server
- vakros-dashboard/: Next.js SOC dashboard (app.vakros.com)
- vakros-portal/: Multi-tenant customer portal
- vakroks-mvp/: GRC API, n8n workflows, Supabase migrations
- vakros-chrome-extension/: Chrome extension for SOC ops
- vakros-platform/: GRC compliance platform (Next.js)
- Docs: SOC architecture analysis, platform system design, product spec"

echo ""
echo "🚀 Pushing to GitHub..."
git push origin main

echo ""
echo "✅ Done! All SOC code is on GitHub."
echo "🔗 https://github.com/EngagedEntree3/vakros-grc"
