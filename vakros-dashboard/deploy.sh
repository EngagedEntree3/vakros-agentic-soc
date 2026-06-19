#!/bin/bash
# Vakros SOC Dashboard — Vercel Deployment Script
# Run this once from the vakros-dashboard directory

set -e
echo "=== Vakros SOC Dashboard Deployment ==="

# Check for required env vars in .env.local
if [ ! -f ".env.local" ]; then
  echo "ERROR: .env.local not found. Copy .env.local.example and fill in your keys."
  exit 1
fi

# Check keys are filled in
if grep -q "YOUR_" .env.local; then
  echo "WARNING: .env.local still has placeholder values. Fill in SERVICE_KEY and ANTHROPIC_API_KEY."
fi

# Install deps
echo "Installing dependencies..."
npm install

# Deploy to Vercel
echo "Deploying to Vercel..."
npx vercel deploy --prod \
  --env NEXT_PUBLIC_SUPABASE_URL="$(grep NEXT_PUBLIC_SUPABASE_URL .env.local | cut -d= -f2)" \
  --env NEXT_PUBLIC_SUPABASE_ANON_KEY="$(grep NEXT_PUBLIC_SUPABASE_ANON_KEY .env.local | cut -d= -f2)" \
  --env SUPABASE_SERVICE_KEY="$(grep SUPABASE_SERVICE_KEY .env.local | cut -d= -f2)" \
  --env ANTHROPIC_API_KEY="$(grep ANTHROPIC_API_KEY .env.local | cut -d= -f2)" \
  --yes

echo "=== Deployment complete! ==="
