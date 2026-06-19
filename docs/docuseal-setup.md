# DocuSeal Setup Guide — Vakros Self-Hosted Instance

## Overview

DocuSeal is deployed as an isolated AGPL-3.0 microservice at `signing.vakros.com`.
It has **zero code overlap** with the Vakros proprietary codebase.
All interaction is via REST API and webhooks only.

---

## 1. Deploy DocuSeal on Fly.io (Recommended)

```bash
# Create a new Fly app for DocuSeal
fly apps create vakros-docuseal

# Set the required secrets
fly secrets set \
  SECRET_KEY_BASE="$(openssl rand -hex 64)" \
  DATABASE_URL="postgres://..." \
  RAILS_FORCE_SSL=true \
  -a vakros-docuseal

# Deploy using the official DocuSeal Docker image
fly deploy \
  --image docuseal/docuseal:latest \
  --app vakros-docuseal \
  --env FORCE_SSL=true \
  --env APP_URL=https://signing.vakros.com
```

**`fly.toml` for DocuSeal:**
```toml
app = "vakros-docuseal"
primary_region = "iad"

[build]
  image = "docuseal/docuseal:latest"

[env]
  PORT = "3000"
  RAILS_ENV = "production"
  FORCE_SSL = "true"
  APP_URL = "https://signing.vakros.com"

[[services]]
  internal_port = 3000
  protocol = "tcp"
  [services.concurrency]
    hard_limit = 50
    soft_limit = 25
  [[services.ports]]
    handlers = ["http"]
    port = 80
  [[services.ports]]
    handlers = ["tls", "http"]
    port = 443

[[volumes]]
  source = "docuseal_data"
  destination = "/data"
```

---

## 2. First-Time Admin Setup

1. Navigate to `https://signing.vakros.com`
2. Complete the admin registration (email + password)
3. You are now the DocuSeal admin — **do not share these credentials**

---

## 3. Generate API Key

```
DocuSeal Admin → Settings → API → Create API Token
```

Copy the token. Add it to Fly.io secrets on the Vakros backend:

```bash
fly secrets set DOCUSEAL_API_KEY="your-token-here" \
  -a vakros-backend-long-rain-1451
```

And to your local `.env` for development:
```bash
DOCUSEAL_API_KEY=your-token-here
DOCUSEAL_BASE_URL=https://signing.vakros.com/api
```

**Never commit this key. Never send it to the frontend.**

---

## 4. Configure Webhook

```
DocuSeal Admin → Settings → Webhooks → Add Endpoint
```

| Field | Value |
|---|---|
| URL | `https://n8n.vakros.com/webhook/docuseal` |
| Events | `document.completed`, `document.viewed`, `document.declined`, `form.started` |
| Secret | Generate with `openssl rand -hex 32` |

Add the secret to both Fly.io and n8n:

```bash
# Fly.io backend
fly secrets set DOCUSEAL_WEBHOOK_SECRET="your-secret" \
  -a vakros-backend-long-rain-1451

# n8n — add as environment variable in n8n settings:
# DOCUSEAL_WEBHOOK_SECRET=your-secret
```

---

## 5. Create Your First Template

### Via DocuSeal UI (easiest):
```
DocuSeal Admin → Templates → New Template
→ Upload your PDF (e.g. NDA, MSA, Service Agreement)
→ Drag signature field onto the PDF
→ Set role name: "Signer"
→ Save → Note the template ID from the URL
```

### Via API:
```bash
curl -X POST https://signing.vakros.com/api/templates \
  -H "X-Auth-Token: $DOCUSEAL_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Vakros MSA",
    "fields": [
      {
        "name": "signature",
        "type": "signature",
        "role": "Signer",
        "required": true
      },
      {
        "name": "date",
        "type": "date",
        "role": "Signer",
        "required": true
      }
    ]
  }'
```

Template IDs to record in your Vakros config:
```bash
# Add to Fly.io secrets
fly secrets set \
  DOCUSEAL_TEMPLATE_MSA=1 \
  DOCUSEAL_TEMPLATE_NDA=2 \
  DOCUSEAL_TEMPLATE_SOW=3 \
  -a vakros-backend-long-rain-1451
```

---

## 6. Branding — Remove DocuSeal Branding from Embedded View

```
DocuSeal Admin → Settings → Appearance
```

| Setting | Value |
|---|---|
| Logo | Upload Vakros logo |
| Primary colour | `#6366f1` (Vakros indigo) |
| Company name | `Vakros` |
| Custom CSS | See below |

**Custom CSS to inject (Settings → Appearance → Custom CSS):**
```css
/* Hide DocuSeal branding in embedded view */
.docuseal-brand,
[data-docuseal-brand],
footer .powered-by {
  display: none !important;
}

/* Vakros font + colour override */
body {
  font-family: 'Inter', -apple-system, sans-serif;
  --primary: #6366f1;
  --primary-hover: #4f46e5;
}

button[type="submit"],
.btn-primary {
  background-color: var(--primary);
  border-color: var(--primary);
}
```

---

## 7. Environment Variables Reference

| Variable | Where | Description |
|---|---|---|
| `DOCUSEAL_API_KEY` | Fly.io secret | DocuSeal API token — never frontend |
| `DOCUSEAL_BASE_URL` | Fly.io env | `https://signing.vakros.com/api` |
| `DOCUSEAL_WEBHOOK_SECRET` | Fly.io secret + n8n | HMAC secret for webhook validation |
| `DOCUSEAL_TEMPLATE_MSA` | Fly.io env | Template ID for MSA document |
| `NEXT_PUBLIC_DOCUSEAL_HOST` | Vercel/frontend env | `https://signing.vakros.com` (public) |

---

## 8. AGPL Compliance Checklist

- [x] DocuSeal deployed as separate Fly.io app (`vakros-docuseal`)
- [x] No DocuSeal source code in `vakros-agentic-soc` or `vakros-grc` repos
- [x] All interaction via REST API + webhooks only
- [x] DocuSeal AGPL source link available at `https://signing.vakros.com/source` *(required by AGPL §13)*
- [ ] Add `https://signing.vakros.com/source` → redirect to `https://github.com/docuseal/docuseal`
