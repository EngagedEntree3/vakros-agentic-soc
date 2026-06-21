# New Vakros Components

## 1. Wazuh Webhook Ingestion (`webhook_server.py`)
Real-time alert pipeline from Wazuh into Supabase.

**Start the server:**
```bash
SUPABASE_URL=... SUPABASE_SERVICE_KEY=... ANTHROPIC_API_KEY=... \
python webhook_server.py
# Listens on :8001
```

**Configure Wazuh** (`/var/ossec/etc/ossec.conf`):
```xml
<integration>
  <name>custom-vakros</name>
  <hook_url>http://YOUR_SERVER:8001/webhook/wazuh</hook_url>
  <api_key>YOUR_WEBHOOK_SECRET</api_key>
  <level>3</level>
  <alert_format>json</alert_format>
</integration>
```

**Test with simulated alerts:**
```bash
python test_webhook.py --url http://localhost:8001 --count 10
```

**Endpoints:**
- `POST /webhook/wazuh` — Wazuh JSON alerts
- `POST /webhook/generic` — Any normalized alert (Splunk, Elastic, etc.)
- `GET  /health` — Queue size + status
- `GET  /stats` — Live ingest stats from Supabase

Auto-triage fires for severity >= `AUTO_TRIAGE_THRESHOLD` (default: 7).

---

## 2. Threat Hunting Agent (`agent/hunt_agent.py`)
Proactive hunt across logs for IOCs and MITRE TTPs.

**Run a hunt:**
```bash
# Single hypothesis
python hunt_runner.py --hypothesis lateral_movement --hours 48

# All hypotheses
python hunt_runner.py --all --hours 24

# Custom
python hunt_runner.py --hypothesis custom \
  --query "Find evidence of data exfiltration from DB servers in the last week"
```

**Built-in hypotheses:**
| Hypothesis | What it hunts |
|---|---|
| `ioc_spread` | Same IP/hash across multiple hosts |
| `lateral_movement` | Sequential auth/access across internal hosts |
| `ttp_cluster` | Burst of same MITRE technique across hosts |
| `credential_access` | T1003/T1078/T1110 patterns on same host |
| `beaconing` | Repeated same-rule alerts = C2 check-ins |
| `insider_threat` | Unusual workstation access patterns |

Findings are written to `agent_actions` table (type=`hunt_finding`) and  
high-confidence/high-severity findings also create synthetic alerts visible in the SOC dashboard.

---

## 3. Customer Portal (`vakros-portal/`)
Multi-tenant Next.js portal with Supabase Auth + RLS.

**Each customer:**
- Signs in via magic link (no password)
- Sees only their `tenant_id` data (enforced by Postgres RLS)
- Has role: `admin | analyst | viewer`

**Pages:**
- `/portal` — Dashboard: metrics + recent alerts + hunt findings
- `/portal/alerts` — Full alert queue with search + filters
- `/portal/hunt` — Threat hunt findings with MITRE links
- `/portal/agents` — Monitored endpoints grid

**Run locally:**
```bash
cd vakros-portal
npm install && npm run dev   # → http://localhost:3001
```

**Deploy:**
```bash
npx vercel deploy --prod
```

**Onboard a new customer:**
```sql
-- 1. Create tenant
INSERT INTO tenants (name, slug, plan) VALUES ('Acme Corp', 'acme', 'pro');

-- 2. Invite user (they sign in via magic link, then run this)
INSERT INTO tenant_members (tenant_id, user_id, role)
VALUES ('<tenant_id>', auth.uid(), 'admin');
```

**Supabase RLS** ensures complete data isolation — no client can ever see another tenant's alerts, even with a valid JWT.
