# Vakros Platform — System Design

**Version:** MVP v1  
**Stage:** 0→1, 1–10 customers  
**Date:** 2026-05-29

---

## 1. Requirements

### Functional
- Ingest security events from SIEM/XDR, cloud APIs, endpoints, threat intel feeds
- AI agents to triage, investigate, and respond to alerts autonomously
- Continuous compliance monitoring mapped to SOC 2, ISO 27001, NIST, HIPAA
- Automated evidence collection and gap detection
- Trust graph relating assets, vendors, risks, and controls
- Customer-facing dashboards: SOC workbench + GRC portal
- REST API + notification delivery (Slack, email, webhook)
- Multi-tenant architecture — complete data isolation between customers

### Non-Functional
- Latency: alert triage < 30s end-to-end for P1 events
- Availability: 99.9% uptime target (MVP — single region acceptable)
- Scale: 1–10 orgs, up to 10k events/day per org
- Security: SOC 2 Type I self-attestation by launch

### Constraints
- Small team, fast iteration
- Supabase as primary data platform (already chosen)
- Vercel for frontend/API deployment
- Budget-conscious: minimize managed service sprawl at MVP

---

## 2. High-Level Architecture

Five horizontal layers:

```
[Data Sources]  →  [Ingestion Bus]  →  [AI Agent Layer]
                                              ↓
                              [GRC + Trust Graph + Data Store]
                                              ↓
                              [Delivery: Dashboards + API]
```

All layers sit behind a unified **Auth + Multi-tenancy** guard (Supabase Auth, JWT, RLS).

---

## 3. Component Design

### 3.1 Ingestion Bus

**What:** An async event queue that normalizes incoming data before it hits the AI agents.

**Implementation (MVP):**
- Supabase `pg_notify` + Realtime for low-volume async dispatch
- A thin Python/FastAPI ingestor service normalizes events into a canonical schema and writes to `raw_events` table
- Triggers a Supabase Edge Function (or webhook) to enqueue the event for agent processing

**Canonical event schema:**
```json
{
  "id": "uuid",
  "org_id": "uuid",
  "source": "crowdstrike | aws_guardduty | manual | ...",
  "event_type": "alert | log | finding | compliance_signal",
  "severity": "critical | high | medium | low | info",
  "raw_payload": {},
  "normalized_at": "timestamp",
  "status": "pending | triaged | resolved"
}
```

**Scale path:** Replace `pg_notify` with a proper message queue (Upstash/Redis Streams or AWS SQS) when volume exceeds ~50k events/day.

---

### 3.2 AI Agent Layer

Four specialized agents, each a Python service (FastAPI) calling Claude API (claude-sonnet-4-6 or claude-haiku-4-5 for high-volume low-stakes tasks).

#### Triage Agent
- **Input:** raw normalized event
- **Output:** severity classification, duplicate detection, priority score (0–100)
- **Logic:** LLM prompt + deterministic rules (regex patterns for known FP signatures)
- **SLA:** < 10s per event

#### Investigation Agent
- **Input:** triaged alert + context from DB (asset inventory, recent incidents, threat intel)
- **Output:** enriched incident record — affected assets, likely attack vector, related CVEs
- **Logic:** multi-step tool-use — queries asset table, checks CVE feed, correlates past incidents
- **SLA:** < 60s per incident

#### Response Agent
- **Input:** investigated incident
- **Output:** executed playbook steps + audit trail
- **Logic:** reads playbook definitions from DB, executes steps (API calls, quarantine commands, notification triggers), logs each action
- **Escalation:** if confidence < threshold or severity = critical → human review queue

#### Compliance Agent
- **Input:** events + control definitions
- **Output:** evidence records mapped to controls, gap alerts
- **Logic:** continuously scans events for compliance signals, maps to framework controls, flags missing evidence
- **Runs:** scheduled (every 6h) + triggered on relevant events

**Agent orchestration (MVP):** Simple sequential pipeline managed by a FastAPI background task. No dedicated orchestration framework needed at this scale.

**Scale path:** Migrate to a proper agent framework (LangGraph, CrewAI, or custom) when parallel agent execution and complex branching are needed.

---

### 3.3 GRC Intelligence Layer

Manages compliance state continuously — not point-in-time.

**Core concepts:**
- **Control:** a requirement from a framework (e.g., CC6.1 from SOC 2)
- **Evidence:** an artifact proving a control is met (log, screenshot, config export)
- **Risk:** a finding with likelihood + impact scores
- **Framework mapping:** one control can map to multiple frameworks

**Key tables:**
```sql
frameworks (id, name, version)           -- SOC 2, ISO 27001, NIST, HIPAA
controls (id, framework_id, code, title, description)
control_mappings (control_id, mapped_control_id)  -- cross-framework
evidence (id, org_id, control_id, type, file_url, collected_at, expires_at)
risks (id, org_id, title, likelihood, impact, score, status)
vendors (id, org_id, name, risk_tier, last_assessed_at)
```

**Risk scoring:** `score = likelihood (1–5) × impact (1–5)` → normalized to 0–100. Displayed on dashboard with trend.

**Compliance posture:** % of controls with valid, non-expired evidence. Broken down by framework and domain.

---

### 3.4 Trust Graph

The strategic differentiator — a queryable relationship map across the security estate.

**Nodes:** Asset, Vendor, Risk, Control, Incident, User  
**Edges:** `affects`, `mitigates`, `depends_on`, `owns`, `caused_by`

**MVP implementation:** Stored in Postgres using adjacency list + materialized path pattern. No graph DB needed at this scale.

```sql
trust_nodes (id, org_id, type, label, metadata jsonb)
trust_edges (id, org_id, from_node_id, to_node_id, relationship, weight)
```

**Queries enabled:**
- "Which controls mitigate this risk?"
- "What assets does this vendor have access to?"
- "What's the blast radius if this vendor is compromised?"
- "Which incidents share root cause?"

**Visualization:** D3.js force graph in the GRC portal. Nodes colored by type, edges labeled.

**Scale path:** Migrate to Apache AGE (Postgres graph extension) or Neo4j when graph traversal becomes a bottleneck (typically >500k edges).

---

### 3.5 Core Data Store — Supabase (Postgres)

**Multi-tenancy:** Row-Level Security (RLS) on every table using `org_id`. Every query automatically scoped to the authenticated org. No shared data ever leaks.

**Key schema areas:**

| Schema area | Tables |
|---|---|
| Auth | orgs, users, roles, api_keys |
| SOC | raw_events, incidents, alerts, playbooks, playbook_runs |
| GRC | frameworks, controls, evidence, risks, vendors |
| Trust | trust_nodes, trust_edges |
| Audit | audit_log (append-only, immutable) |
| Config | integrations, notification_rules |

**Audit log:** Every write to sensitive tables is mirrored to `audit_log` via Postgres triggers. Append-only — no UPDATE/DELETE permitted. Critical for SOC 2 compliance.

**Storage:** Supabase Storage for evidence files (screenshots, exports, PDFs). Organized by `org_id/control_id/`.

---

### 3.6 Auth + Multi-tenancy

- **Authentication:** Supabase Auth (email/password + SSO via SAML for enterprise)
- **Authorization:** JWT carries `org_id` + `role`. RLS policies enforce org_id match on every query.
- **Roles:**
  - `analyst` — view + respond to incidents
  - `manager` — full SOC + GRC read/write
  - `auditor` — read-only across all GRC data
  - `admin` — full platform access
- **API keys:** scoped per org, rotatable, used for integrations and ingestor auth

---

### 3.7 Delivery Layer

#### SOC Dashboard (Next.js, Vercel)
- Incident queue with priority sort, filter by severity/status
- Incident detail: timeline, enrichment, playbook execution log
- Alert triage UI for human review queue
- Playbook builder (CRUD for response playbooks)

#### GRC Portal (Next.js, Vercel)
- Compliance scorecard by framework with % posture
- Control detail: evidence attached, gaps flagged
- Trust graph explorer (D3.js visualization)
- Vendor risk register
- Evidence upload and management

#### API + Notifications (FastAPI on Vercel/Railway)
- `POST /api/events` — ingest events
- `GET /api/incidents` — list incidents
- `GET /api/compliance/posture` — current compliance score
- `GET /api/trust-graph` — graph data for visualization
- Outbound: Slack webhooks, email (Resend/SendGrid), generic webhook
- Customer report generation: PDF export of compliance posture

---

## 4. Data Flow — End to End

### Alert → Resolution

```
1. Source (e.g. CrowdStrike) pushes event to POST /api/events
2. Ingestor normalizes + writes to raw_events, publishes pg_notify
3. Triage Agent picks up event → classifies → writes to incidents
4. Investigation Agent enriches incident → queries assets, CVEs, history
5. Response Agent checks playbooks → executes steps → logs to audit_log
6. If escalated → analyst sees in SOC Dashboard human queue
7. Resolution closes incident, updates risk scores in GRC layer
8. Compliance Agent maps incident to relevant controls, updates evidence
```

### Compliance Signal → Evidence

```
1. Compliance Agent scheduled run (every 6h)
2. Scans events for compliance signals (e.g. access review completed)
3. Maps signal to control (e.g. CC6.2 — logical access)
4. Creates evidence record with reference to source event
5. Updates control status from "gap" → "met"
6. GRC Portal reflects updated posture score
```

---

## 5. Scale + Reliability

### MVP (1–10 customers, <100k events/day total)
- Single Supabase project (Pro plan)
- Vercel for frontend + edge functions
- FastAPI services on Railway or Vercel serverless
- No dedicated queue needed — pg_notify sufficient
- Single region (us-east-1 or eu-west-1 based on customer location)

### Growth path (10–100 customers)
- Introduce Upstash Redis Streams as event queue
- Separate Supabase projects per customer (enterprise isolation option)
- Add read replicas for analytics queries
- Agent services containerized on Fly.io or ECS
- CDN for evidence file delivery (Cloudflare R2)

### Reliability
- Supabase managed Postgres: automatic failover, daily backups
- Vercel: global edge, automatic scaling
- Agent services: retry with exponential backoff on LLM API failures
- Dead letter queue for failed events (separate `failed_events` table)
- Alerting: Datadog or Supabase dashboard for DB health

---

## 6. Trade-off Analysis

| Decision | Chosen | Alternative | Why |
|---|---|---|---|
| Data store | Supabase (Postgres) | Dedicated graph DB + separate OLTP | Supabase handles both; graph at scale via AGE extension. Avoids ops overhead at MVP. |
| Event queue | pg_notify | Redis Streams / SQS | Sufficient at MVP scale. Reduces infra cost by ~$200/mo. Revisit at >50k events/day. |
| Agent framework | Custom FastAPI pipeline | LangGraph / CrewAI | Simpler, fewer dependencies. Custom gives full control over retry and logging. Revisit when agents need parallel execution. |
| LLM | Claude API (Anthropic) | Fine-tuned open-source model | Fastest to ship, best reasoning quality. Cost is predictable at MVP scale. |
| Multi-tenancy | RLS per org_id | Schema-per-tenant | RLS is simpler operationally. Schema-per-tenant considered for enterprise tier later. |
| Frontend | Next.js on Vercel | React SPA on S3/CF | Vercel + Next.js = fastest deployment iteration. Server components help with data-heavy GRC views. |

---

## 7. What to Revisit as Vakros Grows

- **Agent orchestration:** Move to LangGraph or equivalent when multi-agent parallelism and complex branching are needed
- **Event queue:** Upgrade from pg_notify to Redis Streams or AWS SQS at >50k events/day
- **Graph storage:** Evaluate Apache AGE or Neo4j when trust graph exceeds ~500k edges
- **Tenant isolation:** Offer schema-per-tenant or project-per-tenant as enterprise upgrade option
- **LLM cost optimization:** Fine-tune a smaller model on security-specific tasks once training data accumulates
- **SOC 2 Type II:** Begin audit period tracking from day one — the audit log and evidence collection are already designed for it

---

## 8. Immediate Next Steps (MVP Build Order)

1. **Supabase schema** — orgs, users, raw_events, incidents, controls, evidence (with RLS)
2. **Ingestor API** — FastAPI service, event normalization, pg_notify
3. **Triage Agent** — Claude API integration, severity classification
4. **SOC Dashboard** — incident queue, basic triage UI
5. **Compliance Agent** — control definitions, evidence mapping
6. **GRC Portal** — posture scorecard, evidence upload
7. **Trust Graph** — node/edge tables, D3 visualization
8. **Investigation + Response Agents** — playbook engine, auto-remediation
9. **Notifications** — Slack + email delivery
10. **Customer-facing reports** — PDF export

---
