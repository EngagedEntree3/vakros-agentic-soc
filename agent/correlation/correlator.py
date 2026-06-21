"""
Alert Correlation Engine
Inspired by agentic-soc-platform's Correlation UID design:
  - Multiple Alerts with the same Correlation UID → merged into one Case
  - Cases are the investigation layer; Alerts are the detection layer

Correlation strategies:
  1. Same source IP within time window
  2. Same user within time window + attack pattern match
  3. Same host within time window (lateral movement chain)
  4. Same CVE / rule ID burst (brute force pattern)
  5. Attack chain detection (escalation sequence)
"""

from __future__ import annotations

import hashlib
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

logger = logging.getLogger(__name__)


class CorrelationKey(str, Enum):
    """Dimension to correlate alerts on."""
    SOURCE_IP     = "src_ip"
    USER          = "user"
    HOST          = "host"
    RULE_BURST    = "rule_burst"
    ATTACK_CHAIN  = "attack_chain"
    TENANT        = "tenant"


@dataclass
class CorrelationRule:
    """A single correlation rule definition."""
    name: str
    key: CorrelationKey
    window_minutes: int = 60
    min_alerts: int = 2           # minimum alerts to trigger a case
    severity_threshold: int = 5   # only correlate alerts above this severity
    tags: list[str] = field(default_factory=list)
    description: str = ""

    def compute_uid(self, alert: dict[str, Any]) -> str | None:
        """Return a Correlation UID for this alert under this rule, or None if not applicable."""
        severity = alert.get("severity", 0)
        if isinstance(severity, str):
            severity = {"low": 3, "medium": 7, "high": 11, "critical": 15}.get(severity.lower(), 0)
        if severity < self.severity_threshold:
            return None

        tenant = alert.get("tenant_id", "default")

        if self.key == CorrelationKey.SOURCE_IP:
            src = alert.get("src_ip") or alert.get("source_ip") or _extract_src_ip(alert)
            if not src:
                return None
            raw = f"{self.name}:{tenant}:{src}"

        elif self.key == CorrelationKey.USER:
            user = alert.get("user") or alert.get("username") or _extract_user(alert)
            if not user:
                return None
            raw = f"{self.name}:{tenant}:{user}"

        elif self.key == CorrelationKey.HOST:
            host = alert.get("agent_name") or alert.get("host") or alert.get("hostname")
            if not host:
                return None
            raw = f"{self.name}:{tenant}:{host}"

        elif self.key == CorrelationKey.RULE_BURST:
            rule_id = alert.get("rule_id") or alert.get("rule", {}).get("id", "")
            if not rule_id:
                return None
            raw = f"{self.name}:{tenant}:{rule_id}"

        elif self.key == CorrelationKey.ATTACK_CHAIN:
            # Group by tenant — all alerts in a suspected chain
            raw = f"{self.name}:{tenant}"

        else:
            return None

        # Deterministic short hash
        return "COR-" + hashlib.sha256(raw.encode()).hexdigest()[:12].upper()


@dataclass
class CorrelatedCase:
    """A Case formed by correlating multiple alerts."""
    id: str = field(default_factory=lambda: str(uuid4()))
    correlation_uid: str = ""
    rule_name: str = ""
    tenant_id: str = ""
    title: str = ""
    severity: int = 0
    alert_ids: list[str] = field(default_factory=list)
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "open"
    tags: list[str] = field(default_factory=list)
    enrichments: list[dict] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "correlation_uid": self.correlation_uid,
            "rule_name": self.rule_name,
            "tenant_id": self.tenant_id,
            "title": self.title,
            "severity": self.severity,
            "alert_count": len(self.alert_ids),
            "alert_ids": self.alert_ids,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "status": self.status,
            "tags": self.tags,
        }


class AlertCorrelator:
    """
    Groups alerts into Cases using Correlation UIDs.

    Pipeline:
      1. Fetch uncorrelated alerts from Supabase
      2. Apply each CorrelationRule to each alert → compute UID
      3. Group alerts sharing the same UID within the time window
      4. Create or update a Case in Supabase for each group
      5. Mark alerts with their correlation_uid

    Inspired by agentic-soc-platform's Correlation UID architecture.
    """

    DEFAULT_RULES: list[CorrelationRule] = [
        CorrelationRule(
            name="brute_force_src_ip",
            key=CorrelationKey.SOURCE_IP,
            window_minutes=15,
            min_alerts=5,
            severity_threshold=5,
            tags=["brute_force", "credential_attack"],
            description="Multiple authentication alerts from same source IP → brute force",
        ),
        CorrelationRule(
            name="lateral_movement_host",
            key=CorrelationKey.HOST,
            window_minutes=60,
            min_alerts=3,
            severity_threshold=8,
            tags=["lateral_movement", "t1021"],
            description="Multiple high-severity alerts on same host → lateral movement",
        ),
        CorrelationRule(
            name="compromised_account",
            key=CorrelationKey.USER,
            window_minutes=120,
            min_alerts=2,
            severity_threshold=10,
            tags=["account_compromise", "credential_theft"],
            description="High-severity alerts for same user → account compromise",
        ),
        CorrelationRule(
            name="rule_burst",
            key=CorrelationKey.RULE_BURST,
            window_minutes=10,
            min_alerts=10,
            severity_threshold=3,
            tags=["alert_storm", "noisy_rule"],
            description="Same rule firing 10+ times in 10 min → potential alert storm",
        ),
        CorrelationRule(
            name="attack_chain",
            key=CorrelationKey.ATTACK_CHAIN,
            window_minutes=240,
            min_alerts=4,
            severity_threshold=12,
            tags=["apt", "attack_chain", "kill_chain"],
            description="Multiple critical alerts across tenant → suspected APT kill chain",
        ),
    ]

    def __init__(
        self,
        supabase_client=None,
        rules: list[CorrelationRule] | None = None,
    ):
        self._sb = supabase_client
        self.rules = rules or self.DEFAULT_RULES

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def correlate(
        self,
        alerts: list[dict[str, Any]],
        tenant_id: str | None = None,
    ) -> list[CorrelatedCase]:
        """
        Run correlation rules across a batch of alerts.
        Returns newly created CorrelatedCase objects.
        """
        now = datetime.now(timezone.utc)
        uid_buckets: dict[str, list[dict]] = {}  # uid → [alert, ...]
        uid_rule: dict[str, CorrelationRule] = {}

        for alert in alerts:
            for rule in self.rules:
                # Skip if alert is outside the rule's time window
                ts = _parse_ts(alert.get("created_at") or alert.get("timestamp"))
                if ts and (now - ts) > timedelta(minutes=rule.window_minutes):
                    continue

                uid = rule.compute_uid(alert)
                if uid is None:
                    continue

                bucket_key = f"{rule.name}:{uid}"
                uid_buckets.setdefault(bucket_key, []).append(alert)
                uid_rule[bucket_key] = rule

        cases: list[CorrelatedCase] = []
        for bucket_key, bucket_alerts in uid_buckets.items():
            rule = uid_rule[bucket_key]
            uid = bucket_key.split(":", 1)[1]

            if len(bucket_alerts) < rule.min_alerts:
                continue  # Not enough alerts to form a case

            case = self._build_case(uid, rule, bucket_alerts, tenant_id)
            cases.append(case)

            if self._sb:
                await self._persist_case(case, bucket_alerts)

            logger.info(
                "Correlated %d alerts into Case %s via rule '%s'",
                len(bucket_alerts), case.id, rule.name,
            )

        return cases

    # ------------------------------------------------------------------
    # Case building
    # ------------------------------------------------------------------

    def _build_case(
        self,
        correlation_uid: str,
        rule: CorrelationRule,
        alerts: list[dict],
        tenant_id: str | None,
    ) -> CorrelatedCase:
        severities = [
            _to_int_severity(a.get("severity", 0)) for a in alerts
        ]
        max_severity = max(severities, default=0)

        timestamps = [
            _parse_ts(a.get("created_at") or a.get("timestamp"))
            for a in alerts
        ]
        timestamps = [t for t in timestamps if t]
        first_seen = min(timestamps) if timestamps else datetime.now(timezone.utc)
        last_seen = max(timestamps) if timestamps else datetime.now(timezone.utc)

        tid = tenant_id or alerts[0].get("tenant_id", "default")
        alert_ids = [a.get("id") or a.get("alert_id") for a in alerts if a.get("id") or a.get("alert_id")]

        title = _generate_case_title(rule, alerts)

        return CorrelatedCase(
            correlation_uid=correlation_uid,
            rule_name=rule.name,
            tenant_id=tid,
            title=title,
            severity=max_severity,
            alert_ids=alert_ids,
            first_seen=first_seen,
            last_seen=last_seen,
            tags=rule.tags.copy(),
        )

    # ------------------------------------------------------------------
    # Supabase persistence
    # ------------------------------------------------------------------

    async def _persist_case(self, case: CorrelatedCase, alerts: list[dict]) -> None:
        """Write Case to Supabase and tag alerts with correlation_uid."""
        try:
            # Upsert case (match on correlation_uid to avoid duplicates)
            self._sb.table("correlated_cases").upsert(
                {
                    "id": case.id,
                    "correlation_uid": case.correlation_uid,
                    "rule_name": case.rule_name,
                    "tenant_id": case.tenant_id,
                    "title": case.title,
                    "severity": case.severity,
                    "alert_count": len(case.alert_ids),
                    "first_seen": case.first_seen.isoformat(),
                    "last_seen": case.last_seen.isoformat(),
                    "status": case.status,
                    "tags": case.tags,
                },
                on_conflict="correlation_uid",
            ).execute()

            # Tag each alert with the correlation_uid
            for alert_id in case.alert_ids:
                self._sb.table("alerts").update(
                    {"correlation_uid": case.correlation_uid, "correlated_case_id": case.id}
                ).eq("id", alert_id).execute()

        except Exception as exc:
            logger.error("Failed to persist correlated case: %s", exc)

    # ------------------------------------------------------------------
    # Runner helper
    # ------------------------------------------------------------------

    async def run_from_supabase(
        self,
        tenant_id: str | None = None,
        lookback_hours: int = 4,
    ) -> list[CorrelatedCase]:
        """Fetch recent uncorrelated alerts from Supabase and correlate."""
        if not self._sb:
            raise RuntimeError("Supabase client required")

        since = (datetime.now(timezone.utc) - timedelta(hours=lookback_hours)).isoformat()

        q = (
            self._sb.table("alerts")
            .select("*")
            .gte("created_at", since)
            .is_("correlation_uid", "null")
        )
        if tenant_id:
            q = q.eq("tenant_id", tenant_id)

        res = q.execute()
        alerts = res.data or []
        logger.info("Fetched %d uncorrelated alerts for correlation run", len(alerts))
        return await self.correlate(alerts, tenant_id=tenant_id)


# ------------------------------------------------------------------
# Supabase migration helper
# ------------------------------------------------------------------

MIGRATION_SQL = """
-- Correlated Cases table
CREATE TABLE IF NOT EXISTS public.correlated_cases (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    correlation_uid   TEXT UNIQUE NOT NULL,
    rule_name         TEXT NOT NULL,
    tenant_id         UUID REFERENCES public.tenants(id) ON DELETE CASCADE,
    title             TEXT NOT NULL,
    severity          INT DEFAULT 0,
    alert_count       INT DEFAULT 0,
    first_seen        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status            TEXT NOT NULL DEFAULT 'open',
    tags              TEXT[] DEFAULT '{}',
    enrichments       JSONB DEFAULT '[]',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- RLS
ALTER TABLE public.correlated_cases ENABLE ROW LEVEL SECURITY;

CREATE POLICY "tenant_read_cases" ON public.correlated_cases
    FOR SELECT USING (tenant_id = auth.uid() OR auth.jwt() ->> 'role' IN ('soc_analyst', 'soc_manager', 'admin'));

CREATE POLICY "service_insert_cases" ON public.correlated_cases
    FOR INSERT WITH CHECK (true);

CREATE POLICY "soc_update_cases" ON public.correlated_cases
    FOR UPDATE USING (auth.jwt() ->> 'role' IN ('soc_analyst', 'soc_manager', 'admin'));

-- Add correlation columns to alerts table
ALTER TABLE public.alerts
    ADD COLUMN IF NOT EXISTS correlation_uid        TEXT,
    ADD COLUMN IF NOT EXISTS correlated_case_id     UUID REFERENCES public.correlated_cases(id);

-- Index for fast correlation lookups
CREATE INDEX IF NOT EXISTS idx_alerts_correlation_uid ON public.alerts(correlation_uid);
CREATE INDEX IF NOT EXISTS idx_alerts_tenant_created  ON public.alerts(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_cases_tenant_status    ON public.correlated_cases(tenant_id, status);
"""


# ------------------------------------------------------------------
# Utility functions
# ------------------------------------------------------------------

def _extract_src_ip(alert: dict) -> str | None:
    """Try common field paths for source IP."""
    for path in ["data.srcip", "data.src_ip", "data.win.eventdata.ipAddress"]:
        val = _deep_get(alert, path)
        if val:
            return str(val)
    return None


def _extract_user(alert: dict) -> str | None:
    for path in ["data.win.eventdata.subjectUserName", "data.dstuser", "data.srcuser", "user"]:
        val = _deep_get(alert, path)
        if val:
            return str(val)
    return None


def _deep_get(obj: dict, path: str) -> Any:
    parts = path.split(".")
    cur = obj
    for p in parts:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(p)
    return cur


def _parse_ts(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, AttributeError):
        return None


def _to_int_severity(sev: Any) -> int:
    if isinstance(sev, int):
        return sev
    if isinstance(sev, str):
        return {"low": 3, "medium": 7, "high": 11, "critical": 15}.get(sev.lower(), 0)
    return 0


def _generate_case_title(rule: CorrelationRule, alerts: list[dict]) -> str:
    """Human-readable case title based on rule and alert context."""
    templates = {
        "brute_force_src_ip": lambda a: f"Brute Force from {_extract_src_ip(a[0]) or 'unknown'}",
        "lateral_movement_host": lambda a: f"Lateral Movement on {a[0].get('agent_name', 'unknown host')}",
        "compromised_account": lambda a: f"Account Compromise — {_extract_user(a[0]) or 'unknown user'}",
        "rule_burst": lambda a: f"Alert Storm: Rule {a[0].get('rule_id', '?')} ({len(a)} events)",
        "attack_chain": lambda a: f"Suspected APT Kill Chain — {len(a)} Critical Events",
    }
    try:
        return templates[rule.name](alerts)
    except (KeyError, IndexError):
        return f"{rule.name.replace('_', ' ').title()} ({len(alerts)} alerts)"
