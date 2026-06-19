"""
Artifact Enricher
Attaches structured Enrichment objects to Artifacts, Alerts, and Cases.

Inspired by agentic-soc-platform's Enrichment layer:
  "Enrichment is a structured result layer — attach AI analysis, threat intel,
   asset lookups, and external query results to Case / Alert / Artifact
   without polluting the original object fields."

Enrichment sources:
  - VirusTotal (IP + domain + hash reputation)
  - AbuseIPDB (IP abuse score)
  - AI analysis (Claude verdict + MITRE mapping)
  - Internal asset lookup (from Supabase agents table)
  - Geo-IP (country, ASN)
"""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

import httpx

from .extractor import Artifact, ArtifactType

logger = logging.getLogger(__name__)

VIRUSTOTAL_URL  = "https://www.virustotal.com/api/v3"
ABUSEIPDB_URL   = "https://api.abuseipdb.com/api/v2"


class EnrichmentSource(str, Enum):
    VIRUSTOTAL   = "virustotal"
    ABUSEIPDB    = "abuseipdb"
    AI_ANALYSIS  = "ai_analysis"
    ASSET_LOOKUP = "asset_lookup"
    GEO_IP       = "geo_ip"
    MANUAL       = "manual"


@dataclass
class Enrichment:
    """
    Structured result attached to a Case, Alert, or Artifact.
    Can hold threat intel, AI results, asset data, etc.
    """
    id: str = field(default_factory=lambda: str(uuid4()))
    source: EnrichmentSource = EnrichmentSource.VIRUSTOTAL
    target_type: str = "artifact"          # "artifact" | "alert" | "case"
    target_id: str = ""
    tenant_id: str = ""
    summary: str = ""
    data: dict = field(default_factory=dict)
    score: int | None = None               # 0-100 maliciousness score
    is_malicious: bool | None = None
    tags: list[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    provider: str = ""
    link: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "source": self.source.value,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "tenant_id": self.tenant_id,
            "summary": self.summary,
            "data": self.data,
            "score": self.score,
            "is_malicious": self.is_malicious,
            "tags": self.tags,
            "provider": self.provider,
            "link": self.link,
            "created_at": self.created_at.isoformat(),
        }


class ArtifactEnricher:
    """
    Enriches Artifact objects with threat intel and context.

    Supports:
      - VirusTotal: IP, domain, file hash lookups
      - AbuseIPDB: IP abuse score
      - Supabase asset lookup: match hostnames/IPs to known internal assets
      - AI analysis summary (via Claude)

    Enrichments are persisted to the `enrichments` Supabase table and
    linked back to the artifact.
    """

    def __init__(
        self,
        vt_api_key: str | None = None,
        abuse_api_key: str | None = None,
        supabase_client=None,
        anthropic_client=None,
        cache_ttl_hours: int = 24,
    ):
        self._vt_key     = vt_api_key or os.getenv("VIRUSTOTAL_API_KEY", "")
        self._abuse_key  = abuse_api_key or os.getenv("ABUSEIPDB_API_KEY", "")
        self._sb         = supabase_client
        self._ai         = anthropic_client
        self._cache_ttl  = cache_ttl_hours

    async def enrich_batch(
        self,
        artifacts: list[Artifact],
        tenant_id: str = "",
    ) -> list[Enrichment]:
        """Enrich a list of artifacts concurrently. Returns all enrichments produced."""
        tasks = [self.enrich(a, tenant_id) for a in artifacts]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        enrichments: list[Enrichment] = []
        for r in results:
            if isinstance(r, list):
                enrichments.extend(r)
            elif isinstance(r, Exception):
                logger.warning("Enrichment error: %s", r)
        return enrichments

    async def enrich(
        self,
        artifact: Artifact,
        tenant_id: str = "",
    ) -> list[Enrichment]:
        """Enrich a single artifact. Returns list of Enrichment objects."""
        enrs: list[Enrichment] = []
        tid = tenant_id or artifact.tenant_id

        # 1. Check cache in Supabase ioc_cache table
        cached = await self._check_cache(artifact)
        if cached:
            logger.debug("Cache hit for %s %s", artifact.type, artifact.value)
            return cached

        # 2. Dispatch to appropriate enrichers
        if artifact.type == ArtifactType.IP:
            if self._vt_key:
                enrs.append(await self._vt_ip(artifact, tid))
            if self._abuse_key:
                enrs.append(await self._abuse_ip(artifact, tid))

        elif artifact.type == ArtifactType.DOMAIN:
            if self._vt_key:
                enrs.append(await self._vt_domain(artifact, tid))

        elif artifact.type == ArtifactType.FILE_HASH:
            if self._vt_key:
                enrs.append(await self._vt_hash(artifact, tid))

        elif artifact.type == ArtifactType.HOSTNAME:
            enrs.append(await self._asset_lookup(artifact, tid))

        elif artifact.type == ArtifactType.USERNAME:
            enrs.append(await self._asset_lookup(artifact, tid))

        # Filter None results
        enrs = [e for e in enrs if e is not None]

        # 3. Persist
        if enrs and self._sb:
            await self._persist(enrs)
            await self._cache(artifact, enrs)

        return enrs

    # ------------------------------------------------------------------
    # VirusTotal
    # ------------------------------------------------------------------

    async def _vt_ip(self, artifact: Artifact, tenant_id: str) -> Enrichment | None:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(
                    f"{VIRUSTOTAL_URL}/ip_addresses/{artifact.value}",
                    headers={"x-apikey": self._vt_key},
                )
            if r.status_code != 200:
                return None
            data = r.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = sum(stats.values()) or 1
            score = int((malicious / total) * 100)
            return Enrichment(
                source=EnrichmentSource.VIRUSTOTAL,
                target_type="artifact",
                target_id=artifact.id,
                tenant_id=tenant_id,
                summary=f"VT: {malicious}/{total} engines flagged {artifact.value}",
                data=stats,
                score=score,
                is_malicious=malicious > 0,
                tags=["virustotal", "ip_reputation"],
                provider="VirusTotal",
                link=f"https://www.virustotal.com/gui/ip-address/{artifact.value}",
            )
        except Exception as exc:
            logger.warning("VT IP lookup failed for %s: %s", artifact.value, exc)
            return None

    async def _vt_domain(self, artifact: Artifact, tenant_id: str) -> Enrichment | None:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(
                    f"{VIRUSTOTAL_URL}/domains/{artifact.value}",
                    headers={"x-apikey": self._vt_key},
                )
            if r.status_code != 200:
                return None
            data = r.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = sum(stats.values()) or 1
            score = int((malicious / total) * 100)
            return Enrichment(
                source=EnrichmentSource.VIRUSTOTAL,
                target_type="artifact",
                target_id=artifact.id,
                tenant_id=tenant_id,
                summary=f"VT: {malicious}/{total} engines flagged {artifact.value}",
                data=stats,
                score=score,
                is_malicious=malicious > 0,
                tags=["virustotal", "domain_reputation"],
                provider="VirusTotal",
                link=f"https://www.virustotal.com/gui/domain/{artifact.value}",
            )
        except Exception as exc:
            logger.warning("VT domain lookup failed for %s: %s", artifact.value, exc)
            return None

    async def _vt_hash(self, artifact: Artifact, tenant_id: str) -> Enrichment | None:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(
                    f"{VIRUSTOTAL_URL}/files/{artifact.value}",
                    headers={"x-apikey": self._vt_key},
                )
            if r.status_code != 200:
                return None
            data = r.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = sum(stats.values()) or 1
            score = int((malicious / total) * 100)
            name = data.get("meaningful_name", artifact.value[:20])
            return Enrichment(
                source=EnrichmentSource.VIRUSTOTAL,
                target_type="artifact",
                target_id=artifact.id,
                tenant_id=tenant_id,
                summary=f"VT: {malicious}/{total} AV engines flagged '{name}'",
                data={
                    "stats": stats,
                    "name": name,
                    "type_description": data.get("type_description", ""),
                    "size": data.get("size"),
                },
                score=score,
                is_malicious=malicious > 0,
                tags=["virustotal", "file_reputation"],
                provider="VirusTotal",
                link=f"https://www.virustotal.com/gui/file/{artifact.value}",
            )
        except Exception as exc:
            logger.warning("VT hash lookup failed for %s: %s", artifact.value, exc)
            return None

    # ------------------------------------------------------------------
    # AbuseIPDB
    # ------------------------------------------------------------------

    async def _abuse_ip(self, artifact: Artifact, tenant_id: str) -> Enrichment | None:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(
                    f"{ABUSEIPDB_URL}/check",
                    headers={"Key": self._abuse_key, "Accept": "application/json"},
                    params={"ipAddress": artifact.value, "maxAgeInDays": 90},
                )
            if r.status_code != 200:
                return None
            d = r.json().get("data", {})
            score = d.get("abuseConfidenceScore", 0)
            return Enrichment(
                source=EnrichmentSource.ABUSEIPDB,
                target_type="artifact",
                target_id=artifact.id,
                tenant_id=tenant_id,
                summary=(
                    f"AbuseIPDB: {score}% confidence — "
                    f"{d.get('totalReports', 0)} reports, "
                    f"country={d.get('countryCode', '?')}, "
                    f"ISP={d.get('isp', '?')}"
                ),
                data=d,
                score=score,
                is_malicious=score >= 25,
                tags=["abuseipdb", "ip_abuse"],
                provider="AbuseIPDB",
                link=f"https://www.abuseipdb.com/check/{artifact.value}",
            )
        except Exception as exc:
            logger.warning("AbuseIPDB lookup failed for %s: %s", artifact.value, exc)
            return None

    # ------------------------------------------------------------------
    # Internal asset lookup (Supabase)
    # ------------------------------------------------------------------

    async def _asset_lookup(self, artifact: Artifact, tenant_id: str) -> Enrichment | None:
        if not self._sb:
            return None
        try:
            field = "name" if artifact.type == ArtifactType.HOSTNAME else "ip_address"
            res = (
                self._sb.table("agents")
                .select("id,name,ip_address,os,type,status,tenant_id")
                .eq(field, artifact.value)
                .eq("tenant_id", tenant_id)
                .limit(1)
                .execute()
            )
            if not res.data:
                return None
            asset = res.data[0]
            return Enrichment(
                source=EnrichmentSource.ASSET_LOOKUP,
                target_type="artifact",
                target_id=artifact.id,
                tenant_id=tenant_id,
                summary=(
                    f"Known internal asset: {asset.get('name')} "
                    f"({asset.get('os', '?')}, {asset.get('type', '?')}, "
                    f"status={asset.get('status', '?')})"
                ),
                data=asset,
                score=0,
                is_malicious=False,
                tags=["internal_asset", "cmdb"],
                provider="Vakros CMDB",
            )
        except Exception as exc:
            logger.warning("Asset lookup failed for %s: %s", artifact.value, exc)
            return None

    # ------------------------------------------------------------------
    # Cache helpers
    # ------------------------------------------------------------------

    async def _check_cache(self, artifact: Artifact) -> list[Enrichment] | None:
        if not self._sb:
            return None
        try:
            res = (
                self._sb.table("ioc_cache")
                .select("result")
                .eq("ioc_type", artifact.type.value)
                .eq("ioc_value", artifact.value)
                .limit(1)
                .execute()
            )
            if res.data:
                # Return cached — don't re-create full Enrichment objects, just return empty
                # (the actual enrichment rows are already in the enrichments table)
                return []
        except Exception:
            pass
        return None

    async def _cache(self, artifact: Artifact, enrichments: list[Enrichment]) -> None:
        if not self._sb or not enrichments:
            return
        summary = enrichments[0].summary if enrichments else ""
        try:
            self._sb.table("ioc_cache").upsert({
                "ioc_type":  artifact.type.value,
                "ioc_value": artifact.value,
                "result":    summary,
                "is_malicious": any(e.is_malicious for e in enrichments if e.is_malicious is not None),
                "score":     max((e.score or 0) for e in enrichments),
            }, on_conflict="ioc_type,ioc_value").execute()
        except Exception as exc:
            logger.warning("Failed to cache enrichment: %s", exc)

    async def _persist(self, enrichments: list[Enrichment]) -> None:
        if not self._sb:
            return
        try:
            self._sb.table("enrichments").insert(
                [e.to_dict() for e in enrichments]
            ).execute()
        except Exception as exc:
            logger.error("Failed to persist enrichments: %s", exc)
