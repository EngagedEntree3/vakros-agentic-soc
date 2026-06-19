"""
Artifact Extractor
Parses alerts to extract atomic IOC objects (IP, domain, hash, hostname, user, URL, email).
Each Artifact becomes an independent object that can be enriched and pivoted across cases.

Inspired by agentic-soc-platform ARCHITECTURE.md:
  "Artifact 是最小原子 — the smallest atom for pivot, threat intel, and asset lookup"
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from uuid import uuid4

logger = logging.getLogger(__name__)


class ArtifactType(str, Enum):
    IP           = "ip"
    DOMAIN       = "domain"
    URL          = "url"
    FILE_HASH    = "file_hash"
    HOSTNAME     = "hostname"
    USERNAME     = "username"
    EMAIL        = "email"
    PROCESS      = "process"
    CLOUD_RESOURCE = "cloud_resource"
    CVE          = "cve"


@dataclass
class Artifact:
    """
    Atomic IOC / observable extracted from an alert.
    Multiple enrichments can be attached to a single Artifact.
    """
    id: str = field(default_factory=lambda: str(uuid4()))
    type: ArtifactType = ArtifactType.IP
    value: str = ""
    alert_id: str = ""
    tenant_id: str = ""
    case_id: str = ""
    tags: list[str] = field(default_factory=list)
    enrichments: list[dict] = field(default_factory=list)
    first_seen_in_alert: str = ""  # alert.created_at
    is_internal: bool = False      # True if matches internal IP range
    tlp: str = "amber"             # TLP marking

    @property
    def dedup_key(self) -> str:
        """Stable key — same artifact value from same tenant = same key (deduplication)."""
        raw = f"{self.tenant_id}:{self.type.value}:{self.value.lower()}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.type.value,
            "value": self.value,
            "alert_id": self.alert_id,
            "tenant_id": self.tenant_id,
            "case_id": self.case_id,
            "tags": self.tags,
            "is_internal": self.is_internal,
            "tlp": self.tlp,
            "dedup_key": self.dedup_key,
        }


# Regex patterns
_RE_IP      = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_DOMAIN  = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE)
_RE_URL     = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_RE_MD5     = re.compile(r"\b[0-9a-fA-F]{32}\b")
_RE_SHA1    = re.compile(r"\b[0-9a-fA-F]{40}\b")
_RE_SHA256  = re.compile(r"\b[0-9a-fA-F]{64}\b")
_RE_EMAIL   = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")
_RE_CVE     = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)

_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]

# Fields to extract from, in priority order
_ALERT_FIELD_MAP: list[tuple[str, ArtifactType]] = [
    ("src_ip",              ArtifactType.IP),
    ("dst_ip",              ArtifactType.IP),
    ("data.srcip",          ArtifactType.IP),
    ("data.dstip",          ArtifactType.IP),
    ("data.win.eventdata.ipAddress", ArtifactType.IP),
    ("agent_name",          ArtifactType.HOSTNAME),
    ("hostname",            ArtifactType.HOSTNAME),
    ("data.win.eventdata.subjectUserName", ArtifactType.USERNAME),
    ("data.dstuser",        ArtifactType.USERNAME),
    ("data.srcuser",        ArtifactType.USERNAME),
    ("data.win.eventdata.sha256", ArtifactType.FILE_HASH),
    ("data.md5",            ArtifactType.FILE_HASH),
    ("data.sha256",         ArtifactType.FILE_HASH),
    ("data.url",            ArtifactType.URL),
    ("data.win.eventdata.destinationHostname", ArtifactType.DOMAIN),
    ("data.win.eventdata.commandLine", None),  # freetext — scan for IOCs
    ("description",         None),             # freetext — scan for IOCs
]


class ArtifactExtractor:
    """
    Extracts Artifact objects from alert dicts.

    Usage:
        extractor = ArtifactExtractor()
        artifacts = extractor.extract(alert)
        # Returns list of Artifact objects, deduplicated by value+type
    """

    def __init__(
        self,
        internal_ranges: list[str] | None = None,
        skip_internal_ips: bool = False,
        supabase_client=None,
    ):
        self._internal = [
            ipaddress.ip_network(r) for r in (internal_ranges or [])
        ] + _PRIVATE_RANGES
        self._skip_internal = skip_internal_ips
        self._sb = supabase_client

    def extract(self, alert: dict[str, Any]) -> list[Artifact]:
        """Extract all artifacts from a single alert dict."""
        seen: set[str] = set()
        artifacts: list[Artifact] = []

        alert_id   = str(alert.get("id") or "")
        tenant_id  = str(alert.get("tenant_id") or "")
        case_id    = str(alert.get("correlated_case_id") or "")
        created_at = str(alert.get("created_at") or "")

        def _add(a_type: ArtifactType, value: str, tags: list[str] | None = None) -> None:
            if not value or len(value) > 512:
                return
            art = Artifact(
                type=a_type,
                value=value.strip(),
                alert_id=alert_id,
                tenant_id=tenant_id,
                case_id=case_id,
                first_seen_in_alert=created_at,
                tags=tags or [],
            )
            if a_type == ArtifactType.IP:
                art.is_internal = self._is_internal(value)
                if self._skip_internal and art.is_internal:
                    return
            key = art.dedup_key
            if key not in seen:
                seen.add(key)
                artifacts.append(art)

        # 1. Extract from known fields
        for field_path, a_type in _ALERT_FIELD_MAP:
            value = _deep_get(alert, field_path)
            if not value:
                continue
            if a_type is not None:
                _add(a_type, str(value))
            else:
                # Freetext field — scan for IOCs
                self._scan_text(str(value), _add)

        # 2. CVEs from rule description
        rule_desc = str(alert.get("rule", {}).get("description", "") or alert.get("description", ""))
        for cve in _RE_CVE.findall(rule_desc):
            _add(ArtifactType.CVE, cve.upper(), tags=["vulnerability"])

        # 3. Process names
        proc = _deep_get(alert, "data.win.eventdata.process") or _deep_get(alert, "data.processName")
        if proc:
            _add(ArtifactType.PROCESS, str(proc))

        # 4. Cloud resource IDs (AWS ARN / Azure resource ID patterns)
        full_text = str(alert)
        for arn in re.findall(r"arn:aws:[a-z0-9\-:/*]+", full_text):
            _add(ArtifactType.CLOUD_RESOURCE, arn, tags=["aws"])

        logger.debug("Extracted %d artifacts from alert %s", len(artifacts), alert_id)
        return artifacts

    def extract_batch(self, alerts: list[dict]) -> list[Artifact]:
        """Extract artifacts from a list of alerts, globally deduplicated."""
        all_arts: list[Artifact] = []
        seen: set[str] = set()
        for alert in alerts:
            for art in self.extract(alert):
                if art.dedup_key not in seen:
                    seen.add(art.dedup_key)
                    all_arts.append(art)
        return all_arts

    async def persist(self, artifacts: list[Artifact]) -> None:
        """Write artifacts to Supabase artifacts table (upsert by dedup_key)."""
        if not self._sb:
            return
        rows = [
            {**a.to_dict(), "id": a.id}
            for a in artifacts
        ]
        try:
            self._sb.table("artifacts").upsert(rows, on_conflict="dedup_key").execute()
        except Exception as exc:
            logger.error("Failed to persist %d artifacts: %s", len(artifacts), exc)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _is_internal(self, ip_str: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip_str)
            return any(addr in net for net in self._internal)
        except ValueError:
            return False

    def _scan_text(self, text: str, add_fn) -> None:
        for ip in _RE_IP.findall(text):
            add_fn(ArtifactType.IP, ip)
        for url in _RE_URL.findall(text):
            add_fn(ArtifactType.URL, url)
        for email in _RE_EMAIL.findall(text):
            add_fn(ArtifactType.EMAIL, email)
        for h in _RE_SHA256.findall(text):
            add_fn(ArtifactType.FILE_HASH, h, ["sha256"])
        for h in _RE_SHA1.findall(text):
            if not _RE_SHA256.match(h):
                add_fn(ArtifactType.FILE_HASH, h, ["sha1"])
        for h in _RE_MD5.findall(text):
            if not _RE_SHA1.match(h) and not _RE_SHA256.match(h):
                add_fn(ArtifactType.FILE_HASH, h, ["md5"])
        for domain in _RE_DOMAIN.findall(text):
            if "." in domain and not _RE_IP.match(domain):
                add_fn(ArtifactType.DOMAIN, domain)


def _deep_get(obj: dict, path: str) -> Any:
    parts = path.split(".")
    cur = obj
    for p in parts:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(p)
    return cur
