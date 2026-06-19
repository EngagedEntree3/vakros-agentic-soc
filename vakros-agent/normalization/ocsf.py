"""
OCSF (Open Cybersecurity Schema Framework) Normalization
Inspired by agentic-soc-platform v0.2.0 "OCSF and BaseModel" release.

Maps raw alerts from:
  - Wazuh
  - Elastic Security (ECS)
  - Splunk
  - Generic webhook

→ OCSF 1.x standardized format

Key OCSF concepts used:
  class_uid    — alert class (4001=Detection Finding, 4002=Vulnerability Finding, etc.)
  category_uid — alert category (4=Findings)
  severity_id  — 1(Info) 2(Low) 3(Medium) 4(High) 5(Critical)
  status_id    — 1(New) 2(In Progress) 3(Suppressed) 4(Resolved)
  activity_id  — what happened (1=Detected, 2=Updated, etc.)
  metadata     — version, product, profiles
  observables  — extracted IOC objects (maps to our Artifact layer)
  finding_info — rule name, uid, title, types
  actor        — who/what triggered the alert
  target       — what was affected
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# OCSF Enums (subset relevant to SOC alerts)
# ------------------------------------------------------------------

class OCSFCategory(IntEnum):
    FINDINGS = 4
    NETWORK  = 4
    IAM      = 3
    SYSTEM   = 1


class OCSFClassUID(IntEnum):
    DETECTION_FINDING    = 4001
    VULNERABILITY_FINDING = 4002
    COMPLIANCE_FINDING   = 4003
    NETWORK_ACTIVITY     = 4004
    DNS_ACTIVITY         = 4006
    AUTH_ACTIVITY        = 3002
    PROCESS_ACTIVITY     = 1007
    FILE_ACTIVITY        = 1001


class OCSFSeverity(IntEnum):
    UNKNOWN  = 0
    INFO     = 1
    LOW      = 2
    MEDIUM   = 3
    HIGH     = 4
    CRITICAL = 5
    FATAL    = 6

    @classmethod
    def from_string(cls, sev: str) -> "OCSFSeverity":
        return {
            "info":      cls.INFO,
            "low":       cls.LOW,
            "medium":    cls.MEDIUM,
            "high":      cls.HIGH,
            "critical":  cls.CRITICAL,
            "fatal":     cls.FATAL,
        }.get(sev.lower(), cls.UNKNOWN)

    @classmethod
    def from_wazuh_level(cls, level: int) -> "OCSFSeverity":
        if level <= 3:   return cls.INFO
        if level <= 6:   return cls.LOW
        if level <= 10:  return cls.MEDIUM
        if level <= 13:  return cls.HIGH
        return cls.CRITICAL


class OCSFStatus(IntEnum):
    NEW         = 1
    IN_PROGRESS = 2
    SUPPRESSED  = 3
    RESOLVED    = 4

    @classmethod
    def from_string(cls, status: str) -> "OCSFStatus":
        return {
            "new":          cls.NEW,
            "open":         cls.NEW,
            "in_progress":  cls.IN_PROGRESS,
            "suppressed":   cls.SUPPRESSED,
            "closed":       cls.RESOLVED,
            "resolved":     cls.RESOLVED,
        }.get(status.lower(), cls.NEW)


# ------------------------------------------------------------------
# OCSF Alert dataclass
# ------------------------------------------------------------------

@dataclass
class OCSFAlert:
    """
    OCSF 1.x Detection Finding (class_uid=4001).
    Covers all inbound alerts after normalization.
    """
    # Core OCSF fields
    class_uid:    int = OCSFClassUID.DETECTION_FINDING
    class_name:   str = "Detection Finding"
    category_uid: int = OCSFCategory.FINDINGS
    category_name: str = "Findings"
    activity_id:  int = 1        # 1=Detected
    activity_name: str = "Detected"
    severity_id:  int = OCSFSeverity.UNKNOWN
    severity:     str = "Unknown"
    status_id:    int = OCSFStatus.NEW
    status:       str = "New"
    time:         int = 0        # Unix epoch ms
    start_time:   int = 0

    # Finding Info
    finding_info: dict = field(default_factory=dict)
    # {
    #   "uid": rule_id,
    #   "title": rule_description,
    #   "types": ["Security Rule"],
    #   "created_time": ...,
    # }

    # Metadata
    metadata: dict = field(default_factory=dict)
    # {
    #   "version": "1.1.0",
    #   "product": { "name": "Wazuh", "vendor_name": "Wazuh Inc." },
    #   "profiles": ["security_control"],
    # }

    # Actor (who/what triggered)
    actor: dict = field(default_factory=dict)
    # { "user": {"name": "...", "type_id": 1}, "process": {...} }

    # Target (what was affected)
    resources: list[dict] = field(default_factory=list)
    # [{ "type": "Host", "name": "WIN-DC01", "uid": "agent_id" }]

    # Observables (IOCs — maps to our Artifact layer)
    observables: list[dict] = field(default_factory=list)
    # [{ "type_id": 2, "type": "IP Address", "name": "src_ip", "value": "1.2.3.4" }]

    # MITRE ATT&CK
    attacks: list[dict] = field(default_factory=list)
    # [{ "technique": { "uid": "T1078", "name": "Valid Accounts" }, "tactic": {...} }]

    # Raw data preserved
    raw_data: dict = field(default_factory=dict)

    # Vakros-specific extensions (not OCSF standard)
    vakros_tenant_id: str = ""
    vakros_alert_id:  str = ""
    vakros_source:    str = ""   # "wazuh" | "elastic" | "splunk" | "generic"

    def to_dict(self) -> dict:
        return {
            "class_uid":    self.class_uid,
            "class_name":   self.class_name,
            "category_uid": self.category_uid,
            "severity_id":  self.severity_id,
            "severity":     self.severity,
            "status_id":    self.status_id,
            "status":       self.status,
            "time":         self.time,
            "finding_info": self.finding_info,
            "metadata":     self.metadata,
            "actor":        self.actor,
            "resources":    self.resources,
            "observables":  self.observables,
            "attacks":      self.attacks,
            "unmapped":     self.raw_data,
            "_vakros": {
                "tenant_id": self.vakros_tenant_id,
                "alert_id":  self.vakros_alert_id,
                "source":    self.vakros_source,
            },
        }


# ------------------------------------------------------------------
# Observable type IDs (OCSF 1.1)
# ------------------------------------------------------------------
_OBSERVABLE_TYPES = {
    "ip":        (2,  "IP Address"),
    "domain":    (4,  "Domain"),
    "url":       (6,  "URL"),
    "hash":      (7,  "File Hash"),
    "hostname":  (1,  "Hostname"),
    "username":  (9,  "User Name"),
    "email":     (10, "Email Address"),
    "process":   (8,  "Process Name"),
}


# ------------------------------------------------------------------
# Normalizer
# ------------------------------------------------------------------

class OCSFNormalizer:
    """
    Normalizes vendor-specific alert dicts to OCSF 1.x OCSFAlert objects.

    Supported sources:
      - Wazuh (rule.level, rule.id, rule.description, data.*)
      - Elastic Security (kibana.alert.*, signal.*)
      - Splunk (result.*, search_name)
      - Generic Vakros alerts (our own DB schema)
    """

    def normalize(self, alert: dict[str, Any], source: str = "auto") -> OCSFAlert:
        """Detect source and normalize."""
        if source == "auto":
            source = self._detect_source(alert)

        if source == "wazuh":
            return self._from_wazuh(alert)
        elif source == "elastic":
            return self._from_elastic(alert)
        elif source == "splunk":
            return self._from_splunk(alert)
        else:
            return self._from_generic(alert)

    def normalize_batch(
        self,
        alerts: list[dict],
        source: str = "auto",
    ) -> list[OCSFAlert]:
        return [self.normalize(a, source) for a in alerts]

    # ------------------------------------------------------------------
    # Source detection
    # ------------------------------------------------------------------

    def _detect_source(self, alert: dict) -> str:
        if "rule" in alert and "level" in alert.get("rule", {}):
            return "wazuh"
        if "kibana.alert.rule.uuid" in str(alert) or "signal" in alert:
            return "elastic"
        if "search_name" in alert and "result" in alert:
            return "splunk"
        return "generic"

    # ------------------------------------------------------------------
    # Wazuh normalizer
    # ------------------------------------------------------------------

    def _from_wazuh(self, alert: dict) -> OCSFAlert:
        rule = alert.get("rule", {})
        level = int(rule.get("level", 0))
        severity_id = OCSFSeverity.from_wazuh_level(level)

        ts = _parse_epoch(alert.get("timestamp") or alert.get("created_at"))

        agent = alert.get("agent", {})
        src_ip = (
            alert.get("src_ip")
            or alert.get("data", {}).get("srcip")
            or alert.get("data", {}).get("src_ip")
        )
        dst_user = alert.get("data", {}).get("dstuser")
        src_user = alert.get("data", {}).get("srcuser")

        mitre = rule.get("mitre", {})
        attacks = []
        for technique_id, technique_name in zip(
            mitre.get("id", []), mitre.get("technique", [])
        ):
            attacks.append({
                "technique": {"uid": technique_id, "name": technique_name},
                "tactic": {"name": mitre.get("tactic", [""])[0] if mitre.get("tactic") else ""},
            })

        observables = []
        if src_ip:
            observables.append({"type_id": 2, "type": "IP Address", "name": "src_ip", "value": src_ip})
        if dst_user or src_user:
            observables.append({
                "type_id": 9, "type": "User Name",
                "name": "user", "value": dst_user or src_user,
            })
        hostname = agent.get("name") or alert.get("agent_name")
        if hostname:
            observables.append({"type_id": 1, "type": "Hostname", "name": "agent", "value": hostname})

        return OCSFAlert(
            class_uid=_detect_class(rule.get("groups", [])),
            severity_id=severity_id.value,
            severity=severity_id.name.title(),
            status_id=OCSFStatus.from_string(alert.get("status", "new")).value,
            status=alert.get("status", "New").title(),
            time=ts,
            start_time=ts,
            finding_info={
                "uid":   str(rule.get("id", "")),
                "title": rule.get("description", ""),
                "types": rule.get("groups", ["Security Rule"]),
            },
            metadata={
                "version": "1.1.0",
                "product": {"name": "Wazuh", "vendor_name": "Wazuh Inc."},
                "profiles": ["security_control"],
                "original_time": alert.get("timestamp", ""),
            },
            actor={
                "process": {"name": alert.get("data", {}).get("processName", "")},
                "user": {"name": src_user or ""},
            },
            resources=[{
                "type": "Host",
                "name": hostname or "",
                "uid": str(agent.get("id", "")),
            }],
            observables=observables,
            attacks=attacks,
            raw_data=alert,
            vakros_tenant_id=str(alert.get("tenant_id", "")),
            vakros_alert_id=str(alert.get("id", "")),
            vakros_source="wazuh",
        )

    # ------------------------------------------------------------------
    # Elastic Security normalizer
    # ------------------------------------------------------------------

    def _from_elastic(self, alert: dict) -> OCSFAlert:
        signal = alert.get("signal", {}) or alert.get("kibana.alert", {})
        rule = signal.get("rule", {}) or alert.get("kibana.alert.rule", {})
        severity_str = (
            alert.get("kibana.alert.severity")
            or signal.get("severity", "unknown")
        )
        severity_id = OCSFSeverity.from_string(str(severity_str))
        ts = _parse_epoch(alert.get("@timestamp") or alert.get("created_at"))

        src_ip = _ecs_get(alert, "source.ip") or _ecs_get(alert, "destination.ip")
        user   = _ecs_get(alert, "user.name")
        host   = _ecs_get(alert, "host.name")

        observables = []
        if src_ip:
            observables.append({"type_id": 2, "type": "IP Address", "name": "src_ip", "value": src_ip})
        if user:
            observables.append({"type_id": 9, "type": "User Name", "name": "user", "value": user})
        if host:
            observables.append({"type_id": 1, "type": "Hostname", "name": "host", "value": host})

        return OCSFAlert(
            class_uid=OCSFClassUID.DETECTION_FINDING,
            severity_id=severity_id.value,
            severity=severity_id.name.title(),
            time=ts,
            finding_info={
                "uid":   str(rule.get("id", "")),
                "title": rule.get("name", ""),
                "types": rule.get("type", ["query"]) if isinstance(rule.get("type"), list)
                         else [rule.get("type", "query")],
            },
            metadata={
                "version": "1.1.0",
                "product": {"name": "Elastic Security", "vendor_name": "Elastic"},
                "profiles": ["security_control"],
            },
            resources=[{"type": "Host", "name": host or ""}],
            observables=observables,
            raw_data=alert,
            vakros_tenant_id=str(alert.get("tenant_id", "")),
            vakros_alert_id=str(alert.get("id", "")),
            vakros_source="elastic",
        )

    # ------------------------------------------------------------------
    # Splunk normalizer
    # ------------------------------------------------------------------

    def _from_splunk(self, alert: dict) -> OCSFAlert:
        result = alert.get("result", alert)
        severity_str = result.get("urgency") or result.get("severity", "unknown")
        severity_id = OCSFSeverity.from_string(str(severity_str))
        ts = _parse_epoch(result.get("_time") or alert.get("created_at"))

        return OCSFAlert(
            class_uid=OCSFClassUID.DETECTION_FINDING,
            severity_id=severity_id.value,
            severity=severity_id.name.title(),
            time=ts,
            finding_info={
                "uid":   alert.get("search_name", ""),
                "title": alert.get("search_name", ""),
                "types": ["Correlation Rule"],
            },
            metadata={
                "version": "1.1.0",
                "product": {"name": "Splunk", "vendor_name": "Splunk Inc."},
                "profiles": ["security_control"],
            },
            observables=[],
            raw_data=alert,
            vakros_tenant_id=str(alert.get("tenant_id", "")),
            vakros_alert_id=str(alert.get("id", "")),
            vakros_source="splunk",
        )

    # ------------------------------------------------------------------
    # Generic Vakros DB alert normalizer
    # ------------------------------------------------------------------

    def _from_generic(self, alert: dict) -> OCSFAlert:
        severity_id = OCSFSeverity.from_string(str(alert.get("severity", "unknown")))
        ts = _parse_epoch(alert.get("created_at") or alert.get("timestamp"))

        src_ip = alert.get("src_ip")
        hostname = alert.get("agent_name") or alert.get("hostname")

        observables = []
        if src_ip:
            observables.append({"type_id": 2, "type": "IP Address", "name": "src_ip", "value": src_ip})
        if hostname:
            observables.append({"type_id": 1, "type": "Hostname", "name": "host", "value": hostname})

        return OCSFAlert(
            class_uid=OCSFClassUID.DETECTION_FINDING,
            severity_id=severity_id.value,
            severity=severity_id.name.title(),
            status_id=OCSFStatus.from_string(alert.get("status", "new")).value,
            time=ts,
            finding_info={
                "uid":   str(alert.get("rule_id", "")),
                "title": alert.get("description", alert.get("title", "")),
                "types": ["Security Rule"],
            },
            metadata={
                "version": "1.1.0",
                "product": {"name": "Vakros SOC", "vendor_name": "Vakros"},
                "profiles": ["security_control"],
            },
            resources=[{"type": "Host", "name": hostname or ""}],
            observables=observables,
            raw_data=alert,
            vakros_tenant_id=str(alert.get("tenant_id", "")),
            vakros_alert_id=str(alert.get("id", "")),
            vakros_source="generic",
        )


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _parse_epoch(ts: Any) -> int:
    if not ts:
        return int(datetime.now(timezone.utc).timestamp() * 1000)
    if isinstance(ts, (int, float)):
        return int(ts) if ts > 1e10 else int(ts * 1000)
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        return int(dt.timestamp() * 1000)
    except (ValueError, AttributeError):
        return int(datetime.now(timezone.utc).timestamp() * 1000)


def _ecs_get(alert: dict, path: str) -> Any:
    """Get a dotted ECS path from alert dict."""
    parts = path.split(".")
    cur = alert
    for p in parts:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(p)
    return cur


def _detect_class(rule_groups: list[str]) -> int:
    """Infer OCSF class_uid from Wazuh rule groups."""
    groups_lower = [g.lower() for g in rule_groups]
    if any(g in groups_lower for g in ["vulnerability", "cve"]):
        return OCSFClassUID.VULNERABILITY_FINDING
    if any(g in groups_lower for g in ["compliance", "gdpr", "hipaa", "pci"]):
        return OCSFClassUID.COMPLIANCE_FINDING
    if any(g in groups_lower for g in ["authentication", "pam", "sshd"]):
        return OCSFClassUID.AUTH_ACTIVITY
    if any(g in groups_lower for g in ["process", "execve"]):
        return OCSFClassUID.PROCESS_ACTIVITY
    if any(g in groups_lower for g in ["file", "syscheck"]):
        return OCSFClassUID.FILE_ACTIVITY
    return OCSFClassUID.DETECTION_FINDING
