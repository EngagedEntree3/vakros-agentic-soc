"""
Abstract base interfaces for SOC integrations.
Pattern from: github.com/M507/ai-soc-agent

All concrete clients implement these ABCs so agents interact
with a stable interface regardless of the underlying vendor.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional
from enum import Enum


class AlertSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(str, Enum):
    NEW = "new"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


@dataclass
class Alert:
    id: str
    title: str
    severity: AlertSeverity
    source: str
    timestamp: datetime
    raw: dict = field(default_factory=dict)
    description: str = ""
    host: str = ""
    ip: str = ""
    user: str = ""
    process: str = ""
    mitre_tactic: str = ""
    mitre_technique: str = ""


@dataclass
class Case:
    id: str
    title: str
    severity: AlertSeverity
    status: str
    created_at: datetime
    description: str = ""
    tags: list[str] = field(default_factory=list)
    observables: list[dict] = field(default_factory=list)
    tasks: list[dict] = field(default_factory=list)
    assignee: str = ""
    tlp: int = 2  # TLP:AMBER default


@dataclass
class HostStatus:
    hostname: str
    ip: str
    os: str
    isolated: bool
    last_seen: datetime
    agent_version: str = ""
    tags: list[str] = field(default_factory=list)


# ─── SIEM Interface ────────────────────────────────────────────────────────────

class SIEMClient(ABC):
    """Abstract SIEM client — Elastic, Splunk, QRadar, etc."""

    @abstractmethod
    async def get_alerts(
        self,
        severity: Optional[AlertSeverity] = None,
        limit: int = 50,
        since_minutes: int = 60,
    ) -> list[Alert]:
        """Fetch recent alerts, optionally filtered by severity."""
        ...

    @abstractmethod
    async def get_alert(self, alert_id: str) -> Alert:
        """Fetch a single alert by ID."""
        ...

    @abstractmethod
    async def search_events(
        self,
        query: str,
        index: str = "*",
        since_minutes: int = 60,
        limit: int = 100,
    ) -> list[dict]:
        """Run a raw search query against event logs."""
        ...

    @abstractmethod
    async def get_timeline(self, host: str, since_minutes: int = 120) -> list[dict]:
        """Get host timeline — process, network, file events."""
        ...

    @abstractmethod
    async def update_alert_status(self, alert_id: str, status: AlertStatus) -> bool:
        """Update an alert's triage status."""
        ...


# ─── EDR Interface ─────────────────────────────────────────────────────────────

class EDRClient(ABC):
    """Abstract EDR client — Wazuh, CrowdStrike, SentinelOne, etc."""

    @abstractmethod
    async def get_host_status(self, host: str) -> HostStatus:
        """Get current status of a host/endpoint."""
        ...

    @abstractmethod
    async def isolate_host(self, host: str, reason: str) -> bool:
        """Network-isolate a host. HIGH-RISK — requires HITL approval."""
        ...

    @abstractmethod
    async def unisolate_host(self, host: str) -> bool:
        """Remove network isolation from a host."""
        ...

    @abstractmethod
    async def kill_process(self, host: str, pid: int, reason: str) -> bool:
        """Terminate a process on a remote host."""
        ...

    @abstractmethod
    async def run_command(self, host: str, command: str) -> dict:
        """Run a live-response command on a host."""
        ...

    @abstractmethod
    async def get_process_tree(self, host: str, pid: int) -> dict:
        """Get process ancestry tree for a given PID."""
        ...

    @abstractmethod
    async def collect_artefact(self, host: str, path: str) -> bytes:
        """Collect a file/artefact from a remote host for forensics."""
        ...


# ─── Case Management Interface ─────────────────────────────────────────────────

class CaseManagementClient(ABC):
    """Abstract case management client — TheHive, IRIS, Jira, ServiceNow."""

    @abstractmethod
    async def create_case(
        self,
        title: str,
        description: str,
        severity: AlertSeverity,
        tags: list[str] | None = None,
    ) -> Case:
        """Create a new incident case."""
        ...

    @abstractmethod
    async def get_case(self, case_id: str) -> Case:
        """Fetch case by ID."""
        ...

    @abstractmethod
    async def update_case(self, case_id: str, updates: dict) -> Case:
        """Update case fields (status, assignee, description, etc.)."""
        ...

    @abstractmethod
    async def add_observable(
        self,
        case_id: str,
        data_type: str,  # ip, domain, hash, url, email, hostname
        value: str,
        tlp: int = 2,
        tags: list[str] | None = None,
    ) -> dict:
        """Add an observable (IOC) to a case."""
        ...

    @abstractmethod
    async def add_task(
        self,
        case_id: str,
        title: str,
        description: str,
        assignee: str = "",
    ) -> dict:
        """Add a task/action item to a case."""
        ...

    @abstractmethod
    async def add_comment(self, case_id: str, comment: str) -> dict:
        """Add a comment/note to a case."""
        ...

    @abstractmethod
    async def list_cases(
        self,
        status: str = "open",
        severity: Optional[AlertSeverity] = None,
        limit: int = 20,
    ) -> list[Case]:
        """List cases, optionally filtered."""
        ...
