"""
Case management implementations — TheHive and IRIS.
Pattern from: github.com/M507/ai-soc-agent TheHive/IRIS integration.
"""

import os
import httpx
from datetime import datetime, timezone
from typing import Optional

from .base import CaseManagementClient, Case, Alert, AlertSeverity


# ─── TheHive ───────────────────────────────────────────────────────────────────

class TheHiveClient(CaseManagementClient):
    """TheHive 5 case management client."""

    SEV_MAP = {
        AlertSeverity.INFO:     1,
        AlertSeverity.LOW:      1,
        AlertSeverity.MEDIUM:   2,
        AlertSeverity.HIGH:     3,
        AlertSeverity.CRITICAL: 4,
    }
    REV_SEV = {v: k for k, v in SEV_MAP.items()}

    def __init__(self, host: str | None = None, api_key: str | None = None):
        self.host = (host or os.getenv("THEHIVE_HOST", "http://localhost:9000")).rstrip("/")
        self.api_key = api_key or os.getenv("THEHIVE_API_KEY", "")
        self._headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    def _parse_case(self, data: dict) -> Case:
        sev_int = data.get("severity", 2)
        return Case(
            id=data.get("_id", data.get("id", "")),
            title=data.get("title", ""),
            severity=self.REV_SEV.get(sev_int, AlertSeverity.MEDIUM),
            status=data.get("status", "open"),
            created_at=datetime.fromtimestamp(data.get("createdAt", 0) / 1000, tz=timezone.utc),
            description=data.get("description", ""),
            tags=data.get("tags", []),
            assignee=data.get("assignee", ""),
            tlp=data.get("tlp", 2),
        )

    async def create_case(
        self,
        title: str,
        description: str,
        severity: AlertSeverity,
        tags: list[str] | None = None,
    ) -> Case:
        body = {
            "title": title,
            "description": description,
            "severity": self.SEV_MAP.get(severity, 2),
            "tags": tags or [],
            "tlp": 2,
            "flag": False,
        }
        async with httpx.AsyncClient() as client:
            r = await client.post(
                f"{self.host}/api/case",
                headers=self._headers,
                json=body,
                timeout=15,
            )
            r.raise_for_status()
            return self._parse_case(r.json())

    async def get_case(self, case_id: str) -> Case:
        async with httpx.AsyncClient() as client:
            r = await client.get(f"{self.host}/api/case/{case_id}", headers=self._headers, timeout=10)
            r.raise_for_status()
            return self._parse_case(r.json())

    async def update_case(self, case_id: str, updates: dict) -> Case:
        async with httpx.AsyncClient() as client:
            r = await client.patch(
                f"{self.host}/api/case/{case_id}",
                headers=self._headers,
                json=updates,
                timeout=10,
            )
            r.raise_for_status()
            return self._parse_case(r.json())

    async def add_observable(
        self,
        case_id: str,
        data_type: str,
        value: str,
        tlp: int = 2,
        tags: list[str] | None = None,
    ) -> dict:
        body = {
            "dataType": data_type,
            "data": value,
            "tlp": tlp,
            "tags": tags or [],
            "ioc": True,
        }
        async with httpx.AsyncClient() as client:
            r = await client.post(
                f"{self.host}/api/case/{case_id}/artifact",
                headers=self._headers,
                json=body,
                timeout=10,
            )
            r.raise_for_status()
            return r.json()

    async def add_task(
        self,
        case_id: str,
        title: str,
        description: str,
        assignee: str = "",
    ) -> dict:
        body = {"title": title, "description": description, "status": "Waiting"}
        if assignee:
            body["owner"] = assignee
        async with httpx.AsyncClient() as client:
            r = await client.post(
                f"{self.host}/api/case/{case_id}/task",
                headers=self._headers,
                json=body,
                timeout=10,
            )
            r.raise_for_status()
            return r.json()

    async def add_comment(self, case_id: str, comment: str) -> dict:
        async with httpx.AsyncClient() as client:
            r = await client.post(
                f"{self.host}/api/case/{case_id}/log",
                headers=self._headers,
                json={"message": comment},
                timeout=10,
            )
            r.raise_for_status()
            return r.json()

    async def list_cases(
        self,
        status: str = "open",
        severity: Optional[AlertSeverity] = None,
        limit: int = 20,
    ) -> list[Case]:
        query = [{"_field": "status", "_value": status.capitalize()}]
        if severity:
            query.append({"_field": "severity", "_value": self.SEV_MAP.get(severity, 2)})
        body = {
            "query": {"_and": query},
            "range": f"0-{limit}",
            "sort": ["-createdAt"],
        }
        async with httpx.AsyncClient() as client:
            r = await client.post(
                f"{self.host}/api/case/_search",
                headers=self._headers,
                json=body,
                timeout=15,
            )
            r.raise_for_status()
            return [self._parse_case(c) for c in r.json()]


# ─── IRIS ──────────────────────────────────────────────────────────────────────

class IRISClient(CaseManagementClient):
    """IRIS (dfir-iris) case management client — alternative to TheHive."""

    SEV_MAP = {
        AlertSeverity.INFO:     1,
        AlertSeverity.LOW:      2,
        AlertSeverity.MEDIUM:   3,
        AlertSeverity.HIGH:     4,
        AlertSeverity.CRITICAL: 5,
    }

    def __init__(self, host: str | None = None, api_key: str | None = None):
        self.host = (host or os.getenv("IRIS_HOST", "http://localhost:8080")).rstrip("/")
        self.api_key = api_key or os.getenv("IRIS_API_KEY", "")
        self._headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    def _parse_case(self, data: dict) -> Case:
        d = data.get("data", data)
        return Case(
            id=str(d.get("case_id", "")),
            title=d.get("case_name", ""),
            severity=AlertSeverity.MEDIUM,
            status=d.get("case_state", {}).get("case_state_name", "open"),
            created_at=datetime.fromisoformat(d.get("open_date", "2024-01-01").replace("Z", "+00:00")),
            description=d.get("case_description", ""),
            tags=[],
        )

    async def create_case(
        self,
        title: str,
        description: str,
        severity: AlertSeverity,
        tags: list[str] | None = None,
    ) -> Case:
        body = {
            "case_name": title,
            "case_description": description,
            "case_customer": 1,
            "case_soc_id": "",
            "case_template_id": 0,
        }
        async with httpx.AsyncClient() as client:
            r = await client.post(
                f"{self.host}/api/v2/cases",
                headers=self._headers,
                json=body,
                timeout=15,
            )
            r.raise_for_status()
            return self._parse_case(r.json())

    async def get_case(self, case_id: str) -> Case:
        async with httpx.AsyncClient() as client:
            r = await client.get(f"{self.host}/api/v2/cases/{case_id}", headers=self._headers, timeout=10)
            r.raise_for_status()
            return self._parse_case(r.json())

    async def update_case(self, case_id: str, updates: dict) -> Case:
        async with httpx.AsyncClient() as client:
            r = await client.patch(
                f"{self.host}/api/v2/cases/{case_id}",
                headers=self._headers,
                json=updates,
                timeout=10,
            )
            r.raise_for_status()
            return self._parse_case(r.json())

    async def add_observable(self, case_id: str, data_type: str, value: str, tlp: int = 2, tags: list[str] | None = None) -> dict:
        body = {"ioc_value": value, "ioc_type_id": 1, "ioc_description": f"{data_type}: {value}", "ioc_tlp_id": tlp}
        async with httpx.AsyncClient() as client:
            r = await client.post(f"{self.host}/api/v2/cases/{case_id}/iocs", headers=self._headers, json=body, timeout=10)
            r.raise_for_status()
            return r.json()

    async def add_task(self, case_id: str, title: str, description: str, assignee: str = "") -> dict:
        body = {"task_title": title, "task_description": description, "task_status_id": 1, "task_assignees_id": []}
        async with httpx.AsyncClient() as client:
            r = await client.post(f"{self.host}/api/v2/cases/{case_id}/tasks", headers=self._headers, json=body, timeout=10)
            r.raise_for_status()
            return r.json()

    async def add_comment(self, case_id: str, comment: str) -> dict:
        body = {"comment_text": comment}
        async with httpx.AsyncClient() as client:
            r = await client.post(f"{self.host}/api/v2/cases/{case_id}/comments", headers=self._headers, json=body, timeout=10)
            r.raise_for_status()
            return r.json()

    async def list_cases(self, status: str = "open", severity: Optional[AlertSeverity] = None, limit: int = 20) -> list[Case]:
        async with httpx.AsyncClient() as client:
            r = await client.get(f"{self.host}/api/v2/cases", headers=self._headers, params={"page": 1, "per_page": limit}, timeout=15)
            r.raise_for_status()
            items = r.json().get("data", {}).get("cases", [])
            return [self._parse_case({"data": i}) for i in items]
