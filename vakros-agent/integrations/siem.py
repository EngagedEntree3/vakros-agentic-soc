"""
Concrete SIEM implementations — Elastic and Wazuh.
Pattern from: github.com/M507/ai-soc-agent Elastic integration.
"""

import os
import httpx
from datetime import datetime, timezone, timedelta
from typing import Optional

from .base import SIEMClient, Alert, AlertSeverity, AlertStatus


class ElasticSIEMClient(SIEMClient):
    """Elasticsearch / Elastic Security SIEM client."""

    def __init__(
        self,
        host: str | None = None,
        api_key: str | None = None,
        index_pattern: str = "logs-*,filebeat-*,winlogbeat-*",
    ):
        self.host = host or os.getenv("ELASTIC_HOST", "http://localhost:9200")
        self.api_key = api_key or os.getenv("ELASTIC_API_KEY", "")
        self.index_pattern = index_pattern
        self._headers = {
            "Authorization": f"ApiKey {self.api_key}",
            "Content-Type": "application/json",
        }

    def _since_iso(self, minutes: int) -> str:
        return (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()

    def _parse_alert(self, hit: dict) -> Alert:
        src = hit.get("_source", {})
        signal = src.get("signal", src)
        rule = signal.get("rule", {})
        sev_str = (signal.get("severity") or src.get("event", {}).get("severity", "medium")).lower()
        sev_map = {"critical": AlertSeverity.CRITICAL, "high": AlertSeverity.HIGH,
                   "medium": AlertSeverity.MEDIUM, "low": AlertSeverity.LOW}
        return Alert(
            id=hit["_id"],
            title=rule.get("name") or src.get("message", "Unknown Alert"),
            severity=sev_map.get(sev_str, AlertSeverity.MEDIUM),
            source="elastic",
            timestamp=datetime.fromisoformat(src.get("@timestamp", datetime.now(timezone.utc).isoformat()).rstrip("Z")),
            raw=src,
            description=rule.get("description", ""),
            host=src.get("host", {}).get("name", ""),
            ip=src.get("source", {}).get("ip", ""),
            user=src.get("user", {}).get("name", ""),
            process=src.get("process", {}).get("name", ""),
            mitre_tactic=str(rule.get("threat", [{}])[0].get("tactic", {}).get("name", "") if rule.get("threat") else ""),
            mitre_technique=str(rule.get("threat", [{}])[0].get("technique", [{}])[0].get("id", "") if rule.get("threat") else ""),
        )

    async def get_alerts(
        self,
        severity: Optional[AlertSeverity] = None,
        limit: int = 50,
        since_minutes: int = 60,
    ) -> list[Alert]:
        query: dict = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": self._since_iso(since_minutes)}}},
                        {"term": {"signal.status": "open"}},
                    ]
                }
            },
            "size": limit,
            "sort": [{"@timestamp": "desc"}],
        }
        if severity:
            query["query"]["bool"]["must"].append(
                {"term": {"signal.severity": severity.value}}
            )
        async with httpx.AsyncClient() as client:
            r = await client.post(
                f"{self.host}/.siem-signals-*/_search",
                headers=self._headers,
                json=query,
                timeout=15,
            )
            r.raise_for_status()
            hits = r.json().get("hits", {}).get("hits", [])
            return [self._parse_alert(h) for h in hits]

    async def get_alert(self, alert_id: str) -> Alert:
        async with httpx.AsyncClient() as client:
            r = await client.get(
                f"{self.host}/.siem-signals-*/_doc/{alert_id}",
                headers=self._headers,
                timeout=10,
            )
            r.raise_for_status()
            return self._parse_alert(r.json())

    async def search_events(
        self,
        query: str,
        index: str = "*",
        since_minutes: int = 60,
        limit: int = 100,
    ) -> list[dict]:
        body = {
            "query": {
                "bool": {
                    "must": [
                        {"query_string": {"query": query}},
                        {"range": {"@timestamp": {"gte": self._since_iso(since_minutes)}}},
                    ]
                }
            },
            "size": limit,
            "sort": [{"@timestamp": "desc"}],
        }
        async with httpx.AsyncClient() as client:
            r = await client.post(
                f"{self.host}/{index}/_search",
                headers=self._headers,
                json=body,
                timeout=20,
            )
            r.raise_for_status()
            return [h["_source"] for h in r.json().get("hits", {}).get("hits", [])]

    async def get_timeline(self, host: str, since_minutes: int = 120) -> list[dict]:
        return await self.search_events(
            query=f'host.name:"{host}"',
            since_minutes=since_minutes,
            limit=200,
        )

    async def update_alert_status(self, alert_id: str, status: AlertStatus) -> bool:
        body = {"doc": {"signal": {"status": status.value}}}
        async with httpx.AsyncClient() as client:
            r = await client.post(
                f"{self.host}/.siem-signals-*/_update/{alert_id}",
                headers=self._headers,
                json=body,
                timeout=10,
            )
            return r.is_success


class WazuhSIEMClient(SIEMClient):
    """Wazuh SIEM client — uses Wazuh API for alert retrieval."""

    def __init__(
        self,
        host: str | None = None,
        username: str | None = None,
        password: str | None = None,
    ):
        self.host = host or os.getenv("WAZUH_HOST", "https://localhost:55000")
        self.username = username or os.getenv("WAZUH_USER", "wazuh")
        self.password = password or os.getenv("WAZUH_PASSWORD", "")
        self._token: str | None = None

    async def _authenticate(self) -> str:
        async with httpx.AsyncClient(verify=False) as client:
            r = await client.post(
                f"{self.host}/security/user/authenticate",
                auth=(self.username, self.password),
                timeout=10,
            )
            r.raise_for_status()
            self._token = r.json()["data"]["token"]
            return self._token

    async def _headers(self) -> dict:
        token = self._token or await self._authenticate()
        return {"Authorization": f"Bearer {token}"}

    def _sev_from_level(self, level: int) -> AlertSeverity:
        if level >= 14: return AlertSeverity.CRITICAL
        if level >= 10: return AlertSeverity.HIGH
        if level >= 7:  return AlertSeverity.MEDIUM
        return AlertSeverity.LOW

    async def get_alerts(
        self,
        severity: Optional[AlertSeverity] = None,
        limit: int = 50,
        since_minutes: int = 60,
    ) -> list[Alert]:
        headers = await self._headers()
        params = {"limit": limit, "sort": "-timestamp"}
        async with httpx.AsyncClient(verify=False) as client:
            r = await client.get(
                f"{self.host}/alerts",
                headers=headers,
                params=params,
                timeout=15,
            )
            r.raise_for_status()
            items = r.json().get("data", {}).get("affected_items", [])
            alerts = []
            for item in items:
                rule = item.get("rule", {})
                sev = self._sev_from_level(rule.get("level", 5))
                if severity and sev != severity:
                    continue
                alerts.append(Alert(
                    id=item.get("id", ""),
                    title=rule.get("description", "Wazuh Alert"),
                    severity=sev,
                    source="wazuh",
                    timestamp=datetime.fromisoformat(item.get("timestamp", "").replace("Z", "+00:00")),
                    raw=item,
                    host=item.get("agent", {}).get("name", ""),
                    mitre_tactic=rule.get("mitre", {}).get("tactic", [""])[0] if rule.get("mitre") else "",
                    mitre_technique=rule.get("mitre", {}).get("id", [""])[0] if rule.get("mitre") else "",
                ))
            return alerts

    async def get_alert(self, alert_id: str) -> Alert:
        alerts = await self.get_alerts(limit=1)
        for a in alerts:
            if a.id == alert_id:
                return a
        raise ValueError(f"Alert {alert_id} not found")

    async def search_events(self, query: str, index: str = "*", since_minutes: int = 60, limit: int = 100) -> list[dict]:
        headers = await self._headers()
        async with httpx.AsyncClient(verify=False) as client:
            r = await client.get(
                f"{self.host}/alerts",
                headers=headers,
                params={"q": query, "limit": limit},
                timeout=20,
            )
            r.raise_for_status()
            return r.json().get("data", {}).get("affected_items", [])

    async def get_timeline(self, host: str, since_minutes: int = 120) -> list[dict]:
        return await self.search_events(f"agent.name={host}", since_minutes=since_minutes, limit=200)

    async def update_alert_status(self, alert_id: str, status: AlertStatus) -> bool:
        # Wazuh uses acknowledgement
        headers = await self._headers()
        async with httpx.AsyncClient(verify=False) as client:
            r = await client.put(
                f"{self.host}/alerts/{alert_id}",
                headers=headers,
                json={"status": status.value},
                timeout=10,
            )
            return r.is_success
