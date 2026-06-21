"""
EDR implementations — Wazuh active response and CrowdStrike.
"""

import os
import httpx
from datetime import datetime, timezone
from .base import EDRClient, HostStatus


class WazuhEDRClient(EDRClient):
    """Wazuh active response + agent API as EDR."""

    def __init__(self, host: str | None = None, username: str | None = None, password: str | None = None):
        self.host = (host or os.getenv("WAZUH_HOST", "https://localhost:55000")).rstrip("/")
        self.username = username or os.getenv("WAZUH_USER", "wazuh")
        self.password = password or os.getenv("WAZUH_PASSWORD", "")
        self._token: str | None = None

    async def _auth_headers(self) -> dict:
        if not self._token:
            async with httpx.AsyncClient(verify=False) as client:
                r = await client.post(
                    f"{self.host}/security/user/authenticate",
                    auth=(self.username, self.password),
                    timeout=10,
                )
                r.raise_for_status()
                self._token = r.json()["data"]["token"]
        return {"Authorization": f"Bearer {self._token}"}

    async def _get_agent_id(self, host: str) -> str:
        headers = await self._auth_headers()
        async with httpx.AsyncClient(verify=False) as client:
            r = await client.get(
                f"{self.host}/agents",
                headers=headers,
                params={"name": host},
                timeout=10,
            )
            r.raise_for_status()
            items = r.json().get("data", {}).get("affected_items", [])
            if not items:
                raise ValueError(f"Agent not found for host: {host}")
            return items[0]["id"]

    async def get_host_status(self, host: str) -> HostStatus:
        headers = await self._auth_headers()
        agent_id = await self._get_agent_id(host)
        async with httpx.AsyncClient(verify=False) as client:
            r = await client.get(
                f"{self.host}/agents/{agent_id}",
                headers=headers,
                timeout=10,
            )
            r.raise_for_status()
            d = r.json()["data"]["affected_items"][0]
            return HostStatus(
                hostname=d.get("name", host),
                ip=d.get("ip", ""),
                os=d.get("os", {}).get("platform", "unknown"),
                isolated="isolated" in d.get("group", []),
                last_seen=datetime.fromisoformat(d.get("lastKeepAlive", "2024-01-01").replace("Z", "+00:00")),
                agent_version=d.get("version", ""),
            )

    async def isolate_host(self, host: str, reason: str) -> bool:
        """Trigger Wazuh active response to isolate host network."""
        headers = await self._auth_headers()
        agent_id = await self._get_agent_id(host)
        body = {"command": "!disable-firewall", "arguments": [], "alert": {"data": {"reason": reason}}}
        async with httpx.AsyncClient(verify=False) as client:
            r = await client.put(
                f"{self.host}/active-response",
                headers=headers,
                json=body,
                params={"agents_list": agent_id},
                timeout=15,
            )
            return r.is_success

    async def unisolate_host(self, host: str) -> bool:
        headers = await self._auth_headers()
        agent_id = await self._get_agent_id(host)
        body = {"command": "!enable-firewall", "arguments": []}
        async with httpx.AsyncClient(verify=False) as client:
            r = await client.put(
                f"{self.host}/active-response",
                headers=headers,
                json=body,
                params={"agents_list": agent_id},
                timeout=15,
            )
            return r.is_success

    async def kill_process(self, host: str, pid: int, reason: str) -> bool:
        headers = await self._auth_headers()
        agent_id = await self._get_agent_id(host)
        body = {"command": "!kill-process", "arguments": [str(pid)]}
        async with httpx.AsyncClient(verify=False) as client:
            r = await client.put(
                f"{self.host}/active-response",
                headers=headers,
                json=body,
                params={"agents_list": agent_id},
                timeout=10,
            )
            return r.is_success

    async def run_command(self, host: str, command: str) -> dict:
        headers = await self._auth_headers()
        agent_id = await self._get_agent_id(host)
        body = {"command": "run-command", "arguments": [command]}
        async with httpx.AsyncClient(verify=False) as client:
            r = await client.put(
                f"{self.host}/active-response",
                headers=headers,
                json=body,
                params={"agents_list": agent_id},
                timeout=30,
            )
            r.raise_for_status()
            return r.json()

    async def get_process_tree(self, host: str, pid: int) -> dict:
        events = await self.run_command(host, f"ps --ppid {pid} -o pid,ppid,cmd 2>/dev/null || true")
        return {"pid": pid, "host": host, "response": events}

    async def collect_artefact(self, host: str, path: str) -> bytes:
        events = await self.run_command(host, f"cat '{path}' | base64")
        import base64
        raw = events.get("data", {}).get("output", "")
        try:
            return base64.b64decode(raw)
        except Exception:
            return raw.encode()


class CrowdStrikeEDRClient(EDRClient):
    """CrowdStrike Falcon EDR via Falcon API."""

    def __init__(
        self,
        client_id: str | None = None,
        client_secret: str | None = None,
        base_url: str = "https://api.crowdstrike.com",
    ):
        self.client_id = client_id or os.getenv("CROWDSTRIKE_CLIENT_ID", "")
        self.client_secret = client_secret or os.getenv("CROWDSTRIKE_CLIENT_SECRET", "")
        self.base_url = base_url
        self._token: str | None = None

    async def _auth_headers(self) -> dict:
        if not self._token:
            async with httpx.AsyncClient() as client:
                r = await client.post(
                    f"{self.base_url}/oauth2/token",
                    data={"client_id": self.client_id, "client_secret": self.client_secret},
                    timeout=10,
                )
                r.raise_for_status()
                self._token = r.json()["access_token"]
        return {"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"}

    async def _get_device_id(self, host: str) -> str:
        headers = await self._auth_headers()
        async with httpx.AsyncClient() as client:
            r = await client.get(
                f"{self.base_url}/devices/queries/devices/v1",
                headers=headers,
                params={"filter": f"hostname:'{host}'"},
                timeout=10,
            )
            r.raise_for_status()
            ids = r.json().get("resources", [])
            if not ids:
                raise ValueError(f"Device not found: {host}")
            return ids[0]

    async def get_host_status(self, host: str) -> HostStatus:
        headers = await self._auth_headers()
        device_id = await self._get_device_id(host)
        async with httpx.AsyncClient() as client:
            r = await client.get(
                f"{self.base_url}/devices/entities/devices/v2",
                headers=headers,
                params={"ids": device_id},
                timeout=10,
            )
            r.raise_for_status()
            d = r.json()["resources"][0]
            return HostStatus(
                hostname=d.get("hostname", host),
                ip=d.get("local_ip", ""),
                os=d.get("os_version", "unknown"),
                isolated=d.get("status", "") == "contained",
                last_seen=datetime.fromisoformat(d.get("last_seen", "2024-01-01T00:00:00Z").replace("Z", "+00:00")),
                agent_version=d.get("agent_version", ""),
                tags=d.get("tags", []),
            )

    async def isolate_host(self, host: str, reason: str) -> bool:
        headers = await self._auth_headers()
        device_id = await self._get_device_id(host)
        async with httpx.AsyncClient() as client:
            r = await client.post(
                f"{self.base_url}/devices/entities/devices-actions/v2",
                headers=headers,
                params={"action_name": "contain"},
                json={"ids": [device_id], "comment": reason},
                timeout=15,
            )
            return r.is_success

    async def unisolate_host(self, host: str) -> bool:
        headers = await self._auth_headers()
        device_id = await self._get_device_id(host)
        async with httpx.AsyncClient() as client:
            r = await client.post(
                f"{self.base_url}/devices/entities/devices-actions/v2",
                headers=headers,
                params={"action_name": "lift_containment"},
                json={"ids": [device_id]},
                timeout=15,
            )
            return r.is_success

    async def kill_process(self, host: str, pid: int, reason: str) -> bool:
        session = await self._start_rtr_session(host)
        return await self._run_rtr_command(session, f"kill {pid}")

    async def run_command(self, host: str, command: str) -> dict:
        session = await self._start_rtr_session(host)
        return {"output": await self._run_rtr_command(session, command)}

    async def _start_rtr_session(self, host: str) -> str:
        headers = await self._auth_headers()
        device_id = await self._get_device_id(host)
        async with httpx.AsyncClient() as client:
            r = await client.post(
                f"{self.base_url}/real-time-response/entities/sessions/v1",
                headers=headers,
                json={"device_id": device_id},
                timeout=15,
            )
            r.raise_for_status()
            return r.json()["resources"][0]["session_id"]

    async def _run_rtr_command(self, session_id: str, command: str) -> bool:
        headers = await self._auth_headers()
        async with httpx.AsyncClient() as client:
            r = await client.post(
                f"{self.base_url}/real-time-response/entities/active-responder-command/v1",
                headers=headers,
                json={"session_id": session_id, "base_command": command.split()[0], "command_string": command},
                timeout=30,
            )
            return r.is_success

    async def get_process_tree(self, host: str, pid: int) -> dict:
        result = await self.run_command(host, f"ps -p {pid} --forest")
        return {"pid": pid, "tree": result}

    async def collect_artefact(self, host: str, path: str) -> bytes:
        headers = await self._auth_headers()
        session_id = await self._start_rtr_session(host)
        async with httpx.AsyncClient() as client:
            r = await client.post(
                f"{self.base_url}/real-time-response/entities/file/v1",
                headers=headers,
                json={"session_id": session_id, "path": path},
                timeout=60,
            )
            r.raise_for_status()
            return r.content
