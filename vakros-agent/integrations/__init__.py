"""
Vakros Agentic SOC — Vendor-Neutral Integration Layer
Inspired by ai-soc-agent (SamiGPT) vendor-neutral pattern.

Abstract interfaces decouple the SOC agents from specific tools,
so swapping Elastic → Splunk or TheHive → IRIS requires no agent changes.
"""

from .base import SIEMClient, EDRClient, CaseManagementClient
from .siem import ElasticSIEMClient, WazuhSIEMClient
from .edr import WazuhEDRClient, CrowdStrikeEDRClient
from .case import TheHiveClient, IRISClient
from .factory import IntegrationFactory

__all__ = [
    "SIEMClient", "EDRClient", "CaseManagementClient",
    "ElasticSIEMClient", "WazuhSIEMClient",
    "WazuhEDRClient", "CrowdStrikeEDRClient",
    "TheHiveClient", "IRISClient",
    "IntegrationFactory",
]
