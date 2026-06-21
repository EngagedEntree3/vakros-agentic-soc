"""
Integration factory — instantiate the right client based on config/env vars.

Usage:
    from vakros_agent.integrations import IntegrationFactory
    siem   = IntegrationFactory.siem()
    edr    = IntegrationFactory.edr()
    cases  = IntegrationFactory.case_management()
"""

import os
from .base import SIEMClient, EDRClient, CaseManagementClient
from .siem import ElasticSIEMClient, WazuhSIEMClient
from .edr import WazuhEDRClient, CrowdStrikeEDRClient
from .case import TheHiveClient, IRISClient


class IntegrationFactory:
    """
    Reads VAKROS_SIEM, VAKROS_EDR, VAKROS_CASE env vars to pick implementations.

    VAKROS_SIEM=elastic  → ElasticSIEMClient
    VAKROS_SIEM=wazuh    → WazuhSIEMClient  (default)

    VAKROS_EDR=wazuh     → WazuhEDRClient   (default)
    VAKROS_EDR=crowdstrike → CrowdStrikeEDRClient

    VAKROS_CASE=thehive  → TheHiveClient    (default)
    VAKROS_CASE=iris     → IRISClient
    """

    @staticmethod
    def siem() -> SIEMClient:
        provider = os.getenv("VAKROS_SIEM", "wazuh").lower()
        match provider:
            case "elastic" | "elasticsearch":
                return ElasticSIEMClient()
            case "wazuh" | _:
                return WazuhSIEMClient()

    @staticmethod
    def edr() -> EDRClient:
        provider = os.getenv("VAKROS_EDR", "wazuh").lower()
        match provider:
            case "crowdstrike" | "falcon":
                return CrowdStrikeEDRClient()
            case "wazuh" | _:
                return WazuhEDRClient()

    @staticmethod
    def case_management() -> CaseManagementClient:
        provider = os.getenv("VAKROS_CASE", "thehive").lower()
        match provider:
            case "iris" | "dfir-iris":
                return IRISClient()
            case "thehive" | _:
                return TheHiveClient()
