"""
Vakros Artifact Layer
Inspired by agentic-soc-platform:
  Artifact = smallest atomic IOC object (IP, domain, hash, hostname, user, URL, email)
  Enrichment = structured results attached to Case / Alert / Artifact
"""

from .extractor import ArtifactExtractor, Artifact, ArtifactType
from .enricher import ArtifactEnricher, Enrichment, EnrichmentSource

__all__ = [
    "ArtifactExtractor", "Artifact", "ArtifactType",
    "ArtifactEnricher", "Enrichment", "EnrichmentSource",
]
