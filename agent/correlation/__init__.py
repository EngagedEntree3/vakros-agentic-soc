"""
Vakros Alert Correlation Engine
Inspired by agentic-soc-platform — groups related alerts into Cases via Correlation UID.
"""

from .correlator import AlertCorrelator, CorrelationRule, CorrelatedCase, CorrelationKey

__all__ = ["AlertCorrelator", "CorrelationRule", "CorrelatedCase", "CorrelationKey"]
