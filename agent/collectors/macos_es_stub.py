"""Placeholder for macOS Endpoint Security framework collector.

The Endpoint Security framework requires the
``com.apple.developer.endpoint-security.client`` entitlement, which is only
available to signed binaries with an Apple-approved provisioning profile.

This stub exists so the collector can be registered in the architecture
without breaking imports. Once the entitlement is obtained, replace this
with a real ES client implementation.
"""

from __future__ import annotations

import logging

from .base import Collector, RawEvent

logger = logging.getLogger(__name__)


class MacOSEndpointSecurityCollector(Collector):
    """Stub collector for macOS Endpoint Security framework.

    Returns no events. Logs an info message on start() explaining the
    entitlement requirement.
    """

    def name(self) -> str:
        return "macos_es"

    def start(self) -> None:
        logger.info(
            "Endpoint Security collector is a stub — requires "
            "com.apple.developer.endpoint-security.client entitlement"
        )

    def collect(self) -> list[RawEvent]:
        return []
