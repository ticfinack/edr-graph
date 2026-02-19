"""DNS sinkhole via /etc/hosts manipulation.

Redirects malicious domains to 127.0.0.1 by appending entries to /etc/hosts
with a marker comment for clean removal.
"""

from __future__ import annotations

import logging
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

_MARKER = "# EDR-GRAPH-SINKHOLE"

# Basic domain validation: labels separated by dots, no wildcards, no IPs
_DOMAIN_RE = re.compile(r"^(?!-)[a-zA-Z0-9-]{1,63}(?:\.[a-zA-Z0-9-]{1,63})+$")


@dataclass
class SinkholeOutcome:
    """Result of a sinkhole operation."""

    result: str  # "success", "failed", "already_sinkholed", "not_sinkholed"
    domain: str
    detail: str = ""


class DnsSinkhole:
    """Redirect malicious domains to 127.0.0.1 via /etc/hosts."""

    def __init__(self, hosts_path: Path | None = None) -> None:
        self._hosts_path = hosts_path or Path("/etc/hosts")
        self._sinkholed: set[str] = set()
        self._load_existing()

    def _load_existing(self) -> None:
        """Parse /etc/hosts for existing sinkhole markers."""
        try:
            content = self._hosts_path.read_text()
            for line in content.splitlines():
                if _MARKER in line:
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] == "127.0.0.1":
                        self._sinkholed.add(parts[1].lower())
        except Exception:
            logger.debug("Could not read hosts file for existing sinkhole entries")

    def sinkhole(self, domain: str) -> SinkholeOutcome:
        """Append '127.0.0.1 <domain> # EDR-GRAPH-SINKHOLE' to /etc/hosts."""
        domain = domain.strip().lower()

        if domain in self._sinkholed:
            return SinkholeOutcome(
                result="already_sinkholed",
                domain=domain,
                detail=f"{domain} is already sinkholed",
            )

        if not _DOMAIN_RE.match(domain):
            return SinkholeOutcome(
                result="failed",
                domain=domain,
                detail=f"Invalid domain: {domain}",
            )

        entry = f"127.0.0.1 {domain} {_MARKER}\n"
        try:
            with open(self._hosts_path, "a") as f:
                f.write(entry)
            self._sinkholed.add(domain)
            self._flush_dns_cache()
            logger.info("Sinkholed domain: %s", domain)
            return SinkholeOutcome(
                result="success",
                domain=domain,
                detail=f"Sinkholed {domain} → 127.0.0.1",
            )
        except PermissionError:
            return SinkholeOutcome(
                result="failed",
                domain=domain,
                detail="Permission denied writing to /etc/hosts (requires root)",
            )
        except Exception as e:
            return SinkholeOutcome(
                result="failed",
                domain=domain,
                detail=str(e),
            )

    def restore(self, domain: str) -> SinkholeOutcome:
        """Remove the sinkhole entry from /etc/hosts."""
        domain = domain.strip().lower()

        if domain not in self._sinkholed:
            return SinkholeOutcome(
                result="not_sinkholed",
                domain=domain,
                detail=f"{domain} is not currently sinkholed",
            )

        try:
            content = self._hosts_path.read_text()
            lines = content.splitlines(keepends=True)
            filtered = [
                line
                for line in lines
                if not (
                    _MARKER in line
                    and domain in line.lower()
                )
            ]
            self._hosts_path.write_text("".join(filtered))
            self._sinkholed.discard(domain)
            self._flush_dns_cache()
            logger.info("Restored domain from sinkhole: %s", domain)
            return SinkholeOutcome(
                result="success",
                domain=domain,
                detail=f"Removed sinkhole for {domain}",
            )
        except PermissionError:
            return SinkholeOutcome(
                result="failed",
                domain=domain,
                detail="Permission denied writing to /etc/hosts (requires root)",
            )
        except Exception as e:
            return SinkholeOutcome(
                result="failed",
                domain=domain,
                detail=str(e),
            )

    def restore_all(self) -> int:
        """Remove all EDR-GRAPH-SINKHOLE entries. Returns count removed."""
        try:
            content = self._hosts_path.read_text()
            lines = content.splitlines(keepends=True)
            filtered = [line for line in lines if _MARKER not in line]
            removed = len(lines) - len(filtered)
            if removed > 0:
                self._hosts_path.write_text("".join(filtered))
                self._flush_dns_cache()
            self._sinkholed.clear()
            logger.info("Restored all sinkholed domains (%d entries removed)", removed)
            return removed
        except Exception:
            logger.exception("Failed to restore all sinkhole entries")
            return 0

    @property
    def sinkholed_domains(self) -> set[str]:
        return set(self._sinkholed)

    def _flush_dns_cache(self) -> None:
        """Platform-specific DNS cache flush."""
        try:
            if sys.platform == "darwin":
                subprocess.run(
                    ["killall", "-HUP", "mDNSResponder"],
                    capture_output=True,
                    timeout=5,
                )
            elif sys.platform.startswith("linux"):
                subprocess.run(
                    ["systemd-resolve", "--flush-caches"],
                    capture_output=True,
                    timeout=5,
                )
        except Exception:
            logger.debug("DNS cache flush failed (non-fatal)", exc_info=True)
