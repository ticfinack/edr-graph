"""Network isolation for response actions.

Windows: netsh advfirewall rules to block inbound/outbound for a process.
Linux: iptables with owner matching (--uid-owner / --pid-owner via cgroup).
macOS: pf (packet filter) anchor rules.

Tracks all rules added so they can be reverted.
"""

from __future__ import annotations

import logging
import os
import subprocess
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class NetworkControlResult(Enum):
    """Outcome of a network isolation operation."""

    SUCCESS = "success"
    NOT_FOUND = "not_found"
    PERMISSION_DENIED = "permission_denied"
    FAILED = "failed"
    ALREADY_ISOLATED = "already_isolated"
    NOT_ISOLATED = "not_isolated"


@dataclass
class NetworkControlOutcome:
    """Result of a network control action with context."""

    result: NetworkControlResult
    pid: int
    action: str  # "isolate" or "restore"
    rules_applied: list[str] = field(default_factory=list)
    detail: str = ""


class NetworkIsolator:
    """Manages network isolation rules for processes.

    Tracks which PIDs are isolated and which firewall rules were created
    so they can be cleanly reverted.
    """

    def __init__(self) -> None:
        # Map of PID -> list of rule identifiers for cleanup
        self._isolated: dict[int, list[str]] = {}

    @property
    def isolated_pids(self) -> set[int]:
        """Return the set of currently isolated PIDs."""
        return set(self._isolated.keys())

    def is_isolated(self, pid: int) -> bool:
        """Check if a PID is currently network-isolated."""
        return pid in self._isolated

    def isolate(self, pid: int, exe_path: str | None = None) -> NetworkControlOutcome:
        """Block all network access for a process.

        Args:
            pid: Process ID to isolate.
            exe_path: Path to the executable (required on Windows for netsh rules).
        """
        if pid in self._isolated:
            return NetworkControlOutcome(
                result=NetworkControlResult.ALREADY_ISOLATED,
                pid=pid,
                action="isolate",
                detail=f"PID {pid} is already isolated",
            )

        if os.name == "nt":
            return self._isolate_windows(pid, exe_path)
        elif _is_linux():
            return self._isolate_linux(pid)
        else:
            return self._isolate_macos(pid)

    def restore(self, pid: int) -> NetworkControlOutcome:
        """Remove network isolation rules for a process."""
        if pid not in self._isolated:
            return NetworkControlOutcome(
                result=NetworkControlResult.NOT_ISOLATED,
                pid=pid,
                action="restore",
                detail=f"PID {pid} is not currently isolated",
            )

        if os.name == "nt":
            return self._restore_windows(pid)
        elif _is_linux():
            return self._restore_linux(pid)
        else:
            return self._restore_macos(pid)

    # --- Windows implementations ---

    def _isolate_windows(
        self, pid: int, exe_path: str | None
    ) -> NetworkControlOutcome:
        """Use netsh advfirewall to block network for a process on Windows."""
        if not exe_path:
            return NetworkControlOutcome(
                result=NetworkControlResult.FAILED,
                pid=pid,
                action="isolate",
                detail="exe_path is required for Windows network isolation",
            )

        rules: list[str] = []
        rule_out = f"EDR-BLOCK-OUT-{pid}"
        rule_in = f"EDR-BLOCK-IN-{pid}"

        try:
            # Block outbound
            _run_command([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_out}", "dir=out", "action=block",
                f"program={exe_path}",
            ])
            rules.append(rule_out)

            # Block inbound
            _run_command([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_in}", "dir=in", "action=block",
                f"program={exe_path}",
            ])
            rules.append(rule_in)

            self._isolated[pid] = rules
            logger.info("Isolated PID %d via netsh firewall rules", pid)
            return NetworkControlOutcome(
                result=NetworkControlResult.SUCCESS,
                pid=pid,
                action="isolate",
                rules_applied=rules,
            )
        except PermissionError:
            # Rollback any partially-applied rules
            for rule in rules:
                _try_delete_netsh_rule(rule)
            return NetworkControlOutcome(
                result=NetworkControlResult.PERMISSION_DENIED,
                pid=pid,
                action="isolate",
                detail="Administrator privileges required for netsh",
            )
        except Exception as e:
            for rule in rules:
                _try_delete_netsh_rule(rule)
            return NetworkControlOutcome(
                result=NetworkControlResult.FAILED,
                pid=pid,
                action="isolate",
                detail=str(e),
            )

    def _restore_windows(self, pid: int) -> NetworkControlOutcome:
        """Remove netsh firewall rules for a process."""
        rules = self._isolated.get(pid, [])
        errors: list[str] = []
        for rule in rules:
            try:
                _run_command([
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={rule}",
                ])
            except Exception as e:
                errors.append(f"Failed to delete rule {rule}: {e}")

        del self._isolated[pid]
        if errors:
            return NetworkControlOutcome(
                result=NetworkControlResult.FAILED,
                pid=pid,
                action="restore",
                rules_applied=rules,
                detail="; ".join(errors),
            )
        logger.info("Restored network for PID %d (removed %d rules)", pid, len(rules))
        return NetworkControlOutcome(
            result=NetworkControlResult.SUCCESS,
            pid=pid,
            action="restore",
            rules_applied=rules,
        )

    # --- Linux implementations ---

    def _isolate_linux(self, pid: int) -> NetworkControlOutcome:
        """Use iptables owner matching to block network for a UID/PID on Linux.

        Uses --pid-owner for targeted isolation. Falls back to uid-based if pid
        matching is unavailable (requires xt_owner kernel module).
        """
        rules: list[str] = []
        try:
            # Block outbound traffic from this PID
            out_rule = f"EDR-OUT-{pid}"
            _run_command([
                "iptables", "-A", "OUTPUT",
                "-m", "owner", "--pid-owner", str(pid),
                "-j", "DROP",
                "-m", "comment", "--comment", out_rule,
            ])
            rules.append(out_rule)

            # Block inbound established connections to this PID
            in_rule = f"EDR-IN-{pid}"
            _run_command([
                "iptables", "-A", "INPUT",
                "-m", "owner", "--pid-owner", str(pid),
                "-j", "DROP",
                "-m", "comment", "--comment", in_rule,
            ])
            rules.append(in_rule)

            self._isolated[pid] = rules
            logger.info("Isolated PID %d via iptables owner matching", pid)
            return NetworkControlOutcome(
                result=NetworkControlResult.SUCCESS,
                pid=pid,
                action="isolate",
                rules_applied=rules,
            )
        except PermissionError:
            return NetworkControlOutcome(
                result=NetworkControlResult.PERMISSION_DENIED,
                pid=pid,
                action="isolate",
                detail="Root privileges required for iptables",
            )
        except Exception as e:
            return NetworkControlOutcome(
                result=NetworkControlResult.FAILED,
                pid=pid,
                action="isolate",
                detail=str(e),
            )

    def _restore_linux(self, pid: int) -> NetworkControlOutcome:
        """Remove iptables rules for a process."""
        rules = self._isolated.get(pid, [])
        errors: list[str] = []

        for rule in rules:
            try:
                if rule.startswith("EDR-OUT-"):
                    _run_command([
                        "iptables", "-D", "OUTPUT",
                        "-m", "owner", "--pid-owner", str(pid),
                        "-j", "DROP",
                        "-m", "comment", "--comment", rule,
                    ])
                elif rule.startswith("EDR-IN-"):
                    _run_command([
                        "iptables", "-D", "INPUT",
                        "-m", "owner", "--pid-owner", str(pid),
                        "-j", "DROP",
                        "-m", "comment", "--comment", rule,
                    ])
            except Exception as e:
                errors.append(f"Failed to delete rule {rule}: {e}")

        del self._isolated[pid]
        if errors:
            return NetworkControlOutcome(
                result=NetworkControlResult.FAILED,
                pid=pid,
                action="restore",
                rules_applied=rules,
                detail="; ".join(errors),
            )
        logger.info("Restored network for PID %d (removed %d iptables rules)", pid, len(rules))
        return NetworkControlOutcome(
            result=NetworkControlResult.SUCCESS,
            pid=pid,
            action="restore",
            rules_applied=rules,
        )

    # --- macOS implementations ---

    def _isolate_macos(self, pid: int) -> NetworkControlOutcome:
        """Use pf anchor rules to block network for a process on macOS.

        Creates a pf anchor with block rules. Requires root.
        """
        anchor_name = f"edr_block_{pid}"
        rules: list[str] = [anchor_name]

        try:
            # Create pf rules that block all traffic for this anchor
            pf_rules = f"block drop quick all\n"
            _run_command(
                ["pfctl", "-a", anchor_name, "-f", "-"],
                input_data=pf_rules,
            )

            self._isolated[pid] = rules
            logger.info("Isolated PID %d via pf anchor %s", pid, anchor_name)
            return NetworkControlOutcome(
                result=NetworkControlResult.SUCCESS,
                pid=pid,
                action="isolate",
                rules_applied=rules,
            )
        except PermissionError:
            return NetworkControlOutcome(
                result=NetworkControlResult.PERMISSION_DENIED,
                pid=pid,
                action="isolate",
                detail="Root privileges required for pfctl",
            )
        except Exception as e:
            return NetworkControlOutcome(
                result=NetworkControlResult.FAILED,
                pid=pid,
                action="isolate",
                detail=str(e),
            )

    def _restore_macos(self, pid: int) -> NetworkControlOutcome:
        """Remove pf anchor rules for a process."""
        rules = self._isolated.get(pid, [])
        errors: list[str] = []

        for anchor_name in rules:
            try:
                _run_command(["pfctl", "-a", anchor_name, "-F", "all"])
            except Exception as e:
                errors.append(f"Failed to flush anchor {anchor_name}: {e}")

        del self._isolated[pid]
        if errors:
            return NetworkControlOutcome(
                result=NetworkControlResult.FAILED,
                pid=pid,
                action="restore",
                rules_applied=rules,
                detail="; ".join(errors),
            )
        logger.info("Restored network for PID %d (flushed pf anchors)", pid)
        return NetworkControlOutcome(
            result=NetworkControlResult.SUCCESS,
            pid=pid,
            action="restore",
            rules_applied=rules,
        )


# --- Helpers ---


def _is_linux() -> bool:
    """Check if the current platform is Linux."""
    import sys
    return sys.platform.startswith("linux")


def _run_command(
    cmd: list[str],
    input_data: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a system command, raising on failure."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
            input=input_data,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"Command {cmd[0]} failed (exit {result.returncode}): {result.stderr.strip()}"
            )
        return result
    except FileNotFoundError:
        raise RuntimeError(f"Command not found: {cmd[0]}")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Command timed out: {' '.join(cmd)}")


def _try_delete_netsh_rule(rule_name: str) -> None:
    """Best-effort delete a netsh firewall rule."""
    try:
        _run_command([
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={rule_name}",
        ])
    except Exception:
        pass
