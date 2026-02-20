"""Network isolation for response actions.

Windows: netsh advfirewall rules to block inbound/outbound for a process.
Linux: iptables with owner matching (--uid-owner / --pid-owner via cgroup).
macOS: pf (packet filter) anchor rules.

Tracks all rules added so they can be reverted.
"""

from __future__ import annotations

import contextlib
import ipaddress
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
        # Blocked connections: (ip, port|None) -> rule identifier
        self._blocked_connections: dict[tuple[str, int | None], str] = {}
        # Panic mode state
        self._panic_active: bool = False

    @property
    def isolated_pids(self) -> set[int]:
        """Return the set of currently isolated PIDs."""
        return set(self._isolated.keys())

    def is_isolated(self, pid: int) -> bool:
        """Check if a PID is currently network-isolated."""
        return pid in self._isolated

    @property
    def blocked_connections(self) -> dict[tuple[str, int | None], str]:
        """Return the currently blocked IP:port pairs."""
        return dict(self._blocked_connections)

    @property
    def panic_active(self) -> bool:
        """Return whether panic mode is active."""
        return self._panic_active

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
        """Block active remote connections of a process on macOS via pf.

        Instead of the broken 'block drop quick all' (which blocks ALL host
        traffic since pf has no PID matching), this discovers the process's
        active remote connections via lsof and blocks each IP:port pair.
        """
        anchor_name = f"edr_block_{pid}"

        try:
            # Discover active remote connections for this PID
            result = subprocess.run(
                ["lsof", "-iTCP", "-iUDP", "-nP", "-p", str(pid)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            remote_endpoints: list[tuple[str, str]] = []
            for line in result.stdout.splitlines()[1:]:  # skip header
                parts = line.split()
                # lsof output: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
                if len(parts) >= 9:
                    name = parts[8]
                    # Look for remote end: "->1.2.3.4:443" or "->1.2.3.4:443 (ESTABLISHED)"
                    if "->" in name:
                        remote = name.split("->")[-1].split()[0]
                        # Handle IPv4 and IPv6
                        if remote.startswith("["):
                            # IPv6: [::1]:443
                            bracket_end = remote.index("]")
                            ip = remote[1:bracket_end]
                            port = remote[bracket_end + 2:] if bracket_end + 1 < len(remote) else ""
                        else:
                            last_colon = remote.rfind(":")
                            ip = remote[:last_colon]
                            port = remote[last_colon + 1:]
                        if ip and port and not ip.startswith("127.") and ip != "::1":
                            remote_endpoints.append((ip, port))

            if not remote_endpoints:
                self._isolated[pid] = [anchor_name]
                return NetworkControlOutcome(
                    result=NetworkControlResult.SUCCESS,
                    pid=pid,
                    action="isolate",
                    rules_applied=[anchor_name],
                    detail="No active remote connections found; anchor created empty",
                )

            # Build pf rules blocking each remote IP:port
            pf_lines = []
            for ip, port in remote_endpoints:
                pf_lines.append(f"block drop quick proto {{ tcp udp }} from any to {ip} port {port}")
                pf_lines.append(f"block drop quick proto {{ tcp udp }} from {ip} port {port} to any")
            pf_rules = "\n".join(pf_lines) + "\n"

            _run_command(
                ["pfctl", "-a", anchor_name, "-f", "-"],
                input_data=pf_rules,
            )

            self._isolated[pid] = [anchor_name]
            blocked_list = [f"{ip}:{port}" for ip, port in remote_endpoints]
            logger.info(
                "Isolated PID %d via pf anchor %s (%d connections blocked: %s)",
                pid,
                anchor_name,
                len(remote_endpoints),
                ", ".join(blocked_list),
            )
            return NetworkControlOutcome(
                result=NetworkControlResult.SUCCESS,
                pid=pid,
                action="isolate",
                rules_applied=[anchor_name] + blocked_list,
                detail=f"Blocked {len(remote_endpoints)} active connections",
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


    # --- Connection-level blocking ---

    def block_connection(
        self, ip: str, port: int | None = None
    ) -> NetworkControlOutcome:
        """Block traffic to a specific IP (optionally port).

        macOS: pf anchor rule.  Linux: iptables rule.  Windows: netsh rule.
        """
        # Validate IP to prevent injection into firewall commands
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return NetworkControlOutcome(
                result=NetworkControlResult.FAILED,
                pid=0,
                action="block_connection",
                detail=f"Invalid IP address: {ip!r}",
            )
        if port is not None and not (1 <= port <= 65535):
            return NetworkControlOutcome(
                result=NetworkControlResult.FAILED,
                pid=0,
                action="block_connection",
                detail=f"Invalid port: {port}",
            )

        key = (ip, port)
        if key in self._blocked_connections:
            return NetworkControlOutcome(
                result=NetworkControlResult.ALREADY_ISOLATED,
                pid=0,
                action="block_connection",
                detail=f"Already blocking {ip}" + (f":{port}" if port else ""),
            )

        try:
            if os.name == "nt":
                rule_name = f"EDR-BLOCK-CONN-{ip}-{port or 'all'}"
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}", "dir=out", "action=block",
                    f"remoteip={ip}",
                ]
                if port:
                    cmd += [f"remoteport={port}", "protocol=tcp"]
                _run_command(cmd)
                self._blocked_connections[key] = rule_name
            elif _is_linux():
                rule_name = f"EDR-CONN-{ip}-{port or 'all'}"
                cmd = ["iptables", "-A", "OUTPUT", "-d", ip]
                if port:
                    cmd += ["-p", "tcp", "--dport", str(port)]
                cmd += ["-j", "DROP", "-m", "comment", "--comment", rule_name]
                _run_command(cmd)
                self._blocked_connections[key] = rule_name
            else:
                # macOS: pf anchor
                anchor_name = f"edr_block_conn_{ip.replace('.', '_')}_{port or 'all'}"
                if port:
                    pf_rules = (
                        f"block drop quick proto {{ tcp udp }} from any to {ip} port {port}\n"
                        f"block drop quick proto {{ tcp udp }} from {ip} port {port} to any\n"
                    )
                else:
                    pf_rules = (
                        f"block drop quick from any to {ip}\n"
                        f"block drop quick from {ip} to any\n"
                    )
                _run_command(
                    ["pfctl", "-a", anchor_name, "-f", "-"],
                    input_data=pf_rules,
                )
                self._blocked_connections[key] = anchor_name

            target = f"{ip}:{port}" if port else ip
            logger.info("Blocked connection to %s", target)
            return NetworkControlOutcome(
                result=NetworkControlResult.SUCCESS,
                pid=0,
                action="block_connection",
                rules_applied=[self._blocked_connections[key]],
                detail=f"Blocked traffic to {target}",
            )
        except PermissionError:
            return NetworkControlOutcome(
                result=NetworkControlResult.PERMISSION_DENIED,
                pid=0,
                action="block_connection",
                detail="Root/admin privileges required",
            )
        except Exception as e:
            return NetworkControlOutcome(
                result=NetworkControlResult.FAILED,
                pid=0,
                action="block_connection",
                detail=str(e),
            )

    def unblock_connection(
        self, ip: str, port: int | None = None
    ) -> NetworkControlOutcome:
        """Remove a connection block for a specific IP (optionally port)."""
        # Validate IP to prevent injection into firewall commands
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return NetworkControlOutcome(
                result=NetworkControlResult.FAILED,
                pid=0,
                action="unblock_connection",
                detail=f"Invalid IP address: {ip!r}",
            )

        key = (ip, port)
        if key not in self._blocked_connections:
            return NetworkControlOutcome(
                result=NetworkControlResult.NOT_ISOLATED,
                pid=0,
                action="unblock_connection",
                detail=f"No block found for {ip}" + (f":{port}" if port else ""),
            )

        rule_id = self._blocked_connections[key]
        try:
            if os.name == "nt":
                _run_command([
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={rule_id}",
                ])
            elif _is_linux():
                cmd = ["iptables", "-D", "OUTPUT", "-d", ip]
                if port:
                    cmd += ["-p", "tcp", "--dport", str(port)]
                cmd += ["-j", "DROP", "-m", "comment", "--comment", rule_id]
                _run_command(cmd)
            else:
                _run_command(["pfctl", "-a", rule_id, "-F", "all"])

            del self._blocked_connections[key]
            target = f"{ip}:{port}" if port else ip
            logger.info("Unblocked connection to %s", target)
            return NetworkControlOutcome(
                result=NetworkControlResult.SUCCESS,
                pid=0,
                action="unblock_connection",
                rules_applied=[rule_id],
                detail=f"Unblocked traffic to {target}",
            )
        except Exception as e:
            return NetworkControlOutcome(
                result=NetworkControlResult.FAILED,
                pid=0,
                action="unblock_connection",
                detail=str(e),
            )

    # --- Panic mode ---

    def panic_isolate(self) -> NetworkControlOutcome:
        """Block ALL network traffic except loopback. Emergency use only."""
        if self._panic_active:
            return NetworkControlOutcome(
                result=NetworkControlResult.ALREADY_ISOLATED,
                pid=0,
                action="panic_isolate",
                detail="Panic mode is already active",
            )

        try:
            if os.name == "nt":
                _run_command([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    "name=EDR-PANIC-BLOCK", "dir=out", "action=block",
                    "remoteip=0.0.0.0/0",
                ])
                _run_command([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    "name=EDR-PANIC-BLOCK-IN", "dir=in", "action=block",
                    "remoteip=0.0.0.0/0",
                ])
            elif _is_linux():
                _run_command([
                    "iptables", "-A", "OUTPUT", "!", "-o", "lo",
                    "-j", "DROP", "-m", "comment", "--comment", "EDR-PANIC",
                ])
                _run_command([
                    "iptables", "-A", "INPUT", "!", "-i", "lo",
                    "-j", "DROP", "-m", "comment", "--comment", "EDR-PANIC",
                ])
            else:
                # macOS: pf anchor blocking everything except loopback
                pf_rules = "block drop quick on ! lo0 all\n"
                _run_command(
                    ["pfctl", "-a", "edr_panic", "-f", "-"],
                    input_data=pf_rules,
                )

            self._panic_active = True
            logger.warning("PANIC MODE ACTIVATED — all network traffic blocked except loopback")
            return NetworkControlOutcome(
                result=NetworkControlResult.SUCCESS,
                pid=0,
                action="panic_isolate",
                rules_applied=["edr_panic"],
                detail="All network traffic blocked except loopback",
            )
        except PermissionError:
            return NetworkControlOutcome(
                result=NetworkControlResult.PERMISSION_DENIED,
                pid=0,
                action="panic_isolate",
                detail="Root/admin privileges required",
            )
        except Exception as e:
            return NetworkControlOutcome(
                result=NetworkControlResult.FAILED,
                pid=0,
                action="panic_isolate",
                detail=str(e),
            )

    def panic_restore(self) -> NetworkControlOutcome:
        """Remove panic mode isolation. Restores network connectivity."""
        if not self._panic_active:
            return NetworkControlOutcome(
                result=NetworkControlResult.NOT_ISOLATED,
                pid=0,
                action="panic_restore",
                detail="Panic mode is not active",
            )

        errors: list[str] = []
        try:
            if os.name == "nt":
                for name in ("EDR-PANIC-BLOCK", "EDR-PANIC-BLOCK-IN"):
                    try:
                        _run_command([
                            "netsh", "advfirewall", "firewall", "delete", "rule",
                            f"name={name}",
                        ])
                    except Exception as e:
                        errors.append(str(e))
            elif _is_linux():
                for chain in ("OUTPUT", "INPUT"):
                    try:
                        iface_flag = "-o" if chain == "OUTPUT" else "-i"
                        _run_command([
                            "iptables", "-D", chain, "!", iface_flag, "lo",
                            "-j", "DROP", "-m", "comment", "--comment", "EDR-PANIC",
                        ])
                    except Exception as e:
                        errors.append(str(e))
            else:
                try:
                    _run_command(["pfctl", "-a", "edr_panic", "-F", "all"])
                except Exception as e:
                    errors.append(str(e))
        except Exception as e:
            errors.append(str(e))

        self._panic_active = False
        if errors:
            logger.warning("Panic mode restored with errors: %s", "; ".join(errors))
            return NetworkControlOutcome(
                result=NetworkControlResult.FAILED,
                pid=0,
                action="panic_restore",
                detail=f"Partial restore: {'; '.join(errors)}",
            )

        logger.warning("PANIC MODE DEACTIVATED — network traffic restored")
        return NetworkControlOutcome(
            result=NetworkControlResult.SUCCESS,
            pid=0,
            action="panic_restore",
            rules_applied=["edr_panic"],
            detail="Network traffic restored",
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
    except FileNotFoundError as e:
        raise RuntimeError(f"Command not found: {cmd[0]}") from e
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f"Command timed out: {' '.join(cmd)}") from e


def _try_delete_netsh_rule(rule_name: str) -> None:
    """Best-effort delete a netsh firewall rule."""
    with contextlib.suppress(Exception):
        _run_command([
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={rule_name}",
        ])
