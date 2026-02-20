"""Process identity enrichment: code signing, bundle ID, app metadata."""

from __future__ import annotations

import logging
import platform
import plistlib
import subprocess
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

_MAX_CACHE_SIZE = 500


@dataclass
class ProcessIdentity:
    """Identity metadata for a running process."""

    pid: int = 0
    path: str = ""
    name: str = ""
    bundle_id: str | None = None
    code_signed: bool = False
    signing_authority: str | None = None
    team_id: str | None = None
    is_apple_binary: bool = False
    is_notarized: bool = False
    app_name: str | None = None
    app_version: str | None = None


# Module-level LRU cache keyed by exe_path
_identity_cache: OrderedDict[str, ProcessIdentity] = OrderedDict()


def get_process_identity(pid: int, exe_path: str) -> ProcessIdentity:
    """Look up process identity. Uses cache when available."""
    if not exe_path:
        return ProcessIdentity(pid=pid, path="", name="")

    # Check cache
    if exe_path in _identity_cache:
        _identity_cache.move_to_end(exe_path)
        cached = _identity_cache[exe_path]
        # Return a copy with the current PID
        return ProcessIdentity(
            pid=pid,
            path=cached.path,
            name=cached.name,
            bundle_id=cached.bundle_id,
            code_signed=cached.code_signed,
            signing_authority=cached.signing_authority,
            team_id=cached.team_id,
            is_apple_binary=cached.is_apple_binary,
            is_notarized=cached.is_notarized,
            app_name=cached.app_name,
            app_version=cached.app_version,
        )

    identity = _lookup_identity(pid, exe_path)

    # Store in cache, evict oldest if full
    _identity_cache[exe_path] = identity
    if len(_identity_cache) > _MAX_CACHE_SIZE:
        _identity_cache.popitem(last=False)

    return identity


def _lookup_identity(pid: int, exe_path: str) -> ProcessIdentity:
    """Platform-specific identity lookup."""
    name = Path(exe_path).name if exe_path else ""
    identity = ProcessIdentity(pid=pid, path=exe_path, name=name)

    if platform.system() != "Darwin":
        return identity

    # macOS: codesign + plist lookup
    codesign_info = _get_codesign_info(exe_path)
    if codesign_info:
        identity.code_signed = True
        identity.signing_authority = codesign_info.get("Authority")
        identity.team_id = codesign_info.get("TeamIdentifier")
        identifier = codesign_info.get("Identifier", "")

        # Check if Apple-signed
        authority = identity.signing_authority or ""
        identity.is_apple_binary = (
            "Apple" in authority or "Software Signing" in authority
        )

        # Check notarization flag from codesign flags
        flags = codesign_info.get("Flags", "")
        identity.is_notarized = "notarized" in flags.lower() or "runtime" in flags.lower()

        # Use Identifier as fallback bundle_id
        if identifier and not identity.bundle_id:
            identity.bundle_id = identifier

    # Try to get bundle ID from .app bundle
    bundle_info = _get_bundle_info(exe_path)
    if bundle_info:
        if bundle_info.get("bundle_id"):
            identity.bundle_id = bundle_info["bundle_id"]
        if bundle_info.get("app_name"):
            identity.app_name = bundle_info["app_name"]
        if bundle_info.get("app_version"):
            identity.app_version = bundle_info["app_version"]

    return identity


def _get_codesign_info(binary_path: str) -> dict | None:
    """Run codesign -dvv and parse key=value output from stderr."""
    try:
        result = subprocess.run(
            ["codesign", "-dvv", binary_path],
            capture_output=True,
            text=True,
            timeout=5,
        )
        # codesign outputs to stderr
        output = result.stderr
        if not output:
            return None

        info = {}
        for line in output.splitlines():
            if "=" in line:
                key, _, value = line.partition("=")
                info[key.strip()] = value.strip()
            elif ":" in line:
                key, _, value = line.partition(":")
                info[key.strip()] = value.strip()

        # If we got no useful data, treat as unsigned
        if not info.get("Authority") and not info.get("Identifier"):
            return None

        return info
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None
    except Exception:
        logger.debug("codesign lookup failed for %s", binary_path, exc_info=True)
        return None


def _get_bundle_info(binary_path: str) -> dict | None:
    """Walk up from binary to find .app bundle and read Info.plist."""
    try:
        path = Path(binary_path).resolve()
        # Walk up looking for .app bundle
        for parent in path.parents:
            if parent.suffix == ".app":
                plist_path = parent / "Contents" / "Info.plist"
                if plist_path.exists():
                    with open(plist_path, "rb") as f:
                        plist = plistlib.load(f)
                    return {
                        "bundle_id": plist.get("CFBundleIdentifier"),
                        "app_name": plist.get("CFBundleName") or plist.get("CFBundleDisplayName"),
                        "app_version": plist.get("CFBundleShortVersionString"),
                    }
                break
    except Exception:
        logger.debug("Bundle info lookup failed for %s", binary_path, exc_info=True)
    return None


def warm_cache() -> None:
    """Pre-warm the identity cache by iterating running processes."""
    if platform.system() != "Darwin":
        return
    try:
        import psutil

        for proc in psutil.process_iter(["pid", "exe"]):
            try:
                info = proc.info
                pid = info.get("pid", 0)
                exe = info.get("exe")
                if exe and pid:
                    get_process_identity(pid, exe)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except ImportError:
        logger.debug("psutil not available for cache warming")
    except Exception:
        logger.debug("Cache warming failed", exc_info=True)

    logger.info("Process identity cache warmed: %d entries", len(_identity_cache))


def clear_cache() -> None:
    """Clear the identity cache (for testing)."""
    _identity_cache.clear()
