"""Tests for application allowlist."""

from __future__ import annotations

import pytest

from agent.enrichment.application_allowlist import (
    AllowlistEntry,
    BUILTIN_ALLOWLIST,
    NetworkPattern,
    _rebuild_indexes,
    check_allowlist,
    load_custom_entries,
)
from agent.enrichment.process_identity import ProcessIdentity


@pytest.fixture(autouse=True)
def _reset_indexes():
    """Reset allowlist indexes to builtin defaults before each test."""
    _rebuild_indexes(list(BUILTIN_ALLOWLIST))
    yield
    _rebuild_indexes(list(BUILTIN_ALLOWLIST))


class TestBundleIdMatch:
    def test_orbstack_localhost_ipc_allowed(self):
        """OrbStack connecting to localhost should be allowed."""
        identity = ProcessIdentity(
            pid=100,
            path="/Applications/OrbStack.app/Contents/MacOS/OrbStack",
            name="OrbStack",
            bundle_id="dev.kdrag0n.OrbStack",
            code_signed=True,
        )
        result = check_allowlist(
            process_identity=identity,
            dest_ip="127.0.0.1",
            dest_port=62874,
        )
        assert result.is_allowed is True
        assert result.confidence == "high"
        assert result.matched_entry is not None
        assert result.matched_entry.app_name == "OrbStack"
        assert "Docker" in result.matched_pattern.description or "IPC" in result.matched_pattern.description

    def test_orbstack_docker_registry_allowed(self):
        """OrbStack connecting to Docker registry should match domain pattern."""
        identity = ProcessIdentity(
            pid=100,
            name="OrbStack",
            bundle_id="dev.kdrag0n.OrbStack",
        )
        result = check_allowlist(
            process_identity=identity,
            dest_ip="52.2.3.4",
            dest_port=443,
            tls_sni="registry-1.docker.io",
        )
        assert result.is_allowed is True
        assert "docker" in result.matched_pattern.description.lower()


class TestDomainGlobMatching:
    def test_wildcard_domain_match(self):
        """*.docker.io should match registry-1.docker.io."""
        identity = ProcessIdentity(
            bundle_id="dev.kdrag0n.OrbStack",
            name="OrbStack",
        )
        result = check_allowlist(
            process_identity=identity,
            dest_ip="1.2.3.4",
            dest_port=443,
            tls_sni="registry-1.docker.io",
        )
        assert result.is_allowed is True

    def test_non_matching_domain(self):
        """OrbStack connecting to unknown domain should not be allowed."""
        identity = ProcessIdentity(
            bundle_id="dev.kdrag0n.OrbStack",
            name="OrbStack",
        )
        result = check_allowlist(
            process_identity=identity,
            dest_ip="1.2.3.4",
            dest_port=443,
            tls_sni="evil-c2-server.com",
        )
        assert result.is_allowed is False
        assert "unexpected" in result.explanation.lower()


class TestIpRangeMatching:
    def test_apple_ip_range(self):
        """17.0.0.1 should match Apple's 17.0.0.0/8 range."""
        identity = ProcessIdentity(
            bundle_id="com.apple.nsurlsessiond",
            name="nsurlsessiond",
        )
        result = check_allowlist(
            process_identity=identity,
            dest_ip="17.253.100.1",
            dest_port=443,
        )
        assert result.is_allowed is True

    def test_non_apple_ip(self):
        """Non-Apple IP without matching SNI should not match ip_range."""
        identity = ProcessIdentity(
            bundle_id="com.apple.nsurlsessiond",
            name="nsurlsessiond",
        )
        result = check_allowlist(
            process_identity=identity,
            dest_ip="93.184.216.34",
            dest_port=443,
        )
        # nsurlsessiond has any_outbound on port 443, so should still match
        assert result.is_allowed is True


class TestProcessNameFallback:
    def test_fallback_to_name(self):
        """When bundle_id is not available, fall back to process name."""
        identity = ProcessIdentity(
            pid=100,
            name="Slack",
            bundle_id=None,
        )
        result = check_allowlist(
            process_identity=identity,
            dest_ip="1.2.3.4",
            dest_port=443,
            tls_sni="api.slack.com",
        )
        assert result.is_allowed is True
        assert result.confidence == "medium"

    def test_name_only_no_identity(self):
        """When no ProcessIdentity, use process_name parameter."""
        result = check_allowlist(
            process_identity=None,
            dest_ip="1.2.3.4",
            dest_port=443,
            tls_sni="api.slack.com",
            process_name="Slack",
        )
        assert result.is_allowed is True
        assert result.confidence == "medium"


class TestUnknownApp:
    def test_unknown_app_not_in_allowlist(self):
        """Unknown application should not match."""
        identity = ProcessIdentity(
            pid=100,
            name="totally_legit",
            bundle_id="com.evil.malware",
        )
        result = check_allowlist(
            process_identity=identity,
            dest_ip="10.10.10.10",
            dest_port=4444,
        )
        assert result.is_allowed is False
        assert result.confidence == "none"

    def test_known_app_unexpected_behavior(self):
        """Known app with unexpected connection should be flagged."""
        identity = ProcessIdentity(
            bundle_id="com.googlecode.iterm2",
            name="iTerm2",
        )
        # iTerm2 connecting to a suspicious domain (not iterm2.com or localhost)
        result = check_allowlist(
            process_identity=identity,
            dest_ip="1.2.3.4",
            dest_port=4444,
            tls_sni="evil-c2.example.com",
        )
        assert result.is_allowed is False
        assert result.matched_entry is not None  # Known app but unexpected
        assert "unexpected" in result.explanation.lower()


class TestCustomEntries:
    def test_load_custom_entries(self):
        """Custom entries should be loadable from config dict."""
        custom = [
            {
                "bundle_id": "com.custom.myapp",
                "app_name": "My Custom App",
                "expected_network": [
                    {
                        "pattern_type": "domain",
                        "value": "*.myapp.com",
                        "description": "Custom app API",
                    },
                    {
                        "pattern_type": "localhost_ipc",
                        "value": "",
                        "description": "Local IPC",
                    },
                ],
                "description": "A custom application",
                "category": "custom",
            },
        ]

        load_custom_entries(custom)

        identity = ProcessIdentity(
            bundle_id="com.custom.myapp",
            name="My Custom App",
        )
        result = check_allowlist(
            process_identity=identity,
            dest_ip="1.2.3.4",
            dest_port=443,
            tls_sni="api.myapp.com",
        )
        assert result.is_allowed is True
        assert result.confidence == "high"

    def test_custom_entry_localhost(self):
        """Custom entry with localhost_ipc pattern."""
        custom = [
            {
                "bundle_id": "com.custom.localapp",
                "app_name": "LocalApp",
                "expected_network": [
                    {
                        "pattern_type": "localhost_ipc",
                        "value": "",
                        "description": "Local API",
                    },
                ],
            },
        ]
        load_custom_entries(custom)

        identity = ProcessIdentity(
            bundle_id="com.custom.localapp",
            name="LocalApp",
        )
        result = check_allowlist(
            process_identity=identity,
            dest_ip="127.0.0.1",
            dest_port=5000,
        )
        assert result.is_allowed is True


class TestBuiltinAllowlist:
    def test_has_entries(self):
        """Builtin allowlist should have entries."""
        assert len(BUILTIN_ALLOWLIST) >= 15

    def test_all_entries_have_bundle_id(self):
        """All entries should have a bundle_id."""
        for entry in BUILTIN_ALLOWLIST:
            assert entry.bundle_id, f"Entry {entry.app_name} missing bundle_id"

    def test_all_entries_have_patterns(self):
        """All entries should have at least one network pattern."""
        for entry in BUILTIN_ALLOWLIST:
            assert len(entry.expected_network) > 0, (
                f"Entry {entry.app_name} has no network patterns"
            )
