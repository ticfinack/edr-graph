"""Tests for Phase 2 Commit 3: DGA Detection Heuristic (2B).

Tests domain scoring, allowlisting, edge cases, and graph integration.
"""

from datetime import datetime

from agent.analysis.dga_detector import analyze_domain
from agent.processor.entity_extractor import extract_entities
from agent.schema.ocsf_types import DeviceInfo, DnsActivity, ProcessInfo


class TestDGAScoring:
    def test_legitimate_domain_scores_low(self):
        """google.com should score low (< 0.3)."""
        result = analyze_domain("google.com")
        assert result.score < 0.3
        assert result.is_dga_candidate is False

    def test_dga_domain_scores_high(self):
        """A DGA-style domain like xjk82mfq3p.xyz should score high (> 0.6)."""
        result = analyze_domain("xjk82mfq3p.xyz")
        assert result.score > 0.6
        assert result.is_dga_candidate is True
        assert len(result.reasons) > 0

    def test_another_legit_domain(self):
        """stackoverflow.com should score low."""
        result = analyze_domain("stackoverflow.com")
        assert result.score < 0.4
        assert result.is_dga_candidate is False

    def test_long_random_domain(self):
        """Long random domains should score high."""
        result = analyze_domain("a8f3k2m9v7x4q1w6.net")
        assert result.score > 0.5
        assert result.is_dga_candidate is True

    def test_numeric_heavy_domain(self):
        """Domain with many digits should get a higher score."""
        result = analyze_domain("abc123456789.com")
        assert result.score > 0.3  # Numeric ratio contributes


class TestDGAAllowlist:
    def test_allowlisted_domain_returns_false(self):
        """Allowlisted domains always return is_dga_candidate = False."""
        allowlist = {"googleapis.com", "cloudflare.com"}
        result = analyze_domain("googleapis.com", allowlist=allowlist)
        assert result.is_dga_candidate is False
        assert result.score == 0.0
        assert "Allowlisted" in result.reasons

    def test_subdomain_of_allowlisted(self):
        """Subdomains of allowlisted domains are also allowlisted."""
        allowlist = {"amazonaws.com"}
        result = analyze_domain("s3.amazonaws.com", allowlist=allowlist)
        assert result.is_dga_candidate is False
        assert result.score == 0.0

    def test_non_allowlisted_still_analyzed(self):
        """Domains not in allowlist are still analyzed normally."""
        allowlist = {"googleapis.com"}
        result = analyze_domain("xjk82mfq3p.xyz", allowlist=allowlist)
        assert result.is_dga_candidate is True


class TestDGAEdgeCases:
    def test_single_character_domain(self):
        """Single-character domain should not crash."""
        result = analyze_domain("x.com")
        assert isinstance(result.score, float)

    def test_ip_literal_domain(self):
        """IP-literal domains should not crash."""
        result = analyze_domain("192.168.1.1")
        assert isinstance(result.score, float)

    def test_punycode_domain(self):
        """Punycode domains should not crash."""
        result = analyze_domain("xn--nxasmq6b.com")
        assert isinstance(result.score, float)

    def test_empty_domain(self):
        """Empty domain should not crash."""
        result = analyze_domain("")
        assert result.score == 0.0
        assert result.is_dga_candidate is False

    def test_single_label_no_tld(self):
        """Single label (no TLD) domain returns safe."""
        result = analyze_domain("localhost")
        assert result.is_dga_candidate is False


class TestDGAGraphIntegration:
    def test_dga_result_attached_to_domain_node(self):
        """DGA result is correctly set on Domain node in the graph."""
        event = DnsActivity(
            activity_id=1,
            time=datetime(2025, 6, 1, 12, 0),
            process=ProcessInfo(
                pid=1234,
                name="malware",
                created_time=datetime(2025, 6, 1, 12, 0),
            ),
            query_domain="xjk82mfq3p.xyz",
            resolved_ips=["1.2.3.4"],
            device=DeviceInfo(hostname="testhost"),
        )
        entities = extract_entities(event, event_id=100)

        assert len(entities.domains) == 1
        domain = entities.domains[0]
        assert domain.is_dga_candidate is True

    def test_legit_domain_not_flagged(self):
        """Legitimate domain is not flagged as DGA."""
        event = DnsActivity(
            activity_id=1,
            time=datetime(2025, 6, 1, 12, 0),
            process=ProcessInfo(
                pid=1234,
                name="chrome",
                created_time=datetime(2025, 6, 1, 12, 0),
            ),
            query_domain="google.com",
            resolved_ips=["142.250.80.46"],
            device=DeviceInfo(hostname="testhost"),
        )
        entities = extract_entities(event, event_id=101)

        assert len(entities.domains) == 1
        assert entities.domains[0].is_dga_candidate is False

    def test_allowlisted_domain_not_flagged_in_extraction(self):
        """Allowlisted domains are not flagged during entity extraction."""
        allowlist = {"googleapis.com"}
        event = DnsActivity(
            activity_id=1,
            time=datetime(2025, 6, 1, 12, 0),
            query_domain="storage.googleapis.com",
            device=DeviceInfo(hostname="testhost"),
        )
        entities = extract_entities(event, event_id=102, dga_allowlist=allowlist)

        assert len(entities.domains) == 1
        assert entities.domains[0].is_dga_candidate is False
