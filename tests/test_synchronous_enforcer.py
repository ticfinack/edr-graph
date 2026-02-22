"""Tests for the synchronous fast-path blocklist enforcer."""

from __future__ import annotations

import sqlite3
from datetime import datetime
from unittest.mock import patch

import pytest

from agent.processor.entity_extractor import ExtractedEntities
from agent.processor.synchronous_enforcer import FastBlocklist, _build_chain_from_caches
from agent.response.baseline import ResponseBlocklist
from agent.schema.graph_types import (
    DomainNode,
    ProcessNode,
)
from agent.schema.queue_schema import init_queue_db


@pytest.fixture
def db_path(tmp_path):
    """Create a temporary SQLite database with schema."""
    path = tmp_path / "test.db"
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    init_queue_db(conn)
    conn.close()
    return path


@pytest.fixture
def blocklist(db_path):
    """ResponseBlocklist backed by temp database."""
    return ResponseBlocklist(db_path)


@pytest.fixture
def fast_blocklist(blocklist):
    """FastBlocklist wrapping the temp blocklist."""
    return FastBlocklist(blocklist, refresh_interval=0.0)


def _make_entities(
    processes=None,
    connected_edges=None,
    domains=None,
    file_edges=None,
) -> ExtractedEntities:
    """Helper to build ExtractedEntities with common defaults."""
    ent = ExtractedEntities()
    now = datetime.now()
    if processes:
        for name, pid in processes:
            ent.processes.append(
                ProcessNode(
                    id=f"host:{pid}:1000",
                    name=name,
                    pid=pid,
                    hostname="host",
                    start_time=now,
                )
            )
    if connected_edges:
        for ip in connected_edges:
            ent.connected_edges.append(
                {
                    "process_id": "host:100:1000",
                    "ip_id": ip,
                    "timestamp": now,
                    "dst_port": 443,
                    "protocol": "TCP",
                    "direction": "outbound",
                    "event_id": 1,
                }
            )
    if domains:
        for d in domains:
            ent.domains.append(DomainNode(id=d, name=d, first_seen=now, last_seen=now))
    if file_edges:
        for fp in file_edges:
            ent.file_edges.append(
                {"process_id": "host:100:1000", "file_id": fp, "operation": "MODIFIED", "timestamp": now, "event_id": 1}
            )
    return ent


# ── Rule compilation tests ──


class TestRuleCompilation:
    def test_ip_rules_compiled_to_set(self, blocklist, fast_blocklist):
        blocklist.add_rule("dst_ip", "1.2.3.4", "test ip")
        blocklist.add_rule("dst_ip", "5.6.7.8", "test ip2")
        fast_blocklist.invalidate()
        fast_blocklist._refresh_if_stale()
        assert fast_blocklist._ips == {"1.2.3.4", "5.6.7.8"}

    def test_domain_rules_compiled_to_lowered_set(self, blocklist, fast_blocklist):
        blocklist.add_rule("domain", "Evil.COM", "test domain")
        fast_blocklist.invalidate()
        fast_blocklist._refresh_if_stale()
        assert fast_blocklist._domains == {"evil.com"}

    def test_cidr_rules_compiled_to_network_list(self, blocklist, fast_blocklist):
        blocklist.add_rule("dst_cidr", "10.0.0.0/8", "internal range")
        fast_blocklist.invalidate()
        fast_blocklist._refresh_if_stale()
        assert len(fast_blocklist._cidrs) == 1

    def test_process_name_rules_compiled_to_fnmatch_list(self, blocklist, fast_blocklist):
        blocklist.add_rule("process_name", "ncat*", "netcat variants")
        fast_blocklist.invalidate()
        fast_blocklist._refresh_if_stale()
        assert len(fast_blocklist._process_names) == 1
        assert fast_blocklist._process_names[0][0] == "ncat*"

    def test_file_path_rules_compiled_to_fnmatch_list(self, blocklist, fast_blocklist):
        blocklist.add_rule("file_path", "/tmp/evil*", "evil files")
        fast_blocklist.invalidate()
        fast_blocklist._refresh_if_stale()
        assert len(fast_blocklist._file_paths) == 1

    def test_chain_pattern_rules_compiled_to_split_parts(self, blocklist, fast_blocklist):
        blocklist.add_rule("chain_pattern", "USER:* > bash > ncat", "reverse shell")
        fast_blocklist.invalidate()
        fast_blocklist._refresh_if_stale()
        assert len(fast_blocklist._chain_patterns) == 1
        assert fast_blocklist._chain_patterns[0][0] == ["USER:*", "bash", "ncat"]


# ── Matching tests ──


class TestIpMatch:
    def test_exact_ip_match(self, blocklist, fast_blocklist):
        blocklist.add_rule("dst_ip", "1.2.3.4", "bad ip")
        fast_blocklist.invalidate()
        entities = _make_entities(
            processes=[("curl", 100)],
            connected_edges=["1.2.3.4"],
        )
        result = fast_blocklist.evaluate(entities, None, 42)
        assert result is not None
        finding, desc = result
        assert finding.severity == "critical"
        assert "1.2.3.4" in finding.title
        assert 42 in finding.evidence_event_ids

    def test_ip_no_match(self, blocklist, fast_blocklist):
        blocklist.add_rule("dst_ip", "1.2.3.4", "bad ip")
        fast_blocklist.invalidate()
        entities = _make_entities(
            processes=[("curl", 100)],
            connected_edges=["9.9.9.9"],
        )
        result = fast_blocklist.evaluate(entities, None, 42)
        assert result is None


class TestDomainMatch:
    def test_exact_domain_match_case_insensitive(self, blocklist, fast_blocklist):
        blocklist.add_rule("domain", "evil.com", "bad domain")
        fast_blocklist.invalidate()
        entities = _make_entities(
            processes=[("curl", 100)],
            domains=["EVIL.COM"],
        )
        result = fast_blocklist.evaluate(entities, None, 42)
        assert result is not None
        finding, _ = result
        assert "evil.com" in finding.title.lower()

    def test_domain_no_match(self, blocklist, fast_blocklist):
        blocklist.add_rule("domain", "evil.com", "bad domain")
        fast_blocklist.invalidate()
        entities = _make_entities(domains=["good.com"])
        result = fast_blocklist.evaluate(entities, None, 42)
        assert result is None


class TestCidrMatch:
    def test_cidr_match(self, blocklist, fast_blocklist):
        blocklist.add_rule("dst_cidr", "10.0.0.0/8", "internal range")
        fast_blocklist.invalidate()
        entities = _make_entities(
            processes=[("curl", 100)],
            connected_edges=["10.1.2.3"],
        )
        result = fast_blocklist.evaluate(entities, None, 42)
        assert result is not None
        finding, _ = result
        assert "10.1.2.3" in finding.title

    def test_cidr_no_match(self, blocklist, fast_blocklist):
        blocklist.add_rule("dst_cidr", "10.0.0.0/8", "internal range")
        fast_blocklist.invalidate()
        entities = _make_entities(
            processes=[("curl", 100)],
            connected_edges=["192.168.1.1"],
        )
        result = fast_blocklist.evaluate(entities, None, 42)
        assert result is None


class TestProcessNameMatch:
    def test_fnmatch_process_name(self, blocklist, fast_blocklist):
        blocklist.add_rule("process_name", "ncat*", "netcat")
        fast_blocklist.invalidate()
        entities = _make_entities(processes=[("ncat", 100)])
        result = fast_blocklist.evaluate(entities, None, 42)
        assert result is not None
        finding, _ = result
        assert "ncat" in finding.title

    def test_fnmatch_process_name_glob(self, blocklist, fast_blocklist):
        blocklist.add_rule("process_name", "ncat*", "netcat")
        fast_blocklist.invalidate()
        entities = _make_entities(processes=[("ncat.exe", 100)])
        result = fast_blocklist.evaluate(entities, None, 42)
        assert result is not None

    def test_process_name_no_match(self, blocklist, fast_blocklist):
        blocklist.add_rule("process_name", "ncat*", "netcat")
        fast_blocklist.invalidate()
        entities = _make_entities(processes=[("curl", 100)])
        result = fast_blocklist.evaluate(entities, None, 42)
        assert result is None


class TestFilePathMatch:
    def test_fnmatch_file_path(self, blocklist, fast_blocklist):
        blocklist.add_rule("file_path", "/tmp/evil*", "evil files")
        fast_blocklist.invalidate()
        entities = _make_entities(
            processes=[("bash", 100)],
            file_edges=["/tmp/evil_payload.sh"],
        )
        result = fast_blocklist.evaluate(entities, None, 42)
        assert result is not None
        finding, _ = result
        assert "/tmp/evil_payload.sh" in finding.title

    def test_file_path_no_match(self, blocklist, fast_blocklist):
        blocklist.add_rule("file_path", "/tmp/evil*", "evil files")
        fast_blocklist.invalidate()
        entities = _make_entities(
            processes=[("bash", 100)],
            file_edges=["/tmp/good_file.txt"],
        )
        result = fast_blocklist.evaluate(entities, None, 42)
        assert result is None


class TestChainPatternMatch:
    def test_chain_pattern_match_from_caches(self, blocklist, fast_blocklist):
        # Pattern uses ** to match zero-or-more intermediate processes
        blocklist.add_rule("chain_pattern", "USER:* > ** > bash > ncat", "reverse shell")
        fast_blocklist.invalidate()

        # Populate caches to simulate process ancestry: launchd(1) -> bash(50) -> ncat(100)
        from agent.processor import entity_extractor

        entity_extractor._ppid_cache[100] = 50
        entity_extractor._ppid_cache[50] = 1
        entity_extractor._ppid_cache[1] = 0
        entity_extractor._name_cache[50] = "bash"
        entity_extractor._name_cache[1] = "launchd"
        entity_extractor._username_cache[100] = "admin"

        try:
            entities = _make_entities(processes=[("ncat", 100)])
            result = fast_blocklist.evaluate(entities, None, 42)
            assert result is not None
            finding, _ = result
            assert finding.severity == "critical"
            assert "chain_pattern" in finding.title
        finally:
            # Clean up caches
            entity_extractor._ppid_cache.pop(100, None)
            entity_extractor._ppid_cache.pop(50, None)
            entity_extractor._ppid_cache.pop(1, None)
            entity_extractor._name_cache.pop(50, None)
            entity_extractor._name_cache.pop(1, None)
            entity_extractor._username_cache.pop(100, None)

    def test_chain_pattern_no_match(self, blocklist, fast_blocklist):
        blocklist.add_rule("chain_pattern", "USER:* > bash > ncat", "reverse shell")
        fast_blocklist.invalidate()
        # No caches populated, so chain is just ["curl"]
        entities = _make_entities(processes=[("curl", 200)])
        result = fast_blocklist.evaluate(entities, None, 42)
        assert result is None


# ── Edge cases ──


class TestEmptyBlocklist:
    def test_empty_blocklist_returns_none(self, fast_blocklist):
        """Empty blocklist should fast bail-out."""
        entities = _make_entities(
            processes=[("curl", 100)],
            connected_edges=["1.2.3.4"],
            domains=["example.com"],
        )
        result = fast_blocklist.evaluate(entities, None, 42)
        assert result is None

    def test_has_rules_false_when_empty(self, fast_blocklist):
        fast_blocklist._refresh_if_stale()
        assert fast_blocklist._has_rules is False


class TestNoMatch:
    def test_unrelated_entities_pass_through(self, blocklist, fast_blocklist):
        blocklist.add_rule("dst_ip", "1.2.3.4", "bad ip")
        blocklist.add_rule("domain", "evil.com", "bad domain")
        fast_blocklist.invalidate()
        entities = _make_entities(
            processes=[("safe_app", 100)],
            connected_edges=["9.9.9.9"],
            domains=["safe.org"],
        )
        result = fast_blocklist.evaluate(entities, None, 42)
        assert result is None


# ── Finding synthesis ──


class TestFindingSynthesis:
    def test_finding_fields(self, blocklist, fast_blocklist):
        blocklist.add_rule("dst_ip", "1.2.3.4", "test")
        fast_blocklist.invalidate()
        entities = _make_entities(
            processes=[("curl", 100)],
            connected_edges=["1.2.3.4"],
        )
        result = fast_blocklist.evaluate(entities, None, 99)
        assert result is not None
        finding, match_desc = result
        assert finding.severity == "critical"
        assert "Blocklist Hit" in finding.title
        assert "dst_ip" in finding.title
        assert 99 in finding.evidence_event_ids
        assert len(finding.chain) >= 1
        assert finding.affected_pids == [100]
        assert "1.2.3.4" in finding.affected_entities
        assert finding.iocs.get("ips") == ["1.2.3.4"]

    def test_domain_finding_has_domain_ioc(self, blocklist, fast_blocklist):
        blocklist.add_rule("domain", "evil.com", "test")
        fast_blocklist.invalidate()
        entities = _make_entities(domains=["evil.com"])
        result = fast_blocklist.evaluate(entities, None, 1)
        assert result is not None
        finding, _ = result
        assert finding.iocs.get("domains") == ["evil.com"]

    def test_file_finding_has_file_ioc(self, blocklist, fast_blocklist):
        blocklist.add_rule("file_path", "/tmp/bad*", "test")
        fast_blocklist.invalidate()
        entities = _make_entities(
            processes=[("bash", 100)],
            file_edges=["/tmp/bad_file"],
        )
        result = fast_blocklist.evaluate(entities, None, 1)
        assert result is not None
        finding, _ = result
        assert finding.iocs.get("files") == ["/tmp/bad_file"]


# ── Invalidation ──


class TestInvalidation:
    def test_invalidation_triggers_refresh(self, blocklist, fast_blocklist):
        # Initial: no rules
        entities = _make_entities(
            processes=[("curl", 100)],
            connected_edges=["1.2.3.4"],
        )
        result = fast_blocklist.evaluate(entities, None, 1)
        assert result is None

        # Add rule and invalidate
        blocklist.add_rule("dst_ip", "1.2.3.4", "bad ip")
        fast_blocklist.invalidate()

        # Now should match
        result = fast_blocklist.evaluate(entities, None, 1)
        assert result is not None


# ── Chain building helper ──


class TestBuildChainFromCaches:
    def test_build_chain_with_ancestry(self):
        from agent.processor import entity_extractor

        entity_extractor._ppid_cache[300] = 200
        entity_extractor._ppid_cache[200] = 100
        entity_extractor._ppid_cache[100] = 0
        entity_extractor._name_cache[200] = "bash"
        entity_extractor._name_cache[100] = "Terminal"
        entity_extractor._username_cache[300] = "alice"

        try:
            chain = _build_chain_from_caches(300, "ncat")
            assert chain == ["USER:alice", "Terminal", "bash", "ncat"]
        finally:
            for pid in (300, 200, 100):
                entity_extractor._ppid_cache.pop(pid, None)
                entity_extractor._name_cache.pop(pid, None)
            entity_extractor._username_cache.pop(300, None)

    def test_build_chain_no_ancestry(self):
        chain = _build_chain_from_caches(99999, "solo_process")
        assert chain == ["solo_process"]

    def test_build_chain_no_username(self):
        from agent.processor import entity_extractor

        entity_extractor._ppid_cache[400] = 0

        try:
            chain = _build_chain_from_caches(400, "myproc")
            assert chain == ["myproc"]
        finally:
            entity_extractor._ppid_cache.pop(400, None)


# ── Integration with response engine ──


class TestResponseIntegration:
    def test_trigger_response_called_on_match(self, blocklist, fast_blocklist):
        """Verify that a fast-path hit produces a finding suitable for _trigger_response."""
        blocklist.add_rule("dst_ip", "6.6.6.6", "evil ip")
        fast_blocklist.invalidate()
        entities = _make_entities(
            processes=[("curl", 100)],
            connected_edges=["6.6.6.6"],
        )
        result = fast_blocklist.evaluate(entities, None, 42)
        assert result is not None
        finding, match_desc = result

        # Verify finding is compatible with _trigger_response expectations
        assert finding.severity == "critical"
        assert len(finding.evidence_event_ids) == 1
        assert finding.evidence_event_ids[0] == 42
        assert finding.chain  # Non-empty chain
        assert finding.id  # Has UUID
        assert finding.timestamp  # Has timestamp


# ── Chain building from PidIndex ──


class TestBuildChainFromPidIndex:
    def test_chain_from_pid_index(self):
        """PidIndex has full ancestry — no entity_extractor caches needed."""
        from agent.graph.pid_index import PidIndex

        mock_idx = PidIndex()
        mock_idx._built = True
        # containerd-shim(1) → runc(50) → perl(100)
        mock_idx.on_upsert("host:1:1000", 1, 0, "containerd-shim")
        mock_idx.on_upsert("host:50:2000", 50, 1, "runc")
        mock_idx.on_upsert("host:100:3000", 100, 50, "perl")

        with patch("agent.processor.synchronous_enforcer.get_pid_index", return_value=mock_idx):
            chain = _build_chain_from_caches(100, "perl")

        assert chain == ["containerd-shim", "runc", "perl"]

    def test_fallback_to_extractor_caches(self):
        """When PidIndex is not built, fall back to entity_extractor caches."""
        from agent.graph.pid_index import PidIndex
        from agent.processor import entity_extractor

        mock_idx = PidIndex()
        # _built is False by default

        entity_extractor._ppid_cache[100] = 50
        entity_extractor._ppid_cache[50] = 0
        entity_extractor._name_cache[50] = "bash"

        try:
            with patch("agent.processor.synchronous_enforcer.get_pid_index", return_value=mock_idx):
                chain = _build_chain_from_caches(100, "perl")
            assert chain == ["bash", "perl"]
        finally:
            entity_extractor._ppid_cache.pop(100, None)
            entity_extractor._ppid_cache.pop(50, None)
            entity_extractor._name_cache.pop(50, None)

    def test_index_and_cache_merge(self):
        """Index has ppid for 100→50 but no name for 50; name_cache fills the gap."""
        from agent.graph.pid_index import PidIndex
        from agent.processor import entity_extractor

        mock_idx = PidIndex()
        mock_idx._built = True
        # Index knows 100's parent is 50, but doesn't know 50's name
        mock_idx.on_upsert("host:100:3000", 100, 50, "perl")
        mock_idx.on_upsert("host:50:2000", 50, 0)  # no name stored in index

        # entity_extractor cache has the name for pid 50
        entity_extractor._name_cache[50] = "bash"

        try:
            with patch("agent.processor.synchronous_enforcer.get_pid_index", return_value=mock_idx):
                chain = _build_chain_from_caches(100, "perl")
            assert chain == ["bash", "perl"]
        finally:
            entity_extractor._name_cache.pop(50, None)


# ── Scoped rules (Gap 2 fix) ──


class TestScopedRules:
    def test_scoped_rule_not_in_fast_bucket(self, blocklist, fast_blocklist):
        """A rule with chain_filter should go to _scoped_rules, not _process_names."""
        blocklist.add_rule("process_name", "ncat*", "netcat", chain_filter="** > bash > ncat*")
        fast_blocklist.invalidate()
        fast_blocklist._refresh_if_stale()
        assert len(fast_blocklist._process_names) == 0
        assert len(fast_blocklist._scoped_rules) == 1

    def test_scoped_rule_blocks_matching_chain(self, blocklist, fast_blocklist):
        """Scoped process_name rule with matching chain ancestry → hit."""
        blocklist.add_rule("process_name", "ncat*", "scoped ncat", chain_filter="** > containerd-shim > ** > ncat*")
        fast_blocklist.invalidate()

        from agent.graph.pid_index import PidIndex

        mock_idx = PidIndex()
        mock_idx._built = True
        mock_idx.on_upsert("host:1:1000", 1, 0, "containerd-shim")
        mock_idx.on_upsert("host:50:2000", 50, 1, "runc")
        mock_idx.on_upsert("host:100:3000", 100, 50, "ncat")

        with patch("agent.processor.synchronous_enforcer.get_pid_index", return_value=mock_idx):
            entities = _make_entities(processes=[("ncat", 100)])
            result = fast_blocklist.evaluate(entities, None, 42)

        assert result is not None
        finding, _ = result
        assert finding.severity == "critical"

    def test_scoped_rule_passes_non_matching_chain(self, blocklist, fast_blocklist):
        """Scoped rule with non-matching chain → no hit."""
        blocklist.add_rule("process_name", "ncat*", "scoped ncat", chain_filter="** > containerd-shim > ** > ncat*")
        fast_blocklist.invalidate()

        from agent.graph.pid_index import PidIndex

        mock_idx = PidIndex()
        mock_idx._built = True
        mock_idx.on_upsert("host:50:2000", 50, 0, "bash")
        mock_idx.on_upsert("host:100:3000", 100, 50, "perl")

        with patch("agent.processor.synchronous_enforcer.get_pid_index", return_value=mock_idx):
            entities = _make_entities(processes=[("perl", 100)])
            result = fast_blocklist.evaluate(entities, None, 42)

        assert result is None

    def test_unscoped_rule_stays_in_fast_bucket(self, blocklist, fast_blocklist):
        """A rule without chain_filter should stay in the fast bucket."""
        blocklist.add_rule("process_name", "ncat*", "netcat")
        fast_blocklist.invalidate()
        fast_blocklist._refresh_if_stale()
        assert len(fast_blocklist._process_names) == 1
        assert len(fast_blocklist._scoped_rules) == 0

    def test_scoped_ip_rule_matching(self, blocklist, fast_blocklist):
        """Scoped dst_ip rule with matching chain → hit."""
        blocklist.add_rule("dst_ip", "6.6.6.6", "evil ip", chain_filter="** > curl")
        fast_blocklist.invalidate()

        from agent.graph.pid_index import PidIndex

        mock_idx = PidIndex()
        mock_idx._built = True
        mock_idx.on_upsert("host:100:3000", 100, 0, "curl")

        with patch("agent.processor.synchronous_enforcer.get_pid_index", return_value=mock_idx):
            entities = _make_entities(processes=[("curl", 100)], connected_edges=["6.6.6.6"])
            result = fast_blocklist.evaluate(entities, None, 42)

        assert result is not None
        finding, _ = result
        assert "6.6.6.6" in finding.title

    def test_scoped_ip_rule_non_matching(self, blocklist, fast_blocklist):
        """Scoped dst_ip rule with non-matching chain → no hit."""
        blocklist.add_rule("dst_ip", "6.6.6.6", "evil ip", chain_filter="** > curl")
        fast_blocklist.invalidate()

        from agent.graph.pid_index import PidIndex

        mock_idx = PidIndex()
        mock_idx._built = True
        mock_idx.on_upsert("host:100:3000", 100, 0, "wget")

        with patch("agent.processor.synchronous_enforcer.get_pid_index", return_value=mock_idx):
            entities = _make_entities(processes=[("wget", 100)], connected_edges=["6.6.6.6"])
            result = fast_blocklist.evaluate(entities, None, 42)

        assert result is None
