"""Tests for Neo4j client with mocked driver."""

import sys
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def mock_neo4j_module():
    """Mock the neo4j module since it's not installed in the test environment."""
    mock_neo4j = MagicMock()
    mock_driver = MagicMock()
    mock_neo4j.GraphDatabase.driver.return_value = mock_driver
    mock_session = MagicMock()
    mock_driver.session.return_value.__enter__ = MagicMock(return_value=mock_session)
    mock_driver.session.return_value.__exit__ = MagicMock(return_value=False)

    with patch.dict(sys.modules, {"neo4j": mock_neo4j}):
        yield mock_neo4j, mock_driver, mock_session


def _make_client(mock_neo4j):
    """Create a Neo4jClient with mocked driver."""
    # Force re-import to pick up the mocked neo4j module
    import importlib
    import server.neo4j_client
    importlib.reload(server.neo4j_client)
    from server.neo4j_client import Neo4jClient
    return Neo4jClient("bolt://localhost:7687", "neo4j", "test")


class TestNeo4jClientRegistration:
    def test_register_agent(self, mock_neo4j_module):
        mock_neo4j, mock_driver, mock_session = mock_neo4j_module
        client = _make_client(mock_neo4j)

        client.register_agent({
            "agent_id": "agent-001",
            "hostname": "test-host",
            "platform": "linux",
            "os_version": "5.15",
            "agent_version": "0.1.0",
            "registered_at": 1700000000,
        })

        mock_session.run.assert_called_once()
        query = mock_session.run.call_args[0][0]
        assert "MERGE (h:Host" in query
        params = mock_session.run.call_args[0][1]
        assert params["agent_id"] == "agent-001"
        assert params["hostname"] == "test-host"

    def test_update_heartbeat(self, mock_neo4j_module):
        mock_neo4j, mock_driver, mock_session = mock_neo4j_module
        client = _make_client(mock_neo4j)

        client.update_heartbeat("agent-001", 1700000100)

        mock_session.run.assert_called_once()
        params = mock_session.run.call_args[0][1]
        assert params["agent_id"] == "agent-001"
        assert params["timestamp"] == 1700000100


class TestNeo4jClientIngestFinding:
    def test_ingest_finding_creates_nodes_and_edges(self, mock_neo4j_module):
        mock_neo4j, mock_driver, mock_session = mock_neo4j_module
        client = _make_client(mock_neo4j)

        client.ingest_finding("agent-001", {
            "id": "finding-001",
            "timestamp": 1700000000,
            "severity": "high",
            "title": "Test",
            "description": "Test finding",
            "recommendation": "Block",
            "affected_entities": ["process:bash"],
            "affected_pids": [42],
            "iocs": {"ips": ["10.0.0.1"], "domains": ["evil.com"]},
        })

        # Should have 3 calls: main finding query + IP IOC + Domain IOC
        assert mock_session.run.call_count == 3

    def test_ingest_finding_without_iocs(self, mock_neo4j_module):
        mock_neo4j, mock_driver, mock_session = mock_neo4j_module
        client = _make_client(mock_neo4j)

        client.ingest_finding("agent-001", {
            "id": "finding-002",
            "timestamp": 1700000000,
            "severity": "low",
            "title": "No IOCs",
            "description": "Test",
            "recommendation": "Monitor",
            "iocs": {},
        })

        # Only 1 call: the main finding query (no IOC nodes)
        assert mock_session.run.call_count == 1


class TestNeo4jClientOcsfEvent:
    def test_ingest_network_event(self, mock_neo4j_module):
        mock_neo4j, mock_driver, mock_session = mock_neo4j_module
        client = _make_client(mock_neo4j)

        client.ingest_ocsf_event("agent-001", {
            "class_uid": 4001,
            "dst_endpoint": {"ip": "10.0.0.1"},
            "process": {"name": "curl"},
            "time": "2025-01-15T10:30:00",
        })

        mock_session.run.assert_called_once()
        query = mock_session.run.call_args[0][0]
        assert "CONNECTED_TO" in query

    def test_ingest_dns_event(self, mock_neo4j_module):
        mock_neo4j, mock_driver, mock_session = mock_neo4j_module
        client = _make_client(mock_neo4j)

        client.ingest_ocsf_event("agent-001", {
            "class_uid": 4003,
            "query_domain": "example.com",
            "time": "2025-01-15T10:30:00",
        })

        mock_session.run.assert_called_once()
        query = mock_session.run.call_args[0][0]
        assert "RESOLVED" in query

    def test_ignores_unknown_event_class(self, mock_neo4j_module):
        mock_neo4j, mock_driver, mock_session = mock_neo4j_module
        client = _make_client(mock_neo4j)

        client.ingest_ocsf_event("agent-001", {
            "class_uid": 9999,
            "data": "unknown",
        })

        mock_session.run.assert_not_called()
