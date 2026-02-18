"""Tests for entity extraction and graph building."""

from datetime import datetime

from agent.processor.entity_extractor import extract_entities
from agent.schema.ocsf_types import (
    ActorInfo,
    Authentication,
    DeviceInfo,
    NetworkActivity,
    NetworkEndpoint,
    ProcessActivity,
    ProcessInfo,
    UserInfo,
)


class TestEntityExtraction:
    def test_process_activity_extraction(self):
        event = ProcessActivity(
            activity_id=1,
            severity_id=1,
            time=datetime(2025, 1, 15, 10, 0),
            actor=ActorInfo(user=UserInfo(name="alice")),
            process=ProcessInfo(
                pid=1234,
                name="curl",
                cmd_line="curl https://example.com",
                exe_path="/usr/bin/curl",
                created_time=datetime(2025, 1, 15, 10, 0),
            ),
            device=DeviceInfo(hostname="testhost"),
        )
        entities = extract_entities(event, event_id=1)

        assert len(entities.users) == 1
        assert entities.users[0].id == "alice"

        assert len(entities.processes) == 1
        assert entities.processes[0].name == "curl"
        assert entities.processes[0].pid == 1234

        assert len(entities.spawned_edges) == 1
        assert entities.spawned_edges[0]["user_id"] == "alice"

    def test_network_activity_extraction(self):
        event = NetworkActivity(
            activity_id=1,
            severity_id=1,
            time=datetime(2025, 1, 15, 10, 0),
            process=ProcessInfo(
                pid=1234,
                name="curl",
                created_time=datetime(2025, 1, 15, 10, 0),
            ),
            dst_endpoint=NetworkEndpoint(ip="93.184.216.34", port=443),
            device=DeviceInfo(hostname="testhost"),
        )
        entities = extract_entities(event, event_id=2)

        assert len(entities.processes) == 1
        assert len(entities.ips) == 1
        assert entities.ips[0].id == "93.184.216.34"
        assert entities.ips[0].is_private is False

        assert len(entities.connected_edges) == 1
        assert entities.connected_edges[0]["dst_port"] == 443

    def test_private_ip_detection(self):
        event = NetworkActivity(
            activity_id=1,
            severity_id=1,
            time=datetime(2025, 1, 15, 10, 0),
            process=ProcessInfo(pid=1, name="test", created_time=datetime(2025, 1, 15, 10, 0)),
            dst_endpoint=NetworkEndpoint(ip="192.168.1.1", port=80),
            device=DeviceInfo(hostname="testhost"),
        )
        entities = extract_entities(event, event_id=3)
        assert entities.ips[0].is_private is True

    def test_authentication_extraction(self):
        event = Authentication(
            activity_id=1,
            status_id=1,
            severity_id=1,
            time=datetime(2025, 1, 15, 10, 0),
            user=UserInfo(name="bob"),
            src_endpoint=NetworkEndpoint(ip="10.0.0.1"),
            device=DeviceInfo(hostname="testhost"),
        )
        entities = extract_entities(event, event_id=4)

        assert len(entities.users) == 1
        assert entities.users[0].id == "bob"
        assert len(entities.ips) == 1
        assert entities.ips[0].id == "10.0.0.1"

    def test_process_without_actor(self):
        event = ProcessActivity(
            activity_id=1,
            severity_id=1,
            time=datetime(2025, 1, 15, 10, 0),
            process=ProcessInfo(
                pid=1,
                name="init",
                created_time=datetime(2025, 1, 15, 10, 0),
            ),
            device=DeviceInfo(hostname="testhost"),
        )
        entities = extract_entities(event, event_id=5)

        assert len(entities.processes) == 1
        assert len(entities.users) == 0
        assert len(entities.spawned_edges) == 0
