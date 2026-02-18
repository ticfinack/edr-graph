"""Tests for Phase 2 Commit 1: Graph Schema Expansion (2A).

Tests the new Domain, File, and RegistryKey node types, new edge types,
deduplication, and file_read_tracking config gating.
"""

from datetime import datetime

from agent.processor.entity_extractor import ExtractedEntities, extract_entities
from agent.schema.ocsf_types import (
    DeviceInfo,
    DnsActivity,
    FileActivity,
    ProcessInfo,
    RegistryActivity,
)


class TestDnsActivityExtraction:
    def test_dns_creates_domain_and_edges(self):
        """A dns_resolve event creates Domain node, IP node, and correct edges."""
        event = DnsActivity(
            activity_id=1,
            time=datetime(2025, 6, 1, 12, 0),
            process=ProcessInfo(
                pid=1234,
                name="curl",
                created_time=datetime(2025, 6, 1, 12, 0),
            ),
            query_domain="evil.example.com",
            resolved_ips=["93.184.216.34", "93.184.216.35"],
            device=DeviceInfo(hostname="testhost"),
        )
        entities = extract_entities(event, event_id=100)

        # Domain node created
        assert len(entities.domains) == 1
        domain = entities.domains[0]
        assert domain.name == "evil.example.com"
        assert domain.tld == "com"
        assert domain.is_dga_candidate is False

        # Process node created
        assert len(entities.processes) == 1
        assert entities.processes[0].name == "curl"

        # IP nodes created for resolved IPs
        assert len(entities.ips) == 2
        ip_addrs = {ip.address for ip in entities.ips}
        assert ip_addrs == {"93.184.216.34", "93.184.216.35"}

        # RESOLVED edge: Process -> Domain
        assert len(entities.resolved_edges) == 1
        assert entities.resolved_edges[0]["domain_id"] == "evil.example.com"

        # RESOLVES_TO edges: Domain -> IP
        assert len(entities.resolves_to_edges) == 2
        resolves_ips = {e["ip_id"] for e in entities.resolves_to_edges}
        assert resolves_ips == {"93.184.216.34", "93.184.216.35"}

    def test_dns_without_resolved_ips(self):
        """DNS event with no resolved IPs still creates Domain node."""
        event = DnsActivity(
            activity_id=1,
            time=datetime(2025, 6, 1, 12, 0),
            process=ProcessInfo(pid=10, name="dig", created_time=datetime(2025, 6, 1, 12, 0)),
            query_domain="nxdomain.test.",
            resolved_ips=[],
            device=DeviceInfo(hostname="testhost"),
        )
        entities = extract_entities(event, event_id=101)

        assert len(entities.domains) == 1
        assert entities.domains[0].name == "nxdomain.test"  # trailing dot stripped
        assert len(entities.ips) == 0
        assert len(entities.resolves_to_edges) == 0

    def test_dns_domain_normalization(self):
        """Domain names are lowercased and trailing dots stripped."""
        event = DnsActivity(
            activity_id=1,
            time=datetime(2025, 6, 1, 12, 0),
            query_domain="Google.COM.",
            device=DeviceInfo(hostname="testhost"),
        )
        entities = extract_entities(event, event_id=102)
        assert entities.domains[0].name == "google.com"
        assert entities.domains[0].tld == "com"


class TestFileActivityExtraction:
    def test_file_modify_creates_file_node(self):
        """A file_modify event creates File node with correct fields."""
        event = FileActivity(
            activity_id=3,  # Modify
            time=datetime(2025, 6, 1, 12, 0),
            process=ProcessInfo(
                pid=5678,
                name="vim",
                created_time=datetime(2025, 6, 1, 12, 0),
            ),
            file_path="/etc/passwd",
            file_hash_sha256="abc123def456",
            file_size=2048,
            device=DeviceInfo(hostname="testhost"),
        )
        entities = extract_entities(event, event_id=200)

        assert len(entities.files) == 1
        f = entities.files[0]
        assert f.path == "/etc/passwd"
        assert f.hash_sha256 == "abc123def456"
        assert f.size == 2048

        assert len(entities.file_edges) == 1
        assert entities.file_edges[0]["operation"] == "MODIFIED"

    def test_file_without_hash(self):
        """File node created without hash when file doesn't exist."""
        event = FileActivity(
            activity_id=1,  # Create
            time=datetime(2025, 6, 1, 12, 0),
            process=ProcessInfo(pid=100, name="touch", created_time=datetime(2025, 6, 1, 12, 0)),
            file_path="/tmp/new_file.txt",
            file_hash_sha256=None,
            file_size=None,
            device=DeviceInfo(hostname="testhost"),
        )
        entities = extract_entities(event, event_id=201)

        assert len(entities.files) == 1
        assert entities.files[0].hash_sha256 is None
        assert entities.files[0].size is None
        assert entities.file_edges[0]["operation"] == "CREATED"

    def test_file_delete_edge(self):
        """File delete event creates DELETED operation edge."""
        event = FileActivity(
            activity_id=4,  # Delete
            time=datetime(2025, 6, 1, 12, 0),
            process=ProcessInfo(pid=200, name="rm", created_time=datetime(2025, 6, 1, 12, 0)),
            file_path="/tmp/malware.exe",
            device=DeviceInfo(hostname="testhost"),
        )
        entities = extract_entities(event, event_id=202)
        assert entities.file_edges[0]["operation"] == "DELETED"

    def test_file_read_edge(self):
        """File read event creates READ operation edge."""
        event = FileActivity(
            activity_id=2,  # Read
            time=datetime(2025, 6, 1, 12, 0),
            process=ProcessInfo(pid=300, name="cat", created_time=datetime(2025, 6, 1, 12, 0)),
            file_path="/etc/shadow",
            device=DeviceInfo(hostname="testhost"),
        )
        entities = extract_entities(event, event_id=203)
        assert entities.file_edges[0]["operation"] == "READ"


class TestRegistryActivityExtraction:
    def test_registry_modify_creates_node(self):
        """A registry_modify event creates RegistryKey node with previous_data."""
        event = RegistryActivity(
            activity_id=3,  # Modify
            time=datetime(2025, 6, 1, 12, 0),
            process=ProcessInfo(
                pid=9999,
                name="malware.exe",
                created_time=datetime(2025, 6, 1, 12, 0),
            ),
            reg_path=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            reg_value_name="EvilStartup",
            reg_value_data=r"C:\malware.exe",
            reg_previous_data=None,
            device=DeviceInfo(hostname="testhost"),
        )
        entities = extract_entities(event, event_id=300)

        assert len(entities.registry_keys) == 1
        reg = entities.registry_keys[0]
        assert reg.path == r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        assert reg.value_name == "EvilStartup"
        assert reg.value_data == r"C:\malware.exe"

        # ID includes value_name
        assert reg.id == r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\EvilStartup"

        assert len(entities.registry_edges) == 1
        assert entities.registry_edges[0]["operation"] == "MODIFIED"

    def test_registry_create_edge(self):
        """Registry create event creates CREATED operation edge."""
        event = RegistryActivity(
            activity_id=1,
            time=datetime(2025, 6, 1, 12, 0),
            process=ProcessInfo(pid=500, name="reg.exe", created_time=datetime(2025, 6, 1, 12, 0)),
            reg_path=r"HKCU\SOFTWARE\TestKey",
            device=DeviceInfo(hostname="testhost"),
        )
        entities = extract_entities(event, event_id=301)
        assert entities.registry_edges[0]["operation"] == "CREATED"

    def test_registry_delete_edge(self):
        """Registry delete event creates DELETED operation edge."""
        event = RegistryActivity(
            activity_id=4,
            time=datetime(2025, 6, 1, 12, 0),
            process=ProcessInfo(pid=600, name="reg.exe", created_time=datetime(2025, 6, 1, 12, 0)),
            reg_path=r"HKLM\SOFTWARE\OldKey",
            device=DeviceInfo(hostname="testhost"),
        )
        entities = extract_entities(event, event_id=302)
        assert entities.registry_edges[0]["operation"] == "DELETED"


class TestDeduplication:
    def test_domain_deduplication(self):
        """Duplicate Domain nodes are deduplicated (upserted, not duplicated)."""
        event1 = DnsActivity(
            activity_id=1,
            time=datetime(2025, 6, 1, 12, 0),
            query_domain="example.com",
            resolved_ips=["1.2.3.4"],
            device=DeviceInfo(hostname="testhost"),
        )
        event2 = DnsActivity(
            activity_id=1,
            time=datetime(2025, 6, 1, 12, 5),
            query_domain="example.com",
            resolved_ips=["1.2.3.4"],
            device=DeviceInfo(hostname="testhost"),
        )
        e1 = extract_entities(event1, event_id=400)
        e2 = extract_entities(event2, event_id=401)

        # Simulate batch deduplication (same logic as GraphBuilder.write_batch)
        domains: dict[str, object] = {}
        for entities in [e1, e2]:
            for d in entities.domains:
                existing = domains.get(d.id)
                if existing is None or d.last_seen > existing.last_seen:
                    domains[d.id] = d

        assert len(domains) == 1
        assert domains["example.com"].last_seen == datetime(2025, 6, 1, 12, 5)

    def test_file_deduplication(self):
        """Duplicate File nodes are deduplicated."""
        event1 = FileActivity(
            activity_id=3,
            time=datetime(2025, 6, 1, 12, 0),
            file_path="/etc/passwd",
            file_hash_sha256="hash1",
            device=DeviceInfo(hostname="testhost"),
        )
        event2 = FileActivity(
            activity_id=3,
            time=datetime(2025, 6, 1, 12, 5),
            file_path="/etc/passwd",
            file_hash_sha256="hash2",
            device=DeviceInfo(hostname="testhost"),
        )
        e1 = extract_entities(event1, event_id=410)
        e2 = extract_entities(event2, event_id=411)

        files: dict[str, object] = {}
        for entities in [e1, e2]:
            for f in entities.files:
                existing = files.get(f.id)
                if existing is None or f.last_seen > existing.last_seen:
                    files[f.id] = f

        assert len(files) == 1
        # Latest hash wins
        assert files["/etc/passwd"].hash_sha256 == "hash2"

    def test_registry_deduplication(self):
        """Duplicate RegistryKey nodes are deduplicated."""
        event1 = RegistryActivity(
            activity_id=3,
            time=datetime(2025, 6, 1, 12, 0),
            reg_path=r"HKLM\SOFTWARE\Test",
            reg_value_name="Val",
            reg_value_data="old",
            device=DeviceInfo(hostname="testhost"),
        )
        event2 = RegistryActivity(
            activity_id=3,
            time=datetime(2025, 6, 1, 12, 5),
            reg_path=r"HKLM\SOFTWARE\Test",
            reg_value_name="Val",
            reg_value_data="new",
            device=DeviceInfo(hostname="testhost"),
        )
        e1 = extract_entities(event1, event_id=420)
        e2 = extract_entities(event2, event_id=421)

        regs: dict[str, object] = {}
        for entities in [e1, e2]:
            for r in entities.registry_keys:
                existing = regs.get(r.id)
                if existing is None or r.last_seen > existing.last_seen:
                    regs[r.id] = r

        assert len(regs) == 1
        assert regs[r"HKLM\SOFTWARE\Test\Val"].value_data == "new"


class TestFileReadTrackingGating:
    def test_read_edges_suppressed_when_disabled(self):
        """file_read_tracking: false suppresses READ edge creation."""
        event = FileActivity(
            activity_id=2,  # Read
            time=datetime(2025, 6, 1, 12, 0),
            process=ProcessInfo(pid=300, name="cat", created_time=datetime(2025, 6, 1, 12, 0)),
            file_path="/etc/shadow",
            device=DeviceInfo(hostname="testhost"),
        )
        entities = extract_entities(event, event_id=500)

        # Before filtering - READ edge exists
        assert len(entities.file_edges) == 1
        assert entities.file_edges[0]["operation"] == "READ"

        # Simulate config gating (same logic as processor_thread)
        file_read_tracking = False
        if not file_read_tracking:
            entities.file_edges = [
                e for e in entities.file_edges if e["operation"] != "READ"
            ]

        assert len(entities.file_edges) == 0

    def test_non_read_edges_preserved_when_disabled(self):
        """Non-READ file edges are preserved when file_read_tracking is disabled."""
        event = FileActivity(
            activity_id=1,  # Create
            time=datetime(2025, 6, 1, 12, 0),
            process=ProcessInfo(pid=300, name="touch", created_time=datetime(2025, 6, 1, 12, 0)),
            file_path="/tmp/test.txt",
            device=DeviceInfo(hostname="testhost"),
        )
        entities = extract_entities(event, event_id=501)

        # Apply config gating
        file_read_tracking = False
        if not file_read_tracking:
            entities.file_edges = [
                e for e in entities.file_edges if e["operation"] != "READ"
            ]

        # CREATED edge is preserved
        assert len(entities.file_edges) == 1
        assert entities.file_edges[0]["operation"] == "CREATED"


class TestBackwardCompatibility:
    def test_existing_process_activity_unchanged(self):
        """Existing ProcessActivity extraction still works."""
        from agent.schema.ocsf_types import ActorInfo, ProcessActivity, UserInfo

        event = ProcessActivity(
            activity_id=1,
            severity_id=1,
            time=datetime(2025, 6, 1, 12, 0),
            actor=ActorInfo(user=UserInfo(name="alice")),
            process=ProcessInfo(
                pid=1234,
                name="curl",
                created_time=datetime(2025, 6, 1, 12, 0),
            ),
            device=DeviceInfo(hostname="testhost"),
        )
        entities = extract_entities(event, event_id=600)

        assert len(entities.users) == 1
        assert len(entities.processes) == 1
        assert len(entities.spawned_edges) == 1
        # New fields should be empty
        assert len(entities.domains) == 0
        assert len(entities.files) == 0
        assert len(entities.registry_keys) == 0
        assert len(entities.resolved_edges) == 0
        assert len(entities.file_edges) == 0
        assert len(entities.registry_edges) == 0

    def test_existing_network_activity_unchanged(self):
        """Existing NetworkActivity extraction still works."""
        from agent.schema.ocsf_types import NetworkActivity, NetworkEndpoint

        event = NetworkActivity(
            activity_id=1,
            severity_id=1,
            time=datetime(2025, 6, 1, 12, 0),
            process=ProcessInfo(
                pid=1234, name="curl", created_time=datetime(2025, 6, 1, 12, 0)
            ),
            dst_endpoint=NetworkEndpoint(ip="93.184.216.34", port=443),
            device=DeviceInfo(hostname="testhost"),
        )
        entities = extract_entities(event, event_id=601)

        assert len(entities.processes) == 1
        assert len(entities.ips) == 1
        assert len(entities.connected_edges) == 1
