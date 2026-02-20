"""Tests for fleet serializers: Pydantic <-> protobuf conversion."""

import json
from datetime import datetime

from agent.fleet.proto import fleet_pb2
from agent.fleet.serializers import finding_to_proto, proto_to_finding_dict
from agent.schema.graph_types import ChainStep, SecurityFinding


class TestFindingToProto:
    def test_basic_conversion(self):
        finding = SecurityFinding(
            id="test-001",
            timestamp=datetime(2025, 6, 1, 12, 0, 0),
            severity="high",
            title="Test finding",
            description="A test finding",
            affected_entities=["process:bash"],
            evidence_event_ids=[1, 2],
            recommendation="Investigate",
            chain=[],
            affected_pids=[100],
            iocs={"ips": ["1.2.3.4"]},
        )
        proto = finding_to_proto(finding)
        assert proto.id == "test-001"
        assert proto.severity == "high"
        assert proto.title == "Test finding"
        assert list(proto.affected_entities) == ["process:bash"]
        assert list(proto.evidence_event_ids) == [1, 2]
        assert list(proto.affected_pids) == [100]
        assert json.loads(proto.iocs_json) == {"ips": ["1.2.3.4"]}

    def test_chain_steps_preserved(self):
        finding = SecurityFinding(
            id="test-002",
            timestamp=datetime(2025, 6, 1, 12, 0, 0),
            severity="critical",
            title="Chain test",
            description="Test chain preservation",
            affected_entities=[],
            evidence_event_ids=[],
            recommendation="Block",
            chain=[
                ChainStep(
                    entity_type="user",
                    entity_id="root",
                    entity_name="root",
                    pid=None,
                    timestamp=datetime(2025, 6, 1, 11, 0, 0),
                ),
                ChainStep(
                    entity_type="process",
                    entity_id="host:42:0",
                    entity_name="bash",
                    pid=42,
                    timestamp=datetime(2025, 6, 1, 11, 30, 0),
                ),
            ],
        )
        proto = finding_to_proto(finding)
        assert len(proto.chain) == 2
        assert proto.chain[0].entity_type == "user"
        assert proto.chain[0].entity_name == "root"
        assert proto.chain[0].pid == 0  # None -> 0
        assert proto.chain[1].entity_type == "process"
        assert proto.chain[1].pid == 42

    def test_empty_iocs(self):
        finding = SecurityFinding(
            id="test-003",
            timestamp=datetime(2025, 6, 1, 12, 0, 0),
            severity="low",
            title="No IOCs",
            description="Test",
            affected_entities=[],
            evidence_event_ids=[],
            recommendation="None",
            chain=[],
        )
        proto = finding_to_proto(finding)
        assert json.loads(proto.iocs_json) == {}

    def test_timestamp_is_unix(self):
        ts = datetime(2025, 6, 1, 12, 0, 0)
        finding = SecurityFinding(
            id="test-004",
            timestamp=ts,
            severity="info",
            title="TS test",
            description="Test",
            affected_entities=[],
            evidence_event_ids=[],
            recommendation="None",
            chain=[],
        )
        proto = finding_to_proto(finding)
        assert proto.timestamp == int(ts.timestamp())


class TestProtoToFindingDict:
    def test_roundtrip(self):
        finding = SecurityFinding(
            id="roundtrip-001",
            timestamp=datetime(2025, 6, 1, 12, 0, 0),
            severity="medium",
            title="Roundtrip test",
            description="Testing roundtrip conversion",
            affected_entities=["ip:10.0.0.1"],
            evidence_event_ids=[10, 20, 30],
            recommendation="Monitor",
            chain=[
                ChainStep(
                    entity_type="process",
                    entity_id="host:99:0",
                    entity_name="wget",
                    pid=99,
                    timestamp=datetime(2025, 6, 1, 11, 0, 0),
                ),
            ],
            affected_pids=[99],
            iocs={"domains": ["bad.example.com"]},
        )

        proto = finding_to_proto(finding)
        result = proto_to_finding_dict(proto)

        assert result["id"] == "roundtrip-001"
        assert result["severity"] == "medium"
        assert result["affected_entities"] == ["ip:10.0.0.1"]
        assert result["evidence_event_ids"] == [10, 20, 30]
        assert result["affected_pids"] == [99]
        assert result["iocs"] == {"domains": ["bad.example.com"]}
        assert len(result["chain"]) == 1
        assert result["chain"][0]["entity_name"] == "wget"
