"""Tests for fleet configuration: Settings fields, YAML loading, CLI overrides."""

from agent.config import Settings, generate_default_config, load_config_file


class TestFleetSettingsDefaults:
    def test_fleet_disabled_by_default(self):
        s = Settings()
        assert s.fleet_enabled is False

    def test_fleet_url_empty_by_default(self):
        s = Settings()
        assert s.fleet_url == ""

    def test_fleet_forward_interval_default(self):
        s = Settings()
        assert s.fleet_forward_interval == 10.0

    def test_fleet_heartbeat_interval_default(self):
        s = Settings()
        assert s.fleet_heartbeat_interval == 30.0

    def test_fleet_queue_max_size_default(self):
        s = Settings()
        assert s.fleet_queue_max_size == 10000

    def test_fleet_retry_max_default(self):
        s = Settings()
        assert s.fleet_retry_max == 5

    def test_fleet_forward_events_disabled_by_default(self):
        s = Settings()
        assert s.fleet_forward_events is False


class TestFleetYamlConfig:
    def test_load_fleet_enabled(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text("fleet:\n  enabled: true\n  url: server:50051\n")
        result = load_config_file(f)
        assert result["fleet_enabled"] is True
        assert result["fleet_url"] == "server:50051"

    def test_load_fleet_forward_interval(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text("fleet:\n  forward_interval: 30\n")
        result = load_config_file(f)
        assert result["fleet_forward_interval"] == 30

    def test_load_fleet_heartbeat_interval(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text("fleet:\n  heartbeat_interval: 60\n")
        result = load_config_file(f)
        assert result["fleet_heartbeat_interval"] == 60

    def test_load_fleet_forward_events(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text("fleet:\n  forward_events: true\n")
        result = load_config_file(f)
        assert result["fleet_forward_events"] is True

    def test_load_fleet_tls_paths(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text(
            "fleet:\n"
            "  ca_cert: /path/to/ca.pem\n"
            "  client_cert: /path/to/client.pem\n"
            "  client_key: /path/to/client-key.pem\n"
        )
        result = load_config_file(f)
        assert result["fleet_ca_cert"] == "/path/to/ca.pem"
        assert result["fleet_client_cert"] == "/path/to/client.pem"
        assert result["fleet_client_key"] == "/path/to/client-key.pem"

    def test_load_fleet_queue_settings(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text("fleet:\n  queue_max_size: 5000\n  retry_max: 3\n")
        result = load_config_file(f)
        assert result["fleet_queue_max_size"] == 5000
        assert result["fleet_retry_max"] == 3

    def test_fleet_not_present_returns_no_fleet_keys(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text("metrics:\n  port: 9100\n")
        result = load_config_file(f)
        assert "fleet_enabled" not in result
        assert "fleet_url" not in result


class TestGenerateDefaultConfig:
    def test_fleet_section_in_generated_config(self):
        config = generate_default_config()
        assert "fleet:" in config
        assert "enabled: false" in config
        assert "forward_interval:" in config
        assert "heartbeat_interval:" in config
