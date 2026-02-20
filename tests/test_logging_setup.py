"""Tests for structured logging setup."""

import json
import logging

from agent.logging_setup import setup_logging


class TestLoggingSetup:
    def test_text_mode(self, capsys):
        setup_logging(log_level="DEBUG", log_format="text")
        logger = logging.getLogger("test.text")
        logger.info("hello text")
        captured = capsys.readouterr()
        assert "hello text" in captured.err

    def test_json_mode(self, capsys):
        setup_logging(log_level="DEBUG", log_format="json")
        logger = logging.getLogger("test.json")
        logger.info("hello json")
        captured = capsys.readouterr()
        # Should contain valid JSON with the message
        for line in captured.err.strip().splitlines():
            data = json.loads(line)
            if data.get("event") == "hello json":
                assert data["level"] == "info"
                assert "timestamp" in data
                return
        raise AssertionError("JSON log line with 'hello json' not found")

    def test_context_binding(self, capsys):
        import structlog

        setup_logging(log_level="DEBUG", log_format="json")
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id="abc-123")
        logger = logging.getLogger("test.ctx")
        logger.info("with context")
        structlog.contextvars.clear_contextvars()
        captured = capsys.readouterr()
        for line in captured.err.strip().splitlines():
            data = json.loads(line)
            if data.get("event") == "with context":
                assert data["request_id"] == "abc-123"
                return
        raise AssertionError("Context-bound log line not found")
