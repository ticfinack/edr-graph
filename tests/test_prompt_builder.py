"""Tests for the threat-intel system prompt builder."""

from __future__ import annotations

from agent.intel.prompt_builder import build_intel_prompt


def test_rfc1918_section_present():
    """Verify RFC 1918 guidance exists in the prompt."""
    prompt = build_intel_prompt()
    assert "Internal Networks & RFC 1918" in prompt
    assert "10.0.0.0/8" in prompt
    assert "172.16.0.0/12" in prompt
    assert "192.168.0.0/16" in prompt


def test_docker_k8s_subnets_mentioned():
    """Verify Docker/K8s subnet guidance exists."""
    prompt = build_intel_prompt()
    assert "172.17.0.0/16" in prompt
    assert "10.96.0.0/12" in prompt
    assert "docker0" in prompt


def test_microservice_ports_mentioned():
    """Verify common microservice ports are listed."""
    prompt = build_intel_prompt()
    for port in ("5432", "6379", "27017", "9090"):
        assert port in prompt, f"microservice port {port} missing from prompt"
