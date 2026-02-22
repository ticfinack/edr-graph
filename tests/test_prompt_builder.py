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


def test_cloud_native_section_present():
    prompt = build_intel_prompt()
    assert "CLOUD-NATIVE & AUTOMATION EXCEPTIONS" in prompt


def test_container_runtimes_mentioned():
    prompt = build_intel_prompt()
    for runtime in ("containerd-shim", "runc", "docker-init", "kubelet", "tini"):
        assert runtime in prompt, f"container runtime {runtime!r} missing from prompt"


def test_cicd_tools_mentioned():
    prompt = build_intel_prompt()
    for tool in ("gitlab-runner", "jenkins", "ansible", "puppet", "chef", "salt-minion"):
        assert tool in prompt, f"CI/CD tool {tool!r} missing from prompt"


def test_package_managers_mentioned():
    prompt = build_intel_prompt()
    for pm in ("dnf", "apt", "dpkg", "rpm", "pacman"):
        assert pm in prompt, f"package manager {pm!r} missing from prompt"


def test_gtfobins_parent_context():
    prompt = build_intel_prompt()
    assert "T1611" in prompt
    assert "Escape to Host" in prompt
    assert "parent process" in prompt


def test_section_ordering():
    prompt = build_intel_prompt()
    ip_idx = prompt.index("IP INTELLIGENCE INTERPRETATION")
    cloud_idx = prompt.index("CLOUD-NATIVE & AUTOMATION EXCEPTIONS")
    ioc_idx = prompt.index("IOC FEED MATCHING")
    assert ip_idx < cloud_idx < ioc_idx, (
        "Sections must be ordered: IP Intelligence → Cloud-Native → IOC Feed"
    )
