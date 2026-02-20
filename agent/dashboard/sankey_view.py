"""Plotly Sankey chain visualization for the dashboard."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta

import plotly.graph_objects as go
from nicegui import ui

from agent.queue.sqlite_queue import SqliteQueue
from agent.schema.graph_types import SecurityFinding

SEVERITY_COLORS = {
    "critical": "rgba(220, 38, 38, 0.7)",
    "high": "rgba(234, 88, 12, 0.7)",
    "medium": "rgba(245, 158, 11, 0.7)",
    "low": "rgba(251, 191, 36, 0.7)",
    "info": "rgba(59, 130, 246, 0.7)",
}

NODE_COLORS = {
    "user": "rgba(99, 102, 241, 0.8)",
    "process": "rgba(16, 185, 129, 0.8)",
    "ip_private": "rgba(107, 114, 128, 0.6)",
    "ip_public": "rgba(239, 68, 68, 0.8)",
}


def create(queue: SqliteQueue, refresh_interval: float = 10.0) -> None:
    """Create the Sankey chain visualization view."""
    with ui.column().classes("w-full"):
        ui.label("Event Chain Visualization").classes("text-h6")

        with ui.row().classes("w-full items-center gap-4"):
            hours_back = ui.number(label="Hours back", value=24, min=1, max=168, step=1).classes("w-32")
            ui.button("Refresh", on_click=lambda: refresh())

        plot_container = ui.column().classes("w-full")

        def refresh():
            try:
                end = datetime.now()
                start = end - timedelta(hours=int(hours_back.value or 24))
                findings = queue.get_findings_in_range(start, end)

                plot_container.clear()
                with plot_container:
                    if not findings:
                        ui.label("No findings in this time range.").classes("text-grey")
                        return

                    fig = _build_sankey(findings)
                    ui.plotly(fig).classes("w-full").style("height: 600px")
            except Exception:
                with plot_container:
                    plot_container.clear()
                    ui.label("Error building visualization.").classes("text-red")

        ui.timer(refresh_interval, refresh)
        refresh()


def _build_sankey(findings: list[SecurityFinding]) -> go.Figure:
    """Build a Plotly Sankey diagram from findings chain data."""
    # Collect all unique nodes and links
    node_labels: list[str] = []
    node_colors: list[str] = []
    node_index: dict[str, int] = {}

    links_agg: dict[tuple[str, str], dict] = defaultdict(lambda: {"count": 0, "severities": []})

    for finding in findings:
        chain = finding.chain
        if len(chain) < 2:
            continue

        for i in range(len(chain) - 1):
            src_step = chain[i]
            tgt_step = chain[i + 1]

            src_key = f"{src_step.entity_type}:{src_step.entity_id}"
            tgt_key = f"{tgt_step.entity_type}:{tgt_step.entity_id}"

            # Register nodes
            for key, step in [(src_key, src_step), (tgt_key, tgt_step)]:
                if key not in node_index:
                    node_index[key] = len(node_labels)
                    label = f"{step.entity_name} ({step.entity_type})"
                    node_labels.append(label)
                    color = _get_node_color(step.entity_type, step.entity_id)
                    node_colors.append(color)

            link_key = (src_key, tgt_key)
            links_agg[link_key]["count"] += 1
            links_agg[link_key]["severities"].append(finding.severity)

    if not links_agg:
        fig = go.Figure()
        fig.update_layout(
            title="No chains to display",
            template="plotly_dark",
        )
        return fig

    sources = []
    targets = []
    values = []
    link_colors = []

    for (src_key, tgt_key), data in links_agg.items():
        sources.append(node_index[src_key])
        targets.append(node_index[tgt_key])
        values.append(data["count"])
        # Use highest severity color for the link
        worst = _worst_severity(data["severities"])
        link_colors.append(SEVERITY_COLORS.get(worst, "rgba(128,128,128,0.4)"))

    fig = go.Figure(
        data=[
            go.Sankey(
                arrangement="snap",
                node={
                    "pad": 15,
                    "thickness": 20,
                    "line": {"color": "rgba(255,255,255,0.3)", "width": 0.5},
                    "label": node_labels,
                    "color": node_colors,
                },
                link={
                    "source": sources,
                    "target": targets,
                    "value": values,
                    "color": link_colors,
                },
            )
        ]
    )

    fig.update_layout(
        title="Finding Chains: User → Process → IP",
        font={"size": 12, "color": "white"},
        paper_bgcolor="rgba(30,30,30,1)",
        plot_bgcolor="rgba(30,30,30,1)",
        height=600,
    )

    return fig


def _get_node_color(entity_type: str, entity_id: str) -> str:
    if entity_type == "user":
        return NODE_COLORS["user"]
    elif entity_type == "process":
        return NODE_COLORS["process"]
    elif entity_type == "ip":
        # Check if private IP (simple heuristic)
        if entity_id.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.3")):
            return NODE_COLORS["ip_private"]
        return NODE_COLORS["ip_public"]
    return "rgba(128,128,128,0.6)"


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _worst_severity(severities: list[str]) -> str:
    """Return the most severe severity from a list."""
    if not severities:
        return "info"
    return min(severities, key=lambda s: _SEVERITY_ORDER.get(s, 99))
