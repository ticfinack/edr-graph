"""Security findings display for the dashboard."""

from __future__ import annotations

from nicegui import ui

from agent.queue.sqlite_queue import SqliteQueue

SEVERITY_BADGE = {
    "critical": "red",
    "high": "deep-orange",
    "medium": "orange",
    "low": "amber",
    "info": "blue",
}


def create(queue: SqliteQueue, refresh_interval: float = 5.0) -> None:
    """Create the findings cards view."""
    with ui.column().classes("w-full"):
        ui.label("Security Findings").classes("text-h6")

        with ui.row().classes("w-full items-center gap-4"):
            severity_filter = ui.select(
                options=["All", "critical", "high", "medium", "low", "info"],
                value="All",
                label="Severity Filter",
            ).classes("w-48")

        findings_container = ui.column().classes("w-full gap-4")

        def refresh():
            try:
                sev = severity_filter.value
                sev_arg = sev if sev != "All" else None
                findings = queue.get_findings(limit=50, severity=sev_arg)

                findings_container.clear()
                with findings_container:
                    if not findings:
                        ui.label("No findings yet.").classes("text-grey")
                        return

                    for finding in findings:
                        badge_color = SEVERITY_BADGE.get(finding.severity, "grey")
                        with ui.card().classes("w-full"):
                            with ui.row().classes("items-center gap-2"):
                                ui.badge(
                                    finding.severity.upper(),
                                    color=badge_color,
                                ).classes("text-white")
                                ui.label(finding.title).classes("text-subtitle1 text-bold")
                                ui.space()
                                ui.label(finding.timestamp.strftime("%Y-%m-%d %H:%M:%S")).classes(
                                    "text-caption text-grey"
                                )

                            ui.label(finding.description).classes("text-body2")

                            if finding.affected_entities:
                                with ui.row().classes("gap-1 q-mt-sm"):
                                    ui.label("Entities:").classes("text-caption text-bold")
                                    for entity in finding.affected_entities:
                                        ui.badge(entity, color="blue-grey").classes("text-white")

                            if finding.chain:
                                with ui.row().classes("gap-1 q-mt-sm items-center"):
                                    ui.label("Chain:").classes("text-caption text-bold")
                                    for i, step in enumerate(finding.chain):
                                        ui.badge(
                                            f"{step.entity_type}: {step.entity_name}",
                                            color="teal",
                                        ).classes("text-white")
                                        if i < len(finding.chain) - 1:
                                            ui.icon("arrow_forward").classes("text-grey")

                            ui.separator()
                            ui.label(f"Recommendation: {finding.recommendation}").classes("text-body2 text-italic")
            except Exception:
                pass

        ui.timer(refresh_interval, refresh)
        refresh()
