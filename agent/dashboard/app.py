"""NiceGUI dashboard application."""

from __future__ import annotations

from nicegui import ui

from agent.dashboard import events_view, findings_view, sankey_view
from agent.queue.sqlite_queue import SqliteQueue


def create_dashboard(queue: SqliteQueue, port: int = 8080, refresh_interval: float = 5.0) -> None:
    """Create and configure the NiceGUI dashboard. Call ui.run() after this."""
    ui.dark_mode(True)

    with ui.header().classes("items-center justify-between bg-dark"):
        ui.label("edr-graph").classes("text-h5 text-bold")
        with ui.row().classes("gap-4 items-center"):
            ui.label("EDR with Graph-Based Event Correlation").classes("text-caption text-grey")

    with ui.column().classes("w-full max-w-7xl mx-auto p-4"):
        with ui.tabs().classes("w-full") as tabs:
            events_tab = ui.tab("Events", icon="list")
            findings_tab = ui.tab("Findings", icon="security")
            sankey_tab = ui.tab("Chain View", icon="account_tree")

        with ui.tab_panels(tabs, value=events_tab).classes("w-full"):
            with ui.tab_panel(events_tab):
                events_view.create(queue, refresh_interval=refresh_interval)
            with ui.tab_panel(findings_tab):
                findings_view.create(queue, refresh_interval=refresh_interval)
            with ui.tab_panel(sankey_tab):
                sankey_view.create(queue, refresh_interval=refresh_interval * 2)


def run_dashboard(queue: SqliteQueue, port: int = 8080, refresh_interval: float = 5.0) -> None:
    """Create and run the dashboard (blocking call)."""
    create_dashboard(queue, port=port, refresh_interval=refresh_interval)
    ui.run(port=port, title="edr-graph", reload=False, show=False)
