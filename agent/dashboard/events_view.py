"""Live events table view for the dashboard."""

from __future__ import annotations

from nicegui import ui

from agent.queue.sqlite_queue import SqliteQueue

SEVERITY_COLORS = {
    1: "green",
    2: "blue",
    3: "orange",
    4: "red",
    5: "red",
}

COLUMNS = [
    {"name": "id", "label": "ID", "field": "_queue_id", "sortable": True},
    {"name": "timestamp", "label": "Timestamp", "field": "timestamp", "sortable": True},
    {"name": "source", "label": "Source", "field": "source", "sortable": True},
    {"name": "message", "label": "Message", "field": "message"},
    {"name": "hostname", "label": "Host", "field": "hostname"},
    {"name": "processed", "label": "Processed", "field": "_processed"},
]


def create(queue: SqliteQueue, refresh_interval: float = 5.0) -> None:
    """Create the events table view."""
    with ui.column().classes("w-full"):
        ui.label("Live Events").classes("text-h6")

        with ui.row().classes("w-full items-center gap-4"):
            source_filter = ui.select(
                options=[
                    "All",
                    "psutil_process",
                    "psutil_network",
                    "ebpf_execve",
                    "ebpf_network",
                    "auth",
                    "auditd",
                    "syslog",
                    "unified_log",
                    "macos_log",
                ],
                value="All",
                label="Source Filter",
            ).classes("w-48")
            limit_input = ui.number(label="Max Events", value=50, min=10, max=500, step=10).classes("w-32")

        table = ui.table(
            columns=COLUMNS,
            rows=[],
            row_key="_queue_id",
            pagination={"rowsPerPage": 20},
        ).classes("w-full")

        # Expandable row detail
        table.add_slot(
            "body-cell-message",
            r"""
            <q-td :props="props">
                <div class="cursor-pointer" @click="props.expand = !props.expand">
                    {{ props.value ? props.value.substring(0, 100) : '' }}
                    <span v-if="props.value && props.value.length > 100">...</span>
                </div>
            </q-td>
            """,
        )

        def refresh():
            try:
                limit = int(limit_input.value) if limit_input.value else 50
                events = queue.get_recent_events(limit=limit)
                source = source_filter.value
                if source and source != "All":
                    events = [e for e in events if e.get("source") == source]
                table.rows = events
                table.update()
            except Exception:
                pass

        ui.timer(refresh_interval, refresh)
        refresh()
