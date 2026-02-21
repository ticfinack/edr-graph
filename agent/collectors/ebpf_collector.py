"""Linux eBPF process collector via BCC.

Hooks ``tracepoint:syscalls:sys_enter_execve`` to capture every ``execve``
synchronously from the kernel, with audit UID (AUID) and cgroup v2 ID for
sudo-transparent attribution and container awareness.

Requires root and the BCC Python library (``python3-bcc`` on Fedora).
"""

from __future__ import annotations

import collections
import logging
import os
import pwd
import socket
import struct
import threading
from datetime import datetime

from .base import Collector, RawEvent

logger = logging.getLogger(__name__)

_BUFFER_MAX = 10_000

_BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <net/sock.h>

struct exec_event_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 gid;
    u64 cgroup_id;
    char comm[16];
    char filename[256];
};

BPF_PERF_OUTPUT(exec_events);

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct exec_event_t event = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 uid_gid = bpf_get_current_uid_gid();

    event.pid = pid_tgid >> 32;
    event.uid = uid_gid & 0xFFFFFFFF;
    event.gid = uid_gid >> 32;
    event.cgroup_id = bpf_get_current_cgroup_id();

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(event.filename, sizeof(event.filename), args->filename);

    exec_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

// ── tcp_v4_connect kprobe / kretprobe ───────────────────────────
struct ipv4_event_t {
    u32 pid;
    u32 uid;
    u32 saddr;
    u32 daddr;
    u16 dport;
    char comm[16];
};

BPF_HASH(currsock, u32, struct sock *);
BPF_PERF_OUTPUT(network_events);

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    currsock.update(&pid, &sk);
    return 0;
}

int kretprobe__tcp_v4_connect(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct sock **skpp = currsock.lookup(&pid);
    if (skpp == 0) {
        return 0;
    }

    // Always clean up the hash entry
    struct sock *skp = *skpp;
    currsock.delete(&pid);

    if (ret != 0) {
        // Connection failed — skip
        return 0;
    }

    struct ipv4_event_t event = {};
    event.pid = pid;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.saddr = skp->__sk_common.skc_rcv_saddr;
    event.daddr = skp->__sk_common.skc_daddr;
    event.dport = skp->__sk_common.skc_dport;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    network_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

# Sentinel value for unset AUID in /proc/<pid>/loginuid
_AUID_UNSET = 4294967295


class EbpfCollector(Collector):
    """Real-time Linux process event collector via eBPF.

    Architecture mirrors :class:`AuditdCollector`: bounded deque + lock +
    daemon thread + start/stop lifecycle.
    """

    def __init__(self) -> None:
        self._hostname = socket.gethostname()
        self._buffer: collections.deque[RawEvent] = collections.deque(maxlen=_BUFFER_MAX)
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._bpf = None
        self._agent_pid = os.getpid()

    def name(self) -> str:
        return "ebpf"

    def start(self) -> None:
        """Load BPF program and spawn perf-buffer consumer thread."""
        if self._thread is not None:
            return
        from bcc import BPF

        self._bpf = BPF(text=_BPF_PROGRAM)
        self._bpf["exec_events"].open_perf_buffer(self._process_exec_event)
        self._bpf["network_events"].open_perf_buffer(self._process_network_event)
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._consume,
            daemon=True,
            name="ebpf-consumer",
        )
        self._thread.start()

    def stop(self) -> None:
        """Signal the consumer to stop and clean up BPF resources."""
        self._stop_event.set()
        if self._bpf is not None:
            self._bpf.cleanup()
            self._bpf = None
        self._thread = None

    def collect(self) -> list[RawEvent]:
        """Drain buffered eBPF events."""
        events: list[RawEvent] = []
        with self._lock:
            while self._buffer:
                events.append(self._buffer.popleft())
        return events

    def _consume(self) -> None:
        """Poll perf buffer in a loop until stopped."""
        try:
            while not self._stop_event.is_set():
                if self._bpf is not None:
                    self._bpf.perf_buffer_poll(timeout=1000)
        except Exception:
            logger.debug("eBPF consumer error", exc_info=True)

    def _process_exec_event(self, cpu, data, size) -> None:
        """Perf buffer callback — transform BPF struct into RawEvent."""
        event = self._bpf["exec_events"].event(data)

        pid = event.pid
        if pid == self._agent_pid:
            return

        ppid = event.ppid
        uid = event.uid
        cgroup_id = event.cgroup_id
        comm = event.comm.decode("utf-8", errors="replace")
        filename = event.filename.decode("utf-8", errors="replace")
        now = datetime.now()

        auid_raw = _read_loginuid(pid)
        username = _resolve_username(auid_raw, uid)

        fields = {
            "pid": str(pid),
            "name": comm,
            "username": username,
            "cmdline": filename,
            "exe": filename,
            "ppid": str(ppid),
            "create_time": now.isoformat(),
            "auid": str(auid_raw) if auid_raw is not None else "",
            "cgroup_id": str(cgroup_id),
            "uid": str(uid),
        }

        raw = RawEvent(
            timestamp=now,
            source="ebpf_execve",
            message=f"execve: {comm} (PID {pid})",
            fields=fields,
            hostname=self._hostname,
        )
        with self._lock:
            self._buffer.append(raw)

    def _process_network_event(self, cpu, data, size) -> None:
        """Perf buffer callback — transform BPF ipv4_event_t into RawEvent."""
        event = self._bpf["network_events"].event(data)

        pid = event.pid
        if pid == self._agent_pid:
            return

        uid = event.uid
        comm = event.comm.decode("utf-8", errors="replace")
        dst_ip = socket.inet_ntop(socket.AF_INET, struct.pack("I", event.daddr))
        src_ip = socket.inet_ntop(socket.AF_INET, struct.pack("I", event.saddr))
        dst_port = socket.ntohs(event.dport)
        now = datetime.now()

        auid_raw = _read_loginuid(pid)
        username = _resolve_username(auid_raw, uid)

        fields = {
            "pid": str(pid),
            "process_name": comm,
            "src_ip": src_ip,
            "src_port": "0",
            "dst_ip": dst_ip,
            "dst_port": str(dst_port),
            "status": "ESTABLISHED",
            "type": "TCP",
            "uid": str(uid),
            "username": username,
        }

        raw = RawEvent(
            timestamp=now,
            source="ebpf_network",
            message=f"connect: {comm} -> {dst_ip}:{dst_port}",
            fields=fields,
            hostname=self._hostname,
        )
        with self._lock:
            self._buffer.append(raw)


def _read_loginuid(pid: int) -> int | None:
    """Read the audit login UID from ``/proc/<pid>/loginuid``.

    Returns the integer AUID, or ``None`` if the file cannot be read
    (process already exited, permission denied, etc.).
    """
    try:
        with open(f"/proc/{pid}/loginuid") as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


def _resolve_username(auid_raw: int | None, effective_uid: int) -> str:
    """Resolve a human-readable username from AUID, falling back to EUID.

    AUID (audit UID) persists through ``sudo`` and ``su``, so a process
    running as root via sudo will be attributed to the original login user.
    """
    # Prefer AUID if set and valid
    if auid_raw is not None and auid_raw != _AUID_UNSET:
        try:
            return pwd.getpwuid(auid_raw).pw_name
        except KeyError:
            pass

    # Fall back to effective UID
    try:
        return pwd.getpwuid(effective_uid).pw_name
    except KeyError:
        return str(effective_uid)
