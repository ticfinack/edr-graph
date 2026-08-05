"""Linux eBPF collector via BCC.

Hooks kernel tracepoints and kprobes for:
- Process creation (``sys_enter_execve``)
- Network connections (``tcp_v4_connect``)
- File activity (``sys_enter_openat``, ``sys_enter_unlinkat``)
- DNS queries (``udp_sendmsg`` with dport 53 filter)

Requires root and the BCC Python library (``python3-bcc`` on Fedora).
"""

from __future__ import annotations

import collections
import ctypes
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

# Sensitive directories to monitor for file activity (in-kernel filter).
# Only file operations touching these prefixes will be emitted to user-space.
_WATCHED_PREFIXES = [
    "/etc/", "/root/", "/home/",
    "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/local/bin/",
    "/tmp/", "/var/tmp/", "/var/log/",
    "/opt/", "/lib/systemd/",
]

_BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <net/sock.h>

// ── Process exec ────────────────────────────────────────────────
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

// ── TCP connect kprobe / kretprobe ──────────────────────────────
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

    struct sock *skp = *skpp;
    currsock.delete(&pid);

    if (ret != 0) {
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

// ── File activity: openat (create/write) and unlinkat (delete) ──
struct file_event_t {
    u32 pid;
    u32 uid;
    u32 flags;       // openat flags (O_CREAT, O_WRONLY, etc.)
    u8  is_delete;   // 1 = unlinkat, 0 = openat
    char comm[16];
    char filename[256];
};

BPF_PERF_OUTPUT(file_events);

// Filter: only emit openat for writes/creates (not pure reads)
// O_WRONLY=1, O_RDWR=2, O_CREAT=0100, O_TRUNC=01000
#define WRITE_FLAGS (1 | 2 | 0100 | 01000)

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    int flags = args->flags;
    if (!(flags & WRITE_FLAGS)) {
        return 0;  // Skip read-only opens — too noisy
    }

    struct file_event_t event = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.flags = flags;
    event.is_delete = 0;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(event.filename, sizeof(event.filename), args->filename);

    file_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat) {
    struct file_event_t event = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.flags = 0;
    event.is_delete = 1;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(event.filename, sizeof(event.filename), args->pathname);

    file_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

// ── DNS: capture UDP sends to port 53, pass raw payload to user-space ──
struct dns_event_t {
    u32 pid;
    u32 uid;
    u32 daddr;
    u16 payload_len;
    char comm[16];
    char payload[256];   // Raw DNS payload (parsed in Python)
};

BPF_PERF_OUTPUT(dns_events);

int kprobe__udp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg) {
    // Filter: only DNS (dport == 53)
    u16 dport = sk->__sk_common.skc_dport;
    if (dport != __constant_htons(53))
        return 0;

    struct dns_event_t event = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.daddr = sk->__sk_common.skc_daddr;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // Read the DNS payload from the iov_iter.
    // iter_iov() checks: ubuf → embedded __ubuf_iovec; otherwise → *__iov
    // Since both share offset 0 in the union, read iov_base/iov_len directly.
    struct iov_iter *iter = &msg->msg_iter;
    char *base = NULL;
    size_t payload_sz = 0;

    // Read from the union at offset 0 (iov_base for ubuf, __iov for iovec)
    bpf_probe_read_kernel(&base, sizeof(base), &iter->__ubuf_iovec.iov_base);
    bpf_probe_read_kernel(&payload_sz, sizeof(payload_sz), &iter->__ubuf_iovec.iov_len);

    // Try reading as direct user pointer (ubuf path)
    if (base && payload_sz >= 13 && payload_sz <= 512) {
        int read_len = payload_sz < 256 ? payload_sz : 256;
        if (bpf_probe_read_user(event.payload, read_len, base) == 0) {
            event.payload_len = read_len;
            dns_events.perf_submit(ctx, &event, sizeof(event));
            return 0;
        }
    }

    // Fallback: try as iovec pointer (sendmsg path)
    if (base) {
        const struct iovec *iov = (const struct iovec *)base;
        char *iov_base = NULL;
        size_t iov_len = 0;
        bpf_probe_read_kernel(&iov_base, sizeof(iov_base), &iov->iov_base);
        bpf_probe_read_kernel(&iov_len, sizeof(iov_len), &iov->iov_len);
        if (iov_base && iov_len >= 13 && iov_len <= 512) {
            int read_len2 = iov_len < 256 ? iov_len : 256;
            if (bpf_probe_read_user(event.payload, read_len2, iov_base) == 0) {
                event.payload_len = read_len2;
                dns_events.perf_submit(ctx, &event, sizeof(event));
                return 0;
            }
        }
    }

    // Emit without payload if both paths failed — at least we get PID/comm/dest
    event.payload_len = 0;
    dns_events.perf_submit(ctx, &event, sizeof(event));

    dns_events.perf_submit(ctx, &event, sizeof(event));
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
        self._bpf["file_events"].open_perf_buffer(self._process_file_event)
        self._bpf["dns_events"].open_perf_buffer(self._process_dns_event)
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

    def _process_file_event(self, cpu, data, size) -> None:
        """Perf buffer callback — transform BPF file_event_t into RawEvent."""
        event = self._bpf["file_events"].event(data)

        pid = event.pid
        if pid == self._agent_pid:
            return

        uid = event.uid
        comm = event.comm.decode("utf-8", errors="replace")
        filename = event.filename.decode("utf-8", errors="replace")

        # User-space path filter: only emit events for sensitive directories
        if not any(filename.startswith(p) for p in _WATCHED_PREFIXES):
            return

        is_delete = event.is_delete
        flags = event.flags
        now = datetime.now()

        auid_raw = _read_loginuid(pid)
        username = _resolve_username(auid_raw, uid)

        # Determine event type from flags/is_delete
        if is_delete:
            event_type = "file_delete"
        elif flags & 0o100:  # O_CREAT
            event_type = "file_create"
        else:
            event_type = "file_modify"

        source = f"ebpf_{event_type}"

        fields = {
            "pid": str(pid),
            "name": comm,
            "file_path": filename,
            "event_type": event_type,
            "uid": str(uid),
            "username": username,
        }

        raw = RawEvent(
            timestamp=now,
            source=source,
            message=f"{event_type}: {comm} -> {filename}",
            fields=fields,
            hostname=self._hostname,
        )
        with self._lock:
            self._buffer.append(raw)

    def _process_dns_event(self, cpu, data, size) -> None:
        """Perf buffer callback — transform BPF dns_event_t into RawEvent."""
        event = self._bpf["dns_events"].event(data)

        pid = event.pid
        if pid == self._agent_pid:
            return

        uid = event.uid
        comm = event.comm.decode("utf-8", errors="replace")
        payload_len = event.payload_len

        # Read raw payload bytes without null-termination truncation.
        # bytes(event.payload) stops at first \x00 — wrong for DNS wire format.
        raw_event = ctypes.string_at(data, size)
        payload_offset = type(event).payload.offset
        payload_bytes = raw_event[payload_offset:payload_offset + payload_len]

        qname = ""
        if len(payload_bytes) >= 13:
            qname = _parse_dns_qname(payload_bytes)
        if not qname:
            return
        dst_ip = socket.inet_ntop(socket.AF_INET, struct.pack("I", event.daddr))
        now = datetime.now()

        auid_raw = _read_loginuid(pid)
        username = _resolve_username(auid_raw, uid)

        fields = {
            "pid": str(pid),
            "name": comm,
            "query_domain": qname,
            "resolved_ips": "",
            "dns_server": dst_ip,
            "uid": str(uid),
            "username": username,
        }

        raw = RawEvent(
            timestamp=now,
            source="ebpf_dns",
            message=f"dns: {comm} -> {qname}",
            fields=fields,
            hostname=self._hostname,
        )
        with self._lock:
            self._buffer.append(raw)


def _parse_dns_qname(payload: bytes) -> str:
    """Parse a DNS query name from raw DNS wire-format payload.

    DNS header is 12 bytes, then the query section: [len][chars]...[0].
    Returns the dotted domain name, or empty string on parse failure.
    """
    if len(payload) < 13:
        return ""
    pos = 12  # skip DNS header
    labels: list[str] = []
    for _ in range(32):  # max labels
        if pos >= len(payload):
            break
        label_len = payload[pos]
        if label_len == 0:
            break
        if label_len > 63 or label_len & 0xC0:  # pointer or invalid
            break
        pos += 1
        if pos + label_len > len(payload):
            break
        labels.append(payload[pos:pos + label_len].decode("ascii", errors="replace"))
        pos += label_len
    return ".".join(labels)


def _read_loginuid(pid: int) -> int | None:
    """Read the audit login UID from ``/proc/<pid>/loginuid``.

    Returns the integer AUID, or ``None`` if the file cannot be read
    (process already exited, permission denied, etc.).

    The PID is coerced to an ``int`` before interpolation so the path cannot
    be steered outside ``/proc`` (CWE-22), matching ``get_container_id``.
    """
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return None
    if pid <= 0:
        return None
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
