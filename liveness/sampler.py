"""Read /proc for a set of pids, one sample per call. No dependencies, no root.

Per-thread state is available at /proc/<pid>/task/<tid>/stat; this reads the process leader and every
thread, because a process can look asleep while one of its threads spins.
"""

from __future__ import annotations

import os
import pathlib
import time

from .classify import ProcSample

PROC = pathlib.Path("/proc")
HZ = os.sysconf("SC_CLK_TCK")


def _read(path: pathlib.Path) -> str:
    try:
        return path.read_text()
    except OSError:
        return ""


def _uptime_s() -> float:
    try:
        return float(_read(PROC / "uptime").split()[0])
    except (OSError, IndexError, ValueError):
        return 0.0


def sample_pid(pid: int) -> ProcSample | None:
    stat = _read(PROC / str(pid) / "stat")
    if not stat:
        return None
    # comm may contain spaces and parentheses; the fields after the last ')' are fixed
    rest = stat[stat.rfind(")") + 2 :].split()
    if len(rest) < 22:
        return None
    state = rest[0]
    ppid = int(rest[1])
    ticks = int(rest[11]) + int(rest[12])
    io = _read(PROC / str(pid) / "io")
    read_bytes = write_bytes = 0
    for line in io.splitlines():
        if line.startswith("read_bytes:"):
            read_bytes = int(line.split()[1])
        elif line.startswith("write_bytes:"):
            write_bytes = int(line.split()[1])
    wchan = _read(PROC / str(pid) / "wchan").strip() or "-"

    # Only a zombie needs the extra two reads, and they are the whole point of the ZOMBIE state: who
    # has to reap it, and for how long it has been sitting there unclaimed.
    parent_comm = ""
    age_s = 0.0
    if state == "Z":
        parent_comm = _read(PROC / str(ppid) / "comm").strip()
        try:
            start_ticks = int(rest[19])
            up = _uptime_s()
            if up:
                age_s = max(0.0, up - start_ticks / HZ)
        except (IndexError, ValueError):
            pass

    return ProcSample(
        pid, ppid, ticks, read_bytes, write_bytes, state, wchan, parent_comm, age_s
    )


def process_tree(root_pids: list[int]) -> set[int]:
    """The registered pids plus every descendant, so a wrapper process does not hide the work."""
    children: dict[int, list[int]] = {}
    for entry in PROC.iterdir():
        if not entry.name.isdigit():
            continue
        s = sample_pid(int(entry.name))
        if s is not None:
            children.setdefault(s.ppid, []).append(s.pid)
    keep: set[int] = set()
    stack = list(root_pids)
    while stack:
        pid = stack.pop()
        if pid in keep:
            continue
        keep.add(pid)
        stack.extend(children.get(pid, []))
    return keep


def snapshot(pids: set[int]) -> dict[int, ProcSample]:
    out: dict[int, ProcSample] = {}
    for pid in pids:
        s = sample_pid(pid)
        if s is not None:
            out[pid] = s
    return out
