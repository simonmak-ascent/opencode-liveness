"""Seven-state liveness classification from /proc samples.

A process is not healthy because it exists, and it is not hung because it is asleep. The states below
are ordered so that each one *excludes* the next, which is what makes the verdict checkable rather
than rhetorical:

    RUNNING            a tracked process burned CPU between samples
    WAITING-ON-IO      no CPU, but I/O counters moved (a hint, not proof — page cache counts too)
    WAITING-ON-CHILD   no CPU here, but a tracked child did work: a parent waiting on its own job
    DEADLOCK           none of the above, and the parent/child graph has a cycle
    NO-PROGRESS        no cycle, but the unit ledger has not advanced inside the profile budget
    STARVED            none of the above; it is alive, idle, and not producing
    ZOMBIE             every tracked process has exited and nobody has reaped it

The third state is mandatory. Without it every healthy parent process — a pool waiting on workers,
a shell waiting on a child — looks dead, which is exactly the false deadlock verdict this module was
written after.

**ZOMBIE is the seventh state for the same reason.** A `Z` process has already exited: it burns no
CPU, moves no bytes and has no children, so every test below reads it as a live process that is
merely idle. It then aged into NO-PROGRESS — "alive and useless" — and was escalated to a kill that
could never succeed, because the kernel discards signals for a process awaiting `wait()`. Naming the
state is what stops the supervisor from trying to kill a corpse.
"""

from __future__ import annotations

from dataclasses import dataclass, field

STATES = (
    "RUNNING",
    "WAITING-ON-IO",
    "WAITING-ON-CHILD",
    "DEADLOCK",
    "NO-PROGRESS",
    "STARVED",
    "ZOMBIE",
)

HEALTHY = frozenset({"RUNNING", "WAITING-ON-IO", "WAITING-ON-CHILD"})

# A zombie is dead. No signal can change that; only its parent calling wait() can. Kept separate from
# HEALTHY so `jobstat` still exits non-zero, and separate from the escalations so it is never killed.
UNREAPABLE = frozenset({"ZOMBIE"})


@dataclass(frozen=True)
class ProcSample:
    pid: int
    ppid: int
    ticks: int  # utime + stime
    read_bytes: int
    write_bytes: int
    state: str  # R, S, D, Z ...
    wchan: str
    parent_comm: str = ""  # who must reap it, when this is a zombie
    age_s: float = (
        0.0  # how long it has existed — for a zombie, how long it has been unreaped
    )

    @property
    def is_zombie(self) -> bool:
        return self.state == "Z"


@dataclass
class Verdict:
    state: str
    detail: str
    progressed: bool
    cycle: list[int] = field(default_factory=list)
    zombies: list[int] = field(default_factory=list)

    @property
    def healthy(self) -> bool:
        return self.state in HEALTHY

    @property
    def unreapable(self) -> bool:
        return self.state in UNREAPABLE


def _delta(prev: dict[int, ProcSample], curr: dict[int, ProcSample], attr: str) -> int:
    total = 0
    for pid, now in curr.items():
        before = prev.get(pid)
        if before is not None:
            total += max(0, getattr(now, attr) - getattr(before, attr))
    return total


def find_cycle(samples: dict[int, ProcSample]) -> list[int]:
    """A cycle among the tracked pids only. Edges: pid -> ppid, both tracked."""
    parent = {pid: s.ppid for pid, s in samples.items() if s.ppid in samples}
    for start in parent:
        seen: list[int] = []
        node = start
        while node in parent:
            if node in seen:
                return seen[seen.index(node) :]
            seen.append(node)
            node = parent[node]
    return []


def classify(
    prev: dict[int, ProcSample],
    curr: dict[int, ProcSample],
    *,
    last_unit_age_s: float | None,
    unit_budget_s: float,
) -> Verdict:
    """One verdict from two consecutive samples. Pure: no clocks, no /proc, no side effects."""
    if not curr:
        return Verdict("STARVED", "no tracked processes", False)

    zombies = [s for s in curr.values() if s.is_zombie]
    live = {pid: s for pid, s in curr.items() if not s.is_zombie}

    if not live:
        # Every tracked process has exited and nobody has reaped it. A `Z` process discards signals,
        # so this is not a kill candidate: the only thing that clears it is the parent calling
        # wait(). Report the parent, because fixing the leaker is the only real remedy.
        ordered = sorted(zombies, key=lambda s: s.pid)
        pids = [s.pid for s in ordered]
        parents = sorted(
            {
                f"{s.ppid}" + (f" ({s.parent_comm})" if s.parent_comm else "")
                for s in ordered
            }
        )
        oldest = max((s.age_s for s in ordered), default=0.0)
        shown = ", ".join(map(str, pids[:4])) + (" …" if len(pids) > 4 else "")
        return Verdict(
            "ZOMBIE",
            f"{len(ordered)} exited process(es) awaiting wait(): pid {shown}"
            f"; parent {', '.join(parents[:3])}"
            f"; process age {oldest:.0f}s (an upper bound on how long it has gone unreaped)"
            " — the parent must call wait()",
            False,
            zombies=pids,
        )

    # A zombie child is not an idle tracked child: it will never work again, so it must not be able
    # to produce WAITING-ON-CHILD for a parent that is genuinely doing nothing.
    curr = live

    cpu = _delta(prev, curr, "ticks")
    if cpu > 0:
        return Verdict("RUNNING", f"{cpu} ticks of CPU since the last sample", True)

    io = _delta(prev, curr, "read_bytes") + _delta(prev, curr, "write_bytes")
    if io > 0:
        return Verdict(
            "WAITING-ON-IO",
            f"{io} bytes moved; accounting, not proof of progress",
            True,
        )

    # A cycle is definitive, so it is checked before the "waiting on a child" shortcut: two processes
    # waiting on each other are children of each other, and the shortcut would hide it.
    cycle = find_cycle(curr)
    if cycle:
        return Verdict(
            "DEADLOCK",
            "wait-for cycle: " + " -> ".join(map(str, cycle + cycle[:1])),
            False,
            cycle,
        )

    outer = set(curr)
    inner = {pid for pid in curr if curr[pid].ppid in outer}
    if inner:
        # a child of a tracked process is itself tracked and already shown to be idle; if it was
        # active we would have returned RUNNING above, so this branch means "waiting on a peer"
        return Verdict(
            "WAITING-ON-CHILD", f"{len(inner)} tracked children, none active", False
        )

    if last_unit_age_s is not None and last_unit_age_s > unit_budget_s:
        return Verdict(
            "NO-PROGRESS",
            f"no unit for {last_unit_age_s:.0f}s (budget {unit_budget_s:.0f}s); alive and useless",
            False,
        )

    return Verdict("STARVED", "idle, no cycle, no unit due yet", False)
