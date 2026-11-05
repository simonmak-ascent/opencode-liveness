"""Live injection: real processes, real /proc, real verdicts."""

from __future__ import annotations

import os
import subprocess
import time

from liveness import sampler
from liveness.classify import classify

BUDGET = 2.0


def observe(pids: list[int], unit_age: float | None = None):
    tree = sampler.process_tree(pids)
    a = sampler.snapshot(tree)
    time.sleep(1.2)
    b = sampler.snapshot(tree)
    return classify(a, b, last_unit_age_s=unit_age, unit_budget_s=BUDGET)


def test_spinning_child_is_running():
    p = subprocess.Popen(["python3", "-c", "while True: pass"])
    try:
        v = observe([p.pid])
        assert v.state == "RUNNING", v
    finally:
        p.kill()


def test_sleeping_parent_with_sleeping_child_is_waiting_not_dead():
    p = subprocess.Popen(["sh", "-c", "sleep 20 & sleep 20"])
    try:
        v = observe([p.pid])
        assert v.state in ("WAITING-ON-CHILD", "STARVED"), v
        assert v.state != "DEADLOCK", v
    finally:
        p.kill()


def test_idle_beyond_budget_is_no_progress():
    p = subprocess.Popen(["sleep", "20"])
    try:
        v = observe([p.pid], unit_age=10.0)
        assert v.state in ("NO-PROGRESS", "WAITING-ON-CHILD"), v
    finally:
        p.kill()


def test_blocked_read_on_a_pipe_is_not_reported_healthy_forever():
    # The read end must be *inherited* and the write end must stay open, or the child sees EOF (or
    # EBADF) and exits immediately — which is not a blocked read at all. That was the old shape of
    # this test: the child died on `OSError: Bad file descriptor`, and the classifier called the
    # resulting corpse NO-PROGRESS. It is now correctly named ZOMBIE, which is what exposed the bug
    # in the fixture rather than in the detector.
    r, w = os.pipe()
    p = subprocess.Popen(
        ["python3", "-c", f"import os; os.read({r}, 1)"], pass_fds=(r,)
    )
    try:
        time.sleep(1.5)  # interpreter startup ticks are not the work
        v = observe([p.pid], unit_age=10.0)
        assert v.state in ("NO-PROGRESS", "STARVED"), v
        assert v.state != "ZOMBIE", "the child must still be blocked, not exited"
    finally:
        p.kill()
        p.wait()  # reap it: an unreaped child is exactly the condition this module now reports
        os.close(r)
        os.close(w)
