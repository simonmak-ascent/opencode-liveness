"""The seventh state: proved synthetically, and against a real unreaped child.

A zombie is the one condition a supervisor cannot fix by signalling, so these tests assert what it
must do instead — name the state, name the parent that has to reap it, and send nothing. The last
three tests use real processes; a zombie is created the only way a zombie can be created: a child
exits and its parent deliberately does not call `wait()`.
"""

from __future__ import annotations

import os
import signal
import time

from liveness import daemon, sampler
from liveness.classify import ProcSample, classify

BUDGET = 60.0
REAL_KILL = os.kill  # captured before any test monkeypatches os.kill


def s(
    pid,
    ppid,
    ticks,
    read=0,
    write=0,
    state="S",
    wchan="do_poll",
    parent_comm="",
    age_s=0.0,
):
    return ProcSample(pid, ppid, ticks, read, write, state, wchan, parent_comm, age_s)


# --------------------------------------------------------------------------- synthetic


def test_all_zombies_is_its_own_state():
    prev = {7: s(7, 1, 0, state="Z", parent_comm="next-server", age_s=7200)}
    curr = {7: s(7, 1, 0, state="Z", parent_comm="next-server", age_s=7260)}
    v = classify(prev, curr, last_unit_age_s=999, unit_budget_s=BUDGET)
    assert v.state == "ZOMBIE"
    assert v.unreapable and not v.healthy
    assert v.zombies == [7]
    assert "next-server" in v.detail and "wait()" in v.detail


def test_a_zombie_never_ages_into_no_progress():
    """The original bug: a corpse aged into NO-PROGRESS and was escalated to an impossible kill."""
    curr = {9: s(9, 4, 0, state="Z")}
    v = classify({}, curr, last_unit_age_s=10_000, unit_budget_s=1.0)
    assert v.state == "ZOMBIE"
    assert not v.healthy


def test_a_zombie_child_cannot_make_its_parent_look_busy():
    """WAITING-ON-CHILD is for a parent whose child works; a zombie child never works again."""
    prev = {1: s(1, 0, 10), 2: s(2, 1, 0, state="Z")}
    curr = {1: s(1, 0, 10), 2: s(2, 1, 0, state="Z")}
    v = classify(prev, curr, last_unit_age_s=5, unit_budget_s=BUDGET)
    assert v.state == "STARVED"


def test_live_and_zombie_mix_reports_the_live_verdict():
    prev = {1: s(1, 0, 10), 2: s(2, 1, 0, state="Z")}
    curr = {1: s(1, 0, 60), 2: s(2, 1, 0, state="Z")}
    v = classify(prev, curr, last_unit_age_s=5, unit_budget_s=BUDGET)
    assert v.state == "RUNNING"


# --------------------------------------------------------------------------- real processes


def _zombie_child() -> int:
    """A child that exits while its parent does not reap it. This is a real Z process."""
    pid = os.fork()
    if pid == 0:  # pragma: no cover - child
        os._exit(0)
    for _ in range(50):  # wait for the kernel to publish the zombie
        time.sleep(0.02)
        sample = sampler.sample_pid(pid)
        if sample is not None and sample.is_zombie:
            return pid
    return pid


def _sleeping_child() -> int:
    pid = os.fork()
    if pid == 0:  # pragma: no cover - child
        time.sleep(60)
        os._exit(0)
    time.sleep(0.2)
    return pid


def test_a_real_zombie_is_detected_with_its_parent_named():
    pid = _zombie_child()
    try:
        sample = sampler.sample_pid(pid)
        assert sample is not None and sample.is_zombie
        assert sample.ppid == os.getpid()
        assert sample.parent_comm, (
            "the parent's comm is what makes the report actionable"
        )
        assert sample.age_s >= 0.0

        v = classify({}, {pid: sample}, last_unit_age_s=5, unit_budget_s=BUDGET)
        assert v.state == "ZOMBIE"
    finally:
        os.waitpid(pid, 0)


def test_a_real_zombie_is_never_signalled(monkeypatch):
    """The claim under test: `os.kill` on a zombie succeeds and does nothing, so never call it."""
    pid = _zombie_child()
    try:
        sent: list[tuple[int, int]] = []
        monkeypatch.setattr(daemon.os, "kill", lambda p, sig: sent.append((p, sig)))

        op = {"pids": [pid], "protected": [], "remedy": "kill"}
        daemon._kill(op)

        assert sent == [], "no signal may be sent to a process that has already exited"
        assert op["killed"] is False
        assert op["unreapable"][0]["pid"] == pid
        assert op["unreapable"][0]["parent"] == os.getpid()
        assert "kill_failed" not in op
    finally:
        os.waitpid(pid, 0)


def test_a_kill_is_only_reported_when_the_process_is_gone():
    pid = _sleeping_child()
    try:
        op = {"pids": [pid], "protected": [], "remedy": "kill"}
        daemon._kill(op)
        assert op["killed"] is True
        assert op["killed_pids"] == [pid]
        assert "kill_failed" not in op
    finally:
        os.waitpid(pid, 0)


def test_a_surviving_process_is_reported_as_a_failure_not_a_kill(monkeypatch):
    """If the signal does not take, the flag must say so — that is the whole fix."""
    pid = _sleeping_child()
    try:
        monkeypatch.setattr(
            daemon.os, "kill", lambda p, sig: None
        )  # accepted, then ignored
        op = {"pids": [pid], "protected": [], "remedy": "kill"}
        daemon._kill(op)
        assert op["killed"] is False
        assert op["kill_failed"][0]["pid"] == pid
    finally:
        REAL_KILL(pid, signal.SIGKILL)
        os.waitpid(pid, 0)


def test_the_agent_remedy_stays_an_interrupt():
    """Regression guard: the fix must not hand the supervisor authority over the harness."""
    op = {"pids": [os.getpid()], "protected": [os.getpid()], "remedy": "interrupt"}
    daemon._kill(op)
    assert op.get("interrupt_requested") is True
    assert "killed_pids" not in op


# --------------------------------------------------------------------------- the remedy that works
#
# "Cannot be signalled" is not "cannot be fixed". A zombie clears when its parent restarts, and the
# supervisor already knows the parent's pid. These tests pin that path, including its refusal to kill
# a parent that nothing is supervising.


def test_cgroup_parsing_finds_the_container():
    text = "12:devices:/docker/3f2a1b4c5d6e7f8091a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f90a1b2c3d4e"
    kind, ident = daemon.supervisor_from_cgroup(text)
    assert kind == "docker"
    assert ident.startswith("3f2a1b4c")


def test_cgroup_parsing_finds_the_systemd_unit():
    assert daemon.supervisor_from_cgroup(
        "0::/system.slice/opencode-liveness.service"
    ) == ("systemd", "opencode-liveness.service")


def test_cgroup_parsing_refuses_an_unsupervised_process():
    assert (
        daemon.supervisor_from_cgroup("0::/user.slice/user-1000.slice/session-2.scope")
        is None
    )


def test_restarting_the_parent_clears_the_zombies(monkeypatch):
    zpid, ppid = 4242, 1234
    zombie = s(zpid, ppid, 0, state="Z", parent_comm="next-server")
    gone = {"v": False}

    def fake_sample(pid):
        if pid == zpid:
            return None if gone["v"] else zombie
        return zombie

    def fake_restart(kind, ident):
        gone["v"] = True  # the supervisor reaped the children
        return True, f"{kind} restarted {ident}"

    monkeypatch.setattr(daemon.sampler, "sample_pid", fake_sample)
    monkeypatch.setattr(daemon, "_supervisor_of", lambda p: ("docker", "abc123def456"))
    monkeypatch.setattr(daemon, "_restart", fake_restart)

    op = {"remedy": "restart-parent"}
    v = classify({}, {zpid: zombie}, last_unit_age_s=5, unit_budget_s=BUDGET)
    daemon._reap_by_restart(op, v)

    result = op["restart_results"][0]
    assert result["ok"] is True
    assert (result["cleared"], result["of"]) == (1, 1)
    assert op["restart_attempts"] == 1


def test_it_refuses_to_kill_an_unsupervised_parent(monkeypatch):
    """Killing a parent nothing restarts would leave a dead service, which is worse than the zombie."""
    zpid, ppid = 4243, 1235
    zombie = s(zpid, ppid, 0, state="Z")
    attempted: list[tuple[str, str]] = []

    monkeypatch.setattr(daemon.sampler, "sample_pid", lambda p: zombie)
    monkeypatch.setattr(daemon, "_supervisor_of", lambda p: None)
    monkeypatch.setattr(
        daemon, "_restart", lambda k, i: attempted.append((k, i)) or (True, "")
    )

    op = {"remedy": "restart-parent"}
    v = classify({}, {zpid: zombie}, last_unit_age_s=5, unit_budget_s=BUDGET)
    daemon._reap_by_restart(op, v)

    assert attempted == []
    assert op["restart_results"][0]["action"] == "none"
    assert op["restart_results"][0]["ok"] is False


def test_restart_is_rate_limited(monkeypatch):
    zpid, ppid = 4244, 1236
    zombie = s(zpid, ppid, 0, state="Z")
    attempted: list[tuple[str, str]] = []

    monkeypatch.setattr(daemon.sampler, "sample_pid", lambda p: zombie)
    monkeypatch.setattr(daemon, "_supervisor_of", lambda p: ("systemd", "x.service"))
    monkeypatch.setattr(
        daemon, "_restart", lambda k, i: attempted.append((k, i)) or (True, "")
    )

    op = {"remedy": "restart-parent", "restart_at": time.time(), "restart_attempts": 1}
    v = classify({}, {zpid: zombie}, last_unit_age_s=5, unit_budget_s=BUDGET)
    daemon._reap_by_restart(op, v)

    assert attempted == [], "a restart must not repeat inside the cooldown"
    assert op["restart_attempts"] == 1


def test_restart_gives_up_after_the_limit(monkeypatch):
    zpid, ppid = 4245, 1237
    zombie = s(zpid, ppid, 0, state="Z")
    attempted: list[tuple[str, str]] = []

    monkeypatch.setattr(daemon.sampler, "sample_pid", lambda p: zombie)
    monkeypatch.setattr(daemon, "_supervisor_of", lambda p: ("systemd", "x.service"))
    monkeypatch.setattr(
        daemon, "_restart", lambda k, i: attempted.append((k, i)) or (True, "")
    )

    op = {
        "remedy": "restart-parent",
        "restart_at": 0,
        "restart_attempts": daemon.MAX_RESTARTS,
    }
    v = classify({}, {zpid: zombie}, last_unit_age_s=5, unit_budget_s=BUDGET)
    daemon._reap_by_restart(op, v)

    assert attempted == [], "three failed restarts is enough; stop touching production"
