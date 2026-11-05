"""The supervisor: a 1 Hz sampler plus a unix-socket protocol.

Design constraints that came out of research, not preference:

* the **work** reports progress; a sidecar thread that pings on its own proves nothing (that is how
  `WatchdogSec` fails silently), so `progress` messages are the only input to NO-PROGRESS;
* classification is per **thread and child**, because a sleeping parent with a working child is the
  normal shape of every pipeline;
* escalation is warn -> dump -> kill, and kill is only acceptable because the caller keeps a ledger
  to resume from;
* this daemon is itself supervised by systemd (`WatchdogSec`), and `jobstat` says so loudly when it is
  absent.

    python -m liveness.daemon --socket /run/opencode-liveness.sock --state /run/opencode-liveness.json
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import shutil
import signal
import socketserver
import subprocess
import threading
import time

from . import classify as C
from . import paths
from . import sampler

PROFILES = {
    "foreground": {"warn": 30.0, "dump": 90.0, "kill": 180.0, "unit_budget": 60.0},
    "background": {"warn": 120.0, "dump": 600.0, "kill": 1800.0, "unit_budget": 180.0},
    # An agent that is thinking is not hung, and a tool call can legitimately run for minutes.
    # 300 s of silence from both is a stall worth interrupting, not killing.
    "agent": {"warn": 120.0, "dump": 210.0, "kill": 300.0, "unit_budget": 300.0},
}

LOCK = threading.Lock()
OPS: dict[str, dict] = {}
STATE_PATH = paths.STATE
LAST_PING = time.time()


def _record(op: dict, verdict: C.Verdict, age: float) -> None:
    op["state"] = verdict.state
    op["detail"] = verdict.detail
    op["last_verdict_at"] = time.time()
    op["unit_age_s"] = age

    if verdict.unreapable:
        # A zombie is already dead. Escalating it to a kill produced the original bug: the signal was
        # accepted by the kernel, discarded, and recorded as a successful kill. Surface it instead —
        # visible in `jobstat`, never reaching level 3, never signalled.
        samples = [sampler.sample_pid(p) for p in verdict.zombies]
        op["zombie"] = {
            "pids": verdict.zombies,
            "detail": verdict.detail,
        }
        # Populate `unreapable` here as well as in `_kill`, so a zombie that was merely *observed* is
        # reported to the operator with its parent — not only one that survived a kill attempt.
        op["unreapable"] = [
            {
                "pid": s.pid,
                "parent": s.ppid,
                "parent_comm": s.parent_comm or "?",
                "unreaped_s": round(s.age_s, 1),
            }
            for s in samples
            if s is not None
        ]
        if op.get("remedy") == "restart-parent":
            # The only action that can actually clear a zombie: restart the parent so its supervisor
            # reaps the children. Opt-in, rate-limited, and verified by re-sampling.
            _reap_by_restart(op, verdict)
        if op.get("level", 0) < 1:
            op["level"] = 1
        return

    # `zombie`/`unreapable` describe the current state, not history: once the parent reaps it, the
    # line must disappear. A stale "ZOMBIE" that outlives the zombie is the same lie as a "killed"
    # flag on a live pid. `kill_failed` is kept — that one is a real, historical failure.
    op.pop("zombie", None)
    op.pop("unreapable", None)

    profile = PROFILES[op.get("profile", "foreground")]
    level = op.get("level", 0)
    want = (
        0
        if verdict.healthy
        else (
            3
            if age > profile["kill"]
            else 2
            if age > profile["dump"]
            else 1
            if age > profile["warn"]
            else 1
        )
    )
    if want > level:
        op["level"] = want
        op.setdefault("events", []).append(
            {"at": time.time(), "level": want, "state": verdict.state}
        )
        if want >= 2:
            op["stack"] = _dump_stack(op)
        if want >= 3:
            _kill(op)


def _dump_stack(op: dict) -> str | None:
    """py-spy does not stop the target; gdb does, and /proc/PID/stack is only the kernel stack."""
    if shutil.which("py-spy") is None:
        return None
    out = []
    for pid in sorted(op.get("pids", []))[:4]:
        try:
            res = subprocess.run(
                ["py-spy", "dump", "--pid", str(pid), "--nonblocking"],
                capture_output=True,
                text=True,
                timeout=20,
            )
            out.append(res.stdout.strip()[:4000])
        except Exception as exc:  # capture must never block detection
            out.append(f"py-spy failed: {exc}")
    return "\n---\n".join(out) or None


def _kill(op: dict) -> None:
    if op.get("remedy") == "interrupt":
        # The remedy for a stalled agent is an interrupt performed by the client, never a signal:
        # SIGTERM here would terminate the harness that is supposed to survive.
        op["interrupt_requested"] = True
        return

    # Signal what the verdict was computed from — the registration *and* its descendants — because a
    # descendant can trigger escalation while the registered pid is innocent.
    targets = set(op.get("pids", [])) | sampler.process_tree(op.get("pids", []))

    killed: list[int] = []
    unreapable: list[dict] = []
    failed: list[dict] = []

    for pid in sorted(targets):
        if pid in op.get("protected", []):
            continue
        before = sampler.sample_pid(pid)
        if before is None:
            continue
        if before.is_zombie:
            # It has already exited. `os.kill` on a `Z` process returns 0 and does nothing, which is
            # why the old code reported success. Only the parent calling wait() clears it.
            unreapable.append(
                {
                    "pid": pid,
                    "parent": before.ppid,
                    "parent_comm": before.parent_comm or "?",
                    "unreaped_s": round(before.age_s, 1),
                }
            )
            continue
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.kill(pid, sig)
            except ProcessLookupError:
                break
            time.sleep(0.2 if sig == signal.SIGTERM else 0)
        after = sampler.sample_pid(pid)
        # Gone means "no longer running". A `Z` process has executed its exit; the pid lingers only
        # as the parent's bookkeeping, so it is gone for our purposes even though /proc still lists it.
        if after is None or after.is_zombie:
            killed.append(pid)
        else:
            failed.append({"pid": pid, "state": after.state, "wchan": after.wchan})

    if killed:
        op["killed_pids"] = killed
    if unreapable:
        op["unreapable"] = unreapable
    if failed:
        op["kill_failed"] = failed

    # `killed` means "we signalled something and it is no longer running". A tree that was already
    # dead before we acted is not a kill, and a pid that survived is not a success — a flag that says
    # "killed" while the pid is still there is worse than no flag at all.
    op["killed"] = bool(killed) and not failed
    if op["killed"]:
        op["state"] = "KILLED"


# ---------------------------------------------------------------------------
# The only remedy that can actually clear a zombie.
#
# A `Z` process cannot be signalled. It disappears when its parent calls wait(), and the practical way
# to make that happen is to restart the parent — the supervisor (systemd unit or container runtime)
# then reaps every child and starts a fresh process. Refusing to signal and merely reporting is not a
# fix; this is. It stays opt-in per operation (`remedy: "restart-parent"`), because restarting a
# parent is a production action.
# ---------------------------------------------------------------------------

RESTART_TIMEOUT_S = 30.0
RESTART_COOLDOWN_S = 300.0
MAX_RESTARTS = 3


def supervisor_from_cgroup(text: str) -> tuple[str, str] | None:
    """Identify what can restart a process: a docker container or a systemd unit.

    Pure, so the parsing is testable without a container runtime.
    """
    m = re.search(r"docker[-/]([0-9a-f]{12,64})", text)
    if m:
        return ("docker", m.group(1))
    m = re.search(r"([A-Za-z0-9@:_.\-]+\.service)", text)
    if m:
        return ("systemd", m.group(1))
    return None


def _supervisor_of(pid: int) -> tuple[str, str] | None:
    try:
        return supervisor_from_cgroup(pathlib.Path(f"/proc/{pid}/cgroup").read_text())
    except OSError:
        return None


def _restart(kind: str, ident: str) -> tuple[bool, str]:
    cmd = {
        "docker": ["docker", "restart", ident],
        "systemd": ["systemctl", "restart", ident],
    }[kind]
    try:
        res = subprocess.run(
            cmd, capture_output=True, text=True, timeout=RESTART_TIMEOUT_S
        )
    except Exception as exc:  # a missing runtime must be reported, never crash the loop
        return False, f"{kind} restart could not run: {exc}"
    if res.returncode != 0:
        return (
            False,
            f"{kind} restart exited {res.returncode}: {(res.stderr or '').strip()[:200]}",
        )
    return True, f"{kind} restarted {ident}"


def _reap_by_restart(op: dict, verdict: C.Verdict) -> None:
    """Restart the parents of the tracked zombies, then verify the zombies are actually gone."""
    now = time.time()
    if op.get("restart_attempts", 0) >= MAX_RESTARTS:
        return
    if now - float(op.get("restart_at") or 0) < RESTART_COOLDOWN_S:
        return

    parents: dict[int, list[int]] = {}
    for pid in verdict.zombies:
        sample = sampler.sample_pid(pid)
        if sample is not None:
            parents.setdefault(sample.ppid, []).append(pid)

    results = []
    for ppid, zids in parents.items():
        target = _supervisor_of(ppid)
        if target is None:
            # Killing an unsupervised parent would leave a dead service behind, which is worse than
            # the zombies. Say so rather than guess.
            results.append(
                {
                    "parent": ppid,
                    "action": "none",
                    "ok": False,
                    "cleared": 0,
                    "of": len(zids),
                    "detail": "no systemd unit or container owns this parent; "
                    "refusing to kill an unsupervised process",
                }
            )
            continue
        kind, ident = target
        ran, detail = _restart(kind, ident)
        cleared = [z for z in zids if sampler.sample_pid(z) is None]
        results.append(
            {
                "parent": ppid,
                "action": kind,
                "ok": ran and len(cleared) == len(zids),
                "cleared": len(cleared),
                "of": len(zids),
                "detail": detail,
            }
        )

    op["restart_at"] = now
    op["restart_attempts"] = op.get("restart_attempts", 0) + 1
    op["restart_results"] = results


def _loop(interval: float) -> None:
    global LAST_PING
    prev: dict[str, dict[int, C.ProcSample]] = {}
    while True:
        LAST_PING = time.time()
        with LOCK:
            for op_id, op in OPS.items():
                if op.get("done") or op.get("killed"):
                    continue
                pids = sampler.process_tree(op.get("pids", []))
                curr = sampler.snapshot(pids)
                age = op.get("unit_age_s")
                if op.get("last_unit_at"):
                    age = max(0.0, time.time() - op["last_unit_at"])
                verdict = C.classify(
                    prev.get(op_id, {}),
                    curr,
                    last_unit_age_s=age,
                    unit_budget_s=PROFILES[op.get("profile", "foreground")][
                        "unit_budget"
                    ],
                )
                prev[op_id] = curr
                _record(op, verdict, age or 0.0)
            STATE_PATH.write_text(
                json.dumps(
                    {
                        "updated": time.time(),
                        "daemon_age_s": 0,
                        "ops": {
                            k: {kk: vv for kk, vv in v.items() if kk != "stack"}
                            for k, v in OPS.items()
                        },
                    },
                    indent=1,
                )
            )
        time.sleep(interval)


class Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        for raw in self.rfile:
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                continue
            with LOCK:
                cmd = msg.get("op")
                op_id = msg.get("id")
                if cmd == "register":
                    OPS[op_id] = {
                        "id": op_id,
                        "pids": [int(p) for p in msg.get("pids", [])],
                        "profile": msg.get("profile", "foreground"),
                        "remedy": msg.get("remedy", "kill"),
                        "protected": [int(p) for p in msg.get("protected", [])],
                        "registered": time.time(),
                        # Registration is the baseline: without it, an operation that never reports
                        # progress has no age, so NO-PROGRESS can never fire — the state exists to
                        # catch exactly that case.
                        "last_unit_at": time.time(),
                        "unit": None,
                        "state": "RUNNING",
                        "level": 0,
                    }
                elif cmd == "progress" and op_id in OPS:
                    OPS[op_id]["last_unit_at"] = time.time()
                    OPS[op_id]["unit"] = msg.get("unit")
                    OPS[op_id]["level"] = 0
                    if msg.get("done"):
                        OPS.pop(
                            op_id, None
                        )  # finished work must not linger as unhealthy
                elif cmd == "status":
                    pass
                payload = {"ops": OPS}
            self.wfile.write(
                (
                    json.dumps(payload if cmd != "register" else {"id": op_id}) + "\n"
                ).encode()
            )


def main() -> int:
    paths.ensure_dir()
    ap = argparse.ArgumentParser()
    ap.add_argument("--socket", default=str(paths.SOCKET))
    ap.add_argument("--state", default=str(paths.STATE))
    ap.add_argument("--interval", type=float, default=1.0)
    args = ap.parse_args()
    global STATE_PATH
    STATE_PATH = pathlib.Path(args.state)
    STATE_PATH.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    sock = pathlib.Path(args.socket)
    sock.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if sock.exists():
        sock.unlink()
    # A client registers once, when its plugin loads. A daemon restart would otherwise erase every
    # registration and the table would read empty while the work continues — which is exactly what
    # happened in production.
    if STATE_PATH.exists():
        try:
            saved = json.loads(STATE_PATH.read_text()).get("ops", {})
            for op_id, op in saved.items():
                op.setdefault("registered", time.time())
                op.setdefault("level", 0)
                OPS[op_id] = op
            if saved:
                print(
                    f"restored {len(saved)} registration(s) from {STATE_PATH}",
                    flush=True,
                )
        except Exception as exc:
            print(f"could not restore registrations: {exc}", flush=True)

    threading.Thread(target=_loop, args=(args.interval,), daemon=True).start()
    server = socketserver.ThreadingUnixStreamServer(str(sock), Handler)
    os.chmod(sock, 0o660)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
