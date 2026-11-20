# AGENTS.md

Instructions for agents working in this repository.

## What this is

`opencode-liveness` is a small, dependency-free supervisor that answers one question per operation:
**is it working, or merely alive?** It samples `/proc` at 1 Hz, classifies each registered operation
into one of six states, and escalates with a stack dump and a resumable kill.

It is published openly (MIT) because the failure it prevents is universal to agent harnesses, not
specific to this estate.

## Commands

```bash
python3 -m pytest tests/test_classify.py -q     # six states, synthetic, deterministic
python3 -m pytest tests/test_zombie.py -q       # the seventh state, incl. a real unreaped child
python3 -m pytest tests/test_inject_live.py -q  # real processes, real /proc
python3 -m liveness.cli --state /run/opencode-liveness.json
python3 -m liveness.daemon --socket /run/opencode-liveness.sock
```

Python 3.11+; standard library only. `py-spy` is optional and used for stack capture when present.

## Rules

- **The seven states are the contract.** A new state needs a test that distinguishes it from every
  other one on synthetic samples — `ZOMBIE` was added that way, because a `Z` process is not a slow
  process and not a starved one: it is dead, and it must never be escalated to a kill.
- **Never signal a process that has already exited.** `os.kill` on a `Z` pid returns success and does
  nothing; the only thing that clears a zombie is its parent calling `wait()`. The supervisor reports
  the parent and sends nothing.
- **`WAITING-ON-CHILD` must never be collapsed into `DEADLOCK`.** That distinction is why this
  repository exists; a parent waiting on a working child is the normal shape of every pipeline.
- **Progress is set inclusion, never a counter.** A unit counts only when its output exists and hashes
  to the ledger's record.
- **Never make the wrapper itself a hang.** Every call to the daemon is bounded and fails open: a
  missing daemon must cost nothing.
- **The daemon runs under `Restart=always` and does not feed `WatchdogSec`** — no module calls
  `sd_notify`, so a watchdog would kill a healthy daemon rather than detect a hang (measured: 38
  restarts in ten minutes before it was removed). A hung-but-alive daemon is therefore not detected
  automatically; `jobstat` reports `WATCHDOG STALE` from the state file's age, and nothing schedules it.
  The fix, when someone implements it, is `sd_notify(WATCHDOG=1)` from the sampler loop.
- **A self-pinging heartbeat proves nothing** — a thread that pings while the work is frozen is the
  classic false negative. That is why `progress` messages are the only input to NO-PROGRESS.

## Release

Merge to `main` publishes. The version served by PyPI and npm is the verification; there is no node
this repository deploys to.
