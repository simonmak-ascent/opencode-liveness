"""Acceptance check against the real zombies in the estate.

Read-only: it samples the existing `Z` processes on this host, classifies them with the shipped code,
and proves that the kill path sends nothing. It never signals a process, and it never reaps one —
these belong to another parent.
"""

from __future__ import annotations

import collections
import os
import sys

from liveness import daemon, sampler
from liveness.classify import classify

BUDGET = 60.0


def main() -> int:
    groups: dict[int, list[int]] = collections.defaultdict(list)
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        sample = sampler.sample_pid(int(entry))
        if sample is not None and sample.is_zombie:
            groups[sample.ppid].append(sample.pid)

    if not groups:
        print("LIVE-SCENARIO no zombies on this host")
        return 0  # nothing to prove here; not a failure

    ppid, pids = max(groups.items(), key=lambda kv: len(kv[1]))
    samples = {p: sampler.sample_pid(p) for p in pids}
    samples = {p: s for p, s in samples.items() if s is not None}

    verdict = classify({}, samples, last_unit_age_s=10_000, unit_budget_s=BUDGET)
    print(f"LIVE-SCENARIO zombies={len(pids)} parent={ppid} state={verdict.state}")
    print(f"  detail: {verdict.detail}")

    sent: list[tuple[int, int]] = []
    real_kill = os.kill
    daemon.os.kill = lambda p, sig: sent.append((p, sig))
    try:
        op = {"pids": pids[:5], "protected": [], "remedy": "kill"}
        daemon._kill(op)
    finally:
        daemon.os.kill = real_kill

    print(
        f"  signals_sent={len(sent)} killed={op.get('killed')} unreapable={len(op.get('unreapable', []))}"
    )
    ok = verdict.state == "ZOMBIE" and not sent and op.get("killed") is False
    print("LIVE-SCENARIO", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
