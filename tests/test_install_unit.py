"""The deployed unit must not name a socket path.

`liveness/paths.py` is the single source for where the socket and state live, and the plugin defaults
to `paths.SOCKET`. The unit used to pass `--socket /tmp/opencode-liveness.sock` as well, so once
`paths.py` moved the socket inside `DIR` the daemon and the plugin disagreed: the daemon listened on
the old path, every beat went nowhere, and the plugin treats a failed connect as free — so the
supervisor was running and supervising nothing.

These assertions read `deploy/install.sh` itself, because that is what writes the unit. A test over
the currently installed file would pass on a workstation that was never re-deployed, which is the
exact state that hid the bug for two releases.

Run: python3 -m pytest tests/test_install_unit.py -q
"""

from __future__ import annotations

import ast
import re
import unittest
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
INSTALL = REPO / "deploy" / "install.sh"
PATHS = REPO / "liveness" / "paths.py"

# What the false claim looked like in three files. Matched without requiring the word `WatchdogSec`:
# AGENTS.md asserted the same mechanism without ever naming it.
AFFIRMATIVE_WATCHDOG_CLAIMS = (
    "supervised by systemd",
    "pings only when",
    "systemd restarts it",
)


def unit_body(path: Path = INSTALL) -> str:
    """The heredoc the script writes to the user unit, or the tests are reading the wrong file."""
    text = path.read_text()
    body = re.search(r'UNIT_BODY="(?P<body>.*?)\n"\n', text, re.S)
    assert body is not None, (
        "install.sh no longer defines UNIT_BODY; update this test with it"
    )
    return body.group("body")


def test_the_unit_does_not_pass_a_socket_or_state_path():
    """Guards the script's unit body, not the installed file.

    The drift that cost two releases was an *installed* unit written by an older script, which no
    assertion over this file can see. What this catches is the script going back to naming the path
    itself, which would defeat `paths.py` regardless of deployment state.
    """
    body = unit_body()
    for flag in ("--socket", "--state"):
        assert flag not in body, (
            f"the unit passes {flag}; paths.py owns that path and the plugin reads paths.SOCKET, "
            "so naming it again lets the two drift apart silently"
        )


def test_the_installer_refuses_to_finish_when_the_socket_is_elsewhere():
    """The check that would have caught the drift: assert the bound path, not just the unit file."""
    text = INSTALL.read_text()
    assert "SOCKET_EXPECTED" in text, (
        "install.sh must assert the socket exists at paths.py's location; without it a daemon "
        "listening on a stale path is reported as a successful install"
    )
    assert 'if [ ! -S "$SOCKET_EXPECTED" ]' in text, (
        "the socket assertion must be able to fail"
    )
    assert "exit 1" in text.split('if [ ! -S "$SOCKET_EXPECTED" ]')[1][:400], (
        "the socket assertion must exit non-zero, or it prints a warning and passes"
    )


def test_the_unit_points_at_the_installed_daemon_with_no_arguments():
    exec_start = [l for l in unit_body().splitlines() if l.startswith("ExecStart=")]
    assert len(exec_start) == 1, exec_start
    assert exec_start[0].strip() == "ExecStart=%h/.local/bin/liveness-daemon", (
        exec_start[0]
    )


def test_paths_py_puts_the_socket_inside_dir():
    """If this changes, the plugin's default has to change with it — hence the assertion."""
    text = PATHS.read_text()
    assert (
        'DIR = pathlib.Path(os.environ.get("LIVENESS_DIR", "/tmp/opencode-liveness"))'
        in text
    )
    assert 'SOCKET = DIR / "liveness.sock"' in text


def directives(body: str) -> list[str]:
    """The unit's live directives, with comments removed.

    Checking the raw body was a real defect: the explanatory comment says "No WatchdogSec … it was
    set to 10 with NotifyAccess=main", so `"NotifyAccess=" in body` was satisfied by prose and the
    assertion could never fail.
    """
    return [
        line.strip()
        for line in body.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def daemon_calls_sd_notify(root: Path = REPO) -> bool:
    """Whether the source contains a notify call expression, not merely a mention of one.

    `"sd_notify" in sources` matched the docstring at `liveness/daemon.py:12`, which documents that
    the daemon does not ping. A mention is not a call, so this walks the AST — though it reads source,
    so a defined-but-never-called `def beat(): sd_notify(...)` still counts. `root` is a parameter
    rather than the module constant so a fixture can exercise the positive path; without that, a
    function that always returned False would pass every test in this file.
    """
    for path in (root / "liveness").glob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            # Only calls count. Scanning every string constant made a docstring that mentions
            # sd_notify(WATCHDOG=1) look like a feeder — which is the original bug in a new shape,
            # and the fixture below caught it.
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
            if "sd_notify" in name or name.lower().endswith("notify"):
                return True
            for arg in node.args:
                if (
                    isinstance(arg, ast.Constant)
                    and isinstance(arg.value, str)
                    # A real payload is newline-separated key=value lines, so the marker is a
                    # substring of the message rather than the whole of it.
                    and "WATCHDOG=1" in arg.value
                ):
                    return True
    return False


def watchdog_problem(body: str, feeds: bool) -> str | None:
    """The sentence explaining why this unit may not claim a watchdog, or None when it is fine."""
    live = directives(body)
    sets = [d for d in live if d.startswith("WatchdogSec=")]
    # No watchdog claimed: nothing to check, whichever way `feeds` goes. Demanding NotifyAccess for a
    # watchdog that is not set was a false alarm waiting for the first unit without one.
    if not sets:
        return None
    if not feeds:
        return (
            f"the unit sets {sets[0]} but no module calls sd_notify/WATCHDOG=1, so systemd "
            "kills the daemon at every deadline"
        )
    if not any(d.startswith("NotifyAccess=") for d in live):
        return "a fed watchdog needs NotifyAccess to receive the ping"
    return None


def test_the_unit_does_not_enable_a_watchdog_the_daemon_cannot_feed():
    """`WatchdogSec` without `sd_notify` is a guaranteed crash loop, not a hang detector.

    Measured: with WatchdogSec=10 the supervisor was killed as "Failed with result 'watchdog'" —
    38 times in ten minutes — while no module calls `sd_notify`. The unit may only claim a watchdog
    the code actually feeds.
    """
    problem = watchdog_problem(unit_body(), daemon_calls_sd_notify())
    assert problem is None, problem


class WatchdogGuard(unittest.TestCase):
    """The guard must fail on a unit that would crash-loop, or it is not a guard."""

    def test_it_rejects_a_unit_that_sets_watchdog_without_a_feeder(self):
        body = unit_body() + "\nWatchdogSec=10\nNotifyAccess=main\n"
        self.assertIsNotNone(watchdog_problem(body, feeds=False))

    def test_it_ignores_a_commented_out_watchdog(self):
        body = unit_body() + "\n# WatchdogSec=10 explained here\n"
        self.assertIsNone(watchdog_problem(body, feeds=False))

    def test_it_accepts_a_watchdog_when_the_daemon_really_feeds_one(self):
        body = unit_body() + "\nWatchdogSec=10\nNotifyAccess=main\n"
        self.assertIsNone(watchdog_problem(body, feeds=True))

    def test_a_feeder_that_only_mentions_sd_notify_is_not_a_feeder(self):
        """The defect this class exists for: a docstring mention must not satisfy the check."""
        self.assertFalse(daemon_calls_sd_notify())


def test_the_unit_body_cannot_terminate_its_own_quoted_string():
    """`UNIT_BODY="…"` is double-quoted: a `"` ends it early and a backtick runs as a command.

    This was not hypothetical. A comment containing Failed with result 'watchdog' — with the double
    quotes around it — ended UNIT_BODY at that line, so the remainder executed as shell and the script
    died with `with: command not found` *after* the daemon had been stopped. `bash -n` accepts the
    file; only a check on the string's contents catches it.
    """
    body = unit_body()
    assert '"' not in body, (
        "a double quote inside UNIT_BODY terminates the shell string early; the text after it "
        "runs as commands"
    )
    assert "`" not in body, (
        "a backtick inside a double-quoted string is command substitution, evaluated at install time"
    )


def test_the_quoted_string_check_rejects_a_real_file(tmp_path):
    """The mutation fixture: the same parse, over a copy of install.sh with the quote injected.

    The earlier version of this test re-asserted Python's `in` rather than exercising the parse, so it
    would have passed with `unit_body` deleted.
    """
    broken = INSTALL.read_text().replace(
        "Description=opencode-liveness supervisor",
        'Description="oops" opencode-liveness supervisor',
    )
    copy = tmp_path / "install.sh"
    copy.write_text(broken)

    body = unit_body(copy)  # the parse still finds the heredoc
    with pytest.raises(AssertionError):
        assert '"' not in body


def test_there_is_no_second_copy_of_the_unit():
    """The unit lives in UNIT_BODY. A checked-in `.service` file is a second copy that drifts.

    There was one: `deploy/opencode-liveness.service` still carried `WatchdogSec=10` two rounds after
    the script stopped writing it, because nothing read the file and nothing failed when it disagreed.
    Installing copies UNIT_BODY, so the file could only ever mislead a reader.
    """
    strays = sorted(p.name for p in (REPO / "deploy").glob("*.service"))
    assert strays == [], f"the unit has one home (install.sh); remove {strays}"


def test_no_document_promises_a_watchdog_the_daemon_cannot_feed():
    """Three documents claimed `WatchdogSec` supervision. All three were false.

    `AGENTS.md` is the copy agents obey, and it was the last to be corrected — the first version of
    this test scanned only README and the daemon docstring, and required the line to name
    `WatchdogSec`, so the AGENTS.md sentence (which never used the word) was invisible.

    The detector now matches only affirmative claims, across all three files. Corrected prose avoids
    those phrases rather than relying on a negation check: an earlier version skipped any line
    containing "not", which also exempted "cannot" and "notice".
    """
    claims = []
    for rel in ("AGENTS.md", "README.md", "liveness/daemon.py"):
        for i, line in enumerate((REPO / rel).read_text().splitlines(), 1):
            if any(phrase in line for phrase in AFFIRMATIVE_WATCHDOG_CLAIMS):
                claims.append(f"{rel}:{i}: {line.strip()[:70]}")
    assert claims == [], f"these still claim watchdog supervision: {claims}"


def test_the_installer_restarts_an_already_running_unit():
    """`enable --now` is a no-op on a running unit, so a rewritten unit never took effect."""
    text = INSTALL.read_text()
    assert re.search(r"systemctl --user restart opencode-liveness\.service", text), (
        "install.sh must restart the unit; without it a changed ExecStart keeps executing the old argv"
    )


def test_the_socket_assertion_waits_before_failing():
    """Step 6 must retry: a daemon may take a moment to bind after `restart` returns."""
    text = INSTALL.read_text()
    block = text.split("SOCKET_EXPECTED=", 1)[1]
    assert "for _ in $(seq 1" in block, (
        "the socket assertion needs a bounded retry, or a slow bind reads as a path mismatch"
    )
    assert "sleep" in block.split("[ ! -S")[0], "the retry must sleep between attempts"


def test_the_installer_states_what_is_no_longer_detected():
    """Removing WatchdogSec leaves hangs undetected; the script must not imply otherwise."""
    text = INSTALL.read_text()
    assert "WHAT IS NOT COVERED" in text, (
        "the unit comment must say that a hung daemon is not detected automatically"
    )
    assert "sd_notify" in text, "and name the real fix"


def test_the_ast_check_fires_on_a_real_call_and_not_on_a_docstring(tmp_path):
    """The positive path, which the repo itself cannot supply: no module currently calls sd_notify.

    Without this, `daemon_calls_sd_notify` could be `return False` and every other test would pass.
    The payload is newline-separated because that is what sd_notify actually sends.
    """
    pkg = tmp_path / "liveness"
    pkg.mkdir()
    (pkg / "mentions.py").write_text(
        '"""It would call sd_notify(WATCHDOG=1) one day, if anyone wired it up."""\n'
    )
    assert daemon_calls_sd_notify(tmp_path) is False

    (pkg / "feeds.py").write_text(
        "def beat(sock):\n    sock.sendall(b'')\n    send_notify('WATCHDOG=1\\nSTATUS=sampling')\n"
    )
    assert daemon_calls_sd_notify(tmp_path) is True

    # The marker branch is short-circuited by the name check above, so it needs a call whose name is
    # not notify-like — in its own root, because with feeds.py present the result is True whichever
    # branch fires. `sock.send(...)` reaches only the argument scan.
    only = tmp_path / "only"
    (only / "liveness").mkdir(parents=True)
    (only / "liveness" / "payload.py").write_text(
        "def beat(sock):\n    sock.send('WATCHDOG=1\\nSTATUS=sampling')\n"
    )
    assert daemon_calls_sd_notify(only) is True
