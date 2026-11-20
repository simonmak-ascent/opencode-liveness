#!/usr/bin/env bash
#
# Install the supervisor so it survives a reboot.
#
# The previous deployment did not: the unit installed to /usr/local/bin, the socket and state lived in
# /run, and a WSL restart removed all three. The plugin treats a missing daemon as free, so nothing
# reported the outage — the supervisor was simply gone, and the only symptom was work that nobody was
# watching. This script installs into the user's own prefix and enables lingering, so the unit starts
# at boot without a login session.
#
#   ./deploy/install.sh            # install + enable + start
#   ./deploy/install.sh --dry-run  # print what it would write
#
set -euo pipefail

DRY_RUN=0
[ "${1:-}" = "--dry-run" ] && DRY_RUN=1

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
UNIT="$UNIT_DIR/opencode-liveness.service"
ENV_FILE="$HOME/.config/opencode-liveness.env"

say() { printf '  %s\n' "$*"; }
run() { if [ "$DRY_RUN" = 1 ]; then say "would: $*"; else "$@"; fi; }

say "repo: $REPO"

# 1. Install the package into the user prefix. `uv tool` is preferred when present: Debian and Ubuntu
#    mark the system interpreter externally managed (PEP 668), where `pip install --user` exits
#    non-zero and, under `set -e`, aborts before the unit is written. That is how the deployed unit
#    came to be two versions behind the code, still passing the stale `--socket /tmp/…sock` flag that
#    `liveness/paths.py` had already replaced — the daemon and the plugin disagreed on the socket and
#    every beat was lost.
if command -v uv >/dev/null 2>&1; then
  run uv tool install --force --quiet "$REPO"
else
  run python3 -m pip install --user --quiet --upgrade "$REPO"
fi

# 2. The socket and state directory. 0700 so a world-writable /tmp is not a symlink surface.
run install -d -m 0700 "${LIVENESS_DIR:-/tmp/opencode-liveness}"

# 3. The unit. `Restart=always` is deliberate: a supervisor that exits is a silent outage.
UNIT_BODY="[Unit]
Description=opencode-liveness supervisor (per-second liveness verdicts)
After=default.target

[Service]
Type=simple
ExecStart=%h/.local/bin/liveness-daemon
Restart=always
RestartSec=2
# No WatchdogSec. It was set to 10 with NotifyAccess=main, but the daemon never calls sd_notify, so
# systemd's deadline expired every ten seconds and killed a healthy supervisor: measured 38 restarts
# in ten minutes between 18:05 and 18:15, each logged as Failed with result 'watchdog'. A watchdog
# nothing feeds does not detect a hang, it guarantees a crash loop, so it is removed rather than kept
# for the appearance of coverage. Restart=always still handles a real exit.
#
# WHAT IS NOT COVERED: a daemon that stays alive but stops sampling is not detected automatically.
# jobstat reports WATCHDOG STALE from the age of the state file, and that needs no cooperation from
# the daemon — but nothing schedules it (verified 2026-11-20: no user timer, no cron entry). Doing
# this properly means the daemon calling sd_notify(WATCHDOG=1) from its sampler loop so systemd can
# restart it; until then, hang detection is a manual command, not a control.
# (No quotes or backticks in this block: UNIT_BODY is a double-quoted string, so either would end it
#  early and the rest would run as shell commands. That happened once; bash -n now catches the shape.)
Environment=LIVENESS_DIR=${LIVENESS_DIR:-/tmp/opencode-liveness}

[Install]
WantedBy=default.target
"

if [ "$DRY_RUN" = 1 ]; then
  say "would write $UNIT:"
  printf '%s' "$UNIT_BODY" | sed 's/^/     /'
else
  mkdir -p "$UNIT_DIR"
  printf '%s' "$UNIT_BODY" > "$UNIT"
  say "wrote $UNIT"
fi

# 4. Enable lingering so the user manager runs at boot, not only when a session is open.
run loginctl enable-linger "$USER"

# 5. Reload and start. `enable --now` starts a stopped unit and does nothing to a running one, so a
#    rewritten unit would sit on disk while the old argv — the stale `--socket` flag — kept running.
#    `restart` after `enable` makes the file on disk the thing that is actually executing.
run systemctl --user daemon-reload
run systemctl --user enable opencode-liveness.service
run systemctl --user restart opencode-liveness.service

if [ "$DRY_RUN" = 0 ]; then
  sleep 1
  systemctl --user --no-pager status opencode-liveness.service | head -8 || true

  # 6. The socket must exist where paths.py puts it. The plugin connects to that path and treats a
  #    failed connect as free, so a daemon listening anywhere else supervises nothing and reports
  #    nothing. This is the check that was missing when the installed unit still carried
  #    `--socket /tmp/opencode-liveness.sock` two versions after paths.py moved it.
  SOCKET_EXPECTED="${LIVENESS_DIR:-/tmp/opencode-liveness}/liveness.sock"
  for _ in $(seq 1 25); do
    [ -S "$SOCKET_EXPECTED" ] && break
    sleep 0.2
  done
  if [ ! -S "$SOCKET_EXPECTED" ]; then
    echo "FAIL: no socket at $SOCKET_EXPECTED" >&2
    echo "      the daemon is listening somewhere else, so no beat is received:" >&2
    systemctl --user --no-pager show -p ExecStart opencode-liveness.service 2>&1 | head -2 >&2
    exit 1
  fi
  say "socket: $SOCKET_EXPECTED"

  say "verify: jobstat          (a working supervisor prints a table and exits 0)"
fi
