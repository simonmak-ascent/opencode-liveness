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

# 1. Install the package into the user prefix, so the daemon binary does not depend on a system pip.
run python3 -m pip install --user --quiet --upgrade "$REPO"

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
# The watchdog cannot be watched by itself: a frozen sampler loop stops pings and systemd restarts it.
WatchdogSec=10
NotifyAccess=main
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

# 5. Reload and start.
run systemctl --user daemon-reload
run systemctl --user enable --now opencode-liveness.service

if [ "$DRY_RUN" = 0 ]; then
  sleep 1
  systemctl --user --no-pager status opencode-liveness.service | head -8 || true
  say "verify: jobstat          (a working supervisor prints a table and exits 0)"
  say "        ls ${LIVENESS_DIR:-/tmp/opencode-liveness}/liveness.sock"
fi
