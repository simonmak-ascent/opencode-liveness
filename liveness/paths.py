"""One place that decides where the socket and the state file live.

The daemon and the plugin previously disagreed: the unit passed `--socket /run/opencode-liveness.sock`
while the plugin defaulted to `/tmp/opencode-liveness.sock`. The daemon could be perfectly healthy and
the plugin still talked to nothing, and because the plugin treats a missing daemon as free, the
failure was silent. Both sides now derive the path from here, so they cannot drift again.

`LIVENESS_DIR` overrides the directory; the socket lives inside it, in a directory only the owner can
enter, so a world-writable `/tmp` is not a symlink attack surface.
"""

from __future__ import annotations

import os
import pathlib

DIR = pathlib.Path(os.environ.get("LIVENESS_DIR", "/tmp/opencode-liveness"))
SOCKET = DIR / "liveness.sock"
STATE = DIR / "state.json"


def ensure_dir() -> pathlib.Path:
    """Create the directory 0700. Idempotent, and never widens an existing mode."""
    DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        os.chmod(DIR, 0o700)
    except OSError:
        pass
    return DIR
