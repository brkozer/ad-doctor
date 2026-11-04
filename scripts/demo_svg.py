"""Render the README terminal screenshot from a real scan of the lab domain.

AD_DOCTOR_PASSWORD=... uv run python scripts/demo_svg.py docs/demo.svg
"""

from __future__ import annotations

import os
import subprocess
import sys

from rich.console import Console
from rich.text import Text

# The lab DC's LDAPS and SMB ports are forwarded to localhost (see lab/build.sh).
SCAN = [
    "ad-doctor", "scan", "127.0.0.1", "--ldaps", "--port", "10636", "--smb-port", "10445",
    "-u", "ADLAB\\adreader",
    "--only", "AD-ADCS-001", "AD-ACL-001", "AD-GPP-001", "AD-KRB-003", "AD-POL-002",
]  # fmt: skip


def main(out: str) -> None:
    console = Console(record=True, width=104, force_terminal=True)
    shown = " ".join(f"'{a}'" if "\\" in a else a for a in SCAN)
    console.print(Text("$ ", style="bold green") + Text(shown, style="bold"))
    console.print()
    env = {**os.environ, "FORCE_COLOR": "1"}
    result = subprocess.run(SCAN, capture_output=True, text=True, check=False, env=env)
    console.print(Text.from_ansi(result.stdout.rstrip()), overflow="fold")
    if result.stderr.strip():
        console.print(Text(result.stderr.strip(), style="yellow"))
    console.save_svg(out, title="ad-doctor")


if __name__ == "__main__":
    main(sys.argv[1])
