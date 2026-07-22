"""Backward-compatible launcher for Security Header Auditor users.

New integrations should install the package and run ``previewshield scan``.
"""

from __future__ import annotations

import sys

from previewshield.cli import main


def legacy_main() -> int:
    """Forward legacy positional arguments to the PreviewShield scan command."""

    arguments = sys.argv[1:]
    commands = {"diff", "init", "policy", "rules", "scan"}
    global_options = {"-h", "--help", "--version"}
    if arguments and arguments[0] not in commands | global_options:
        arguments = ["scan", *arguments]
    return main(arguments)


if __name__ == "__main__":
    raise SystemExit(legacy_main())
