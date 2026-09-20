"""Non-interactive command line.

Placeholder for task 9. Argument parsing deliberately happens inside :func:`run`,
never at module import, so that importing this module has no side effects. The legacy
``minipassword.commands`` called ``parser.parse_args()`` at import time, which meant
any import parsed ``sys.argv`` and could call ``sys.exit``.
"""

from __future__ import annotations

import argparse

from . import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pipw",
        description="A TUI password vault for Raspberry Pi hardware.",
    )
    parser.add_argument("--version", action="version", version=f"pipassword {__version__}")
    return parser


def run(argv: list[str]) -> int:
    parser = build_parser()
    parser.parse_args(argv)
    parser.print_help()
    return 0
