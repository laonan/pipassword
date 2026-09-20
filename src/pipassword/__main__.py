"""Command-line entry point.

The platform guard runs before the CLI module is imported, so an unsupported host
gets the explanatory message from :mod:`pipassword.platform_guard` rather than a
``ModuleNotFoundError`` from inside a dependency (requirement 1.4). That is why the
``cli`` import is deferred into the function body instead of sitting at module top.
"""

from __future__ import annotations

import sys

from .platform_guard import enforce


def main(argv: list[str] | None = None) -> int:
    enforce()

    from . import cli  # noqa: PLC0415 - deliberately deferred; see module docstring

    return cli.run(argv if argv is not None else sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
