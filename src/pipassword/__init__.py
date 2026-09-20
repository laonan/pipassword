"""pipassword — a TUI password vault for Raspberry Pi hardware.

Importing this package is deliberately side-effect free: no argument parsing, no
platform checks, no configuration reads. The legacy ``minipassword`` package called
``parser.parse_args()`` at module import time, which meant importing the library
parsed ``sys.argv`` and could terminate the process. Keeping ``__init__`` inert makes
the storage layer importable from tests and from ``recover.py`` without dragging in
the CLI.

Platform enforcement lives in :mod:`pipassword.platform_guard` and is invoked only
from the command-line entry point.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
