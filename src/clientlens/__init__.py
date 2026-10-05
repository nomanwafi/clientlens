"""ClientLens — Unified client audit engine.

Security and digital marketing reconnaissance in a single, evidence-backed report.
Free, local, and deterministic.

Author: Abdullah Al Noman
"""

from .branding import AUTHOR, AUTHOR_DISPLAY, PROJECT, REPORT_FOOTER, TAGLINE, URL

try:
    from importlib.metadata import PackageNotFoundError
    from importlib.metadata import version as _pkg_version

    try:
        __version__ = _pkg_version("clientlens")
    except PackageNotFoundError:
        __version__ = "0.3.1"
except Exception:  # noqa: BLE001 — importlib.metadata is stdlib but very old Pythons may lack it
    __version__ = "0.3.1"

__author__ = AUTHOR

__all__ = [
    "AUTHOR",
    "AUTHOR_DISPLAY",
    "PROJECT",
    "REPORT_FOOTER",
    "TAGLINE",
    "URL",
    "__author__",
    "__version__",
]
