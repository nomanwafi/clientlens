"""ClientLens branding.

Single source of truth for the author and project identity. Every renderer —
console, HTML, PDF, dashboard — imports from here so the name appears
consistently everywhere.
"""

from __future__ import annotations

AUTHOR = "Abdullah Al Noman"
AUTHOR_DISPLAY = "ABDULLAH AL NOMAN"
PROJECT = "ClientLens"
TAGLINE = "Unified client audit engine — security + marketing reconnaissance"
URL = "https://github.com/abdullahalnoman/clientlens"
REPORT_FOOTER = f"{PROJECT} · prepared by {AUTHOR}"
