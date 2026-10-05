"""Probe package.

Importing this package registers every bundled probe with the global registry.
The engine imports this module once at startup; no other wiring is needed to
add a probe beyond putting a module in ``security/`` or ``marketing/`` and
decorating it with ``@register_probe``.
"""

from __future__ import annotations

# Marketing probes ----------------------------------------------------------------
from .marketing import accessibility as _accessibility  # noqa: F401
from .marketing import consent as _consent  # noqa: F401
from .marketing import content_depth as _content_depth  # noqa: F401
from .marketing import forms as _forms  # noqa: F401
from .marketing import images as _images  # noqa: F401
from .marketing import links as _links  # noqa: F401
from .marketing import meta_seo as _meta_seo  # noqa: F401
from .marketing import performance as _performance  # noqa: F401
from .marketing import pwa as _pwa  # noqa: F401
from .marketing import schema as _schema  # noqa: F401
from .marketing import sitemap as _sitemap  # noqa: F401
from .marketing import social_meta as _social_meta  # noqa: F401
from .marketing import soft_404 as _soft_404  # noqa: F401
from .marketing import tech_stack as _tech_stack  # noqa: F401
from .marketing import third_party as _third_party  # noqa: F401
from .marketing import tracking as _tracking  # noqa: F401

# Security probes -----------------------------------------------------------------
from .security import cookies as _cookies  # noqa: F401
from .security import cors as _cors  # noqa: F401
from .security import csp_deep as _csp_deep  # noqa: F401
from .security import dns_deep as _dns_deep  # noqa: F401
from .security import dns_records as _dns_records  # noqa: F401
from .security import email_auth as _email_auth  # noqa: F401
from .security import exposure as _exposure  # noqa: F401
from .security import exposure_api as _exposure_api  # noqa: F401
from .security import headers as _headers  # noqa: F401
from .security import mixed_content as _mixed_content  # noqa: F401
from .security import redirects as _redirects  # noqa: F401
from .security import subdomain_takeover as _subdomain_takeover  # noqa: F401
from .security import subdomains as _subdomains  # noqa: F401
from .security import tls as _tls  # noqa: F401
from .security import transport as _transport  # noqa: F401

# Shared / capture ----------------------------------------------------------------
from .shared import http_client as _http_client  # noqa: F401

__all__: list[str] = []
