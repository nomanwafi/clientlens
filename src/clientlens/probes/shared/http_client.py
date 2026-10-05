"""Shared HTTP client with a hard request budget and rate limit.

Every request ClientLens makes to the target goes through this module, which
is how the safety rails in :class:`~clientlens.core.config.ScanConfig` are
actually enforced. A probe cannot accidentally hammer a target because it has
no direct access to a socket.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import UTC

import httpx

from ...core.exceptions import RateLimitExceeded

log = logging.getLogger("clientlens.http")


@dataclass
class FetchedResponse:
    """A captured HTTP response, normalised for probes."""

    url: str
    final_url: str
    status: int
    headers: dict[str, str]
    body: str
    elapsed_ms: int
    redirect_chain: list[str] = field(default_factory=list)
    error: str = ""
    fetched_at: str = ""

    @property
    def ok(self) -> bool:
        return not self.error and self.status > 0

    @property
    def is_html(self) -> bool:
        ctype = self.headers.get("content-type", "").lower()
        return "html" in ctype or (not ctype and self.body.lstrip()[:1] == "<")

    def snippet(self, limit: int = 1200) -> str:
        return self.body[:limit]

    def header_block(self) -> str:
        return "\n".join(f"{k}: {v}" for k, v in self.headers.items())


class RateLimiter:
    """Token-bucket limiter enforcing both rate and total budget."""

    def __init__(self, rate_per_second: float, max_requests: int) -> None:
        self._interval = 1.0 / rate_per_second if rate_per_second > 0 else 0.0
        self._max_requests = max_requests
        self._used = 0
        self._lock = asyncio.Lock()
        self._last = 0.0

    @property
    def used(self) -> int:
        return self._used

    @property
    def remaining(self) -> int:
        return max(0, self._max_requests - self._used)

    async def acquire(self) -> None:
        async with self._lock:
            if self._used >= self._max_requests:
                raise RateLimitExceeded(f"request budget exhausted ({self._max_requests} requests)")
            now = time.monotonic()
            wait = self._interval - (now - self._last)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last = time.monotonic()
            self._used += 1


class HttpCaptureClient:
    """Thin async wrapper around httpx with capture semantics."""

    def __init__(self, config) -> None:
        self.config = config
        self.limiter = RateLimiter(config.rate_limit_per_second, config.max_requests_per_scan)
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> HttpCaptureClient:
        timeout = httpx.Timeout(
            self.config.timeout_s,
            connect=self.config.connect_timeout_s,
        )
        self._client = httpx.AsyncClient(
            headers=self.config.headers,
            timeout=timeout,
            follow_redirects=False,
            http2=True,
            verify=True,
        )
        return self

    async def __aexit__(self, *exc) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    @property
    def requests_used(self) -> int:
        return self.limiter.used

    async def get(self, url: str, *, follow: bool = True) -> FetchedResponse:
        """GET a URL, optionally following redirects while recording the chain."""
        if self._client is None:
            raise RuntimeError("HttpCaptureClient must be used as an async context manager")

        chain: list[str] = []
        current = url
        redirects_left = self.config.max_redirects if follow else 0
        started = time.perf_counter()

        while True:
            await self.limiter.acquire()
            try:
                resp = await self._client.get(current)
            except httpx.HTTPError as exc:
                return FetchedResponse(
                    url=url,
                    final_url=current,
                    status=0,
                    headers={},
                    body="",
                    elapsed_ms=int((time.perf_counter() - started) * 1000),
                    redirect_chain=chain,
                    error=f"{type(exc).__name__}: {exc}",
                    fetched_at=_now(),
                )

            headers = {k.lower(): v for k, v in resp.headers.items()}
            location = headers.get("location")

            if resp.status_code in {301, 302, 303, 307, 308} and location and redirects_left > 0:
                chain.append(f"{resp.status_code} -> {location}")
                current = str(resp.url.join(location))
                redirects_left -= 1
                continue

            body = ""
            try:
                body = resp.text
            except Exception:  # noqa: BLE001 - binary/undecodable body
                body = ""
            if len(body) > self.config.max_body_bytes:
                body = body[: self.config.max_body_bytes]

            return FetchedResponse(
                url=url,
                final_url=str(resp.url),
                status=resp.status_code,
                headers=headers,
                body=body,
                elapsed_ms=int((time.perf_counter() - started) * 1000),
                redirect_chain=chain,
                fetched_at=_now(),
            )

    async def head(self, url: str) -> FetchedResponse:
        if self._client is None:
            raise RuntimeError("HttpCaptureClient must be used as an async context manager")
        await self.limiter.acquire()
        started = time.perf_counter()
        try:
            resp = await self._client.head(url)
            return FetchedResponse(
                url=url,
                final_url=str(resp.url),
                status=resp.status_code,
                headers={k.lower(): v for k, v in resp.headers.items()},
                body="",
                elapsed_ms=int((time.perf_counter() - started) * 1000),
                fetched_at=_now(),
            )
        except httpx.HTTPError as exc:
            return FetchedResponse(
                url=url,
                final_url=url,
                status=0,
                headers={},
                body="",
                elapsed_ms=int((time.perf_counter() - started) * 1000),
                error=f"{type(exc).__name__}: {exc}",
                fetched_at=_now(),
            )


def _now() -> str:
    from datetime import datetime

    return datetime.now(UTC).isoformat(timespec="seconds")
