"""Probe registry and plugin contract.

Adding a probe is intentionally a one-file job::

    from clientlens.core.registry import register_probe
    from clientlens.core.models import Finding, ...

    @register_probe(
        id="security.headers.hsts",
        category=Category.SECURITY,
        requires=["http_response"],
        mode="passive",
    )
    async def check_hsts(ctx: ProbeContext) -> list[Finding]:
        ...

The engine discovers probes by importing :mod:`clientlens.probes` and reading
this registry. Nothing else needs to change.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC
from enum import Enum
from typing import Any

from .exceptions import ProbeError
from .models import Category, Finding, ProbeResult

log = logging.getLogger("clientlens.registry")


class ProbeMode(str, Enum):
    """How much the probe touches the target.

    PASSIVE  - one or two requests, or purely local analysis of captured data.
    ACTIVE   - additional requests that enumerate/interact (path probes, param
               injection tests). Only run when explicitly enabled.
    LOCAL    - no network at all; operates on data gathered by other probes.
    """

    PASSIVE = "passive"
    ACTIVE = "active"
    LOCAL = "local"


class ProbePhase(str, Enum):
    """Execution ordering.

    CAPTURE  - gathers raw material (DNS, TLS, HTTP) for later probes.
    ANALYSE  - consumes capture results.
    ACTIVE   - opt-in interaction with the target.
    """

    CAPTURE = "capture"
    ANALYSE = "analyse"
    ACTIVE = "active"


ProbeFn = Callable[..., Awaitable[list[Finding]]]


@dataclass(frozen=True)
class ProbeSpec:
    """Static description of a probe."""

    id: str
    fn: ProbeFn
    category: Category
    mode: ProbeMode = ProbeMode.PASSIVE
    phase: ProbePhase = ProbePhase.ANALYSE
    requires: tuple[str, ...] = ()
    provides: tuple[str, ...] = ()
    title: str = ""
    description: str = ""
    tags: tuple[str, ...] = ()
    timeout_s: float = 25.0

    @property
    def short_id(self) -> str:
        """Last dotted segment, used in logs and console output."""
        return self.id.rsplit(".", 1)[-1]


# --------------------------------------------------------------------------- #
# ProbeContext
# --------------------------------------------------------------------------- #
@dataclass
class ProbeContext:
    """Everything a probe is allowed to see.

    Probes share raw captured material via ``facts``. A probe declares
    ``requires=("http_response",)`` and the engine guarantees that key is
    present (or the probe is skipped, not run with missing data).
    """

    target: Any  # ScanTarget
    config: Any  # ScanConfig
    facts: dict[str, Any] = field(default_factory=dict)
    # Convenience accessors populated by the engine for capture-phase probes.
    http_client: Any = None

    def require(self, key: str) -> Any:
        if key not in self.facts:
            raise ProbeError(f"required fact {key!r} is not available to this probe")
        return self.facts[key]

    def has(self, key: str) -> bool:
        return key in self.facts

    def set_fact(self, key: str, value: Any) -> None:
        self.facts[key] = value


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #
@dataclass
class Registry:
    probes: dict[str, ProbeSpec] = field(default_factory=dict)

    def add(self, spec: ProbeSpec) -> None:
        if spec.id in self.probes:
            raise ValueError(f"duplicate probe id: {spec.id}")
        self.probes[spec.id] = spec

    def get(self, probe_id: str) -> ProbeSpec:
        return self.probes[probe_id]

    def select(
        self,
        *,
        include: Sequence[str] | None = None,
        exclude: Sequence[str] | None = None,
        category: Category | None = None,
        allow_active: bool = False,
    ) -> list[ProbeSpec]:
        """Return probes to run, in phase order.

        ``include`` / ``exclude`` entries are prefixes: ``"security"``,
        ``"security.headers"`` or a full probe id all work.
        """
        specs = list(self.probes.values())

        if category is not None:
            specs = [s for s in specs if s.category is category]
        if include:
            prefixes = tuple(include)
            specs = [s for s in specs if s.id.startswith(prefixes)]
        if exclude:
            banned = tuple(exclude)
            specs = [s for s in specs if not s.id.startswith(banned)]
        if not allow_active:
            specs = [s for s in specs if s.mode is not ProbeMode.ACTIVE]

        phase_order = {
            ProbePhase.CAPTURE: 0,
            ProbePhase.ANALYSE: 1,
            ProbePhase.ACTIVE: 2,
        }
        return sorted(specs, key=lambda s: (phase_order[s.phase], s.id))

    def by_phase(self, specs: Sequence[ProbeSpec]) -> dict[ProbePhase, list[ProbeSpec]]:
        grouped: dict[ProbePhase, list[ProbeSpec]] = {p: [] for p in ProbePhase}
        for s in specs:
            grouped[s.phase].append(s)
        return grouped

    def ids(self) -> list[str]:
        return sorted(self.probes)


REGISTRY = Registry()


def register_probe(
    id: str,
    *,
    category: Category,
    mode: ProbeMode = ProbeMode.PASSIVE,
    phase: ProbePhase = ProbePhase.ANALYSE,
    requires: Sequence[str] = (),
    provides: Sequence[str] = (),
    title: str = "",
    description: str = "",
    tags: Sequence[str] = (),
    timeout_s: float = 25.0,
) -> Callable[[ProbeFn], ProbeFn]:
    """Decorator registering an async probe function."""

    def decorator(fn: ProbeFn) -> ProbeFn:
        spec = ProbeSpec(
            id=id,
            fn=fn,
            category=category,
            mode=mode,
            phase=phase,
            requires=tuple(requires),
            provides=tuple(provides),
            title=title or fn.__doc__.strip().splitlines()[0] if fn.__doc__ else id,
            description=description,
            tags=tuple(tags),
            timeout_s=timeout_s,
        )
        REGISTRY.add(spec)
        return fn

    return decorator


async def run_probe(spec: ProbeSpec, ctx: ProbeContext) -> ProbeResult:
    """Execute one probe defensively and return a :class:`ProbeResult`."""
    started = time.perf_counter()
    started_at = _now()
    result = ProbeResult(
        probe_id=spec.id,
        category=spec.category,
        started_at=started_at,
    )

    missing = [k for k in spec.requires if not ctx.has(k)]
    if missing:
        result.status = "skipped"
        result.error = f"missing required facts: {', '.join(missing)}"
        result.duration_ms = int((time.perf_counter() - started) * 1000)
        result.finished_at = _now()
        return result

    try:
        findings = await asyncio.wait_for(spec.fn(ctx), timeout=spec.timeout_s)
        for f in findings:
            if not f.probe_id:
                f.probe_id = spec.id
            if not f.target:
                f.target = str(ctx.target.domain)
        result.findings = list(findings)
        result.status = "ok"
    except TimeoutError:
        result.status = "error"
        result.error = f"timed out after {spec.timeout_s}s"
        log.warning("probe %s timed out", spec.id)
    except Exception as exc:  # noqa: BLE001 - probes must not crash the scan
        result.status = "error"
        result.error = f"{type(exc).__name__}: {exc}"
        log.exception("probe %s failed", spec.id)

    result.duration_ms = int((time.perf_counter() - started) * 1000)
    result.finished_at = _now()
    return result


def _now() -> str:
    from datetime import datetime

    return datetime.now(UTC).isoformat(timespec="seconds")
