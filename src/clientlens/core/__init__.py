"""ClientLens core — models, registry, engine, config, target parsing."""

from .config import ScanConfig
from .engine import ScanEngine
from .exceptions import (
    AuthorizationRequired,
    ClientLensError,
    InvalidTarget,
    ProbeError,
    RateLimitExceeded,
)
from .models import (
    Category,
    Confidence,
    Evidence,
    EvidenceType,
    Finding,
    FindingKind,
    Presence,
    ProbeResult,
    ScanResult,
    ScanTarget,
    Severity,
)
from .registry import (
    REGISTRY,
    ProbeContext,
    ProbeMode,
    ProbePhase,
    ProbeSpec,
    register_probe,
)
from .target import normalize_target

__all__ = [
    "AuthorizationRequired",
    "Category",
    "ClientLensError",
    "Confidence",
    "Evidence",
    "EvidenceType",
    "Finding",
    "FindingKind",
    "InvalidTarget",
    "Presence",
    "ProbeContext",
    "ProbeError",
    "ProbeMode",
    "ProbePhase",
    "ProbeResult",
    "ProbeSpec",
    "REGISTRY",
    "RateLimitExceeded",
    "ScanConfig",
    "ScanEngine",
    "ScanResult",
    "ScanTarget",
    "Severity",
    "normalize_target",
    "register_probe",
]
