"""Vantage coordinator — the trusted half of the protocol.

Everything an agent sends us arrives here. The rules that make this a
measurement network rather than a botnet live in three modules:

* `models`    — strict wire schemas; reject, never coerce
* `signing`   — Ed25519 manifest signatures, so agents can verify what we asked
* `ratelimit` — global per-target ceilings, so the swarm can never flood a host
* `beacon`    — server-observed vantage points, so location is a fact not a claim
* `resolver`  — the address-to-network lookup the beacon depends on
* `storage`   — append-only persistence; the dataset is the asset
"""

from __future__ import annotations

__version__ = "0.1.0"

from vantage.beacon import BeaconError, BeaconRegistry, NetworkResolver, VantagePoint
from vantage.models import (
    AgentIdentity,
    DnsResult,
    DnsTarget,
    ErrorCode,
    HttpResult,
    HttpTarget,
    Kind,
    Manifest,
    Observation,
    Report,
    Target,
    TlsResult,
    TlsTarget,
)
from vantage.ratelimit import ALLOWED, Decision, Denial, Policy, RateLimiter
from vantage.resolver import (
    CachingResolver,
    CymruDnsResolver,
    NullResolver,
    StaticResolver,
    TxtLookup,
)
from vantage.signing import (
    SignatureError,
    canonical_bytes,
    load_public_key_pem,
    public_key_to_pem,
    sign_payload,
    verify_payload,
)
from vantage.storage import SqliteStore, StorageError, Store, StoredReport

__all__ = [
    "ALLOWED",
    "AgentIdentity",
    "BeaconError",
    "BeaconRegistry",
    "CachingResolver",
    "CymruDnsResolver",
    "Decision",
    "Denial",
    "DnsResult",
    "DnsTarget",
    "ErrorCode",
    "HttpResult",
    "HttpTarget",
    "Kind",
    "Manifest",
    "NetworkResolver",
    "NullResolver",
    "Observation",
    "Policy",
    "RateLimiter",
    "Report",
    "SignatureError",
    "SqliteStore",
    "StaticResolver",
    "StorageError",
    "Store",
    "StoredReport",
    "Target",
    "TlsResult",
    "TlsTarget",
    "TxtLookup",
    "VantagePoint",
    "__version__",
    "canonical_bytes",
    "load_public_key_pem",
    "public_key_to_pem",
    "sign_payload",
    "verify_payload",
]
