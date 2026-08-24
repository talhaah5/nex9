"""Wire schemas for the Vantage protocol.

These types are the boundary between us and anonymous, unreliable, occasionally
adversarial contributors. Two rules govern everything here:

1. Reject, never coerce. If a submission does not match the schema it is thrown
   away. Silently reshaping bad input produces a plausible-looking measurement
   that is wrong, which is the worst possible outcome for this project.
2. Nothing in a submission is ever an instruction. Every string is length-capped
   and pattern-constrained so that it can be stored and counted, never executed
   and never placed in a model prompt.

The shapes here are published in AGENTS.md and clients already exist against
them. Changing a field is a breaking protocol change.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import Enum
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    StringConstraints,
    field_validator,
    model_validator,
)

# A conservative identifier: what we allow in agent-chosen and target ids.
# Deliberately excludes whitespace, quotes, slashes and control characters.
IdStr = Annotated[
    str,
    StringConstraints(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$"),
]

# Free-ish text an agent may send about itself. Capped hard; never interpreted.
SoftwareStr = Annotated[
    str,
    StringConstraints(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._/+ -]+$"),
]

HostnameStr = Annotated[
    str,
    StringConstraints(min_length=1, max_length=253, pattern=r"^[A-Za-z0-9.-]+$"),
]

# Upper bound on how long any single check may claim to have taken. A report
# claiming a 10-minute DNS lookup is broken or lying; either way we don't want it.
MAX_DURATION_MS = 120_000


class StrictModel(BaseModel):
    """Base for every wire type: unknown fields are an error, not a curiosity."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class Kind(str, Enum):
    DNS = "dns"
    HTTP = "http"
    TLS = "tls"


class ErrorCode(str, Enum):
    """Closed set. An agent that cannot express its failure as one of these
    should report the closest match rather than inventing a code."""

    TIMEOUT = "timeout"
    DNS_NXDOMAIN = "dns_nxdomain"
    DNS_SERVFAIL = "dns_servfail"
    DNS_REFUSED = "dns_refused"
    CONNECT_REFUSED = "connect_refused"
    CONNECT_UNREACHABLE = "connect_unreachable"
    TLS_HANDSHAKE_FAILED = "tls_handshake_failed"
    TLS_CERT_INVALID = "tls_cert_invalid"
    HTTP_ERROR = "http_error"
    # The agent's own operator forbade the request. Useful signal, never penalised.
    BLOCKED_BY_POLICY = "blocked_by_policy"


def _require_utc(value: datetime) -> datetime:
    """Timestamps must be explicit UTC.

    A naive datetime is ambiguous, and an offset other than UTC invites
    time-bucketing bugs that would silently smear measurements across hours.
    """
    if value.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware and UTC (ISO-8601 with 'Z')")
    if value.utcoffset() != timedelta(0):
        raise ValueError("timestamp must be UTC")
    return value


# --------------------------------------------------------------------------
# Targets — what we ask agents to measure. Issued by us, never by third parties.
# --------------------------------------------------------------------------


class DnsTarget(StrictModel):
    id: IdStr
    kind: Literal[Kind.DNS] = Kind.DNS
    hostname: HostnameStr
    rrtype: Literal["A", "AAAA", "CNAME", "MX", "TXT", "NS"] = "A"


class HttpTarget(StrictModel):
    id: IdStr
    kind: Literal[Kind.HTTP] = Kind.HTTP
    url: HttpUrl
    # HEAD by default: cheapest thing that still answers "is it reachable".
    method: Literal["GET", "HEAD"] = "HEAD"
    timeout_ms: int = Field(default=10_000, ge=1_000, le=30_000)


class TlsTarget(StrictModel):
    id: IdStr
    kind: Literal[Kind.TLS] = Kind.TLS
    hostname: HostnameStr
    port: int = Field(default=443, ge=1, le=65535)


Target = Annotated[DnsTarget | HttpTarget | TlsTarget, Field(discriminator="kind")]


class Manifest(StrictModel):
    """What an agent fetches. Signed; see signing.py."""

    manifest_id: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    issued_at: datetime
    expires_at: datetime
    signature: str
    signing_key: HttpUrl
    beacon_url: HttpUrl
    submit_url: HttpUrl
    max_targets_per_agent: int = Field(ge=1, le=64)
    targets: list[Target] = Field(min_length=1, max_length=64)

    _utc = field_validator("issued_at", "expires_at")(_require_utc)

    @field_validator("expires_at")
    @classmethod
    def _expires_after_issue(cls, v: datetime, info) -> datetime:
        issued = info.data.get("issued_at")
        if issued is not None and v <= issued:
            raise ValueError("expires_at must be after issued_at")
        return v

    @field_validator("targets")
    @classmethod
    def _unique_target_ids(cls, v: list[Target]) -> list[Target]:
        ids = [t.id for t in v]
        if len(set(ids)) != len(ids):
            raise ValueError("target ids must be unique within a manifest")
        return v


# --------------------------------------------------------------------------
# Reports — what agents send back. Assume every field is hostile.
# --------------------------------------------------------------------------


class DnsResult(StrictModel):
    addresses: list[
        Annotated[str, StringConstraints(min_length=1, max_length=255)]
    ] = Field(min_length=0, max_length=64)


class HttpResult(StrictModel):
    status_code: int = Field(ge=100, le=599)
    final_url: HttpUrl | None = None
    redirect_count: int = Field(default=0, ge=0, le=20)


class TlsResult(StrictModel):
    # SHA-256 of the leaf certificate, lowercase hex.
    fingerprint_sha256: Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]
    issuer: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    not_before: datetime
    not_after: datetime

    _utc = field_validator("not_before", "not_after")(_require_utc)


class Observation(StrictModel):
    """One measurement of one target.

    Exactly one of `result` / `error` is populated. A populated `error` is a
    perfectly good observation — recording that a host was unreachable from
    somewhere is the entire point of the project, not a failed submission.
    """

    target_id: IdStr
    kind: Kind
    started_at: datetime
    duration_ms: int = Field(ge=0, le=MAX_DURATION_MS)
    result: DnsResult | HttpResult | TlsResult | None = None
    error: ErrorCode | None = None

    _utc = field_validator("started_at")(_require_utc)

    @model_validator(mode="after")
    def _exactly_one_outcome(self) -> "Observation":
        """Must be a model validator, not a field validator.

        Field validators do not run for fields left at their default, so an
        observation submitted with *neither* `result` nor `error` — an agent
        reporting nothing while appearing to report something — would otherwise
        be accepted and stored as a measurement.
        """
        if (self.result is None) == (self.error is None):
            raise ValueError("exactly one of 'result' or 'error' must be set")
        return self


class AgentIdentity(StrictModel):
    """Self-declared and therefore worth nothing on its own.

    `id` is a handle for accumulating a contribution record, not a credential.
    Location is never taken from here — it is derived server-side from the
    beacon callback, which an agent cannot forge without actually being there.
    """

    id: IdStr
    software: SoftwareStr | None = None


class Report(StrictModel):
    manifest_id: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    beacon_token: Annotated[
        str,
        StringConstraints(min_length=16, max_length=128, pattern=r"^[A-Za-z0-9_-]+$"),
    ]
    agent: AgentIdentity
    observations: list[Observation] = Field(min_length=1, max_length=64)

    @field_validator("observations")
    @classmethod
    def _one_observation_per_target(cls, v: list[Observation]) -> list[Observation]:
        """A single report may not measure the same target twice.

        Allowing duplicates would let one agent inflate its own weight in
        consensus by simply repeating itself.
        """
        ids = [o.target_id for o in v]
        if len(set(ids)) != len(ids):
            raise ValueError("duplicate target_id in observations")
        return v
