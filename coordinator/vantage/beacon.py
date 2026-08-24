"""Beacon callback — how a vantage point becomes a fact instead of a claim.

An agent telling us "I am in Brazil" is worth nothing: it costs nothing to say
and cannot be checked. So we never ask. Instead every manifest embeds a
single-use beacon URL. When the agent fetches it, *we* observe the source
address and derive ASN and country ourselves. An agent cannot forge that
without actually having a host on that network, which is precisely the property
the whole dataset rests on.

Three rules, each enforced here:

* **Single use.** A token is observed once and claimed once. Replaying a token
  would let one agent attach many reports to one verified location.
* **Bound and expiring.** A token belongs to one manifest and dies with it, so
  a vantage point cannot be established today and spent next month.
* **Raw IP is transient.** We are an EU operator on a `.de` domain and an IP
  address is personal data. The address exists only inside a short abuse-review
  window; what survives is ASN and country. `purge_expired()` is not a
  housekeeping nicety, it is the retention guarantee.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import Callable, Protocol

# 16 bytes of entropy, URL-safe. Comfortably unguessable, and the encoded form
# satisfies the `beacon_token` pattern the wire schema accepts.
TOKEN_BYTES = 16

# How long a raw source address may be kept for abuse review before it is
# discarded. Deliberately short; nothing downstream is allowed to depend on it.
DEFAULT_IP_RETENTION = timedelta(hours=24)


class BeaconError(Exception):
    """A beacon token was unknown, expired, already used, or out of order.

    Raised rather than returned as a falsy value: every one of these cases means
    a report must be rejected, and a silently ignored return would let an
    unverified report into the dataset.
    """


class NetworkResolver(Protocol):
    """Maps an observed address to a network and country.

    Injected so the trust logic can be tested without a GeoIP database, and so
    the database can be swapped without touching anything in this module.
    """

    def resolve(self, ip: str) -> tuple[int | None, str | None]:
        """Return `(asn, country_code)`. Either may be None if unknown."""


@dataclass(frozen=True)
class VantagePoint:
    """Where a report was actually measured from, as observed by us.

    Contains no raw address by construction — this is the object that reaches
    storage, aggregation, and the public dataset.
    """

    asn: int | None
    country: str | None
    observed_at: datetime

    @property
    def is_locatable(self) -> bool:
        """False when we could not place the agent on a network.

        Such reports are still worth keeping — they just cannot contribute to
        per-country or per-ASN consensus, because we do not know which bucket
        they belong in.
        """
        return self.asn is not None


@dataclass
class _BeaconRecord:
    manifest_id: str
    expires_at: datetime
    vantage: VantagePoint | None = None
    claimed: bool = False
    # Present only until `ip_discard_after`; see purge_expired().
    source_ip: str | None = None
    ip_discard_after: datetime | None = None


@dataclass
class BeaconRegistry:
    """Issues, observes, and retires beacon tokens.

    In-memory here: this class defines the rules, and deployment enforces the
    same rules against durable storage. Keeping it storage-free is what lets the
    replay and expiry cases be tested exhaustively.
    """

    resolver: NetworkResolver
    clock: Callable[[], datetime]
    ip_retention: timedelta = DEFAULT_IP_RETENTION

    _records: dict[str, _BeaconRecord] = field(
        default_factory=dict, init=False, repr=False
    )

    # -- issuing -----------------------------------------------------------

    def issue(self, manifest_id: str, expires_at: datetime) -> str:
        """Mint a single-use token for one manifest.

        The token dies with the manifest, so a vantage point cannot be
        established once and reused indefinitely.
        """
        if expires_at <= self.clock():
            raise BeaconError("refusing to issue a token that is already expired")

        token = secrets.token_urlsafe(TOKEN_BYTES)
        self._records[token] = _BeaconRecord(
            manifest_id=manifest_id, expires_at=expires_at
        )
        return token

    # -- the callback itself -----------------------------------------------

    def observe(self, token: str, source_ip: str) -> VantagePoint:
        """Record the agent's fetch of its beacon URL. This is the ground truth.

        Called from the beacon route with the address *we* saw, never with
        anything the agent told us.
        """
        now = self.clock()
        record = self._records.get(token)

        # Unknown and expired are reported identically on purpose: distinguishing
        # them would turn this endpoint into an oracle for probing valid tokens.
        if record is None or record.expires_at <= now:
            raise BeaconError("unknown or expired beacon token")

        if record.vantage is not None:
            raise BeaconError("beacon token has already been observed")

        asn, country = self.resolver.resolve(source_ip)
        vantage = VantagePoint(asn=asn, country=country, observed_at=now)

        self._records[token] = replace(
            record,
            vantage=vantage,
            source_ip=source_ip,
            ip_discard_after=now + self.ip_retention,
        )
        return vantage

    # -- ingest ------------------------------------------------------------

    def claim(self, token: str, manifest_id: str) -> VantagePoint:
        """Resolve a submitted token into the vantage point we observed.

        Every rejection here is a report that does not enter the dataset, which
        is the correct outcome in all four cases.
        """
        now = self.clock()
        record = self._records.get(token)

        if record is None or record.expires_at <= now:
            raise BeaconError("unknown or expired beacon token")

        if record.manifest_id != manifest_id:
            # The token proves a location for the manifest it was issued for.
            # Letting it vouch for a different one would decouple the proof from
            # the work it is supposed to attest to.
            raise BeaconError("beacon token was issued for a different manifest")

        if record.vantage is None:
            raise BeaconError("beacon token was never fetched; vantage point unproven")

        if record.claimed:
            raise BeaconError("beacon token has already been claimed")

        self._records[token] = replace(record, claimed=True)
        return record.vantage

    # -- retention ---------------------------------------------------------

    def purge_expired(self) -> int:
        """Discard raw addresses past their window and drop dead tokens.

        Returns how many addresses were discarded. Must be run on a schedule;
        the retention promise is only true if this actually runs.
        """
        now = self.clock()
        discarded = 0

        for token, record in list(self._records.items()):
            if record.expires_at <= now and (record.claimed or record.vantage is None):
                if record.source_ip is not None:
                    discarded += 1
                del self._records[token]
                continue

            if record.ip_discard_after is not None and record.ip_discard_after <= now:
                if record.source_ip is not None:
                    discarded += 1
                self._records[token] = replace(
                    record, source_ip=None, ip_discard_after=None
                )

        return discarded

    # -- introspection, for the abuse-review window only -------------------

    def source_ip_for(self, token: str) -> str | None:
        """The observed address, if still inside the retention window.

        The only sanctioned reader is abuse review. Nothing that feeds
        aggregation or the public dataset may call this.
        """
        record = self._records.get(token)
        return record.source_ip if record else None
