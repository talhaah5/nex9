"""Turning an observed address into a network, without becoming a nuisance.

`beacon.py` defines the `NetworkResolver` protocol and injects it; this is the
implementation. Three concerns shape it, in order of importance:

**Licensing.** Vantage publishes open data, so the ASN mapping has to come from
a source whose terms permit that. Team Cymru's IP-to-ASN service is public,
free, and derived from public BGP announcements — facts about routing, not a
proprietary dataset. The alternative worth revisiting is loading a RouteViews or
RIPE RIS table locally, which removes the network dependency entirely; the
protocol boundary means that swap touches nothing else.

**Not abusing a free service.** Cymru is run as a public good. Caching is not an
optimisation here, it is a condition of use: one lookup per address per TTL, and
failures cached briefly so an outage cannot turn into a retry storm.

**Not leaking what we do not need to.** Private, loopback, and reserved
addresses are answered locally and never sent anywhere. They have no ASN, so the
query would be pointless as well as careless.

The DNS transport is injected rather than imported, so the parsing and caching
logic — the part that can actually be wrong — is testable without a network.
"""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass, field
from typing import Callable, Protocol

# The protocol lives with its consumer. Importing it here is what makes the
# annotation on `CachingResolver.inner` mean something; beacon imports nothing
# from this module, so there is no cycle.
from vantage.beacon import NetworkResolver

# Cymru publishes these zones; IPv4 is reversed-octet, IPv6 reversed-nibble.
CYMRU_IPV4_ZONE = "origin.asn.cymru.com"
CYMRU_IPV6_ZONE = "origin6.asn.cymru.com"

# Routing changes on the order of days, and our cycle is four hours. An hour is
# fresh enough to catch real reassignments and slow enough to be a good citizen.
DEFAULT_TTL_SECONDS = 3600.0

# Failures are cached too, or an upstream outage becomes a retry storm. Kept
# short so a transient failure does not pin an agent as unlocatable for an hour.
DEFAULT_NEGATIVE_TTL_SECONDS = 60.0

# Bounds memory against an unbounded stream of distinct addresses.
DEFAULT_MAX_ENTRIES = 100_000

UNKNOWN: tuple[int | None, str | None] = (None, None)


class TxtLookup(Protocol):
    """Resolves a DNS name to its TXT records.

    Injected so the transport can be swapped — dnspython, a stub resolver, a
    local BGP table — without touching anything that has logic in it.
    """

    def __call__(self, name: str) -> list[str]: ...


class NullResolver:
    """Answers "unknown" for everything.

    The correct default when no ASN source is configured. Reports still enter
    the dataset flagged not-locatable, which is honest; silently guessing a
    country would be far worse than admitting we do not know.
    """

    def resolve(self, ip: str) -> tuple[int | None, str | None]:
        return UNKNOWN


@dataclass
class StaticResolver:
    """A fixed table. Used in tests, and viable in production with a pinned BGP
    snapshot if we decide the network dependency is not worth it."""

    table: dict[str, tuple[int | None, str | None]] = field(default_factory=dict)

    def resolve(self, ip: str) -> tuple[int | None, str | None]:
        return self.table.get(ip, UNKNOWN)


def parse_cymru_txt(records: list[str]) -> tuple[int | None, str | None]:
    """Parse Cymru's `ASN | prefix | country | registry | allocated` records.

    Returns UNKNOWN rather than raising on anything unexpected. This parses a
    third party's output on a path that runs for every contributing agent: a
    format change should degrade us to "unlocatable", never take the endpoint
    down.
    """
    for record in records:
        fields = [part.strip() for part in record.strip().strip('"').split("|")]
        if len(fields) < 3:
            continue

        asn_field, _prefix, country = fields[0], fields[1], fields[2]

        # An address announced by multiple origins yields a space-separated list.
        # An ambiguous origin is not something to guess at, so accept it only
        # when exactly one ASN is named.
        asn_parts = asn_field.split()
        if len(asn_parts) != 1 or not asn_parts[0].isdigit():
            continue

        asn = int(asn_parts[0])
        is_country_code = len(country) == 2 and country.isalpha()
        return asn, country.upper() if is_country_code else None

    return UNKNOWN


def cymru_query_name(ip: str) -> str | None:
    """Build the lookup name, or None if this address must not be looked up.

    Parsing through `ipaddress` is also the injection guard: only a genuine
    address can produce a query name, so nothing an agent controls reaches the
    DNS layer as text.
    """
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None

    # Private, loopback, link-local, multicast, reserved. No ASN exists for
    # these, and they are not ours to send to a third party.
    #
    # `is_global` alone is not enough: it is defined as "not private", and
    # multicast is not on the private list, so 224.0.0.1 would sail straight
    # through and be handed upstream. The disqualifiers are named explicitly so
    # this keeps matching the sentence above rather than tracking a stdlib
    # definition that was written for a different question.
    if (
        address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        or not address.is_global
    ):
        return None

    if address.version == 4:
        return f"{'.'.join(reversed(address.exploded.split('.')))}.{CYMRU_IPV4_ZONE}"

    nibbles = address.exploded.replace(":", "")
    return f"{'.'.join(reversed(nibbles))}.{CYMRU_IPV6_ZONE}"


@dataclass
class CymruDnsResolver:
    """Team Cymru IP-to-ASN over DNS.

    Always wrap this in `CachingResolver`; see the module docstring. Any lookup
    failure resolves to UNKNOWN — an unreachable ASN service must not stop us
    accepting measurements.
    """

    lookup: TxtLookup

    def resolve(self, ip: str) -> tuple[int | None, str | None]:
        name = cymru_query_name(ip)
        if name is None:
            return UNKNOWN

        try:
            records = self.lookup(name)
        except Exception:
            # Deliberately broad: transports raise their own exception families,
            # and every one of them means the same thing to us.
            return UNKNOWN

        return parse_cymru_txt(records)


@dataclass
class CachingResolver:
    """TTL cache in front of any resolver.

    Required for the Cymru transport rather than optional. Negative results get
    their own shorter TTL so an outage does not persist as bad data.
    """

    inner: NetworkResolver
    clock: Callable[[], float] = time.monotonic
    ttl_seconds: float = DEFAULT_TTL_SECONDS
    negative_ttl_seconds: float = DEFAULT_NEGATIVE_TTL_SECONDS
    max_entries: int = DEFAULT_MAX_ENTRIES

    _cache: dict[str, tuple[tuple[int | None, str | None], float]] = field(
        default_factory=dict, init=False, repr=False
    )
    lookups: int = field(default=0, init=False)
    hits: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        if self.ttl_seconds <= 0 or self.negative_ttl_seconds <= 0:
            raise ValueError("TTLs must be positive")
        if self.max_entries < 1:
            raise ValueError("max_entries must be >= 1")

    def resolve(self, ip: str) -> tuple[int | None, str | None]:
        now = self.clock()
        cached = self._cache.get(ip)

        if cached is not None:
            value, expires_at = cached
            if expires_at > now:
                self.hits += 1
                return value
            del self._cache[ip]

        value = self.inner.resolve(ip)
        self.lookups += 1

        ttl = self.ttl_seconds if value != UNKNOWN else self.negative_ttl_seconds
        self._store(ip, value, now + ttl)
        return value

    def _store(self, ip: str, value, expires_at: float) -> None:
        # Evict the oldest insertion first. Dicts preserve insertion order, so
        # this needs no extra structure; recency of *use* is not worth tracking
        # when entries expire on a timer anyway.
        while len(self._cache) >= self.max_entries:
            self._cache.pop(next(iter(self._cache)))
        self._cache[ip] = (value, expires_at)

    def purge_expired(self) -> int:
        """Drop expired entries. Optional — `resolve` expires lazily — but lets a
        long-lived process release memory between bursts."""
        now = self.clock()
        stale = [ip for ip, (_, exp) in self._cache.items() if exp <= now]
        for ip in stale:
            del self._cache[ip]
        return len(stale)
