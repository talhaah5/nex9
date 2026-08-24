"""Tests for the ASN resolver.

Hermetic: the DNS transport and the clock are both injected, so nothing here
touches the network. That matters beyond speed — a suite that queried Team Cymru
on every CI run would be exactly the abuse the module is written to avoid.

The adversarial cases are the point. `parse_cymru_txt` reads a third party's
output on a path that runs for every contributing agent, and `cymru_query_name`
is the only thing standing between an agent-influenced string and a DNS query.
"""

from __future__ import annotations

import pytest

from vantage.resolver import (
    CYMRU_IPV4_ZONE,
    CYMRU_IPV6_ZONE,
    UNKNOWN,
    CachingResolver,
    CymruDnsResolver,
    NullResolver,
    StaticResolver,
    cymru_query_name,
    parse_cymru_txt,
)

# 1.2.3.4 is globally routable, which is what makes it a valid query target.
# The documentation ranges (203.0.113.0/24 and friends) are *not* global, so
# they exercise the short-circuit instead.
GLOBAL_V4 = "1.2.3.4"
GLOBAL_V6 = "2606:4700:4700::1111"

CYMRU_RECORD = "64512 | 1.2.0.0/16 | US | arin | 2010-01-01"


class FakeClock:
    """A monotonic clock we control, so TTL expiry is tested rather than waited for."""

    def __init__(self, now: float = 1000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class FakeLookup:
    """A stand-in TXT transport that records what it was asked."""

    def __init__(
        self, records: list[str] | None = None, error: Exception | None = None
    ) -> None:
        self.records = records if records is not None else [CYMRU_RECORD]
        self.error = error
        self.calls: list[str] = []

    def __call__(self, name: str) -> list[str]:
        self.calls.append(name)
        if self.error is not None:
            raise self.error
        return self.records


class CountingResolver:
    """Counts resolutions, so cache hits are observable."""

    def __init__(self, value: tuple[int | None, str | None] = (64512, "US")) -> None:
        self.value = value
        self.calls: list[str] = []

    def resolve(self, ip: str) -> tuple[int | None, str | None]:
        self.calls.append(ip)
        return self.value


# --- parsing third-party output ------------------------------------------


def test_a_well_formed_record_yields_asn_and_country() -> None:
    assert parse_cymru_txt([CYMRU_RECORD]) == (64512, "US")


def test_surrounding_quotes_and_whitespace_are_stripped() -> None:
    # Some transports hand back the record with its TXT quoting intact.
    assert parse_cymru_txt(['"  64512 | 1.2.0.0/16 | de | ripencc | 2010-01-01 "']) == (
        64512,
        "DE",
    )


def test_no_records_is_unknown() -> None:
    assert parse_cymru_txt([]) == UNKNOWN


@pytest.mark.parametrize(
    "record",
    [
        "",
        "64512",
        "64512 | 1.2.0.0/16",
        "not-a-number | 1.2.0.0/16 | US | arin | 2010-01-01",
        "| | |",
        "6451x | 1.2.0.0/16 | US | arin | 2010-01-01",
    ],
    ids=["empty", "one-field", "two-fields", "asn-not-numeric", "all-blank", "asn-typo"],
)
def test_malformed_records_degrade_to_unknown_rather_than_raising(record: str) -> None:
    # A format change upstream must cost us locatability, never availability.
    assert parse_cymru_txt([record]) == UNKNOWN


def test_a_multi_origin_prefix_is_refused() -> None:
    """An address announced by two ASNs has no single answer, so we give none.

    Taking the first would silently attribute a vantage point to a network that
    may not be carrying it — and a multi-origin announcement is exactly what a
    prefix hijack looks like.
    """
    assert parse_cymru_txt(["64512 64513 | 1.2.0.0/16 | US | arin | 2010-01-01"]) == UNKNOWN


def test_a_nonsense_country_field_still_yields_the_asn() -> None:
    # The ASN is what consensus is built on; the country is a convenience.
    # A bad country code should not throw away a good ASN.
    assert parse_cymru_txt(["64512 | 1.2.0.0/16 | UNKNOWN | arin | 2010-01-01"]) == (
        64512,
        None,
    )


def test_the_first_parseable_record_wins() -> None:
    assert parse_cymru_txt(["garbage", CYMRU_RECORD]) == (64512, "US")


# --- building the query name ----------------------------------------------


def test_an_ipv4_address_is_reversed_into_the_cymru_zone() -> None:
    assert cymru_query_name(GLOBAL_V4) == f"4.3.2.1.{CYMRU_IPV4_ZONE}"


def test_an_ipv6_address_is_reversed_by_nibble() -> None:
    name = cymru_query_name(GLOBAL_V6)
    assert name is not None
    assert name.endswith(CYMRU_IPV6_ZONE)

    labels = name[: -(len(CYMRU_IPV6_ZONE) + 1)].split(".")
    assert len(labels) == 32  # 32 nibbles, each its own label
    assert labels[0] == "1"  # last nibble of ...:1111
    assert labels[-4:] == ["6", "0", "6", "2"]  # leading 2606, reversed


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "10.0.0.1",
        "192.168.1.1",
        "169.254.1.1",
        "203.0.113.9",
        "224.0.0.1",
        "::1",
        "fe80::1",
    ],
    ids=[
        "loopback",
        "private-10",
        "private-192",
        "link-local",
        "doc-range",
        "multicast",
        "v6-loopback",
        "v6-link-local",
    ],
)
def test_non_global_addresses_are_never_sent_upstream(ip: str) -> None:
    # No ASN exists for these, and they are not ours to hand to a third party.
    assert cymru_query_name(ip) is None


@pytest.mark.parametrize(
    "value",
    [
        "",
        "not-an-ip",
        "1.2.3.4.5",
        "1.2.3.999",
        "1.2.3.4; evil.example.com",
        "1.2.3.4\nevil.example.com",
        "$(whoami)",
        "*.cymru.com",
        "1.2.3.4 ",
    ],
    ids=[
        "empty",
        "words",
        "too-many-octets",
        "octet-out-of-range",
        "semicolon-injection",
        "newline-injection",
        "shell-substitution",
        "wildcard",
        "trailing-space",
    ],
)
def test_only_a_genuine_address_can_produce_a_query(value: str) -> None:
    """Parsing through `ipaddress` is the injection guard.

    An agent controls its own source address only insofar as it controls its own
    packets, but a deployment behind a proxy also carries forwarded-for headers.
    Nothing that is not a parseable address may become a query name.
    """
    assert cymru_query_name(value) is None


# --- the DNS resolver -----------------------------------------------------


def test_a_successful_lookup_resolves_to_the_announced_network() -> None:
    lookup = FakeLookup()
    assert CymruDnsResolver(lookup=lookup).resolve(GLOBAL_V4) == (64512, "US")
    assert lookup.calls == [f"4.3.2.1.{CYMRU_IPV4_ZONE}"]


def test_a_non_global_address_short_circuits_before_any_query() -> None:
    lookup = FakeLookup()
    assert CymruDnsResolver(lookup=lookup).resolve("127.0.0.1") == UNKNOWN
    assert lookup.calls == []


def test_an_unparseable_address_short_circuits_before_any_query() -> None:
    lookup = FakeLookup()
    assert CymruDnsResolver(lookup=lookup).resolve("not-an-ip") == UNKNOWN
    assert lookup.calls == []


@pytest.mark.parametrize(
    "error",
    [
        TimeoutError("timed out"),
        OSError("network unreachable"),
        RuntimeError("transport exploded"),
    ],
    ids=["timeout", "oserror", "unexpected"],
)
def test_a_failing_transport_costs_locatability_not_availability(error: Exception) -> None:
    """An unreachable ASN service must not stop us accepting measurements.

    The observation still lands; it is simply flagged unlocatable. Refusing the
    report instead would let a third party's outage take our ingest down with it.
    """
    resolver = CymruDnsResolver(lookup=FakeLookup(error=error))
    assert resolver.resolve(GLOBAL_V4) == UNKNOWN


def test_an_empty_answer_is_unknown() -> None:
    assert CymruDnsResolver(lookup=FakeLookup(records=[])).resolve(GLOBAL_V4) == UNKNOWN


# --- the trivial resolvers ------------------------------------------------


def test_the_null_resolver_admits_it_does_not_know() -> None:
    # The honest default when no ASN source is configured.
    assert NullResolver().resolve(GLOBAL_V4) == UNKNOWN


def test_the_static_resolver_answers_from_its_table() -> None:
    resolver = StaticResolver(table={GLOBAL_V4: (64512, "DE")})
    assert resolver.resolve(GLOBAL_V4) == (64512, "DE")
    assert resolver.resolve("8.8.8.8") == UNKNOWN


def test_the_static_resolver_defaults_to_an_empty_table() -> None:
    assert StaticResolver().resolve(GLOBAL_V4) == UNKNOWN


# --- caching, which is a condition of use rather than an optimisation ------


def test_a_repeated_address_is_answered_from_cache() -> None:
    inner = CountingResolver()
    cache = CachingResolver(inner=inner, clock=FakeClock())

    for _ in range(50):
        assert cache.resolve(GLOBAL_V4) == (64512, "US")

    # Fifty agents behind one NAT must not become fifty queries upstream.
    assert inner.calls == [GLOBAL_V4]
    assert cache.lookups == 1
    assert cache.hits == 49


def test_a_cached_answer_expires_after_its_ttl() -> None:
    clock = FakeClock()
    inner = CountingResolver()
    cache = CachingResolver(inner=inner, clock=clock, ttl_seconds=100.0)

    cache.resolve(GLOBAL_V4)
    clock.advance(99.0)
    cache.resolve(GLOBAL_V4)
    assert len(inner.calls) == 1

    clock.advance(2.0)
    cache.resolve(GLOBAL_V4)
    assert len(inner.calls) == 2


def test_a_failure_is_cached_only_briefly() -> None:
    """A negative result must not pin an agent as unlocatable for a full hour.

    Caching failures at all is what stops an upstream outage becoming a retry
    storm; caching them as long as successes would turn a blip into an hour of
    degraded data.
    """
    clock = FakeClock()
    inner = CountingResolver(value=UNKNOWN)
    cache = CachingResolver(
        inner=inner, clock=clock, ttl_seconds=3600.0, negative_ttl_seconds=60.0
    )

    cache.resolve(GLOBAL_V4)
    clock.advance(30.0)
    cache.resolve(GLOBAL_V4)
    assert len(inner.calls) == 1  # still suppressed

    clock.advance(31.0)
    cache.resolve(GLOBAL_V4)
    assert len(inner.calls) == 2  # retried well before the positive TTL


def test_a_recovered_upstream_replaces_the_negative_entry() -> None:
    clock = FakeClock()

    class Flaky:
        def __init__(self) -> None:
            self.first = True

        def resolve(self, ip: str) -> tuple[int | None, str | None]:
            if self.first:
                self.first = False
                return UNKNOWN
            return (64512, "US")

    cache = CachingResolver(inner=Flaky(), clock=clock, negative_ttl_seconds=60.0)
    assert cache.resolve(GLOBAL_V4) == UNKNOWN
    clock.advance(61.0)
    assert cache.resolve(GLOBAL_V4) == (64512, "US")


def test_the_cache_is_bounded_against_a_flood_of_distinct_addresses() -> None:
    """An IPv6 swarm could otherwise hand us unbounded distinct keys."""
    cache = CachingResolver(inner=CountingResolver(), clock=FakeClock(), max_entries=100)

    for i in range(5000):
        cache.resolve(f"1.2.{i // 256}.{i % 256}")

    assert len(cache._cache) <= 100


def test_eviction_drops_the_oldest_entry_first() -> None:
    cache = CachingResolver(inner=CountingResolver(), clock=FakeClock(), max_entries=2)

    cache.resolve("1.1.1.1")
    cache.resolve("2.2.2.2")
    cache.resolve("3.3.3.3")  # evicts 1.1.1.1

    assert set(cache._cache) == {"2.2.2.2", "3.3.3.3"}


def test_purging_releases_expired_entries() -> None:
    clock = FakeClock()
    cache = CachingResolver(inner=CountingResolver(), clock=clock, ttl_seconds=100.0)

    cache.resolve("1.1.1.1")
    cache.resolve("2.2.2.2")
    clock.advance(101.0)
    cache.resolve("3.3.3.3")

    assert cache.purge_expired() == 2
    assert set(cache._cache) == {"3.3.3.3"}


def test_purging_a_fresh_cache_removes_nothing() -> None:
    cache = CachingResolver(inner=CountingResolver(), clock=FakeClock())
    cache.resolve(GLOBAL_V4)
    assert cache.purge_expired() == 0


@pytest.mark.parametrize(
    "kwargs",
    [
        {"ttl_seconds": 0.0},
        {"ttl_seconds": -1.0},
        {"negative_ttl_seconds": 0.0},
        {"max_entries": 0},
    ],
    ids=["zero-ttl", "negative-ttl", "zero-negative-ttl", "zero-capacity"],
)
def test_a_nonsensical_cache_policy_is_refused_at_construction(kwargs: dict) -> None:
    # A zero TTL would mean no caching at all, which is the abuse case.
    with pytest.raises(ValueError):
        CachingResolver(inner=NullResolver(), **kwargs)


def test_the_cache_satisfies_the_beacon_resolver_protocol() -> None:
    """The whole stack must be substitutable where beacon.py expects a resolver.

    The Protocol is structural, so nothing enforces this at import time. Wiring
    the real stack into a real registry is the only thing that proves the two
    halves actually fit.
    """
    from datetime import datetime, timedelta, timezone

    from vantage.beacon import BeaconRegistry

    now = datetime(2026, 8, 24, 12, 0, tzinfo=timezone.utc)
    stack = CachingResolver(inner=CymruDnsResolver(lookup=FakeLookup()), clock=FakeClock())
    registry = BeaconRegistry(resolver=stack, clock=lambda: now)

    token = registry.issue(manifest_id="m-1", expires_at=now + timedelta(hours=4))
    point = registry.observe(token=token, source_ip=GLOBAL_V4)

    assert point.asn == 64512
    assert point.country == "US"
    assert point.is_locatable
