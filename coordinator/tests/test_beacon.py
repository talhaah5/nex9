"""The beacon, tested as the thing that decides whether data is real.

Every measurement in the published dataset is only as trustworthy as the claim
about *where* it was taken. The beacon is what converts that from an agent's
assertion into our own observation, so these tests are written as attacks on
that conversion: replay a token, spend it on a different manifest, submit a
report for a beacon never fetched, keep a vantage point alive past its manifest.

The retention tests are not a formality either. We are an EU operator handling
IP addresses; a promise to discard them is only real if something checks.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone

import pytest

from vantage.beacon import (
    DEFAULT_IP_RETENTION,
    TOKEN_BYTES,
    BeaconError,
    BeaconRegistry,
    VantagePoint,
)
from vantage.models import Report

T0 = datetime(2026, 8, 24, 10, 0, tzinfo=timezone.utc)


class FakeClock:
    def __init__(self, start: datetime = T0) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> None:
        self.now += delta


class FakeResolver:
    """Stands in for the GeoIP database, and records what it was asked."""

    def __init__(self, mapping=None, default=(64512, "DE")) -> None:
        self.mapping = mapping or {}
        self.default = default
        self.seen: list[str] = []

    def resolve(self, ip: str):
        self.seen.append(ip)
        return self.mapping.get(ip, self.default)


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def resolver() -> FakeResolver:
    return FakeResolver()


@pytest.fixture
def registry(clock, resolver) -> BeaconRegistry:
    return BeaconRegistry(resolver=resolver, clock=clock)


def issue(registry: BeaconRegistry, manifest_id: str = "m-1", hours: int = 4) -> str:
    return registry.issue(manifest_id, registry.clock() + timedelta(hours=hours))


# ---------------------------------------------------------------------------
# The intended flow
# ---------------------------------------------------------------------------


def test_a_fetched_beacon_yields_the_vantage_point_we_observed(registry) -> None:
    token = issue(registry)
    observed = registry.observe(token, "203.0.113.7")

    assert registry.claim(token, "m-1") == observed
    assert observed.asn == 64512
    assert observed.country == "DE"


def test_location_comes_from_the_resolver_not_from_the_agent(registry, resolver) -> None:
    """The agent never gets a say. It only causes a request; we do the rest."""
    resolver.mapping["198.51.100.9"] = (13335, "BR")
    token = issue(registry)

    vantage = registry.observe(token, "198.51.100.9")

    assert (vantage.asn, vantage.country) == (13335, "BR")
    assert resolver.seen == ["198.51.100.9"]


def test_tokens_are_unguessable_and_wire_legal(registry) -> None:
    """A guessable token would let anyone forge a vantage point from anywhere."""
    tokens = {issue(registry) for _ in range(500)}
    assert len(tokens) == 500, "tokens must not collide"

    for token in tokens:
        assert len(token) >= TOKEN_BYTES
        # Must survive the wire schema's beacon_token constraint.
        Report(
            manifest_id="m-1",
            beacon_token=token,
            agent={"id": "a"},
            observations=[
                {
                    "target_id": "t",
                    "kind": "dns",
                    "started_at": T0,
                    "duration_ms": 1,
                    "result": {"addresses": []},
                }
            ],
        )


# ---------------------------------------------------------------------------
# Replay — one verified location must not vouch for many reports
# ---------------------------------------------------------------------------


def test_a_beacon_can_only_be_fetched_once(registry) -> None:
    """A second fetch from elsewhere could overwrite a real location with a lie."""
    token = issue(registry)
    registry.observe(token, "203.0.113.7")

    with pytest.raises(BeaconError):
        registry.observe(token, "198.51.100.9")


def test_a_second_fetch_does_not_change_the_recorded_location(registry) -> None:
    token = issue(registry)
    first = registry.observe(token, "203.0.113.7")

    with pytest.raises(BeaconError):
        registry.observe(token, "198.51.100.9")

    assert registry.claim(token, "m-1") == first


def test_a_beacon_can_only_be_claimed_once(registry) -> None:
    """Otherwise one proven vantage point backs an unlimited number of reports."""
    token = issue(registry)
    registry.observe(token, "203.0.113.7")
    registry.claim(token, "m-1")

    with pytest.raises(BeaconError):
        registry.claim(token, "m-1")


def test_each_agent_gets_its_own_token(registry) -> None:
    """Two agents, two tokens, two independent vantage points."""
    a, b = issue(registry), issue(registry)
    assert a != b

    registry.observe(a, "203.0.113.7")
    registry.observe(b, "198.51.100.9")

    assert registry.claim(a, "m-1") is not None
    assert registry.claim(b, "m-1") is not None


# ---------------------------------------------------------------------------
# Reports that must not enter the dataset
# ---------------------------------------------------------------------------


def test_a_report_for_a_beacon_never_fetched_is_rejected(registry) -> None:
    """The central case: measurements with no proof of location do not count.

    An agent can fabricate an entire report offline. What it cannot fabricate is
    the request we saw arrive.
    """
    token = issue(registry)

    with pytest.raises(BeaconError):
        registry.claim(token, "m-1")


def test_an_unknown_token_is_rejected(registry) -> None:
    with pytest.raises(BeaconError):
        registry.claim("not-a-real-token", "m-1")

    with pytest.raises(BeaconError):
        registry.observe("not-a-real-token", "203.0.113.7")


def test_a_token_cannot_be_spent_on_a_different_manifest(registry) -> None:
    """Otherwise a cheap manifest's proof could vouch for an expensive one's work."""
    token = issue(registry, manifest_id="m-1")
    registry.observe(token, "203.0.113.7")

    with pytest.raises(BeaconError):
        registry.claim(token, "m-2")


def test_the_token_still_works_for_its_own_manifest_after_a_wrong_claim(
    registry,
) -> None:
    """A rejected claim must not burn a legitimate agent's token."""
    token = issue(registry, manifest_id="m-1")
    registry.observe(token, "203.0.113.7")

    with pytest.raises(BeaconError):
        registry.claim(token, "m-2")

    assert registry.claim(token, "m-1").asn == 64512


# ---------------------------------------------------------------------------
# Expiry — a vantage point is a statement about now, not forever
# ---------------------------------------------------------------------------


def test_an_expired_token_cannot_be_fetched(registry, clock) -> None:
    token = issue(registry, hours=4)
    clock.advance(timedelta(hours=4, minutes=1))

    with pytest.raises(BeaconError):
        registry.observe(token, "203.0.113.7")


def test_an_expired_token_cannot_be_claimed(registry, clock) -> None:
    """Stops a location proven today from backing a report submitted next month."""
    token = issue(registry, hours=4)
    registry.observe(token, "203.0.113.7")
    clock.advance(timedelta(hours=4, minutes=1))

    with pytest.raises(BeaconError):
        registry.claim(token, "m-1")


def test_expiry_is_exclusive_at_the_boundary(registry, clock) -> None:
    token = issue(registry, hours=4)
    clock.advance(timedelta(hours=4))

    with pytest.raises(BeaconError):
        registry.observe(token, "203.0.113.7")


def test_refuses_to_issue_an_already_expired_token(registry, clock) -> None:
    """A token born expired is a bug that would look like agents never calling back."""
    with pytest.raises(BeaconError):
        registry.issue("m-1", clock() - timedelta(seconds=1))

    with pytest.raises(BeaconError):
        registry.issue("m-1", clock())


def test_unknown_and_expired_are_indistinguishable(registry, clock) -> None:
    """The endpoint must not become an oracle for discovering valid tokens."""
    token = issue(registry, hours=1)
    clock.advance(timedelta(hours=2))

    with pytest.raises(BeaconError) as expired:
        registry.observe(token, "203.0.113.7")

    with pytest.raises(BeaconError) as unknown:
        registry.observe("definitely-not-issued", "203.0.113.7")

    assert str(expired.value) == str(unknown.value)


# ---------------------------------------------------------------------------
# Privacy — the retention promise has to be enforced, not just documented
# ---------------------------------------------------------------------------


def test_the_vantage_point_carries_no_raw_address(registry) -> None:
    """This object reaches storage and the public dataset. It must be safe by shape."""
    token = issue(registry)
    vantage = registry.observe(token, "203.0.113.7")

    assert "203.0.113.7" not in repr(vantage)
    assert not hasattr(vantage, "source_ip")
    assert not hasattr(vantage, "ip")


def test_raw_addresses_are_discarded_after_the_retention_window(
    registry, clock
) -> None:
    token = issue(registry, hours=48)
    registry.observe(token, "203.0.113.7")
    assert registry.source_ip_for(token) == "203.0.113.7"

    clock.advance(DEFAULT_IP_RETENTION + timedelta(minutes=1))
    assert registry.purge_expired() == 1

    assert registry.source_ip_for(token) is None


def test_discarding_the_address_does_not_destroy_the_measurement(
    registry, clock
) -> None:
    """Privacy compliance must not cost us the data. ASN and country survive."""
    token = issue(registry, hours=48)
    registry.observe(token, "203.0.113.7")

    clock.advance(DEFAULT_IP_RETENTION + timedelta(minutes=1))
    registry.purge_expired()

    vantage = registry.claim(token, "m-1")
    assert (vantage.asn, vantage.country) == (64512, "DE")


def test_addresses_inside_the_window_are_kept_for_abuse_review(registry, clock) -> None:
    token = issue(registry, hours=48)
    registry.observe(token, "203.0.113.7")

    clock.advance(DEFAULT_IP_RETENTION - timedelta(minutes=1))
    assert registry.purge_expired() == 0
    assert registry.source_ip_for(token) == "203.0.113.7"


def test_a_shorter_retention_can_be_configured(clock, resolver) -> None:
    registry = BeaconRegistry(
        resolver=resolver, clock=clock, ip_retention=timedelta(minutes=15)
    )
    token = registry.issue("m-1", clock() + timedelta(hours=4))
    registry.observe(token, "203.0.113.7")

    clock.advance(timedelta(minutes=16))
    registry.purge_expired()

    assert registry.source_ip_for(token) is None


def test_purging_is_idempotent(registry, clock) -> None:
    token = issue(registry, hours=48)
    registry.observe(token, "203.0.113.7")
    clock.advance(DEFAULT_IP_RETENTION + timedelta(minutes=1))

    assert registry.purge_expired() == 1
    assert registry.purge_expired() == 0


def test_spent_and_dead_tokens_are_dropped_entirely(registry, clock) -> None:
    """Nothing is gained by keeping them, and every retained record is a liability."""
    spent = issue(registry, hours=1)
    registry.observe(spent, "203.0.113.7")
    registry.claim(spent, "m-1")

    never_used = issue(registry, hours=1)

    clock.advance(timedelta(hours=2))
    registry.purge_expired()

    assert registry.source_ip_for(spent) is None
    assert registry.source_ip_for(never_used) is None
    with pytest.raises(BeaconError):
        registry.claim(spent, "m-1")


def test_purge_leaves_live_tokens_alone(registry, clock) -> None:
    """A cleanup job that eats in-flight tokens would silently drop real reports."""
    live = issue(registry, hours=4)
    registry.observe(live, "203.0.113.7")

    clock.advance(timedelta(minutes=5))
    registry.purge_expired()

    assert registry.claim(live, "m-1").asn == 64512


# ---------------------------------------------------------------------------
# Agents we cannot place
# ---------------------------------------------------------------------------


def test_an_unresolvable_address_still_produces_a_vantage_point(clock) -> None:
    """Losing the report entirely would be worse than knowing we cannot place it."""
    registry = BeaconRegistry(resolver=FakeResolver(default=(None, None)), clock=clock)
    token = registry.issue("m-1", clock() + timedelta(hours=4))

    vantage = registry.observe(token, "203.0.113.7")

    assert vantage.is_locatable is False
    assert registry.claim(token, "m-1") == vantage


def test_a_locatable_vantage_point_is_marked_as_such(registry) -> None:
    token = issue(registry)
    assert registry.observe(token, "203.0.113.7").is_locatable is True


def test_country_without_asn_is_still_not_locatable(clock) -> None:
    """ASN is the consensus bucket. Country alone cannot carry Sybil resistance,
    since one operator can hold many hosts in one country."""
    registry = BeaconRegistry(resolver=FakeResolver(default=(None, "DE")), clock=clock)
    token = registry.issue("m-1", clock() + timedelta(hours=4))

    assert registry.observe(token, "203.0.113.7").is_locatable is False


def test_vantage_points_are_immutable() -> None:
    """Nothing downstream may quietly relabel where a measurement came from."""
    vantage = VantagePoint(asn=64512, country="DE", observed_at=T0)
    with pytest.raises(FrozenInstanceError):
        vantage.country = "US"
