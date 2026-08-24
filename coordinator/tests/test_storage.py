"""Tests for persistence.

Each test gets its own database under pytest's tmp_path, so nothing here shares
state and nothing touches a real file.

The cases that matter are not "can it write a row". They are the three
guarantees the dataset's credibility rests on: measurements cannot be rewritten,
a report never lands half-written, and the raw IP actually disappears.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from vantage.models import (
    AgentIdentity,
    DnsResult,
    HttpResult,
    Observation,
    Report,
    TlsResult,
)
from vantage.storage import SqliteStore, StorageError, from_db_time, to_db_time

T0 = datetime(2026, 8, 24, 12, 0, tzinfo=timezone.utc)
MANIFEST_ID = "m_2026082412"
TOKEN = "beacontoken000000001"


@pytest.fixture
def store(tmp_path):
    s = SqliteStore(path=tmp_path / "vantage.db")
    yield s
    s.close()


@pytest.fixture
def seeded(store):
    """A store with a manifest and one beacon token, so FKs are satisfiable."""
    store.save_manifest(MANIFEST_ID, T0, T0 + timedelta(hours=4), '{"manifest_id":"m"}')
    store.save_beacon(TOKEN, MANIFEST_ID, T0, T0 + timedelta(hours=4))
    return store


def make_report(token: str = TOKEN, agent_id: str = "agent_001") -> Report:
    return Report(
        manifest_id=MANIFEST_ID,
        beacon_token=token,
        agent=AgentIdentity(id=agent_id, software="probe/0.1"),
        observations=[
            Observation(
                target_id="t_dns",
                kind="dns",
                started_at=T0,
                duration_ms=12,
                result=DnsResult(addresses=["93.184.216.34"]),
            ),
            Observation(
                target_id="t_http",
                kind="http",
                started_at=T0,
                duration_ms=140,
                result=HttpResult(status_code=200, redirect_count=1),
            ),
            Observation(
                target_id="t_tls",
                kind="tls",
                started_at=T0,
                duration_ms=90,
                result=TlsResult(
                    fingerprint_sha256="a" * 64,
                    issuer="Example CA",
                    not_before=T0 - timedelta(days=30),
                    not_after=T0 + timedelta(days=30),
                ),
            ),
            Observation(
                target_id="t_down",
                kind="http",
                started_at=T0,
                duration_ms=3000,
                error="connect_unreachable",
            ),
        ],
    )


# --- the database is configured the way the schema assumes ----------------


def test_foreign_keys_are_actually_enforced(store):
    """SQLite ships with foreign keys OFF.

    Every REFERENCES clause in the schema is decoration until the PRAGMA runs,
    so this asserts the setting rather than the syntax.
    """
    assert store._conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_the_database_is_in_wal_mode(store):
    # Readers must not block ingest, and ingest must not block the dashboard.
    assert store._conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"


def test_opening_an_existing_database_again_is_safe(tmp_path):
    """Schema creation runs on every boot, so it has to be idempotent."""
    path = tmp_path / "vantage.db"
    first = SqliteStore(path=path)
    first.save_manifest(MANIFEST_ID, T0, T0 + timedelta(hours=4), "{}")
    first.close()

    second = SqliteStore(path=path)
    assert second.get_manifest_payload(MANIFEST_ID) == "{}"
    second.close()


# --- timestamps -----------------------------------------------------------


def test_timestamps_round_trip_as_aware_utc():
    assert from_db_time(to_db_time(T0)) == T0


def test_a_naive_datetime_is_refused():
    # Storage is UTC-only; a naive datetime is an ambiguity we cannot resolve.
    with pytest.raises(ValueError):
        to_db_time(datetime(2026, 8, 24, 12, 0))


def test_a_non_utc_datetime_is_normalised_not_rejected():
    plus_two = timezone(timedelta(hours=2))
    assert to_db_time(datetime(2026, 8, 24, 14, 0, tzinfo=plus_two)) == to_db_time(T0)


def test_text_ordering_matches_chronological_ordering():
    """The reason timestamps are stored fixed-width.

    Python's isoformat drops trailing zeros in the microsecond field, so
    "12:00:00+00:00" would sort *after* "12:00:00.5+00:00" as text — and every
    time-range query in the project would silently return the wrong rows.
    """
    encoded = [
        to_db_time(t)
        for t in (T0, T0 + timedelta(microseconds=500000), T0 + timedelta(seconds=1))
    ]
    assert encoded == sorted(encoded)
    assert len({len(e) for e in encoded}) == 1  # fixed width


# --- reports round-trip ---------------------------------------------------


def test_a_report_round_trips_with_every_result_kind(seeded):
    report_id = seeded.save_report(make_report(), received_at=T0, asn=64512, country="DE")
    stored = seeded.get_report(report_id)

    assert stored is not None
    assert stored.agent_id == "agent_001"
    assert stored.asn == 64512
    assert stored.country == "DE"
    assert stored.received_at == T0
    assert len(stored.observations) == 4

    by_target = {o.target_id: o for o in stored.observations}
    assert by_target["t_dns"].result.addresses == ["93.184.216.34"]
    assert by_target["t_http"].result.status_code == 200
    assert by_target["t_tls"].result.fingerprint_sha256 == "a" * 64
    assert by_target["t_tls"].result.not_after == T0 + timedelta(days=30)


def test_an_error_observation_survives_the_round_trip(seeded):
    """A recorded failure is a measurement, not a missing one.

    "Unreachable from here" is the observation the whole project exists to
    collect, so it has to come back out intact and distinguishable from a gap.
    """
    report_id = seeded.save_report(make_report(), received_at=T0, asn=64512, country="DE")
    failed = next(
        o for o in seeded.get_report(report_id).observations if o.target_id == "t_down"
    )

    assert failed.error == "connect_unreachable"
    assert failed.result is None


def test_an_unknown_report_id_is_none(seeded):
    assert seeded.get_report(9999) is None


def test_location_comes_from_the_caller_not_the_agent(seeded):
    """The agent supplies no location field at all; the server supplies it.

    This is the beacon guarantee expressed in storage: `save_report` takes asn
    and country as arguments precisely so there is no path from agent-supplied
    JSON into those columns.
    """
    report_id = seeded.save_report(make_report(), received_at=T0, asn=None, country=None)
    stored = seeded.get_report(report_id)

    assert stored.asn is None and stored.country is None


# --- append-only ----------------------------------------------------------


def test_a_beacon_token_can_carry_only_one_report(seeded):
    """The single-use guarantee, enforced where the data rests.

    A retrying agent must get a refusal, never a second counted report —
    otherwise one vantage point could weight itself arbitrarily in consensus.
    """
    seeded.save_report(make_report(), received_at=T0, asn=64512, country="DE")

    with pytest.raises(StorageError):
        seeded.save_report(make_report(), received_at=T0, asn=64512, country="DE")


def test_a_report_against_an_unissued_manifest_is_refused(seeded):
    forged = make_report().model_copy(update={"manifest_id": "m_never_issued"})
    with pytest.raises(StorageError):
        seeded.save_report(forged, received_at=T0, asn=64512, country="DE")


def test_a_report_with_an_unissued_beacon_token_is_refused(seeded):
    forged = make_report(token="tokenwenevergaveout1")
    with pytest.raises(StorageError):
        seeded.save_report(forged, received_at=T0, asn=64512, country="DE")


def test_a_failed_report_leaves_nothing_behind(seeded, monkeypatch):
    """Atomicity. A half-written report is corrupt data that looks real.

    Forcing the observation insert to violate the exactly-one-outcome CHECK
    proves the report row rolls back with it, rather than surviving as a report
    with no measurements attached.
    """

    def bad_row(report_id, observation):
        return (
            report_id,
            observation.target_id,
            observation.kind,
            "2026-01-01T00:00:00.000000+00:00",
            1,
            "{}",
            "http_error",  # both an outcome and an error: violates the CHECK
        )

    monkeypatch.setattr(SqliteStore, "_observation_row", staticmethod(bad_row))

    with pytest.raises(StorageError):
        seeded.save_report(make_report(), received_at=T0, asn=64512, country="DE")

    assert seeded.vantage_summary()["reports"] == 0


# --- beacons and the retention promise ------------------------------------


def test_a_beacon_records_where_it_was_fetched_from(seeded):
    seeded.record_beacon_observation(TOKEN, "1.2.3.4", 64512, "DE", T0)
    assert seeded.beacon_vantage(TOKEN) == (64512, "DE")


def test_an_unfetched_beacon_has_no_vantage(seeded):
    assert seeded.beacon_vantage(TOKEN) is None


def test_an_unknown_token_has_no_vantage(seeded):
    assert seeded.beacon_vantage("nosuchtoken000000001") is None


def test_the_first_observation_of_a_beacon_wins(seeded):
    """An agent must not be able to move its own vantage point.

    Fetching the beacon again through a proxy elsewhere would otherwise
    overwrite the location, handing the agent exactly the control the beacon
    exists to deny it.
    """
    seeded.record_beacon_observation(TOKEN, "1.2.3.4", 64512, "DE", T0)
    seeded.record_beacon_observation(
        TOKEN, "5.6.7.8", 64513, "US", T0 + timedelta(minutes=5)
    )

    assert seeded.beacon_vantage(TOKEN) == (64512, "DE")


def test_purging_removes_the_raw_ip_and_keeps_the_science(seeded):
    """The published retention promise, in one assertion.

    ASN and country are what the dataset is made of; the raw address is the
    personal data. After the window, only the former remains.
    """
    seeded.record_beacon_observation(TOKEN, "1.2.3.4", 64512, "DE", T0)
    assert seeded.source_ip_count() == 1

    purged = seeded.purge_source_ips(older_than=T0 + timedelta(hours=24))

    assert purged == 1
    assert seeded.source_ip_count() == 0
    assert seeded.beacon_vantage(TOKEN) == (64512, "DE")


def test_purging_spares_addresses_inside_the_window(seeded):
    seeded.record_beacon_observation(TOKEN, "1.2.3.4", 64512, "DE", T0)
    assert seeded.purge_source_ips(older_than=T0 - timedelta(seconds=1)) == 0
    assert seeded.source_ip_count() == 1


def test_purging_twice_is_harmless(seeded):
    """The purge runs on a timer, so it must be safe when there is nothing to do."""
    seeded.record_beacon_observation(TOKEN, "1.2.3.4", 64512, "DE", T0)
    cutoff = T0 + timedelta(hours=24)

    assert seeded.purge_source_ips(older_than=cutoff) == 1
    assert seeded.purge_source_ips(older_than=cutoff) == 0


def test_an_unfetched_beacon_holds_no_address_to_purge(seeded):
    assert seeded.source_ip_count() == 0


# --- manifests ------------------------------------------------------------


def test_a_manifest_is_stored_byte_for_byte(seeded):
    """The signature covers exact bytes.

    Re-serialising from parsed fields could reorder keys or change spacing and
    invalidate a signature we have already published to agents.
    """
    payload = '{"manifest_id":"m_x","targets":[{"id":"t_1"}]}'
    seeded.save_manifest("m_x", T0, T0 + timedelta(hours=4), payload)
    assert seeded.get_manifest_payload("m_x") == payload


def test_an_unknown_manifest_payload_is_none(seeded):
    assert seeded.get_manifest_payload("m_nope") is None


# --- the numbers the dashboard will show ----------------------------------


def test_the_summary_counts_networks_not_just_agents(seeded):
    """Distinct ASNs is the honest headline.

    A thousand agents behind one network is one vantage point, and a dashboard
    advertising the agent count instead would overstate the independence the
    dataset actually has.
    """
    seeded.save_beacon("beacontoken000000002", MANIFEST_ID, T0, T0 + timedelta(hours=4))
    seeded.save_beacon("beacontoken000000003", MANIFEST_ID, T0, T0 + timedelta(hours=4))

    seeded.save_report(make_report(agent_id="agent_001"), T0, asn=64512, country="DE")
    seeded.save_report(
        make_report(token="beacontoken000000002", agent_id="agent_002"),
        T0,
        asn=64512,
        country="DE",
    )
    seeded.save_report(
        make_report(token="beacontoken000000003", agent_id="agent_003"),
        T0,
        asn=64513,
        country="US",
    )

    summary = seeded.vantage_summary()
    assert summary["reports"] == 3
    assert summary["distinct_agents"] == 3
    assert summary["distinct_asns"] == 2
    assert summary["distinct_countries"] == 2


def test_an_empty_store_summarises_to_zeroes(store):
    assert store.vantage_summary() == {
        "reports": 0,
        "distinct_asns": 0,
        "distinct_countries": 0,
        "distinct_agents": 0,
    }
