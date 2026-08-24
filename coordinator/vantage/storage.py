"""Persistence. The dataset is the asset, so this layer is deliberately dull.

**SQLite, not Postgres.** The plan originally said Postgres; at the scale this
actually runs at — roughly 250 writes an hour with a thousand contributing
agents — Postgres buys concurrency we do not need in exchange for a container, a
volume, a password, and a fresh class of disruption risk on a shared machine.
Everything here sits behind `Store`, so swapping in Postgres later is a boring
change rather than a rewrite. Do it when write contention is measured, not
imagined.

Three properties matter more than speed:

**Append-only.** A measurement is never updated, only inserted. The whole moat
is an un-backfillable time series, and a time series you can rewrite is worth
nothing. Re-submitting a beacon token is refused by a UNIQUE constraint rather
than overwriting the earlier report.

**All-or-nothing reports.** A report and its observations commit in one
transaction. A half-written report is corrupt data that looks like real data,
which is worse than no data at all.

**The raw IP is the only personal data, and it lives in one column.** Retention
nulls `beacon_tokens.source_ip` and keeps the ASN and country. The science
survives; the personal data does not. Keeping it to a single nullable column is
what makes that promise auditable in one glance.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from vantage.models import DnsResult, HttpResult, Observation, Report, TlsResult

# Fixed-width UTC. Variable-width microseconds would break lexicographic
# ordering — "…:00+00:00" sorts after "…:00.5+00:00" — and ordering is how every
# time-series query in this project works.
_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%f+00:00"

_RESULT_TYPES: dict[str, type] = {
    "dns": DnsResult,
    "http": HttpResult,
    "tls": TlsResult,
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS manifests (
    manifest_id TEXT PRIMARY KEY,
    issued_at   TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    -- The exact signed bytes. Re-serialising from parsed fields could change
    -- key order or spacing and invalidate the signature we already published.
    payload     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS beacon_tokens (
    token       TEXT PRIMARY KEY,
    manifest_id TEXT NOT NULL REFERENCES manifests(manifest_id),
    issued_at   TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    observed_at TEXT,
    -- The ONLY personal data in this database. Nulled by purge_source_ips().
    source_ip   TEXT,
    asn         INTEGER,
    country     TEXT,
    claimed_at  TEXT
);
CREATE INDEX IF NOT EXISTS ix_beacon_observed ON beacon_tokens(observed_at);

CREATE TABLE IF NOT EXISTS reports (
    report_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    manifest_id    TEXT NOT NULL REFERENCES manifests(manifest_id),
    -- UNIQUE is the backstop for single-use beacons. A retrying agent gets a
    -- refusal, never a second counted report.
    beacon_token   TEXT NOT NULL UNIQUE REFERENCES beacon_tokens(token),
    agent_id       TEXT NOT NULL,
    agent_software TEXT,
    received_at    TEXT NOT NULL,
    -- Server-observed, copied from the beacon. Never taken from the agent.
    asn            INTEGER,
    country        TEXT
);
CREATE INDEX IF NOT EXISTS ix_reports_received ON reports(received_at);
CREATE INDEX IF NOT EXISTS ix_reports_asn ON reports(asn);

CREATE TABLE IF NOT EXISTS observations (
    observation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id      INTEGER NOT NULL REFERENCES reports(report_id) ON DELETE CASCADE,
    target_id      TEXT NOT NULL,
    kind           TEXT NOT NULL,
    started_at     TEXT NOT NULL,
    duration_ms    INTEGER NOT NULL,
    result_json    TEXT,
    error          TEXT,
    -- The same exactly-one-outcome rule the model enforces, restated where the
    -- data actually rests. A bug in the app layer should not be able to write a
    -- measurement that says nothing.
    CHECK ((result_json IS NULL) != (error IS NULL))
);
CREATE INDEX IF NOT EXISTS ix_obs_target_time ON observations(target_id, started_at);
"""


class StorageError(RuntimeError):
    """Raised when a write is refused for a reason the caller should handle."""


def to_db_time(value: datetime) -> str:
    """Serialise an aware UTC datetime to sortable text."""
    if value.tzinfo is None:
        raise ValueError("naive datetime; storage is UTC-only")
    return value.astimezone(timezone.utc).strftime(_TIME_FORMAT)


def from_db_time(value: str) -> datetime:
    return datetime.strptime(value, _TIME_FORMAT).replace(tzinfo=timezone.utc)


@dataclass(frozen=True)
class StoredReport:
    """What came back out, with location as the server observed it."""

    report_id: int
    manifest_id: str
    agent_id: str
    received_at: datetime
    asn: int | None
    country: str | None
    observations: tuple[Observation, ...]


class Store(Protocol):
    """The seam Postgres will slot into. Keep it narrow."""

    def save_manifest(
        self, manifest_id: str, issued_at: datetime, expires_at: datetime, payload: str
    ) -> None: ...

    def save_report(
        self,
        report: Report,
        received_at: datetime,
        asn: int | None,
        country: str | None,
    ) -> int: ...


class SqliteStore:
    """SQLite in WAL mode.

    One connection guarded by a lock. SQLite allows a single writer regardless,
    so a pool would add complexity without adding throughput; the lock just
    makes that serialisation explicit instead of letting it surface as
    "database is locked" under load.
    """

    def __init__(self, path: str | Path = "vantage.db") -> None:
        self._path = str(path)
        self._lock = threading.Lock()
        # FastAPI serves sync endpoints on a thread pool, so the connection is
        # used from more than one thread; the lock is what makes that safe.
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._configure()
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def _configure(self) -> None:
        # Foreign keys are OFF by default in SQLite. Every REFERENCES clause in
        # the schema above is decoration until this runs.
        self._conn.execute("PRAGMA foreign_keys = ON")
        # WAL lets readers work while a write is in flight — dashboard queries
        # must never block ingest.
        self._conn.execute("PRAGMA journal_mode = WAL")
        # NORMAL with WAL survives process crashes; only power loss can lose the
        # last commits. The right trade for measurements.
        self._conn.execute("PRAGMA synchronous = NORMAL")

    def close(self) -> None:
        self._conn.close()

    # --- manifests --------------------------------------------------------

    def save_manifest(
        self, manifest_id: str, issued_at: datetime, expires_at: datetime, payload: str
    ) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO manifests "
                "(manifest_id, issued_at, expires_at, payload) VALUES (?, ?, ?, ?)",
                (manifest_id, to_db_time(issued_at), to_db_time(expires_at), payload),
            )

    def get_manifest_payload(self, manifest_id: str) -> str | None:
        """Return the exact bytes we signed, or None."""
        row = self._conn.execute(
            "SELECT payload FROM manifests WHERE manifest_id = ?", (manifest_id,)
        ).fetchone()
        return row["payload"] if row else None

    # --- beacons ----------------------------------------------------------

    def save_beacon(
        self, token: str, manifest_id: str, issued_at: datetime, expires_at: datetime
    ) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO beacon_tokens "
                "(token, manifest_id, issued_at, expires_at) VALUES (?, ?, ?, ?)",
                (token, manifest_id, to_db_time(issued_at), to_db_time(expires_at)),
            )

    def record_beacon_observation(
        self,
        token: str,
        source_ip: str,
        asn: int | None,
        country: str | None,
        observed_at: datetime,
    ) -> None:
        """Record where a beacon was fetched from.

        First observation wins — note the `observed_at IS NULL` guard. A token
        fetched twice must not be able to move its own vantage point; that would
        hand an agent exactly the control over its location that the beacon
        exists to deny it.
        """
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE beacon_tokens SET source_ip = ?, asn = ?, country = ?, "
                "observed_at = ? WHERE token = ? AND observed_at IS NULL",
                (source_ip, asn, country, to_db_time(observed_at), token),
            )

    def beacon_vantage(self, token: str) -> tuple[int | None, str | None] | None:
        """The observed (asn, country), or None if the token was never fetched."""
        row = self._conn.execute(
            "SELECT asn, country, observed_at FROM beacon_tokens WHERE token = ?",
            (token,),
        ).fetchone()
        if row is None or row["observed_at"] is None:
            return None
        return row["asn"], row["country"]

    def purge_source_ips(self, older_than: datetime) -> int:
        """Drop raw IPs observed before `older_than`. Keeps ASN and country.

        This is the retention promise in the published privacy notice. It is
        only true while something actually calls it on a timer.
        """
        with self._lock, self._conn:
            cursor = self._conn.execute(
                "UPDATE beacon_tokens SET source_ip = NULL "
                "WHERE source_ip IS NOT NULL AND observed_at < ?",
                (to_db_time(older_than),),
            )
            return cursor.rowcount

    def source_ip_count(self) -> int:
        """How many raw IPs are currently retained. For the privacy audit."""
        row = self._conn.execute(
            "SELECT COUNT(*) AS n FROM beacon_tokens WHERE source_ip IS NOT NULL"
        ).fetchone()
        return int(row["n"])

    # --- reports ----------------------------------------------------------

    def save_report(
        self,
        report: Report,
        received_at: datetime,
        asn: int | None,
        country: str | None,
    ) -> int:
        """Insert a report and its observations atomically. Returns the row id.

        Raises `StorageError` if this beacon token already carries a report —
        the single-use guarantee, enforced where the data rests.
        """
        with self._lock:
            try:
                with self._conn:
                    cursor = self._conn.execute(
                        "INSERT INTO reports (manifest_id, beacon_token, agent_id, "
                        "agent_software, received_at, asn, country) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (
                            report.manifest_id,
                            report.beacon_token,
                            report.agent.id,
                            report.agent.software,
                            to_db_time(received_at),
                            asn,
                            country,
                        ),
                    )
                    report_id = int(cursor.lastrowid)
                    self._conn.executemany(
                        "INSERT INTO observations (report_id, target_id, kind, "
                        "started_at, duration_ms, result_json, error) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        [
                            self._observation_row(report_id, o)
                            for o in report.observations
                        ],
                    )
                    return report_id
            except sqlite3.IntegrityError as exc:
                # Covers the UNIQUE beacon token, the FK to a manifest we never
                # issued, and the exactly-one-outcome CHECK.
                raise StorageError(str(exc)) from exc

    @staticmethod
    def _observation_row(report_id: int, observation: Observation) -> tuple:
        result = observation.result
        return (
            report_id,
            observation.target_id,
            observation.kind,
            to_db_time(observation.started_at),
            observation.duration_ms,
            result.model_dump_json() if result is not None else None,
            observation.error,
        )

    def get_report(self, report_id: int) -> StoredReport | None:
        row = self._conn.execute(
            "SELECT * FROM reports WHERE report_id = ?", (report_id,)
        ).fetchone()
        if row is None:
            return None

        observations = self._conn.execute(
            "SELECT * FROM observations WHERE report_id = ? ORDER BY observation_id",
            (report_id,),
        ).fetchall()

        return StoredReport(
            report_id=row["report_id"],
            manifest_id=row["manifest_id"],
            agent_id=row["agent_id"],
            received_at=from_db_time(row["received_at"]),
            asn=row["asn"],
            country=row["country"],
            observations=tuple(self._to_observation(o) for o in observations),
        )

    @staticmethod
    def _to_observation(row: sqlite3.Row) -> Observation:
        result = None
        if row["result_json"] is not None:
            result_type = _RESULT_TYPES[row["kind"]]
            result = result_type(**json.loads(row["result_json"]))
        return Observation(
            target_id=row["target_id"],
            kind=row["kind"],
            started_at=from_db_time(row["started_at"]),
            duration_ms=row["duration_ms"],
            result=result,
            error=row["error"],
        )

    # --- summaries, for the public surface --------------------------------

    def vantage_summary(self) -> dict[str, int]:
        """Counts the dashboard needs, and the honest headline number.

        `distinct_asns` is the one that matters: consensus is computed across
        independent networks, so a thousand agents behind one ASN is still one
        vantage point.
        """
        row = self._conn.execute(
            "SELECT COUNT(*) AS reports, "
            "COUNT(DISTINCT asn) AS distinct_asns, "
            "COUNT(DISTINCT country) AS distinct_countries, "
            "COUNT(DISTINCT agent_id) AS distinct_agents FROM reports"
        ).fetchone()
        return {
            "reports": int(row["reports"]),
            "distinct_asns": int(row["distinct_asns"]),
            "distinct_countries": int(row["distinct_countries"]),
            "distinct_agents": int(row["distinct_agents"]),
        }
