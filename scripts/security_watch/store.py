"""SQLite state for security-watch (sources, signals, findings, journal, breaker, runs).

One database at ``config.db_path()`` (directory 0700, file 0600, WAL).  Dataclasses are
stored as JSON (``dataclasses.asdict``) and rebuilt with the ``*_from_dict`` helpers.
Timestamps are ISO-8601 UTC strings from ``model.iso`` so they compare lexically.
"""

from __future__ import annotations

import dataclasses
import json
import os
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable

from security_watch import config
from security_watch.model import (
    AdvisoryPackage,
    Finding,
    Inventory,
    Package,
    Plan,
    Reach,
    Refusal,
    Signal,
    iso,
    parse_iso,
    utcnow,
)

__all__ = [
    "Store",
    "finding_from_dict",
    "reach_from_dict",
    "inventory_from_dict",
    "signal_from_dict",
    "plan_from_dict",
]

RETENTION = timedelta(days=30)

# Append-only list; each entry is idempotent (IF NOT EXISTS) and runs once per database.
MIGRATIONS: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS sources (
        name TEXT PRIMARY KEY,
        cursor TEXT,
        etag TEXT,
        last_modified TEXT,
        last_attempt TEXT,
        last_success TEXT,
        last_error TEXT NOT NULL DEFAULT '',
        consecutive_failures INTEGER NOT NULL DEFAULT 0,
        state TEXT NOT NULL DEFAULT '{}'
    );
    CREATE TABLE IF NOT EXISTS source_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        at TEXT NOT NULL,
        ok INTEGER NOT NULL,
        error TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS source_attempts_name_at ON source_attempts(name, at);
    CREATE TABLE IF NOT EXISTS signals (
        source TEXT NOT NULL,
        key TEXT NOT NULL,
        version TEXT NOT NULL,
        data TEXT NOT NULL,
        first_seen TEXT NOT NULL,
        last_changed TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        PRIMARY KEY (source, key)
    );
    CREATE INDEX IF NOT EXISTS signals_last_changed ON signals(last_changed);
    CREATE TABLE IF NOT EXISTS kv (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS osv_cache (
        vuln_id TEXT PRIMARY KEY,
        record TEXT NOT NULL,
        fetched_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS inventory (
        component_id TEXT PRIMARY KEY,
        collected_at TEXT NOT NULL,
        data TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS findings (
        key TEXT PRIMARY KEY,
        component_id TEXT NOT NULL,
        status TEXT NOT NULL,
        data TEXT NOT NULL,
        first_seen TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        resolved_at TEXT
    );
    CREATE INDEX IF NOT EXISTS findings_component ON findings(component_id, status);
    CREATE TABLE IF NOT EXISTS reach_cache (
        cache_key TEXT PRIMARY KEY,
        data TEXT NOT NULL,
        stored_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        playbook TEXT NOT NULL,
        component_id TEXT NOT NULL,
        finding_keys TEXT NOT NULL,
        target TEXT NOT NULL,
        mode TEXT NOT NULL,
        status TEXT NOT NULL,
        detail TEXT NOT NULL DEFAULT '',
        undo TEXT NOT NULL DEFAULT '',
        state TEXT NOT NULL DEFAULT '{}',
        plan TEXT NOT NULL,
        started_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        finished_at TEXT
    );
    CREATE INDEX IF NOT EXISTS actions_component ON actions(component_id, mode, started_at);
    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        dedupe_key TEXT NOT NULL,
        subject TEXT NOT NULL,
        sent_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS notifications_key ON notifications(dedupe_key, sent_at);
    CREATE TABLE IF NOT EXISTS breaker (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        open INTEGER NOT NULL,
        reason TEXT NOT NULL DEFAULT '',
        since TEXT,
        updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        started TEXT NOT NULL,
        finished TEXT NOT NULL,
        outcome TEXT NOT NULL,
        summary TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS runs_started ON runs(started);
    CREATE TABLE IF NOT EXISTS refusals (
        component_id TEXT NOT NULL,
        playbook TEXT NOT NULL,
        reason TEXT NOT NULL,
        alert INTEGER NOT NULL,
        since TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        PRIMARY KEY (component_id, playbook)
    );
    """,
)


# --- serialization -------------------------------------------------------------

def _json_default(value: Any) -> Any:
    if isinstance(value, datetime):
        return iso(value)
    if isinstance(value, (set, frozenset)):
        return sorted(value)
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return dataclasses.asdict(value)
    raise TypeError(f"not JSON serializable: {type(value).__name__}")


def _dumps(value: Any) -> str:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        value = dataclasses.asdict(value)
    return json.dumps(value, sort_keys=True, default=_json_default)


def _loads(text: str | None, default: Any = None) -> Any:
    return default if text is None else json.loads(text)


def _ts(value: datetime | str | None) -> str | None:
    if value is None or isinstance(value, str):
        return value
    return iso(value)


def _known(cls: type, data: dict[str, Any]) -> dict[str, Any]:
    names = {f.name for f in dataclasses.fields(cls)}
    return {k: v for k, v in data.items() if k in names}


def _package_from_dict(data: dict[str, Any] | Package) -> Package:
    return data if isinstance(data, Package) else Package(**_known(Package, data))


def _advisory_package_from_dict(data: dict[str, Any] | AdvisoryPackage) -> AdvisoryPackage:
    if isinstance(data, AdvisoryPackage):
        return data
    fields = _known(AdvisoryPackage, data)
    fields["fixed"] = tuple(fields.get("fixed") or ())
    return AdvisoryPackage(**fields)


def reach_from_dict(data: dict[str, Any] | None) -> Reach | None:
    if data is None:
        return None
    if isinstance(data, Reach):
        return data
    fields = _known(Reach, data)
    fields["evidence"] = list(fields.get("evidence") or [])
    return Reach(**fields)


def finding_from_dict(data: dict[str, Any]) -> Finding:
    fields = _known(Finding, data)
    fields["package"] = _package_from_dict(fields["package"])
    fields["reach"] = reach_from_dict(fields.get("reach"))
    for name in ("advisory_ids", "cves", "fixed_versions", "zero_wire", "reasons"):
        if name in fields:
            fields[name] = list(fields[name] or [])
    return Finding(**fields)


def inventory_from_dict(data: dict[str, Any]) -> Inventory:
    fields = _known(Inventory, data)
    collected = fields["collected_at"]
    fields["collected_at"] = collected if isinstance(collected, datetime) else parse_iso(collected)
    fields["packages"] = [_package_from_dict(p) for p in fields.get("packages") or []]
    fields["meta"] = dict(fields.get("meta") or {})
    return Inventory(**fields)


def signal_from_dict(data: dict[str, Any]) -> Signal:
    fields = _known(Signal, data)
    for name in ("cves", "aliases", "links"):
        if name in fields:
            fields[name] = tuple(fields[name] or ())
    if "packages" in fields:
        fields["packages"] = tuple(_advisory_package_from_dict(p) for p in fields["packages"] or ())
    return Signal(**fields)


def plan_from_dict(data: dict[str, Any]) -> Plan:
    fields = _known(Plan, data)
    for name in ("finding_keys", "lock_keys", "steps"):
        if name in fields:
            fields[name] = list(fields[name] or [])
    fields["state"] = dict(fields.get("state") or {})
    return Plan(**fields)


# --- store ----------------------------------------------------------------------

_ACTION_COLUMNS = ("id, playbook, component_id, finding_keys, target, mode, status, detail, undo, "
                   "state, plan, started_at, updated_at, finished_at")


class Store:
    def __init__(self, path: Path | None = None):
        self.path = Path(path) if path is not None else config.db_path()
        parent = self.path.parent
        if not parent.exists():
            parent.mkdir(parents=True, mode=0o700)
            os.chmod(parent, 0o700)
        if not self.path.exists():
            os.close(os.open(self.path, os.O_CREAT | os.O_WRONLY, 0o600))
        os.chmod(self.path, 0o600)
        self._conn = sqlite3.connect(str(self.path), timeout=30)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA busy_timeout=30000")
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._migrate()

    # lifecycle -----------------------------------------------------------------
    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def _migrate(self) -> None:
        conn = self._conn
        with conn:
            conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        row = conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
        current = int(row["value"]) if row else 0
        for version, script in enumerate(MIGRATIONS[current:], start=current + 1):
            conn.executescript(script)
            with conn:
                conn.execute("INSERT INTO meta(key, value) VALUES('schema_version', ?) "
                             "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (str(version),))

    @property
    def schema_version(self) -> int:
        row = self._conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
        return int(row["value"]) if row else 0

    # sources ---------------------------------------------------------------------
    def source_state(self, name: str) -> dict:
        row = self._conn.execute("SELECT * FROM sources WHERE name = ?", (name,)).fetchone()
        if row is None:
            return {"name": name, "cursor": None, "etag": None, "last_modified": None,
                    "last_attempt": None, "last_success": None, "last_error": "",
                    "consecutive_failures": 0, "state": {}}
        return {
            "name": name,
            "cursor": _loads(row["cursor"]),
            "etag": row["etag"],
            "last_modified": row["last_modified"],
            "last_attempt": row["last_attempt"],
            "last_success": row["last_success"],
            "last_error": row["last_error"],
            "consecutive_failures": int(row["consecutive_failures"]),
            "state": _loads(row["state"], {}),
        }

    def record_source(self, name, *, ok: bool, now, cursor=None, etag=None, last_modified=None,
                      error=None, state: dict | None = None) -> None:
        prev = self.source_state(name)
        at = _ts(now)
        new_cursor = prev["cursor"] if cursor is None else cursor
        new_etag = prev["etag"] if etag is None else etag
        new_lm = prev["last_modified"] if last_modified is None else last_modified
        new_state = prev["state"] if state is None else state
        if ok:
            last_success, last_error, failures = at, "", 0
        else:
            last_success = prev["last_success"]
            last_error = str(error) if error else "failed"
            failures = prev["consecutive_failures"] + 1
        with self._conn:
            self._conn.execute(
                "INSERT INTO sources(name, cursor, etag, last_modified, last_attempt, last_success, "
                "last_error, consecutive_failures, state) VALUES(?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(name) DO UPDATE SET cursor=excluded.cursor, etag=excluded.etag, "
                "last_modified=excluded.last_modified, last_attempt=excluded.last_attempt, "
                "last_success=excluded.last_success, last_error=excluded.last_error, "
                "consecutive_failures=excluded.consecutive_failures, state=excluded.state",
                (name, None if new_cursor is None else _dumps(new_cursor), new_etag, new_lm, at,
                 last_success, last_error, failures, _dumps(new_state or {})),
            )
            self._conn.execute("INSERT INTO source_attempts(name, at, ok, error) VALUES(?,?,?,?)",
                               (name, at, 1 if ok else 0, "" if ok else last_error))

    def source_ok_rate(self, name, since) -> float | None:
        row = self._conn.execute(
            "SELECT COUNT(*) AS total, COALESCE(SUM(ok), 0) AS good FROM source_attempts "
            "WHERE name = ? AND at >= ?", (name, _ts(since))).fetchone()
        total = int(row["total"])
        return None if total == 0 else int(row["good"]) / total

    # signals ---------------------------------------------------------------------
    def upsert_signal(self, sig: Signal, now) -> str:
        at = _ts(now)
        data = _dumps(sig)
        row = self._conn.execute("SELECT version FROM signals WHERE source = ? AND key = ?",
                                 (sig.source, sig.key)).fetchone()
        with self._conn:
            if row is None:
                self._conn.execute(
                    "INSERT INTO signals(source, key, version, data, first_seen, last_changed, last_seen) "
                    "VALUES(?,?,?,?,?,?,?)", (sig.source, sig.key, sig.version, data, at, at, at))
                return "new"
            if row["version"] != sig.version:
                self._conn.execute(
                    "UPDATE signals SET version = ?, data = ?, last_changed = ?, last_seen = ? "
                    "WHERE source = ? AND key = ?", (sig.version, data, at, at, sig.source, sig.key))
                return "updated"
            self._conn.execute("UPDATE signals SET data = ?, last_seen = ? WHERE source = ? AND key = ?",
                               (data, at, sig.source, sig.key))
            return "same"

    def signal(self, source: str, key: str) -> Signal | None:
        row = self._conn.execute("SELECT data FROM signals WHERE source = ? AND key = ?",
                                 (source, key)).fetchone()
        return signal_from_dict(json.loads(row["data"])) if row else None

    def signals_since(self, since, *, sources: Iterable[str] | None = None) -> list[tuple[Signal, str, str]]:
        sql = "SELECT data, first_seen, last_changed FROM signals WHERE last_changed >= ?"
        params: list[Any] = [_ts(since)]
        if sources is not None:
            names = sorted(set(sources))
            if not names:
                return []
            sql += f" AND source IN ({','.join('?' * len(names))})"
            params.extend(names)
        sql += " ORDER BY last_changed, source, key"
        return [(signal_from_dict(json.loads(r["data"])), r["first_seen"], r["last_changed"])
                for r in self._conn.execute(sql, params)]

    def all_signals(self, source: str) -> list[Signal]:
        return [signal_from_dict(json.loads(r["data"])) for r in
                self._conn.execute("SELECT data FROM signals WHERE source = ? ORDER BY key", (source,))]

    # kv ------------------------------------------------------------------------------
    def get_kv(self, key: str, default=None):
        row = self._conn.execute("SELECT value FROM kv WHERE key = ?", (key,)).fetchone()
        return default if row is None else json.loads(row["value"])

    def set_kv(self, key: str, value) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO kv(key, value, updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE "
                "SET value = excluded.value, updated_at = excluded.updated_at",
                (key, _dumps(value), iso(utcnow())))

    # OSV cache -----------------------------------------------------------------------
    def osv_get(self, vuln_id: str) -> tuple[dict, datetime] | None:
        row = self._conn.execute("SELECT record, fetched_at FROM osv_cache WHERE vuln_id = ?",
                                 (vuln_id,)).fetchone()
        return None if row is None else (json.loads(row["record"]), parse_iso(row["fetched_at"]))

    def osv_put(self, vuln_id: str, record: dict, now) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO osv_cache(vuln_id, record, fetched_at) VALUES(?,?,?) ON CONFLICT(vuln_id) "
                "DO UPDATE SET record = excluded.record, fetched_at = excluded.fetched_at",
                (vuln_id, _dumps(record), _ts(now)))

    # inventory -------------------------------------------------------------------------
    def put_inventory(self, inv: Inventory) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO inventory(component_id, collected_at, data) VALUES(?,?,?) "
                "ON CONFLICT(component_id) DO UPDATE SET collected_at = excluded.collected_at, "
                "data = excluded.data", (inv.component_id, _ts(inv.collected_at), _dumps(inv)))

    def get_inventory(self, component_id) -> Inventory | None:
        row = self._conn.execute("SELECT data FROM inventory WHERE component_id = ?",
                                 (component_id,)).fetchone()
        return inventory_from_dict(json.loads(row["data"])) if row else None

    def inventories(self) -> list[Inventory]:
        return [inventory_from_dict(json.loads(r["data"])) for r in
                self._conn.execute("SELECT data FROM inventory ORDER BY component_id")]

    # findings ----------------------------------------------------------------------------
    def upsert_finding(self, f: Finding, now) -> str:
        at = _ts(now)
        row = self._conn.execute("SELECT data, first_seen FROM findings WHERE key = ?", (f.key,)).fetchone()
        if row is None:
            f.first_seen = f.first_seen or at
            result = "new"
        else:
            f.first_seen = row["first_seen"]
        data = _dumps(f)
        if row is not None:
            result = "same" if data == row["data"] else "updated"
        resolved_at = at if f.status == "fixed" else None
        with self._conn:
            if result == "new":
                self._conn.execute(
                    "INSERT INTO findings(key, component_id, status, data, first_seen, updated_at, resolved_at) "
                    "VALUES(?,?,?,?,?,?,?)", (f.key, f.component_id, f.status, data, f.first_seen, at, resolved_at))
            elif result == "updated":
                self._conn.execute(
                    "UPDATE findings SET component_id = ?, status = ?, data = ?, updated_at = ?, "
                    "resolved_at = CASE WHEN ? = 'fixed' THEN COALESCE(resolved_at, ?) ELSE NULL END "
                    "WHERE key = ?", (f.component_id, f.status, data, at, f.status, resolved_at, f.key))
        return result

    def get_finding(self, key) -> Finding | None:
        row = self._conn.execute("SELECT data FROM findings WHERE key = ?", (key,)).fetchone()
        return finding_from_dict(json.loads(row["data"])) if row else None

    def open_findings(self) -> list[Finding]:
        return [finding_from_dict(json.loads(r["data"])) for r in
                self._conn.execute("SELECT data FROM findings WHERE status != 'fixed' ORDER BY key")]

    def close_missing_findings(self, component_id, open_keys: set[str], now) -> list[str]:
        at = _ts(now)
        keep = set(open_keys)
        closed: list[str] = []
        rows = self._conn.execute(
            "SELECT key, data FROM findings WHERE component_id = ? AND status != 'fixed' ORDER BY key",
            (component_id,)).fetchall()
        with self._conn:
            for row in rows:
                if row["key"] in keep:
                    continue
                data = json.loads(row["data"])
                data["status"] = "fixed"
                self._conn.execute(
                    "UPDATE findings SET status = 'fixed', data = ?, updated_at = ?, resolved_at = ? WHERE key = ?",
                    (json.dumps(data, sort_keys=True), at, at, row["key"]))
                closed.append(row["key"])
        return closed

    def findings_resolved_since(self, since) -> list[Finding]:
        return [finding_from_dict(json.loads(r["data"])) for r in self._conn.execute(
            "SELECT data FROM findings WHERE status = 'fixed' AND resolved_at >= ? ORDER BY resolved_at, key",
            (_ts(since),))]

    def finding_resolved_at(self, key) -> datetime | None:
        """When the finding was closed (``None`` while open or unknown)."""
        row = self._conn.execute("SELECT resolved_at FROM findings WHERE key = ?", (key,)).fetchone()
        return parse_iso(row["resolved_at"]) if row and row["resolved_at"] else None

    # reachability cache --------------------------------------------------------------------
    def get_reach(self, cache_key) -> Reach | None:
        row = self._conn.execute("SELECT data FROM reach_cache WHERE cache_key = ?", (cache_key,)).fetchone()
        return reach_from_dict(json.loads(row["data"])) if row else None

    def put_reach(self, cache_key, reach: Reach, now) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO reach_cache(cache_key, data, stored_at) VALUES(?,?,?) ON CONFLICT(cache_key) "
                "DO UPDATE SET data = excluded.data, stored_at = excluded.stored_at",
                (cache_key, _dumps(reach), _ts(now)))

    # action journal --------------------------------------------------------------------------
    @staticmethod
    def _action_row(row: sqlite3.Row) -> dict:
        return {
            "id": int(row["id"]),
            "playbook": row["playbook"],
            "component_id": row["component_id"],
            "finding_keys": json.loads(row["finding_keys"]),
            "target": row["target"],
            "mode": row["mode"],
            "status": row["status"],
            "detail": row["detail"],
            "undo": row["undo"],
            "state": json.loads(row["state"]),
            "plan": json.loads(row["plan"]),
            "started_at": row["started_at"],
            "updated_at": row["updated_at"],
            "finished_at": row["finished_at"],
        }

    def start_action(self, plan: Plan, *, mode: str, status: str, now) -> int:
        if mode not in ("shadow", "active"):
            raise ValueError(f"action mode must be shadow or active, got {mode!r}")
        at = _ts(now)
        with self._conn:
            cur = self._conn.execute(
                "INSERT INTO actions(playbook, component_id, finding_keys, target, mode, status, detail, "
                "undo, state, plan, started_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (plan.playbook, plan.component_id, _dumps(list(plan.finding_keys)), plan.target, mode,
                 status, "", plan.undo, _dumps(plan.state or {}), _dumps(plan), at, at))
        return int(cur.lastrowid)

    def update_action(self, action_id, *, status: str, detail: str, now, undo: str | None = None,
                      state: dict | None = None, finished: bool = False) -> None:
        at = _ts(now)
        sets = ["status = ?", "detail = ?", "updated_at = ?"]
        params: list[Any] = [status, detail, at]
        if undo is not None:
            sets.append("undo = ?")
            params.append(undo)
        if state is not None:
            sets.append("state = ?")
            params.append(_dumps(state))
        if finished:
            sets.append("finished_at = ?")
            params.append(at)
        params.append(int(action_id))
        with self._conn:
            cur = self._conn.execute(f"UPDATE actions SET {', '.join(sets)} WHERE id = ?", params)
        if cur.rowcount == 0:
            raise KeyError(f"no action {action_id}")

    def get_action(self, action_id) -> dict:
        row = self._conn.execute(f"SELECT {_ACTION_COLUMNS} FROM actions WHERE id = ?",
                                 (int(action_id),)).fetchone()
        if row is None:
            raise KeyError(f"no action {action_id}")
        return self._action_row(row)

    def actions_since(self, since) -> list[dict]:
        """Actions started or updated since ``since`` (multi-tick actions stay visible)."""
        ts = _ts(since)
        return [self._action_row(r) for r in self._conn.execute(
            f"SELECT {_ACTION_COLUMNS} FROM actions WHERE started_at >= ? OR updated_at >= ? ORDER BY id",
            (ts, ts))]

    def active_actions(self) -> list[dict]:
        return [self._action_row(r) for r in self._conn.execute(
            f"SELECT {_ACTION_COLUMNS} FROM actions WHERE mode = 'active' AND status IN ('running', 'pending') "
            "ORDER BY id")]

    def executed_actions_since(self, since) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) AS n FROM actions WHERE mode = 'active' AND status NOT IN ('proposed', 'refused') "
            "AND started_at >= ?", (_ts(since),)).fetchone()
        return int(row["n"])

    def last_action(self, component_id, *, mode: str = "active") -> dict | None:
        row = self._conn.execute(
            f"SELECT {_ACTION_COLUMNS} FROM actions WHERE component_id = ? AND mode = ? "
            "ORDER BY started_at DESC, id DESC LIMIT 1", (component_id, mode)).fetchone()
        return self._action_row(row) if row else None

    def proposal_exists(self, component_id, target: str, since) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM actions WHERE component_id = ? AND target = ? AND mode = 'shadow' "
            "AND started_at >= ? LIMIT 1", (component_id, target, _ts(since))).fetchone()
        return row is not None

    # notifications ----------------------------------------------------------------------------
    def notified_at(self, dedupe_key) -> datetime | None:
        row = self._conn.execute("SELECT MAX(sent_at) AS at FROM notifications WHERE dedupe_key = ?",
                                 (dedupe_key,)).fetchone()
        return parse_iso(row["at"]) if row and row["at"] else None

    def record_notification(self, dedupe_key, subject, now) -> None:
        with self._conn:
            self._conn.execute("INSERT INTO notifications(dedupe_key, subject, sent_at) VALUES(?,?,?)",
                               (dedupe_key, subject, _ts(now)))

    def notifications_since(self, since) -> int:
        row = self._conn.execute("SELECT COUNT(*) AS n FROM notifications WHERE sent_at >= ?",
                                 (_ts(since),)).fetchone()
        return int(row["n"])

    # breaker ------------------------------------------------------------------------------------
    def breaker(self) -> dict:
        row = self._conn.execute("SELECT open, reason, since FROM breaker WHERE id = 1").fetchone()
        if row is None:
            return {"open": False, "reason": "", "since": None}
        return {"open": bool(row["open"]), "reason": row["reason"], "since": row["since"]}

    def trip_breaker(self, reason: str, now) -> None:
        """Open the breaker; an already-open breaker keeps its first reason and time."""
        if self.breaker()["open"]:
            return
        at = _ts(now)
        with self._conn:
            self._conn.execute(
                "INSERT INTO breaker(id, open, reason, since, updated_at) VALUES(1, 1, ?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET open = 1, reason = excluded.reason, since = excluded.since, "
                "updated_at = excluded.updated_at", (reason, at, at))

    def reset_breaker(self, now) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO breaker(id, open, reason, since, updated_at) VALUES(1, 0, '', NULL, ?) "
                "ON CONFLICT(id) DO UPDATE SET open = 0, reason = '', since = NULL, "
                "updated_at = excluded.updated_at", (_ts(now),))

    # runs -----------------------------------------------------------------------------------------
    def record_run(self, *, started, finished, outcome: str, summary: dict) -> None:
        started_ts = _ts(started)
        finished_dt = finished if isinstance(finished, datetime) else parse_iso(finished)
        cutoff = iso(finished_dt - RETENTION)
        with self._conn:
            self._conn.execute("INSERT INTO runs(started, finished, outcome, summary) VALUES(?,?,?,?)",
                               (started_ts, _ts(finished), outcome, _dumps(summary or {})))
            self._conn.execute(
                "INSERT INTO meta(key, value) VALUES('first_run_at', ?) ON CONFLICT(key) DO NOTHING",
                (started_ts,))
            self._conn.execute("DELETE FROM runs WHERE started < ?", (cutoff,))
            self._conn.execute("DELETE FROM source_attempts WHERE at < ?", (cutoff,))

    def runs_since(self, since) -> list[dict]:
        return [{"id": int(r["id"]), "started": r["started"], "finished": r["finished"],
                 "outcome": r["outcome"], "summary": json.loads(r["summary"])}
                for r in self._conn.execute(
                    "SELECT id, started, finished, outcome, summary FROM runs WHERE started >= ? ORDER BY started, id",
                    (_ts(since),))]

    def first_run_at(self) -> datetime | None:
        """First recorded run ever (kept in meta, so pruning old runs does not move it)."""
        row = self._conn.execute("SELECT value FROM meta WHERE key = 'first_run_at'").fetchone()
        return parse_iso(row["value"]) if row else None

    # refusals ---------------------------------------------------------------------------------------
    def record_refusal(self, refusal: Refusal, now) -> None:
        """Latest refusal per (component, playbook); ``since`` restarts when the reason changes."""
        at = _ts(now)
        with self._conn:
            self._conn.execute(
                "INSERT INTO refusals(component_id, playbook, reason, alert, since, last_seen) "
                "VALUES(?,?,?,?,?,?) ON CONFLICT(component_id, playbook) DO UPDATE SET "
                "since = CASE WHEN refusals.reason = excluded.reason THEN refusals.since ELSE excluded.since END, "
                "reason = excluded.reason, alert = excluded.alert, last_seen = excluded.last_seen",
                (refusal.component_id, refusal.playbook, refusal.reason, 1 if refusal.alert else 0, at, at))

    def refusals_since(self, since) -> list[dict]:
        """Refusals seen since ``since``; ``component`` mirrors ``component_id`` (report.json shape)."""
        return [{"component_id": r["component_id"], "component": r["component_id"],
                 "playbook": r["playbook"], "reason": r["reason"], "alert": bool(r["alert"]),
                 "since": r["since"], "last_seen": r["last_seen"]}
                for r in self._conn.execute(
                    "SELECT * FROM refusals WHERE last_seen >= ? ORDER BY component_id, playbook",
                    (_ts(since),))]
