"""Shared configuration and the SQLite state plane.

Three processes (web console / resolver / authoritative endpoint) share one
SQLite database in WAL mode:

  control   -- desired behaviour of the authoritative endpoint, written by the
               web console, read by the authoritative endpoint per query.
  trial     -- an in-flight trial cut-over of the A record: a new IPv4 plus an
               absolute confirmation deadline.  While it is active it overlays
               `control`; it is confirmed, revoked or expired exactly once,
               inside one transaction that also invalidates the resolver cache
               and advances a monotonically increasing `generation`.
  cache     -- the resolver's cache.  Absolute epoch deadlines are stored, so a
               resolver restart can never extend the validity of an old A
               record; the stale window simply keeps counting down.  Every row
               also records the state generation it was fetched for, so an
               upstream reply that arrives after the state changed can never be
               written back into the cache.
  query_log -- every client query the resolver answered, with its source.
  auth_log  -- every query the authoritative endpoint saw, with the action it
               took (answered / nxdomain / dropped / delayed).

All state transitions use ``BEGIN IMMEDIATE`` transactions: a transition and
its cache invalidation either both commit or neither does, and the new
generation makes any concurrent in-flight fetch unable to re-populate the
cache with an address from the previous state.
"""
from __future__ import annotations

import contextlib
import os
import secrets
import sqlite3
import time

# --------------------------------------------------------------------------
# Configuration (environment overridable; defaults are the spec values).
# --------------------------------------------------------------------------
FIXED_DOMAIN = os.environ.get("FIXED_DOMAIN", "service.example").strip().rstrip(".")
FQDN = FIXED_DOMAIN + "."

DB_PATH = os.environ.get("DB_PATH", "/data/app.db")

FRESH_TTL = float(os.environ.get("FRESH_TTL", "5"))        # successful answers are fresh for 5s
STALE_WINDOW = float(os.environ.get("STALE_WINDOW", "20"))  # stale A usable <=20s after expiry
UPSTREAM_TIMEOUT = float(os.environ.get("UPSTREAM_TIMEOUT", "2.0"))

TRIAL_MIN_SECONDS = float(os.environ.get("TRIAL_MIN_SECONDS", "10"))
TRIAL_MAX_SECONDS = float(os.environ.get("TRIAL_MAX_SECONDS", "60"))

AUTH_HOST = os.environ.get("AUTH_HOST", "127.0.0.1")
AUTH_PORT = int(os.environ.get("AUTH_PORT", "5354"))
RESOLVER_HOST = os.environ.get("RESOLVER_HOST", "127.0.0.1")
RESOLVER_PORT = int(os.environ.get("RESOLVER_PORT", "5353"))
WEB_PORT = int(os.environ.get("WEB_PORT", "8000"))

DEFAULT_IP = os.environ.get("DEFAULT_IP", "192.0.2.10")
DEFAULT_DELAY = float(os.environ.get("DEFAULT_DELAY", "3.0"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS control (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  mode TEXT NOT NULL,              -- a | nxdomain | delay | timeout
  ip TEXT NOT NULL,
  delay_seconds REAL NOT NULL,
  updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS trial (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  generation INTEGER NOT NULL DEFAULT 0,  -- bumped on every state transition
  trial_no TEXT,                          -- opaque id of the latest trial
  status TEXT NOT NULL DEFAULT 'none',    -- none|active|confirmed|revoked|expired|cancelled
  new_ip TEXT,
  original_ip TEXT,
  original_mode TEXT,
  original_delay REAL,
  deadline REAL,                          -- absolute epoch, never extended by a restart
  started_at REAL,
  ended_at REAL
);
CREATE TABLE IF NOT EXISTS cache (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  qname TEXT NOT NULL,
  rcode TEXT NOT NULL,             -- NOERROR | NXDOMAIN
  a_record TEXT,                   -- NULL once NXDOMAIN is confirmed (old A purged)
  fetched_at REAL NOT NULL,        -- last successful upstream answer (epoch)
  fresh_until REAL NOT NULL,       -- serve-fresh deadline (epoch)
  stale_until REAL,                -- A only: last moment a stale A may be served
  nx_confirmed_at REAL,
  generation INTEGER NOT NULL DEFAULT 0  -- state generation this row belongs to
);
CREATE TABLE IF NOT EXISTS query_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  qname TEXT, qtype TEXT, source TEXT, rcode TEXT, answers TEXT, detail TEXT
);
CREATE TABLE IF NOT EXISTS auth_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  qname TEXT, qtype TEXT, mode TEXT, action TEXT, detail TEXT
);
"""

_LOG_TABLES = ("query_log", "auth_log")


def _connect() -> sqlite3.Connection:
    # Autocommit mode: callers that need atomicity use `_tx()` explicitly.
    # WAL is persistent in the database file (set once in init_db), so it does
    # not need to be re-applied on every connection (which would contend).
    conn = sqlite3.connect(DB_PATH, timeout=15, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=15000")
    return conn


@contextlib.contextmanager
def _tx():
    """One atomic write transaction (BEGIN IMMEDIATE).

    Everything inside either commits together or rolls back together.  This is
    what ties a trial confirmation/revocation, the resulting control change and
    the cache invalidation to the same committed state.
    """
    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
        except BaseException:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        conn.execute("COMMIT")
    finally:
        conn.close()


def init_db() -> None:
    directory = os.path.dirname(DB_PATH)
    if directory:
        os.makedirs(directory, exist_ok=True)
    conn = _connect()
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(SCHEMA)
        # Migrate a cache table created by an older version (no generation).
        cache_cols = {r["name"] for r in conn.execute("PRAGMA table_info(cache)")}
        if "generation" not in cache_cols:
            conn.execute(
                "ALTER TABLE cache ADD COLUMN generation INTEGER NOT NULL DEFAULT 0"
            )
        conn.execute(
            "INSERT OR IGNORE INTO control(id, mode, ip, delay_seconds, updated_at)"
            " VALUES (1, 'a', ?, ?, ?)",
            (DEFAULT_IP, DEFAULT_DELAY, time.time()),
        )
        conn.execute(
            "INSERT OR IGNORE INTO trial(id, generation, status) VALUES (1, 0, 'none')"
        )
    finally:
        conn.close()


# --------------------------------------------------------------------------
# trial / control state (web writes, auth + resolver read)
# --------------------------------------------------------------------------
def _load_trial(c: sqlite3.Connection) -> dict:
    """Read the trial row inside a write transaction, creating it if needed."""
    row = c.execute("SELECT * FROM trial WHERE id = 1").fetchone()
    if row is None:  # defensive: init_db always inserts the row
        c.execute(
            "INSERT INTO trial(id, generation, status) VALUES (1, 0, 'none')"
        )
        row = c.execute("SELECT * FROM trial WHERE id = 1").fetchone()
    return dict(row)


_DEFAULT_TRIAL = {
    "id": 1,
    "generation": 0,
    "trial_no": None,
    "status": "none",
    "new_ip": None,
    "original_ip": None,
    "original_mode": None,
    "original_delay": None,
    "deadline": None,
    "started_at": None,
    "ended_at": None,
}


def _invalidate_cache(c: sqlite3.Connection) -> None:
    c.execute("DELETE FROM cache WHERE id = 1")


def _trial_due(trial: dict, now: float) -> bool:
    return (
        trial["status"] == "active"
        and trial["deadline"] is not None
        and now >= float(trial["deadline"])
    )


def _expire_locked(c: sqlite3.Connection, trial: dict, now: float) -> bool:
    """Expire the current active trial if its absolute deadline has passed.

    Must run inside a BEGIN IMMEDIATE transaction.  The conditional UPDATE
    (on status + trial_no) means a stale expiry can never overwrite a newer
    trial or a control change that was committed in the meantime.  On a real
    transition the generation is advanced and the resolver cache is dropped in
    the same transaction.
    """
    if not _trial_due(trial, now):
        return False
    cur = c.execute(
        "UPDATE trial SET status = 'expired', ended_at = ?,"
        "                 generation = generation + 1"
        " WHERE id = 1 AND status = 'active' AND trial_no IS ?",
        (float(trial["deadline"]), trial["trial_no"]),
    )
    if cur.rowcount:
        _invalidate_cache(c)
        return True
    return False


def expire_if_due(now: float | None = None) -> bool:
    """Run the expiry transition if one is due.  Returns True if it happened."""
    now = time.time() if now is None else now
    with _tx() as c:
        return _expire_locked(c, _load_trial(c), now)


def _read_state(now: float) -> tuple[dict, dict, dict | None]:
    """Consistent read of (trial, control, cache) in one read transaction.

    A WAL read transaction sees a stable snapshot, so the cache row belongs to
    exactly the same committed state (same generation) as the trial row.  No
    write lock is taken unless an expiry is actually due.
    """
    conn = _connect()
    try:
        conn.execute("BEGIN")
        row = conn.execute("SELECT * FROM trial WHERE id = 1").fetchone()
        trial = dict(row) if row else dict(_DEFAULT_TRIAL)
        ctl_row = conn.execute("SELECT * FROM control WHERE id = 1").fetchone()
        control = dict(ctl_row) if ctl_row else {"mode": "a",
                                                 "ip": DEFAULT_IP,
                                                 "delay_seconds": DEFAULT_DELAY}
        cache_row = conn.execute("SELECT * FROM cache WHERE id = 1").fetchone()
        cache = dict(cache_row) if cache_row else None
        conn.execute("COMMIT")
        return trial, control, cache
    finally:
        conn.close()


def snapshot(now: float | None = None) -> tuple[dict, dict, dict | None]:
    """Consistently read (trial, control, cache) and lazily expire a trial.

    Every reader (resolver, auth endpoint, web console) enforces the deadline,
    so expiry takes effect even after a restart or when no web page is open.
    The expiry itself is a single atomic transition that also drops the cache.
    """
    now = time.time() if now is None else now
    trial, control, cache = _read_state(now)
    if _trial_due(trial, now):
        # Another process may have committed the expiry between our read and
        # this call; either way re-read so we never return a trial that is
        # already past its absolute deadline.
        expire_if_due(now)
        trial, control, cache = _read_state(now)
    return trial, control, cache


def get_trial() -> dict:
    return snapshot()[0]


def get_control() -> dict | None:
    return snapshot()[1]


def effective_control(now: float | None = None) -> tuple[dict, dict]:
    """Return (effective control, trial) after applying an active trial.

    During an active trial the authoritative endpoint answers the trial IPv4
    immediately as a plain A record (no configured delay), regardless of the
    base mode.  Once the trial ends, the untouched base control applies again.
    """
    trial, control, _cache = snapshot(now)
    if trial["status"] == "active":
        effective = dict(control)
        effective.update(
            mode="a",
            ip=trial["new_ip"],
            delay_seconds=0.0,
            trial=True,
            trial_no=trial["trial_no"],
            deadline=trial["deadline"],
        )
        return effective, trial
    effective = dict(control)
    effective.update(trial=False, trial_no=None, deadline=None)
    return effective, trial


def start_trial(ip: str, deadline_seconds: float, now: float | None = None) -> dict:
    """Begin a trial cut-over and invalidate the resolver cache atomically.

    An existing active trial is superseded: its trial number becomes stale and
    can no longer be confirmed or revoked.
    """
    now = time.time() if now is None else now
    trial_no = "T-" + secrets.token_hex(4).upper()
    deadline = now + float(deadline_seconds)
    with _tx() as c:
        trial = _load_trial(c)
        if _expire_locked(c, trial, now):  # keep the history accurate
            trial = _load_trial(c)
        ctl_row = c.execute("SELECT * FROM control WHERE id = 1").fetchone()
        control = dict(ctl_row)
        c.execute(
            "UPDATE trial SET trial_no = ?, status = 'active', new_ip = ?,"
            "                 original_ip = ?, original_mode = ?,"
            "                 original_delay = ?, deadline = ?, started_at = ?,"
            "                 ended_at = NULL, generation = generation + 1"
            " WHERE id = 1",
            (
                trial_no,
                ip,
                control["ip"],
                control["mode"],
                control["delay_seconds"],
                deadline,
                now,
            ),
        )
        _invalidate_cache(c)
        trial = _load_trial(c)
    return trial


def confirm_trial(trial_no: str, now: float | None = None) -> tuple[bool, str, dict]:
    """Make the trial address permanent.

    The control update, the status change, the generation bump and the cache
    invalidation commit as one unit.  A trial number that is no longer active
    (expired, revoked, cancelled or superseded) is rejected.
    """
    now = time.time() if now is None else now
    with _tx() as c:
        trial = _load_trial(c)
        _expire_locked(c, trial, now)
        trial = _load_trial(c)
        if trial["status"] != "active":
            if trial["status"] == "expired" and trial["trial_no"] == trial_no:
                return False, "trial expired before confirmation", trial
            return (
                False,
                f"trial {trial_no!r} is not active (status={trial['status']})",
                trial,
            )
        if trial["trial_no"] != trial_no:
            return False, f"trial {trial_no!r} was superseded or is unknown", trial
        if now >= float(trial["deadline"]):
            return False, "trial expired before confirmation", trial
        c.execute(
            "UPDATE control SET mode = 'a', ip = ?, delay_seconds = ?,"
            "                    updated_at = ? WHERE id = 1",
            (
                trial["new_ip"],
                trial["original_delay"]
                if trial["original_delay"] is not None
                else 0.0,
                now,
            ),
        )
        c.execute(
            "UPDATE trial SET status = 'confirmed', ended_at = ?,"
            "                 generation = generation + 1 WHERE id = 1",
            (now,),
        )
        _invalidate_cache(c)
        trial = _load_trial(c)
    return True, "", trial


def revoke_trial(trial_no: str, now: float | None = None) -> tuple[bool, str, dict]:
    """Roll the trial back to the previous address and invalidate the cache."""
    now = time.time() if now is None else now
    with _tx() as c:
        trial = _load_trial(c)
        _expire_locked(c, trial, now)
        trial = _load_trial(c)
        if trial["status"] != "active":
            if trial["status"] == "expired" and trial["trial_no"] == trial_no:
                return False, "trial expired before revocation", trial
            return (
                False,
                f"trial {trial_no!r} is not active (status={trial['status']})",
                trial,
            )
        if trial["trial_no"] != trial_no:
            return False, f"trial {trial_no!r} was superseded or is unknown", trial
        if now >= float(trial["deadline"]):
            return False, "trial expired before revocation", trial
        c.execute(
            "UPDATE trial SET status = 'revoked', ended_at = ?,"
            "                 generation = generation + 1 WHERE id = 1",
            (now,),
        )
        _invalidate_cache(c)
        trial = _load_trial(c)
    return True, "", trial


def set_control(
    mode: str, ip: str, delay_seconds: float, now: float | None = None
) -> dict:
    """Change the base authoritative behaviour.

    A normal mode switch terminates any active trial (and therefore invalidates
    the cache) in the same transaction.  With no active trial the cache is left
    untouched, preserving the ordinary TTL/serve-stale rules.
    """
    now = time.time() if now is None else now
    with _tx() as c:
        trial = _load_trial(c)
        if _expire_locked(c, trial, now):
            trial = _load_trial(c)
        if trial["status"] == "active":
            cur = c.execute(
                "UPDATE trial SET status = 'cancelled', ended_at = ?,"
                "                 generation = generation + 1"
                " WHERE id = 1 AND status = 'active' AND trial_no IS ?",
                (now, trial["trial_no"]),
            )
            if cur.rowcount:
                _invalidate_cache(c)
        c.execute(
            "UPDATE control SET mode = ?, ip = ?, delay_seconds = ?,"
            "                    updated_at = ? WHERE id = 1",
            (mode, ip, float(delay_seconds), now),
        )
    return get_control()  # type: ignore[return-value]


# --------------------------------------------------------------------------
# cache table (resolver only)
# --------------------------------------------------------------------------
def get_cache() -> dict | None:
    with _connect() as c:
        row = c.execute("SELECT * FROM cache WHERE id = 1").fetchone()
        return dict(row) if row else None


def put_cache_a(ip: str, now: float, generation: int | None = None) -> bool:
    """Store a freshly fetched A record, but only for the state generation the
    fetch was started in.

    Returns False (and writes nothing) when the state has changed since the
    upstream query began -- a late reply from the previous trial/control state
    can never re-enter the cache.  Absolute epochs are persisted, so a restart
    does not extend either deadline.
    """
    with _tx() as c:
        row = c.execute("SELECT generation FROM trial WHERE id = 1").fetchone()
        current = int(row[0]) if row else 0
        if generation is not None and int(generation) != current:
            return False
        gen = current if generation is None else int(generation)
        c.execute(
            "INSERT INTO cache(id, qname, rcode, a_record, fetched_at, fresh_until,"
            "                 stale_until, nx_confirmed_at, generation)"
            " VALUES (1, ?, 'NOERROR', ?, ?, ?, ?, NULL, ?)"
            " ON CONFLICT(id) DO UPDATE SET"
            "   qname = excluded.qname, rcode = 'NOERROR',"
            "   a_record = excluded.a_record, fetched_at = excluded.fetched_at,"
            "   fresh_until = excluded.fresh_until, stale_until = excluded.stale_until,"
            "   nx_confirmed_at = NULL, generation = excluded.generation",
            (
                FQDN,
                ip,
                now,
                now + FRESH_TTL,
                now + FRESH_TTL + STALE_WINDOW,
                gen,
            ),
        )
        return True


def put_cache_nxdomain(now: float, generation: int | None = None) -> bool:
    """Confirm NXDOMAIN for the generation the fetch belongs to.

    Any old A record is purged immediately and durably: from this moment no
    answer may contain the old A again, and NXDOMAIN itself is only cached
    fresh (never used as stale backup).  A late reply from a previous state is
    rejected just like an A reply.
    """
    with _tx() as c:
        row = c.execute("SELECT generation FROM trial WHERE id = 1").fetchone()
        current = int(row[0]) if row else 0
        if generation is not None and int(generation) != current:
            return False
        gen = current if generation is None else int(generation)
        c.execute(
            "INSERT INTO cache(id, qname, rcode, a_record, fetched_at, fresh_until,"
            "                 stale_until, nx_confirmed_at, generation)"
            " VALUES (1, ?, 'NXDOMAIN', NULL, ?, ?, NULL, ?, ?)"
            " ON CONFLICT(id) DO UPDATE SET"
            "   qname = excluded.qname, rcode = 'NXDOMAIN', a_record = NULL,"
            "   fetched_at = excluded.fetched_at, fresh_until = excluded.fresh_until,"
            "   stale_until = NULL, nx_confirmed_at = excluded.nx_confirmed_at,"
            "   generation = excluded.generation",
            (FQDN, now, now + FRESH_TTL, now, gen),
        )
        return True


# --------------------------------------------------------------------------
# logs
# --------------------------------------------------------------------------
def _log(table: str, columns: tuple[str, ...], values: tuple) -> None:
    assert table in _LOG_TABLES
    cols = ", ".join(columns)
    marks = ", ".join("?" for _ in columns)
    with _tx() as c:
        c.execute(f"INSERT INTO {table}({cols}) VALUES ({marks})", values)
        c.execute(
            f"DELETE FROM {table} WHERE id NOT IN"
            f" (SELECT id FROM {table} ORDER BY id DESC LIMIT 300)"
        )


def log_query(qname, qtype, source, rcode, answers, detail) -> None:
    _log(
        "query_log",
        ("ts", "qname", "qtype", "source", "rcode", "answers", "detail"),
        (time.time(), qname, qtype, source, rcode, answers, detail),
    )


def log_auth(qname, qtype, mode, action, detail) -> None:
    _log(
        "auth_log",
        ("ts", "qname", "qtype", "mode", "action", "detail"),
        (time.time(), qname, qtype, mode, action, detail),
    )


def recent(table: str, limit: int = 15) -> list[dict]:
    assert table in _LOG_TABLES
    with _connect() as c:
        rows = c.execute(
            f"SELECT * FROM {table} ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
