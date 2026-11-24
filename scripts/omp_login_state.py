"""Read-only age of omp's stored OAuth logins; never reads their tokens.

omp keeps each provider login in ~/.omp/agent/agent.db (table auth_credentials, JSON column
``data``). Anthropic's refresh token lives a fixed time from sign-in and is not extended by
refreshing: the login of 2026-10-22 13:22 UTC last refreshed at 11-21 07:02 and was refused
at 11-22 00:00 with invalid_grant "Refresh token expired" (about 30 days), and the login
before it died the same way on 10-22. Signing in again before then restarts the clock.

Only ``data.authorizedAt`` and ``data.email`` are selected (json_extract in SQL), so the
access and refresh tokens never enter this process. A schema surprise yields "unknown".
"""
import datetime as dt
import json
import sqlite3
import sys
from pathlib import Path

REFRESH_LIFETIME = dt.timedelta(days=30)


def login_state(provider="anthropic", home=None, now=None):
    """Return {provider, status, accounts, authorized_at, expires_at, days_left[, detail]}.

    status: ok (an enabled login exists), none (no enabled login), unknown (unreadable).
    expires_at is an estimate: the latest enabled sign-in plus REFRESH_LIFETIME, because
    omp moves on to another enabled account when one is refused.
    """
    db = Path(home or Path.home()) / ".omp/agent/agent.db"
    now = now or dt.datetime.now(dt.UTC)
    base = {"provider": provider}
    if not db.is_file():
        return {**base, "status": "unknown", "detail": f"{db} not found"}
    try:
        con = sqlite3.connect(f"{db.as_uri()}?mode=ro", uri=True, timeout=5)
        try:
            rows = con.execute(
                "SELECT json_extract(data, '$.authorizedAt'), json_extract(data, '$.email'),"
                " disabled_cause IS NOT NULL FROM auth_credentials"
                " WHERE provider = ? AND credential_type = 'oauth' ORDER BY id",
                (provider,),
            ).fetchall()
        finally:
            con.close()
    except sqlite3.Error as exc:
        return {**base, "status": "unknown", "detail": f"{type(exc).__name__}: {exc}"[:200]}

    accounts = []
    for authorized_ms, email, disabled in rows:
        authorized = None
        if isinstance(authorized_ms, (int, float)) and authorized_ms > 0:
            authorized = dt.datetime.fromtimestamp(authorized_ms / 1000, dt.UTC)
        accounts.append({"email": email if isinstance(email, str) else None,
                         "enabled": not disabled,
                         "authorized_at": authorized.isoformat() if authorized else None})
    enabled = [a for a in accounts if a["enabled"]]
    if not enabled:
        return {**base, "status": "none", "accounts": accounts}
    stamps = [dt.datetime.fromisoformat(a["authorized_at"]) for a in enabled if a["authorized_at"]]
    if len(stamps) != len(enabled):
        return {**base, "status": "unknown", "accounts": accounts,
                "detail": "enabled login without authorizedAt"}
    authorized = max(stamps)
    expires = authorized + REFRESH_LIFETIME
    return {**base, "status": "ok", "accounts": accounts,
            "authorized_at": authorized.isoformat(), "expires_at": expires.isoformat(),
            "days_left": round((expires - now).total_seconds() / 86400, 1)}


if __name__ == "__main__":
    print(json.dumps(login_state(*(sys.argv[1:2] or ["anthropic"])), indent=2))
