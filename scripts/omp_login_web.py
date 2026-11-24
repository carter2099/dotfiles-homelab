#!/usr/bin/env python3
"""Tiny mobile-first page to renew omp's Claude (anthropic) OAuth login.

Served on loopback only (default 127.0.0.1:30146) and published as
https://login.carter2099.com through cloudflared, whose ``originRequest.access`` validates the
Cloudflare Access JWT before a request reaches this process.

It shows the login state (omp_login_state plus an ``omp token anthropic`` probe whose stdout,
the secret access token, goes to /dev/null), drives ``omp login anthropic`` through its
paste-the-redirect-URL prompt, and reruns allowlisted user units that failed. omp itself stores
the new credential; this process never writes ~/.omp. Request bodies and tokens are never logged.
"""
import collections
import datetime as dt
import hmac
import ipaddress
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
import unicodedata
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

_HERE = str(Path(__file__).resolve().parent)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from omp_login_state import login_state  # noqa: E402

PROVIDER = "anthropic"
PUBLIC_ORIGIN = "https://login.carter2099.com"
DEFAULT_ADDR = "127.0.0.1"
DEFAULT_PORT = 30146
AUTHORIZE_PREFIX = "https://claude.ai/oauth/authorize?"
AUTHORIZE_URL = ("https", "claude.ai", "/oauth/authorize")
CALLBACK_URL = ("http", "localhost:54545", "/callback")
ALLOWED_UNITS = frozenset({"digests-daily.service", "hyperliquid-sdk.service"})

MAX_BODY = 4096
MAX_CODE = 2048
BARE_CODE_RE = re.compile(r"[A-Za-z0-9._~#-]{8,1024}")
URL_WAIT = 20
FINISH_WAIT = 90
FLOW_TTL = 600
PROBE_TTL = 30
PROBE_TIMEOUT = 60
SYSTEMCTL_TIMEOUT = 30
CLOCK_SLACK = dt.timedelta(seconds=60)
OUTPUT_LINES = 400
LINE_MAX = 4096
TAIL_LINES = 15

REDACTIONS = [re.compile(p) for p in (
    r"sk-ant-[A-Za-z0-9_-]+",
    r"code=[^&\s]+",
    r"state=[^&\s]+",
    r"[A-Za-z0-9_\-.]{40,}",
)]

SECURITY_HEADERS = (
    ("Content-Security-Policy",
     "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
     "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("Cache-Control", "no-store"),
)


def redact(text):
    for pattern in REDACTIONS:
        text = pattern.sub("<redacted>", text)
    return text


def _clean(text, limit=200):
    """One printable, redacted line for status details and logs."""
    text = "".join(c if c.isprintable() else " " for c in text)
    return redact(text.strip())[:limit]


def _last_line(text):
    lines = [line for line in text.splitlines() if line.strip()]
    return _clean(lines[-1]) if lines else ""


def is_authorize_url(value):
    try:
        parts = urlsplit(value)
    except ValueError:
        return False
    return (parts.scheme, parts.netloc, parts.path) == AUTHORIZE_URL and bool(parts.query)


def validate_code(raw):
    """Return (value, None) for a pasteable redirect URL or bare code, else (None, reason)."""
    if not isinstance(raw, str):
        return None, "Paste the address of the can't-connect page."
    value = raw.strip()
    if not value:
        return None, "Paste the address of the can't-connect page."
    if len(value) > MAX_CODE:
        return None, "That is too long to be the sign-in address."
    if any(unicodedata.category(c).startswith("C") or c.isspace() for c in value):
        return None, "The pasted text contains line breaks or control characters."
    if not value.isascii():
        return None, "The pasted text contains unexpected characters."
    if "://" in value:
        try:
            parts = urlsplit(value)
            query = parse_qs(parts.query, strict_parsing=False)
        except ValueError:
            return None, "That address could not be parsed."
        if (parts.scheme, parts.netloc, parts.path) != CALLBACK_URL:
            return None, "That is not the http://localhost:54545/callback address."
        if not (query.get("code", [""])[0] and query.get("state", [""])[0]):
            return None, "The address is missing its code or state."
        return value, None
    if BARE_CODE_RE.fullmatch(value):
        return value, None
    return None, "That does not look like the sign-in address or code."


def _query_state(url):
    """The ``state`` query value of a URL, or None."""
    try:
        return parse_qs(urlsplit(url).query).get("state", [None])[0]
    except ValueError:
        return None


def pasted_state(value):
    """State carried by a validated paste: URL param, text after the last '#', or None."""
    if "://" in value:
        return _query_state(value) or ""
    if "#" in value:
        return value.rsplit("#", 1)[1]
    return None


@dataclass(frozen=True)
class Config:
    home: Path
    omp_bin: str
    systemctl_bin: str
    addr: str = DEFAULT_ADDR
    port: int = DEFAULT_PORT

    @classmethod
    def from_env(cls, env=os.environ):
        home = Path(env.get("HOME") or Path.home())
        addr = env.get("OMP_LOGIN_WEB_ADDR") or DEFAULT_ADDR
        port = int(env.get("OMP_LOGIN_WEB_PORT") or DEFAULT_PORT)
        if addr != "localhost" and not ipaddress.ip_address(addr).is_loopback:
            raise SystemExit(f"refusing non-loopback OMP_LOGIN_WEB_ADDR {addr!r}")
        if not 0 < port < 65536:
            raise SystemExit(f"invalid OMP_LOGIN_WEB_PORT {port}")
        return cls(home=home,
                   omp_bin=env.get("OMP_BIN") or str(home / ".bun/bin/omp"),
                   systemctl_bin=env.get("SYSTEMCTL_BIN") or "/usr/bin/systemctl",
                   addr=addr, port=port)


class Flow:
    """One running ``omp login anthropic`` process and its captured output."""

    def __init__(self, proc, started_at):
        self.proc = proc
        self.started_at = started_at
        self.started_mono = time.monotonic()
        self.state = "waiting"
        self.url = None
        self.oauth_state = None
        self.message = None
        self.timer = None
        self._lines = collections.deque(maxlen=OUTPUT_LINES)
        self._lines_lock = threading.Lock()
        self.ready = threading.Event()
        self.reader = threading.Thread(target=self._read, name="omp-login-reader", daemon=True)

    def _read(self):
        try:
            for raw in iter(lambda: self.proc.stdout.readline(LINE_MAX), b""):
                line = raw.decode("utf-8", "replace").rstrip("\r\n")
                with self._lines_lock:
                    self._lines.append(line)
                candidate = line.strip()
                if (self.url is None and candidate.startswith(AUTHORIZE_PREFIX)
                        and is_authorize_url(candidate)):
                    self.oauth_state = _query_state(candidate)
                    self.url = candidate
                    self.ready.set()
        except (OSError, ValueError):
            pass
        finally:
            self.ready.set()

    def tail(self):
        with self._lines_lock:
            lines = list(self._lines)
        while lines and not lines[-1].strip():
            lines.pop()
        return "\n".join(redact(line) for line in lines[-TAIL_LINES:])

    def failure_line(self):
        """omp's last "Login failed: ..." message, redacted, or None."""
        with self._lines_lock:
            lines = list(self._lines)
        for line in reversed(lines):
            idx = line.find("Login failed:")
            if idx >= 0:
                return _clean(line[idx:], 200)
        return None

    def kill(self):
        if self.timer:
            self.timer.cancel()
        proc = self.proc
        if proc.poll() is None:
            for sig in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(proc.pid, sig)
                except (ProcessLookupError, PermissionError):
                    break
                try:
                    proc.wait(3)
                    break
                except subprocess.TimeoutExpired:
                    continue
        try:
            proc.stdin.close()
        except (OSError, ValueError):
            pass


class App:
    def __init__(self, config):
        self.cfg = config
        self.env = {**os.environ, "HOME": str(config.home)}
        self.flow = None
        self._lock = threading.Lock()        # guards self.flow and flow.state
        self._op_lock = threading.Lock()     # serialises start/finish
        self._probe_lock = threading.Lock()
        self._rerun_lock = threading.Lock()
        self._probe = None
        self._probe_at = 0.0

    # -- login probe -----------------------------------------------------------------
    def probe(self, fresh=False):
        with self._probe_lock:
            if (not fresh and self._probe is not None
                    and time.monotonic() - self._probe_at < PROBE_TTL):
                return dict(self._probe)
            self._probe = self._run_probe()
            self._probe_at = time.monotonic()
            return dict(self._probe)

    def invalidate_probe(self):
        with self._probe_lock:
            self._probe = None

    def _run_probe(self):
        # stdout of `omp token` IS the secret access token: it must go to /dev/null.
        try:
            proc = subprocess.run([self.cfg.omp_bin, "token", PROVIDER],
                                  stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.PIPE, timeout=PROBE_TIMEOUT,
                                  env=self.env, cwd=str(self.cfg.home), check=False)
        except subprocess.TimeoutExpired:
            return {"probe": "unknown", "probe_detail": "omp token timed out"}
        except OSError as exc:
            return {"probe": "unknown", "probe_detail": _clean(f"cannot run omp: {exc}")}
        err = proc.stderr.decode("utf-8", "replace")
        if proc.returncode == 0:
            return {"probe": "ok"}
        if proc.returncode == 1 and "No active credential found" in err:
            return {"probe": "dead", "probe_detail": _last_line(err) or "No active credential"}
        detail = _last_line(err) or f"omp token exited {proc.returncode}"
        return {"probe": "unknown", "probe_detail": detail}

    # -- systemd jobs ----------------------------------------------------------------
    def _systemctl(self, *args):
        return subprocess.run([self.cfg.systemctl_bin, "--user", *args],
                              stdin=subprocess.DEVNULL, capture_output=True,
                              timeout=SYSTEMCTL_TIMEOUT, env=self.env, check=False)

    def job_state(self, unit):
        job = {"unit": unit, "active_state": "unknown", "sub_state": "", "result": ""}
        try:
            proc = self._systemctl("show", unit, "-p", "ActiveState,SubState,Result")
        except (OSError, subprocess.TimeoutExpired):
            return job
        if proc.returncode != 0:
            return job
        props = {}
        for line in proc.stdout.decode("utf-8", "replace").splitlines():
            key, sep, value = line.partition("=")
            if sep:
                props[key.strip()] = value.strip()
        job["active_state"] = props.get("ActiveState") or "unknown"
        job["sub_state"] = props.get("SubState", "")
        job["result"] = props.get("Result", "")
        return job

    def jobs(self, probe_ok):
        out = []
        for unit in sorted(ALLOWED_UNITS):
            job = self.job_state(unit)
            job["rerunnable"] = job["active_state"] == "failed" and probe_ok
            out.append(job)
        return out

    def rerun(self, unit):
        if not isinstance(unit, str) or unit not in ALLOWED_UNITS:
            return 400, {"ok": False, "message": "That unit cannot be rerun here."}
        with self._rerun_lock:
            if self.job_state(unit)["active_state"] != "failed":
                return 409, {"ok": False, "message": f"{unit} is not in the failed state."}
            if self.probe()["probe"] != "ok":
                return 409, {"ok": False, "message": "Claude login is not working; sign in first."}
            for args in (("reset-failed", unit), ("start", "--no-block", unit)):
                try:
                    proc = self._systemctl(*args)
                except (OSError, subprocess.TimeoutExpired) as exc:
                    return 502, {"ok": False,
                                 "message": _clean(f"systemctl {args[0]} failed: {exc}")}
                if proc.returncode != 0:
                    detail = _last_line(proc.stderr.decode("utf-8", "replace"))
                    return 502, {"ok": False, "message": _clean(
                        f"systemctl {args[0]} failed ({proc.returncode}): {detail}")}
        return 200, {"ok": True, "message": f"Started {unit}."}

    # -- login flow ------------------------------------------------------------------
    def _refresh_flow(self):
        """Expire or fail a waiting flow; caller holds self._lock."""
        flow = self.flow
        if flow is None or flow.state != "waiting":
            return
        if time.monotonic() - flow.started_mono >= FLOW_TTL:
            flow.kill()
            flow.state = "expired"
            flow.message = "The sign-in link expired after 10 minutes. Start again."
        elif flow.proc.poll() is not None:
            flow.state = "failed"
            flow.message = f"omp login exited early ({flow.proc.returncode}). Start again."

    def _expire(self, flow):
        with self._lock:
            if self.flow is flow and flow.state == "waiting":
                flow.kill()
                flow.state = "expired"
                flow.message = "The sign-in link expired after 10 minutes. Start again."

    def flow_status(self):
        with self._lock:
            self._refresh_flow()
            flow = self.flow
            if flow is None:
                return {"state": "idle"}
            out = {"state": flow.state, "started_at": flow.started_at.isoformat()}
            if flow.state == "waiting" and flow.url:
                out["url"] = flow.url
            if flow.message:
                out["message"] = flow.message
            return out

    def start_login(self):
        if not self._op_lock.acquire(timeout=1):
            return 409, {"ok": False, "message": "Another sign-in step is in progress."}
        try:
            with self._lock:
                self._refresh_flow()
                old = self.flow
                if old is not None and old.state == "waiting":
                    return 200, {"ok": True, "url": old.url, "reused": True}
                self.flow = None
            if old is not None:
                old.kill()
            try:
                proc = subprocess.Popen([self.cfg.omp_bin, "login", PROVIDER],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, start_new_session=True,
                                        env=self.env, cwd=str(self.cfg.home), close_fds=True)
            except OSError as exc:
                return 500, {"ok": False, "message": _clean(f"Could not run omp login: {exc}")}
            flow = Flow(proc, dt.datetime.now(dt.UTC))
            flow.reader.start()
            flow.ready.wait(URL_WAIT)
            if flow.url is None:
                flow.kill()
                flow.reader.join(2)
                flow.state = "failed"
                flow.message = "omp did not print a Claude sign-in URL."
                with self._lock:
                    self.flow = flow
                return 502, {"ok": False, "message": flow.message, "output_tail": flow.tail()}
            flow.timer = threading.Timer(FLOW_TTL, self._expire, args=(flow,))
            flow.timer.daemon = True
            flow.timer.start()
            with self._lock:
                self.flow = flow
            return 200, {"ok": True, "url": flow.url}
        finally:
            self._op_lock.release()

    def finish_login(self, raw):
        value, reason = validate_code(raw)
        if reason:
            return 400, {"ok": False, "message": reason}
        if not self._op_lock.acquire(timeout=1):
            return 409, {"ok": False, "message": "Another sign-in step is in progress."}
        try:
            with self._lock:
                self._refresh_flow()
                flow = self.flow
                if flow is None or flow.state != "waiting":
                    return 409, {"ok": False, "message": "No sign-in is waiting. Start again."}
                got = pasted_state(value)
                if (got is not None and flow.oauth_state is not None
                        and not hmac.compare_digest(got.encode(), flow.oauth_state.encode())):
                    return 400, {"ok": False, "message":
                                 "That address is from an older sign-in attempt. "
                                 "Use the link above (or press Start again)."}
                flow.state = "finishing"
                if flow.timer:
                    flow.timer.cancel()
            try:
                flow.proc.stdin.write((value + "\n").encode("ascii"))
                flow.proc.stdin.flush()
                flow.proc.stdin.close()
            except (OSError, ValueError):
                pass
            try:
                code = flow.proc.wait(FINISH_WAIT)
            except subprocess.TimeoutExpired:
                flow.kill()
                code = None
            flow.reader.join(2)
            self.invalidate_probe()
            probe = self.probe(fresh=True)
            state = login_state(PROVIDER, home=self.cfg.home)
            if code is None:
                ok, message = False, "omp login did not finish within 90 seconds."
            elif code != 0:
                ok, message = False, flow.failure_line() or f"omp login failed (exit {code})."
            elif probe["probe"] != "ok":
                ok, message = False, f"omp login exited, but the login probe is {probe['probe']}."
            elif not self._fresh_login(state, flow.started_at):
                ok, message = False, "omp login exited, but no new sign-in was recorded."
            else:
                ok, message = True, "Signed in. Claude login renewed."
            with self._lock:
                if self.flow is flow:
                    flow.state = "succeeded" if ok else "failed"
                    flow.message = message
                else:
                    ok, message = False, "Sign-in was cancelled."
            return 200, {"ok": ok, "message": message, "output_tail": flow.tail()}
        finally:
            self._op_lock.release()

    @staticmethod
    def _fresh_login(state, started_at):
        if state.get("status") != "ok" or not state.get("authorized_at"):
            return False
        try:
            authorized = dt.datetime.fromisoformat(state["authorized_at"])
        except ValueError:
            return False
        return authorized > started_at - CLOCK_SLACK

    def cancel_login(self):
        with self._lock:
            flow, self.flow = self.flow, None
        if flow is not None:
            flow.kill()
        return 200, {"ok": True, "message": "Sign-in cancelled."}

    def status(self):
        login = login_state(PROVIDER, home=self.cfg.home)
        login.update(self.probe())
        return {"login": login, "flow": self.flow_status(),
                "jobs": self.jobs(login["probe"] == "ok")}

    def close(self):
        self.cancel_login()


class Handler(BaseHTTPRequestHandler):
    server_version = "omp-login-web"
    sys_version = ""
    POST_ROUTES = {
        "/api/login/start": "login.start",
        "/api/login/finish": "login.finish",
        "/api/login/cancel": "login.cancel",
        "/api/rerun": "rerun",
    }

    def log_message(self, format, *args):  # noqa: A002 - silence per-request access logs
        pass

    def end_headers(self):
        for name, value in SECURITY_HEADERS:
            self.send_header(name, value)
        super().end_headers()

    def _send(self, status, body, ctype):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status, payload):
        self._send(status, json.dumps(payload).encode(), "application/json; charset=utf-8")

    def do_GET(self):
        path = urlsplit(self.path).path
        static = STATIC.get(path)
        if static:
            ctype, body = static
            self._send(200, body, ctype)
        elif path == "/api/status":
            self._json(200, self.server.app.status())
        else:
            self._json(404, {"ok": False, "message": "Not found"})

    def do_POST(self):
        path = urlsplit(self.path).path
        action = self.POST_ROUTES.get(path, "unknown")
        unit = None
        try:
            status, payload, unit = self._post(path)
        except Exception as exc:  # never echo request data; type only
            status, payload = 500, {"ok": False, "message": "Internal error."}
            print(f"omp-login-web: {action} raised {type(exc).__name__}", file=sys.stderr,
                  flush=True)
        self._json(status, payload)
        user = _clean(self.headers.get("Cf-Access-Authenticated-User-Email", ""), 200)
        outcome = _clean(str(payload.get("message") or ("ok" if payload.get("ok") else "")), 160)
        extra = f" unit={unit}" if unit else ""
        print(f"omp-login-web: action={action}{extra} status={status} outcome={outcome!r}"
              f" user={user or '-'}", file=sys.stderr, flush=True)

    def _same_origin(self):
        if self.headers.get("Sec-Fetch-Site") == "same-origin":
            return True
        port = self.server.server_address[1]
        return self.headers.get("Origin") in {
            PUBLIC_ORIGIN, f"http://127.0.0.1:{port}", f"http://localhost:{port}"}

    def _post(self, path):
        """Return (status, payload, allowlisted unit or None)."""
        if path not in self.POST_ROUTES:
            return 404, {"ok": False, "message": "Not found"}, None
        if not self._same_origin():
            self.close_connection = True
            return 403, {"ok": False, "message": "Cross-origin request refused."}, None
        ctype = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        if ctype != "application/json":
            self.close_connection = True
            return 415, {"ok": False, "message": "Content-Type must be application/json."}, None
        if self.headers.get("Transfer-Encoding"):
            self.close_connection = True
            return 400, {"ok": False, "message": "Chunked bodies are not accepted."}, None
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self.close_connection = True
            return 411, {"ok": False, "message": "Content-Length required."}, None
        if length < 0 or length > MAX_BODY:
            self.close_connection = True
            return 413, {"ok": False, "message": "Request body too large."}, None
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, UnicodeDecodeError):
            return 400, {"ok": False, "message": "Body must be JSON."}, None
        if not isinstance(body, dict):
            return 400, {"ok": False, "message": "Body must be a JSON object."}, None
        app = self.server.app
        if path == "/api/login/start":
            return (*app.start_login(), None)
        if path == "/api/login/finish":
            return (*app.finish_login(body.get("code")), None)
        if path == "/api/login/cancel":
            return (*app.cancel_login(), None)
        unit = body.get("unit")
        return (*app.rerun(unit), unit if unit in ALLOWED_UNITS else None)


def make_server(app, addr, port):
    server = ThreadingHTTPServer((addr, port), Handler)
    server.daemon_threads = True
    server.app = app
    return server


INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>Claude login</title>
<link rel="stylesheet" href="/app.css">
<script src="/app.js" defer></script>
</head>
<body>
<main>
<section id="status" class="card status">
<h1 id="st-title">Claude login: &hellip;</h1>
<p id="st-account" hidden></p>
<p id="st-signed" hidden></p>
<p id="st-expires" hidden></p>
<p id="st-detail" class="muted" hidden></p>
</section>

<section class="card">
<button id="btn-start" type="button" class="primary">Sign in to Claude</button>
<ol id="steps" class="steps" hidden>
<li><a id="auth-link" class="big-link" target="_blank" rel="noopener noreferrer">Open Claude sign-in</a>
<div class="row"><button id="btn-copy" type="button">Copy link</button></div>
<p class="muted">If the Claude app opens instead of the browser, copy the link and paste it into the browser.</p></li>
<li>Approve. Your browser then shows a can't-connect page for localhost &mdash; copy that page's full address.</li>
<li>
<label for="code">Paste the address here</label>
<textarea id="code" rows="4" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" placeholder="http://localhost:54545/callback?code=..."></textarea>
<div class="row">
<button id="btn-paste" type="button">Paste from clipboard</button>
<button id="btn-finish" type="button" class="primary">Finish sign-in</button>
<button id="btn-cancel" type="button">Cancel</button>
</div>
</li>
</ol>
<div id="result" class="banner" hidden>
<p id="result-msg"></p>
<pre id="result-tail" hidden></pre>
</div>
</section>

<section class="card">
<h2>Scheduled jobs</h2>
<ul id="jobs" class="jobs"></ul>
<p id="jobs-msg" class="muted" hidden></p>
</section>
</main>
</body>
</html>
"""

APP_JS = r""""use strict";
(function () {
  const $ = (id) => document.getElementById(id);
  const POLL_ACTIVE = 5000;
  const POLL_IDLE = 60000;
  let timer = null;
  let flowActive = false;
  let inflight = null;

  async function api(path, body) {
    const init = { cache: "no-store", credentials: "same-origin" };
    if (body !== undefined) {
      init.method = "POST";
      init.headers = { "Content-Type": "application/json" };
      init.body = JSON.stringify(body);
    }
    let resp;
    try {
      resp = await fetch(path, init);
    } catch (e) {
      return { ok: false, _status: 0,
        message: "Request failed. Reload the page (the Access session may have expired)." };
    }
    let data;
    try {
      data = await resp.json();
    } catch (e) {
      data = { ok: false, message: "Unexpected response (HTTP " + resp.status + "). Reload the page." };
    }
    data._status = resp.status;
    return data;
  }

  function fmtDate(iso, withTime) {
    if (!iso) return "";
    const d = new Date(iso);
    if (isNaN(d.getTime())) return iso;
    const opts = { year: "numeric", month: "short", day: "numeric" };
    if (withTime) { opts.hour = "2-digit"; opts.minute = "2-digit"; }
    return d.toLocaleString(undefined, opts);
  }

  function setText(id, text) {
    const el = $(id);
    el.textContent = text || "";
    el.hidden = !text;
  }

  function showResult(kind, message, tail) {
    const box = $("result");
    box.className = "banner " + kind;
    $("result-msg").textContent = message || "";
    const pre = $("result-tail");
    pre.textContent = tail || "";
    pre.hidden = !tail;
    box.hidden = false;
  }

  function renderLogin(login) {
    const probe = login.probe;
    let label = "Unknown";
    let cls = "warn";
    if (probe === "ok") { label = "Working"; cls = "ok"; }
    else if (probe === "dead") { label = "Expired"; cls = "err"; }
    if (probe === "ok" && typeof login.days_left === "number" && login.days_left <= 7) cls = "warn";
    $("status").className = "card status " + cls;
    $("st-title").textContent = "Claude login: " + label;
    const emails = (login.accounts || []).filter((a) => a.enabled && a.email).map((a) => a.email);
    setText("st-account", emails.length ? emails.join(", ") : "");
    setText("st-signed", login.authorized_at ? "Signed in " + fmtDate(login.authorized_at, true) : "");
    let exp = "";
    if (login.expires_at && typeof login.days_left === "number") {
      const n = Math.max(0, Math.floor(login.days_left));
      exp = "Expires about " + fmtDate(login.expires_at) + " (" + n + (n === 1 ? " day" : " days") + " left)";
    }
    setText("st-expires", exp);
    setText("st-detail", login.probe_detail || login.detail || "");
  }

  function renderFlow(flow) {
    const st = flow.state;
    flowActive = st === "waiting" || st === "finishing";
    $("steps").hidden = !flowActive;
    $("btn-start").hidden = flowActive;
    if (st === "waiting" && flow.url) $("auth-link").href = flow.url;
    const finishing = st === "finishing";
    $("btn-finish").disabled = finishing;
    $("btn-paste").disabled = finishing;
    $("code").disabled = finishing;
    if ((st === "expired" || st === "failed") && flow.message && $("result").hidden) {
      showResult("err", flow.message, "");
    }
  }

  function renderJobs(jobs) {
    const ul = $("jobs");
    ul.replaceChildren();
    for (const j of jobs) {
      const li = document.createElement("li");
      li.className = "job" + (j.active_state === "failed" ? " failed" : "");
      const name = document.createElement("span");
      name.className = "unit";
      name.textContent = j.unit;
      const state = document.createElement("span");
      state.className = "state";
      let text = j.active_state;
      if (j.sub_state) text += " (" + j.sub_state + ")";
      if (j.result && j.result !== "success") text += ", " + j.result;
      state.textContent = text;
      li.append(name, state);
      if (j.rerunnable) {
        const b = document.createElement("button");
        b.type = "button";
        b.textContent = "Rerun";
        b.addEventListener("click", () => rerun(j.unit, b));
        li.append(b);
      }
      ul.append(li);
    }
  }

  function schedule() {
    clearTimeout(timer);
    timer = setTimeout(refresh, flowActive ? POLL_ACTIVE : POLL_IDLE);
  }

  async function doRefresh() {
    const s = await api("/api/status");
    if (s._status === 200 && s.login) {
      renderLogin(s.login);
      renderFlow(s.flow || { state: "idle" });
      renderJobs(s.jobs || []);
    } else {
      $("st-title").textContent = "Claude login: Unknown";
      setText("st-detail", s.message || "Status unavailable.");
    }
  }

  async function refresh() {
    clearTimeout(timer);
    if (!inflight) inflight = doRefresh().finally(() => { inflight = null; });
    await inflight;
    schedule();
  }

  async function rerun(unit, button) {
    button.disabled = true;
    const r = await api("/api/rerun", { unit: unit });
    setText("jobs-msg", r.message || (r.ok ? "Started." : "Rerun failed."));
    refresh();
  }

  $("btn-start").addEventListener("click", async () => {
    const b = $("btn-start");
    b.disabled = true;
    b.textContent = "Starting\u2026";
    $("result").hidden = true;
    const r = await api("/api/login/start", {});
    b.disabled = false;
    b.textContent = "Sign in to Claude";
    if (r.ok && r.url) {
      $("auth-link").href = r.url;
      flowActive = true;
      $("steps").hidden = false;
      b.hidden = true;
    } else {
      showResult("err", r.message || "Could not start sign-in.", r.output_tail);
    }
    refresh();
  });

  $("btn-finish").addEventListener("click", async () => {
    const value = $("code").value.trim();
    if (!value) { showResult("err", "Paste the address first.", ""); return; }
    const b = $("btn-finish");
    b.disabled = true;
    showResult("info", "Finishing sign-in\u2026", "");
    const r = await api("/api/login/finish", { code: value });
    b.disabled = false;
    showResult(r.ok ? "ok" : "err", r.message || (r.ok ? "Signed in." : "Sign-in failed."), r.output_tail);
    if (r.ok) $("code").value = "";
    refresh();
  });

  $("btn-cancel").addEventListener("click", async () => {
    await api("/api/login/cancel", {});
    $("code").value = "";
    $("result").hidden = true;
    refresh();
  });

  const copy = $("btn-copy");
  let copyTimer = null;
  if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
    copy.addEventListener("click", async () => {
      const url = $("auth-link").getAttribute("href");
      if (!url) return;
      try {
        await navigator.clipboard.writeText(url);
        copy.textContent = "Copied";
        clearTimeout(copyTimer);
        copyTimer = setTimeout(() => { copy.textContent = "Copy link"; }, 2000);
      } catch (e) {
        showResult("err", "Copying was refused; press and hold the link to copy it instead.", "");
      }
    });
  } else {
    copy.hidden = true;
  }

  const paste = $("btn-paste");
  if (navigator.clipboard && typeof navigator.clipboard.readText === "function") {
    paste.addEventListener("click", async () => {
      try {
        $("code").value = (await navigator.clipboard.readText()).trim();
      } catch (e) {
        showResult("err", "Clipboard access was refused; paste into the box instead.", "");
      }
    });
  } else {
    paste.hidden = true;
  }

  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") refresh();
  });
  refresh();
})();
"""

APP_CSS = """:root {
  color-scheme: light dark;
  --bg: #f4f5f7; --fg: #16181d; --muted: #5d6470; --card: #ffffff; --border: #d9dce1;
  --accent: #c15f3c; --accent-fg: #ffffff;
  --ok: #1d7a3e; --ok-bg: #e7f6ec; --warn: #8a5a00; --warn-bg: #fff4d6;
  --err: #b3261e; --err-bg: #fde8e7; --info-bg: #e8eefc;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #111317; --fg: #e8eaee; --muted: #9aa1ad; --card: #1b1e24; --border: #2e333c;
    --accent: #e0805c; --accent-fg: #15171b;
    --ok: #6fd08f; --ok-bg: #16301f; --warn: #f0c35a; --warn-bg: #352a10;
    --err: #ff8a80; --err-bg: #3a1716; --info-bg: #1c2540;
  }
}
[hidden] { display: none !important; }
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body {
  margin: 0; background: var(--bg); color: var(--fg);
  font: 17px/1.45 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
}
main { max-width: 640px; margin: 0 auto; padding: 12px; }
.card {
  background: var(--card); border: 1px solid var(--border); border-radius: 12px;
  padding: 16px; margin: 0 0 12px;
}
h1, h2 { margin: 0 0 8px; line-height: 1.25; }
h1 { font-size: 1.35rem; }
h2 { font-size: 1.15rem; }
p { margin: 4px 0; }
.muted { color: var(--muted); font-size: 0.9rem; overflow-wrap: anywhere; }
.status { border-left: 6px solid var(--border); }
.status.ok { border-left-color: var(--ok); }
.status.ok h1 { color: var(--ok); }
.status.warn { border-left-color: var(--warn); background: var(--warn-bg); }
.status.warn h1 { color: var(--warn); }
.status.err { border-left-color: var(--err); background: var(--err-bg); }
.status.err h1 { color: var(--err); }
button {
  font: inherit; min-height: 44px; padding: 8px 14px; border-radius: 10px;
  border: 1px solid var(--border); background: var(--card); color: var(--fg); cursor: pointer;
}
button.primary { background: var(--accent); border-color: var(--accent); color: var(--accent-fg); font-weight: 600; }
button:disabled { opacity: 0.55; cursor: default; }
#btn-start { width: 100%; }
.steps { margin: 0; padding-left: 1.4em; }
.steps li { margin: 0 0 14px; }
.big-link {
  display: block; text-align: center; padding: 14px; border-radius: 10px; font-weight: 600;
  font-size: 1.1rem; background: var(--accent); color: var(--accent-fg); text-decoration: none;
}
label { display: block; margin: 6px 0 4px; font-weight: 600; }
textarea {
  width: 100%; font: 15px/1.35 ui-monospace, SFMono-Regular, Menlo, monospace; padding: 8px;
  border-radius: 8px; border: 1px solid var(--border); background: var(--bg); color: var(--fg);
}
.row { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 8px; }
.row button { flex: 1 1 auto; }
.banner { border-radius: 10px; padding: 10px 12px; margin-top: 8px; }
.banner.ok { background: var(--ok-bg); color: var(--ok); }
.banner.err { background: var(--err-bg); color: var(--err); }
.banner.info { background: var(--info-bg); }
pre {
  margin: 8px 0 0; padding: 8px; overflow-x: auto; white-space: pre-wrap; overflow-wrap: anywhere;
  font: 12px/1.35 ui-monospace, SFMono-Regular, Menlo, monospace; color: var(--fg);
  background: var(--bg); border-radius: 6px;
}
.jobs { list-style: none; margin: 0; padding: 0; }
.job {
  display: flex; flex-wrap: wrap; align-items: center; gap: 4px 10px; padding: 8px 0;
  border-top: 1px solid var(--border);
}
.job:first-child { border-top: 0; }
.job .unit { font-weight: 600; flex: 1 1 100%; overflow-wrap: anywhere; }
.job .state { color: var(--muted); flex: 1 1 auto; }
.job.failed .state { color: var(--err); }
"""

STATIC = {
    "/": ("text/html; charset=utf-8", INDEX_HTML.encode()),
    "/app.js": ("text/javascript; charset=utf-8", APP_JS.encode()),
    "/app.css": ("text/css; charset=utf-8", APP_CSS.encode()),
}


def main():
    cfg = Config.from_env()
    app = App(cfg)
    server = make_server(app, cfg.addr, cfg.port)

    def stop(_signum, _frame):
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop)
    print(f"omp-login-web: listening on http://{cfg.addr}:{cfg.port}", file=sys.stderr, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        app.close()
        server.server_close()


if __name__ == "__main__":
    main()
