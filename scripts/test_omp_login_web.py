"""Tests for omp_login_web with fake omp/systemctl binaries and a fabricated agent.db."""
import json
import os
import sqlite3
import sys
import tempfile
import textwrap
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import omp_login_web as web  # noqa: E402

# Built at runtime so the dotfiles secret scan does not mistake these fakes for credentials.
SECRET = "-".join(("sk", "ant", "oat01", "FAKESECRET"))
FAKE_REFRESH = "-".join(("sk", "ant", "ort01", "FAKESECRETREFRESH"))
FAKE_STATE = "STATE" + "abcdefghijklmnopqrstuvwxyz" + "0123456789"
VALID_REDIRECT = "http://localhost:54545/callback?code=abcdefgh12345678&state=" + FAKE_STATE
STALE_REDIRECT = "http://localhost:54545/callback?code=abcdefgh12345678&state=st4te5678abcdef"

FAKE_OMP = textwrap.dedent('''\
    #!{python}
    import json, os, re, sqlite3, sys, time
    from pathlib import Path
    from urllib.parse import parse_qs, urlsplit
    home = Path(os.environ["HOME"])
    SECRET = "{secret}"
    STATE = "{state}"
    cmd = sys.argv[1:]
    if cmd[:1] == ["token"]:
        print(SECRET + "TOKENOUTPUTxyz")
        mode = (home / "token_mode").read_text().strip() if (home / "token_mode").exists() else "ok"
        if mode == "ok":
            sys.exit(0)
        print("Error: No active credential found for anthropic", file=sys.stderr)
        sys.exit(1)
    if cmd[:1] == ["login"]:
        print("")
        print("Open this URL in your browser:")
        print("https://claude.ai/oauth/authorize?client_id=9d1c250a-e61b-44d9-88ed-5944d1962f5e"
              "&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A54545%2Fcallback"
              "&scope=org%3Acreate_api_key+user%3Aprofile&code_challenge="
              "CHALLENGEabcdefghijklmnopqrstuvwxyz0123456789&code_challenge_method=S256"
              "&state=" + STATE + "&code=true")
        print("Local shortcut (this machine only): http://localhost:54545/launch")
        print("Complete login in your browser. If the browser cannot reach this machine, "
              "paste the final redirect URL or authorization code when prompted.")
        print("")
        print("Waiting for browser authentication...")
        print("Paste the authorization code (or full redirect URL): ", end="", flush=True)
        line = sys.stdin.readline()
        (home / "login_stdin.txt").write_text(line)
        value = line.strip()
        login_mode = home / "login_mode"
        if login_mode.exists() and login_mode.read_text().strip() == "fail":
            print("Exchanging authorization code for tokens...", flush=True)
            print("Login failed: something", flush=True)
            sys.exit(1)
        got = None
        if value.startswith("http://localhost:54545/callback?"):
            got = parse_qs(urlsplit(value).query).get("state", [""])[0]
        elif re.fullmatch(r"[A-Za-z0-9._~#-]{{8,1024}}", value):
            got = value.rsplit("#", 1)[1] if "#" in value else STATE
        if got == STATE:
            con = sqlite3.connect(home / ".omp/agent/agent.db")
            con.execute("UPDATE auth_credentials SET data = json_set(data, '$.authorizedAt', ?)"
                        " WHERE provider = 'anthropic'", (int(time.time() * 1000),))
            con.commit()
            con.close()
            print("Logged in to anthropic (debug " + SECRET + "LOGINOUTPUT)", flush=True)
            sys.exit(0)
        print("Login failed: Login cancelled", flush=True)
        sys.exit(1)
    sys.exit(2)
    ''')

FAKE_SYSTEMCTL = textwrap.dedent('''\
    #!{python}
    import json, os, sys
    from pathlib import Path
    home = Path(os.environ["HOME"])
    args = sys.argv[1:]
    with open(home / "systemctl_calls.jsonl", "a") as fh:
        fh.write(json.dumps(args) + "\\n")
    if len(args) >= 3 and args[0] == "--user" and args[1] == "show":
        unit = args[2]
        state_file = home / ("state_" + unit)
        state = state_file.read_text().strip() if state_file.exists() else "inactive"
        result = "exit-code" if state == "failed" else "success"
        sub = "failed" if state == "failed" else "dead"
        print("ActiveState=" + state)
        print("SubState=" + sub)
        print("Result=" + result)
    sys.exit(0)
    ''')


def make_db(home):
    db_dir = home / ".omp/agent"
    db_dir.mkdir(parents=True)
    con = sqlite3.connect(db_dir / "agent.db")
    con.execute("CREATE TABLE auth_credentials (id INTEGER PRIMARY KEY, provider TEXT NOT NULL,"
                " credential_type TEXT NOT NULL, data TEXT NOT NULL, disabled_cause TEXT,"
                " created_at INTEGER, updated_at INTEGER)")
    now_ms = int(time.time() * 1000)
    data = {"access": SECRET + "ACCESS", "refresh": FAKE_REFRESH,
            "authorizedAt": now_ms - 25 * 86400 * 1000, "email": "carter@example.com"}
    con.execute("INSERT INTO auth_credentials (provider, credential_type, data, disabled_cause,"
                " created_at, updated_at) VALUES ('anthropic', 'oauth', ?, NULL, ?, ?)",
                (json.dumps(data), now_ms, now_ms))
    con.commit()
    con.close()


def write_exe(path, body):
    path.write_text(body.format(python=sys.executable, secret=SECRET, state=FAKE_STATE))
    path.chmod(0o755)


class OmpLoginWebTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.home = Path(self._tmp.name)
        make_db(self.home)
        bin_dir = self.home / "bin"
        bin_dir.mkdir()
        write_exe(bin_dir / "omp", FAKE_OMP)
        write_exe(bin_dir / "systemctl", FAKE_SYSTEMCTL)
        cfg = web.Config(home=self.home, omp_bin=str(bin_dir / "omp"),
                         systemctl_bin=str(bin_dir / "systemctl"), addr="127.0.0.1", port=0)
        self.app = web.App(cfg)
        self.server = web.make_server(self.app, "127.0.0.1", 0)
        self.port = self.server.server_address[1]
        self.origin = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.app.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)
        self._tmp.cleanup()

    # -- helpers ---------------------------------------------------------------------
    def request(self, method, path, body=None, headers=None):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", data=data,
                                     method=method, headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                return resp.status, resp.headers, resp.read().decode()
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, exc.headers, exc.read().decode()

    def post(self, path, body, headers=None):
        hdrs = {"Content-Type": "application/json", "Origin": self.origin}
        if headers is not None:
            hdrs = headers
        status, _, text = self.request("POST", path, body, hdrs)
        self.assertNotIn("FAKESECRET", text)
        return status, json.loads(text)

    def status(self):
        status, _, text = self.request("GET", "/api/status")
        self.assertEqual(status, 200)
        self.assertNotIn("FAKESECRET", text)
        return json.loads(text)

    def systemctl_calls(self):
        path = self.home / "systemctl_calls.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines() if line]

    # -- tests -----------------------------------------------------------------------
    def test_page_and_security_headers(self):
        status, headers, text = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("Sign in to Claude", text)
        self.assertIn("script-src 'self'", headers["Content-Security-Policy"])
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["Referrer-Policy"], "no-referrer")
        self.assertEqual(headers["Cache-Control"], "no-store")
        for path in ("/app.js", "/app.css"):
            self.assertEqual(self.request("GET", path)[0], 200)
        status, headers, _ = self.request("GET", "/nope")
        self.assertEqual(status, 404)
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_status_never_contains_secret(self):
        data = self.status()
        self.assertEqual(data["login"]["status"], "ok")
        self.assertEqual(data["login"]["probe"], "ok")
        self.assertEqual(data["flow"], {"state": "idle"})
        self.assertEqual({j["unit"] for j in data["jobs"]}, set(web.ALLOWED_UNITS))
        (self.home / "token_mode").write_text("dead")
        self.app.invalidate_probe()
        data = self.status()
        self.assertEqual(data["login"]["probe"], "dead")

    def test_start_returns_claude_url_and_is_single_flight(self):
        status, data = self.post("/api/login/start", {})
        self.assertEqual(status, 200)
        self.assertTrue(data["url"].startswith("https://claude.ai/oauth/authorize?"))
        status, again = self.post("/api/login/start", {})
        self.assertEqual(status, 200)
        self.assertEqual(again["url"], data["url"])
        flow = self.status()["flow"]
        self.assertEqual(flow["state"], "waiting")
        self.assertEqual(flow["url"], data["url"])

    def test_finish_with_redirect_url_succeeds(self):
        self.assertEqual(self.post("/api/login/start", {})[0], 200)
        status, data = self.post("/api/login/finish", {"code": "  " + VALID_REDIRECT + "  "})
        self.assertEqual(status, 200)
        self.assertTrue(data["ok"], data)
        self.assertIn("<redacted>", data["output_tail"])
        self.assertLessEqual(len(data["output_tail"].splitlines()), web.TAIL_LINES)
        self.assertEqual((self.home / "login_stdin.txt").read_text(), VALID_REDIRECT + "\n")
        self.assertEqual(self.status()["flow"]["state"], "succeeded")

    def test_finish_fails_when_probe_dead(self):
        self.assertEqual(self.post("/api/login/start", {})[0], 200)
        (self.home / "token_mode").write_text("dead")
        status, data = self.post("/api/login/finish", {"code": VALID_REDIRECT})
        self.assertEqual(status, 200)
        self.assertFalse(data["ok"])

    def test_finish_rejects_bad_input_without_writing_stdin(self):
        self.assertEqual(self.post("/api/login/start", {})[0], 200)
        bad = [
            VALID_REDIRECT + "\nextra",
            "a" * 3000,
            "https://evil.example/callback?code=abcdefgh1234&state=abcdefgh1234",
            "http://localhost:54545/callback?code=abcdefgh1234",
            "",
            "short",
        ]
        for value in bad:
            with self.subTest(value=value[:40]):
                status, data = self.post("/api/login/finish", {"code": value})
                self.assertEqual(status, 400)
                self.assertFalse(data["ok"])
        self.assertFalse((self.home / "login_stdin.txt").exists())
        self.assertEqual(self.status()["flow"]["state"], "waiting")

    def test_finish_rejects_stale_state_then_accepts_matching(self):
        self.assertEqual(self.post("/api/login/start", {})[0], 200)
        status, data = self.post("/api/login/finish", {"code": STALE_REDIRECT})
        self.assertEqual(status, 400)
        self.assertFalse(data["ok"])
        self.assertIn("older sign-in attempt", data["message"])
        self.assertFalse((self.home / "login_stdin.txt").exists())
        self.assertEqual(self.status()["flow"]["state"], "waiting")
        status, data = self.post("/api/login/finish", {"code": VALID_REDIRECT})
        self.assertEqual(status, 200)
        self.assertTrue(data["ok"], data)
        self.assertEqual((self.home / "login_stdin.txt").read_text(), VALID_REDIRECT + "\n")

    def test_finish_rejects_bare_code_with_wrong_state(self):
        self.assertEqual(self.post("/api/login/start", {})[0], 200)
        status, data = self.post("/api/login/finish", {"code": "abcdefgh12345678#wrongstate"})
        self.assertEqual(status, 400)
        self.assertFalse(data["ok"])
        self.assertFalse((self.home / "login_stdin.txt").exists())
        self.assertEqual(self.status()["flow"]["state"], "waiting")

    def test_finish_reports_omp_login_failed_line(self):
        self.assertEqual(self.post("/api/login/start", {})[0], 200)
        (self.home / "login_mode").write_text("fail")
        status, data = self.post("/api/login/finish", {"code": VALID_REDIRECT})
        self.assertEqual(status, 200)
        self.assertFalse(data["ok"])
        self.assertEqual(data["message"], "Login failed: something")
        self.assertEqual(self.status()["flow"]["state"], "failed")

    def test_finish_without_flow_conflicts(self):
        status, data = self.post("/api/login/finish", {"code": VALID_REDIRECT})
        self.assertEqual(status, 409)

    def test_cancel_returns_to_idle(self):
        self.assertEqual(self.post("/api/login/start", {})[0], 200)
        self.assertEqual(self.post("/api/login/cancel", {})[0], 200)
        self.assertEqual(self.status()["flow"], {"state": "idle"})

    def test_cross_origin_and_missing_origin_forbidden(self):
        cases = [
            {"Content-Type": "application/json", "Origin": "https://evil.example"},
            {"Content-Type": "application/json"},
            {"Content-Type": "application/json", "Sec-Fetch-Site": "cross-site"},
        ]
        for headers in cases:
            with self.subTest(headers=headers):
                status, _ = self.post("/api/login/start", {}, headers=headers)
                self.assertEqual(status, 403)
        self.assertEqual(self.status()["flow"], {"state": "idle"})
        status, _ = self.post("/api/login/cancel", {},
                              headers={"Content-Type": "text/plain", "Origin": self.origin})
        self.assertEqual(status, 415)
        status, _ = self.post("/api/login/cancel", {}, headers={
            "Content-Type": "application/json", "Sec-Fetch-Site": "same-origin"})
        self.assertEqual(status, 200)

    def test_rerun_refuses_unlisted_unit(self):
        (self.home / "state_ssh.service").write_text("failed")
        status, _ = self.post("/api/rerun", {"unit": "ssh.service"})
        self.assertEqual(status, 400)
        self.assertFalse(any("ssh.service" in call for call in self.systemctl_calls()))

    def test_rerun_refuses_non_failed_unit(self):
        status, _ = self.post("/api/rerun", {"unit": "hyperliquid-sdk.service"})
        self.assertEqual(status, 409)
        verbs = [call[1] for call in self.systemctl_calls()]
        self.assertNotIn("reset-failed", verbs)
        self.assertNotIn("start", verbs)

    def test_rerun_failed_unit_resets_then_starts(self):
        unit = "digests-daily.service"
        (self.home / f"state_{unit}").write_text("failed")
        jobs = {j["unit"]: j for j in self.status()["jobs"]}
        self.assertTrue(jobs[unit]["rerunnable"])
        self.assertFalse(jobs["hyperliquid-sdk.service"]["rerunnable"])
        status, data = self.post("/api/rerun", {"unit": unit})
        self.assertEqual(status, 200, data)
        actions = [call for call in self.systemctl_calls() if call[1] != "show"]
        self.assertEqual(actions, [["--user", "reset-failed", unit],
                                   ["--user", "start", "--no-block", unit]])

    def test_rerun_refused_when_login_dead(self):
        unit = "digests-daily.service"
        (self.home / f"state_{unit}").write_text("failed")
        (self.home / "token_mode").write_text("dead")
        status, _ = self.post("/api/rerun", {"unit": unit})
        self.assertEqual(status, 409)

    def test_redact(self):
        text = web.redact("token sk-ant-oat01-abc_DEF-1 code=xyz&state=abc " + "A" * 45)
        self.assertNotIn("sk-ant-oat01", text)
        self.assertNotIn("xyz", text)
        self.assertNotIn("A" * 45, text)


if __name__ == "__main__":
    unittest.main()
