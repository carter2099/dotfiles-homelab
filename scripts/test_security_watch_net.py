import io
import json
import sys
import unittest
import urllib.error
from email.message import Message
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

from security_watch import config, net  # noqa: E402


def headers(**values):
    msg = Message()
    for key, value in values.items():
        msg[key.replace("_", "-")] = value
    return msg


class FakeResponse:
    def __init__(self, body=b"", status=200, hdrs=None, url=None):
        self._body = io.BytesIO(body)
        self.status = status
        self.headers = hdrs if hdrs is not None else headers()
        self._url = url
        self.reads = []
        self.closed = False

    def read(self, n=-1):
        self.reads.append(n)
        return self._body.read(n)

    def geturl(self):
        return self._url

    def getcode(self):
        return self.status

    def close(self):
        self.closed = True


class Recorder:
    def __init__(self, result):
        self.result = result
        self.requests = []

    def __call__(self, request, timeout=None):
        self.requests.append((request, timeout))
        if isinstance(self.result, BaseException):
            raise self.result
        if self.result._url is None:
            self.result._url = request.full_url
        return self.result


def http_error(url, code):
    return urllib.error.HTTPError(url, code, "status", headers(ETag='"abc"'), io.BytesIO(b""))


class FetchTests(unittest.TestCase):
    def patch(self, result):
        recorder = Recorder(result)
        patcher = mock.patch("urllib.request.urlopen", recorder)
        patcher.start()
        self.addCleanup(patcher.stop)
        return recorder

    def test_rejects_hosts_outside_allowlist_without_network(self):
        recorder = self.patch(FakeResponse(b"{}"))
        for url in ("https://evil.example/x", "https://api.osv.dev.evil.example/v1",
                    "https://evil.example/?h=api.osv.dev", "https://user@api.osv.dev/v1",
                    "https://api.osv.dev@evil.example/"):
            with self.assertRaises(net.FetchError) as ctx:
                net.fetch(url)
            self.assertIsNone(ctx.exception.status)
        with self.assertRaises(net.FetchError) as ctx:
            net.fetch("https://evil.example/x")
        self.assertEqual(ctx.exception.reason, "host not allowed")
        self.assertEqual(ctx.exception.url, "https://evil.example/x")
        with self.assertRaises(net.FetchError):
            net.fetch("file:///etc/hostname")
        with self.assertRaises(net.FetchError):
            net.fetch("ftp://api.osv.dev/x")
        self.assertEqual(recorder.requests, [])

    def test_allowed_host_with_port_and_case(self):
        recorder = self.patch(FakeResponse(b"ok"))
        resp = net.fetch("http://127.0.0.1:8081/health")
        self.assertEqual(resp.body, b"ok")
        net.fetch("https://API.OSV.DEV/v1/vulns/x")
        self.assertEqual(len(recorder.requests), 2)

    def test_sends_user_agent_and_conditional_headers(self):
        recorder = self.patch(FakeResponse(b"[]", hdrs=headers(ETag='"v2"', Content_Type="application/json")))
        resp = net.fetch("https://nodejs.org/dist/index.json", etag='"v1"',
                         last_modified="Tue, 03 Nov 2026 10:00:00 GMT", headers={"User-Agent": "spoof"},
                         timeout=7)
        request, timeout = recorder.requests[0]
        self.assertEqual(timeout, 7)
        self.assertEqual(request.get_header("User-agent"), config.USER_AGENT)
        self.assertEqual(request.get_header("If-none-match"), '"v1"')
        self.assertEqual(request.get_header("If-modified-since"), "Tue, 03 Nov 2026 10:00:00 GMT")
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.headers["etag"], '"v2"')
        self.assertEqual(resp.headers["content-type"], "application/json")
        self.assertEqual(resp.json(), [])
        self.assertTrue(recorder.result.closed)

    def test_not_modified_returns_empty_response(self):
        self.patch(http_error("https://www.cisa.gov/feed.json", 304))
        resp = net.fetch("https://www.cisa.gov/feed.json", etag='"abc"')
        self.assertEqual(resp.status, 304)
        self.assertEqual(resp.body, b"")
        self.assertEqual(resp.headers["etag"], '"abc"')

    def test_not_found_raises_with_status(self):
        self.patch(http_error("https://api.osv.dev/v1/vulns/UBUNTU-CVE-2026-1", 404))
        with self.assertRaises(net.FetchError) as ctx:
            net.fetch("https://api.osv.dev/v1/vulns/UBUNTU-CVE-2026-1")
        self.assertEqual(ctx.exception.status, 404)

    def test_network_error_has_no_status(self):
        self.patch(urllib.error.URLError("connection refused"))
        with self.assertRaises(net.FetchError) as ctx:
            net.fetch("https://go.dev/dl/?mode=json")
        self.assertIsNone(ctx.exception.status)
        self.assertIn("connection refused", ctx.exception.reason)

    def test_oversize_body_is_rejected_and_read_is_bounded(self):
        recorder = self.patch(FakeResponse(b"x" * 50))
        with self.assertRaises(net.FetchError) as ctx:
            net.fetch("https://vuln.go.dev/index/vulns.json", max_bytes=10)
        self.assertEqual(recorder.result.reads, [11])
        self.assertIn("larger", ctx.exception.reason)
        self.patch(FakeResponse(b"x" * 10))
        self.assertEqual(net.fetch("https://vuln.go.dev/index/vulns.json", max_bytes=10).body, b"x" * 10)

    def test_redirect_to_disallowed_host_is_rejected(self):
        self.patch(FakeResponse(b"{}", url="https://evil.example/landing"))
        with self.assertRaises(net.FetchError) as ctx:
            net.fetch("https://api.github.com/repos/x/y/security-advisories")
        self.assertIn("redirected", ctx.exception.reason)


class JsonHelperTests(unittest.TestCase):
    def test_post_json_sends_json_body(self):
        calls = []

        def fake_fetch(url, **kw):
            calls.append((url, kw))
            return net.Response(status=200, headers={}, body=b'{"results": []}', url=url)

        out = net.post_json("https://api.osv.dev/v1/querybatch", {"queries": []}, fetch=fake_fetch)
        self.assertEqual(out, {"results": []})
        url, kw = calls[0]
        self.assertEqual(kw["method"], "POST")
        self.assertEqual(kw["headers"]["Content-Type"], "application/json")
        self.assertEqual(json.loads(kw["body"]), {"queries": []})
        self.assertEqual(kw["timeout"], 30)

    def test_get_json_invalid_body_raises_fetch_error(self):
        def fake_fetch(url, **kw):
            return net.Response(status=200, headers={}, body=b"<html>", url=url)

        with self.assertRaises(net.FetchError) as ctx:
            net.get_json("https://www.php.net/releases/active.php", fetch=fake_fetch)
        self.assertEqual(ctx.exception.status, 200)


if __name__ == "__main__":
    unittest.main()
