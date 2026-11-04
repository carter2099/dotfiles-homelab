import json
import sys
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from security_watch import config, feeds, model  # noqa: E402

NOW = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)


class FakeResponse:
    def __init__(self, url, body):
        self.status = 200
        self.headers = {}
        self.url = url
        self.body = body if isinstance(body, bytes) else (
            body.encode() if isinstance(body, str) else json.dumps(body).encode())

    def json(self):
        return json.loads(self.body)

    def text(self):
        return self.body.decode()


class FakeFetchError(Exception):
    pass


class FakeFetch:
    def __init__(self, routes):
        self.routes = dict(routes)
        self.calls = []

    def __call__(self, url, **kwargs):
        self.calls.append(url)
        if url not in self.routes:
            raise FakeFetchError(f"unmapped {url}")
        value = self.routes[url]
        if isinstance(value, Exception):
            raise value
        return FakeResponse(url, value)


class FakeStore:
    def __init__(self):
        self.sources = {}
        self.signals = {}
        self.kv = {}

    def source_state(self, name):
        return dict(self.sources.get(name) or {
            "name": name, "cursor": None, "etag": None, "last_modified": None, "last_attempt": None,
            "last_success": None, "last_error": None, "consecutive_failures": 0, "state": {}})

    def record_source(self, name, *, ok, now, cursor=None, etag=None, last_modified=None, error=None,
                      state=None):
        cur = self.source_state(name)
        cur["last_attempt"] = model.iso(now)
        if ok:
            cur["last_success"] = model.iso(now)
            cur["consecutive_failures"] = 0
            cur["last_error"] = None
        else:
            cur["consecutive_failures"] += 1
            cur["last_error"] = error
        if cursor is not None:
            cur["cursor"] = cursor
        if state is not None:
            cur["state"] = state
        self.sources[name] = cur

    def upsert_signal(self, sig, now):
        old = self.signals.get((sig.source, sig.key))
        self.signals[(sig.source, sig.key)] = sig
        if old is None:
            return "new"
        return "same" if old.version == sig.version else "updated"

    def all_signals(self, source):
        return [s for (src, _), s in self.signals.items() if src == source]

    def get_kv(self, key, default=None):
        return json.loads(self.kv[key]) if key in self.kv else default

    def set_kv(self, key, value):
        self.kv[key] = json.dumps(value)


def make_policy(**overrides):
    policy = config.load_policy()
    return replace(policy, **overrides) if overrides else policy


ZERO_WIRE_RSS = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/">
<channel><title>Zero Wire</title>
<item><title>node2shell</title>
<link>https://radar.cloudflare.com/security/zero-wire/node2shell</link>
<guid isPermaLink="false">node2shell@2026-10-25</guid>
<pubDate>Sun, 25 Oct 2026 00:00:00 GMT</pubDate>
<description>Prioritize &lt;b&gt;patching&lt;/b&gt; Node &amp; Brotli.</description>
<category>Needs attention</category><category>CVE-2026-111497</category><category>Node.js</category>
<content:encoded><![CDATA[<p>See <a href="https://www.cve.org/CVERecord?id=CVE-2026-111497">record</a>
and <a href="https://nodejs.org/en/blog/vulnerability/october-2026">Node</a>; related CVE-2026-111498.
<a href="https://radar.cloudflare.com/security/zero-wire/node2shell">self</a>
<a href="https://dash.cloudflare.com/x">dash</a> <a href="https://blog.cloudflare.com/y">blog</a></p>]]></content:encoded>
</item>
<item><title>WordPress SQLi</title>
<link>https://radar.cloudflare.com/security/zero-wire/wordpress-sqli</link>
<guid isPermaLink="false">wordpress-sqli@2026-07-20</guid>
<pubDate>Mon, 20 Jul 2026 00:00:00 GMT</pubDate>
<description>Reference only.</description>
<category>Reference</category><category>CVE-2026-60137</category>
<content:encoded><![CDATA[<p>Nothing else.</p>]]></content:encoded>
</item>
</channel></rss>"""


class ZeroWireTests(unittest.TestCase):
    def test_zero_wire_extracts_cves_status_links_and_summary(self):
        fetch = FakeFetch({feeds.ZERO_WIRE_URL: ZERO_WIRE_RSS})
        signals, state = feeds.poll_zero_wire({}, fetch, make_policy(), NOW)
        by_key = {s.key: s for s in signals}
        node = by_key["node2shell"]
        self.assertEqual(node.version, "node2shell@2026-10-25")
        self.assertEqual(node.cves, ("CVE-2026-111497", "CVE-2026-111498"))
        self.assertEqual(node.urgency_hint, "needs-attention")
        self.assertEqual(node.tier, model.TIER_CURATED)
        self.assertEqual(node.links, ("https://www.cve.org/CVERecord?id=CVE-2026-111497",
                                      "https://nodejs.org/en/blog/vulnerability/october-2026"))
        self.assertEqual(node.summary, "Prioritize patching Node & Brotli.")
        self.assertEqual(node.published, "2026-10-25T00:00:00+00:00")
        self.assertEqual(by_key["wordpress-sqli"].urgency_hint, "")
        index = state["_kv"]["zero_wire_index"]
        self.assertEqual(index["CVE-2026-60137"][0]["status"], "Reference")
        self.assertEqual(index["CVE-2026-111497"][0]["slug"], "node2shell")

    def test_zero_wire_index_is_maintained_even_when_items_are_not_new(self):
        store = FakeStore()
        fetch = FakeFetch({feeds.ZERO_WIRE_URL: ZERO_WIRE_RSS})
        first = feeds.poll_due(store, make_policy(), now=NOW, fetch=fetch, only={"zero_wire"})
        self.assertEqual(len(first.new), 2)
        store.kv.clear()
        second = feeds.poll_due(store, make_policy(), now=NOW + timedelta(hours=2), fetch=fetch,
                                only={"zero_wire"})
        self.assertEqual(second.new, [])
        self.assertEqual(second.updated, [])
        self.assertIn("CVE-2026-111497", feeds.zero_wire_index(store))


def kev_payload(version, entries):
    return {"catalogVersion": version, "vulnerabilities": [
        {"cveID": cve, "dateAdded": added, "vendorProject": "Acme", "product": "Widget",
         "vulnerabilityName": "Acme Widget RCE", "shortDescription": "Bad <b>bug</b>.",
         "requiredAction": "Patch.", "dueDate": "2026-11-20", "knownRansomwareCampaignUse": "Known"}
        for cve, added in entries]}


class KevTests(unittest.TestCase):
    def test_first_run_emits_last_30_days_and_stores_full_set(self):
        store = FakeStore()
        fetch = FakeFetch({feeds.KEV_URL: kev_payload("2026.11.02", [
            ("CVE-2026-1001", "2026-10-20"), ("CVE-2025-2002", "2026-09-01")])})
        result = feeds.poll_due(store, make_policy(), now=NOW, fetch=fetch, only={"cisa_kev"})
        self.assertEqual([s.key for s in result.new], ["CVE-2026-1001"])
        self.assertTrue(result.new[0].kev)
        self.assertIn("Known ransomware use: Known.", result.new[0].summary)
        self.assertEqual(feeds.kev_cves(store), {"CVE-2026-1001", "CVE-2025-2002"})

    def test_unchanged_catalog_emits_nothing_and_new_catalog_emits_additions(self):
        store = FakeStore()
        entries = [("CVE-2026-1001", "2026-10-20")]
        fetch = FakeFetch({feeds.KEV_URL: kev_payload("2026.11.02", entries)})
        feeds.poll_due(store, make_policy(), now=NOW, fetch=fetch, only={"cisa_kev"})
        again = feeds.poll_due(store, make_policy(), now=NOW, fetch=fetch, only={"cisa_kev"}, force=True)
        self.assertEqual(again.new, [])
        fetch.routes[feeds.KEV_URL] = kev_payload("2026.11.03", entries + [("CVE-2026-1003", "2026-11-03")])
        later = feeds.poll_due(store, make_policy(), now=NOW, fetch=fetch, only={"cisa_kev"}, force=True)
        self.assertEqual([s.key for s in later.new], ["CVE-2026-1003"])
        self.assertIn("CVE-2026-1003", feeds.kev_cves(store))


GO = feeds.GO_VULNDB


class GoVulndbTests(unittest.TestCase):
    def routes(self, db_modified, entries):
        return {
            f"{GO}/index/db.json": {"modified": db_modified},
            f"{GO}/index/vulns.json": entries,
            f"{GO}/ID/GO-2026-0002.json": {"id": "GO-2026-0002", "summary": "Panic in <code>net/http</code>"},
        }

    def test_first_run_emits_recent_ids_with_aliases_and_skips_detail_errors(self):
        store = FakeStore()
        entries = [
            {"id": "GO-2020-0001", "modified": "2024-05-20T16:03:47Z", "aliases": ["CVE-2020-36567"]},
            {"id": "GO-2026-0002", "modified": "2026-10-30T10:00:00Z", "aliases": ["CVE-2026-5001", "GHSA-aaaa-bbbb-cccc"]},
            {"id": "GO-2026-0003", "modified": "2026-10-31T10:00:00Z", "aliases": []},
        ]
        fetch = FakeFetch(self.routes("2026-11-02T22:01:43Z", entries))
        result = feeds.poll_due(store, make_policy(), now=NOW, fetch=fetch, only={"go_vulndb"})
        self.assertEqual(result.health, {"go_vulndb": "ok"})
        by_key = {s.key: s for s in result.new}
        self.assertEqual(set(by_key), {"GO-2026-0002", "GO-2026-0003"})
        self.assertEqual(by_key["GO-2026-0002"].cves, ("CVE-2026-5001",))
        self.assertEqual(by_key["GO-2026-0002"].aliases, ("CVE-2026-5001", "GHSA-aaaa-bbbb-cccc"))
        self.assertEqual(by_key["GO-2026-0002"].summary, "Panic in net/http")
        self.assertEqual(by_key["GO-2026-0003"].summary, "")
        self.assertEqual(len(store.get_kv("go_vulndb_modified")), 3)

    def test_unchanged_db_skips_index_and_changed_ids_are_emitted(self):
        store = FakeStore()
        entries = [{"id": "GO-2020-0001", "modified": "2024-05-20T16:03:47Z", "aliases": []}]
        fetch = FakeFetch(self.routes("2026-11-02T00:00:00Z", entries))
        feeds.poll_due(store, make_policy(), now=NOW, fetch=fetch, only={"go_vulndb"})
        fetch.calls.clear()
        same = feeds.poll_due(store, make_policy(), now=NOW, fetch=fetch, only={"go_vulndb"}, force=True)
        self.assertEqual(fetch.calls, [f"{GO}/index/db.json"])
        self.assertEqual(same.new, [])
        changed = [{"id": "GO-2020-0001", "modified": "2026-11-03T00:00:00Z", "aliases": []}]
        fetch.routes.update(self.routes("2026-11-03T00:00:00Z", changed))
        later = feeds.poll_due(store, make_policy(), now=NOW, fetch=fetch, only={"go_vulndb"}, force=True)
        self.assertEqual([s.key for s in later.new], ["GO-2020-0001"])


class GoReleasesTests(unittest.TestCase):
    def test_stable_versions_stored_newest_first_and_new_versions_signalled(self):
        store = FakeStore()
        fetch = FakeFetch({feeds.GO_DL_URL: [
            {"version": "go1.26.10", "stable": True}, {"version": "go1.27.3", "stable": True},
            {"version": "go1.28rc1", "stable": False}]})
        first = feeds.poll_due(store, make_policy(), now=NOW, fetch=fetch, only={"go_releases"})
        self.assertEqual(feeds.go_stable(store), ["1.27.3", "1.26.10"])
        self.assertEqual({s.version for s in first.new}, {"1.27.3", "1.26.10"})
        fetch.routes[feeds.GO_DL_URL] = [{"version": "go1.27.4", "stable": True},
                                         {"version": "go1.26.10", "stable": True}]
        later = feeds.poll_due(store, make_policy(), now=NOW, fetch=fetch, only={"go_releases"}, force=True)
        self.assertEqual([s.version for s in later.new], ["1.27.4"])
        self.assertEqual(feeds.go_stable(store), ["1.27.4", "1.26.10"])


def gh_url(repo):
    return feeds.GITHUB_ADVISORIES_URL.format(repo=repo)


class GithubAdvisoryTests(unittest.TestCase):
    def test_advisories_parse_packages_and_one_failing_repo_keeps_others(self):
        store = FakeStore()
        policy = make_policy(upstream_repos=("oven-sh/bun", "moby/moby"))
        fetch = FakeFetch({
            gh_url("oven-sh/bun"): [
                {"ghsa_id": "GHSA-cf8x-9m69-3gg3", "cve_id": None, "summary": "QPACK amplification",
                 "severity": "high", "published_at": "2026-10-24T00:13:31Z", "updated_at": "2026-10-24T00:13:31Z",
                 "html_url": "https://github.com/oven-sh/bun/security/advisories/GHSA-cf8x-9m69-3gg3",
                 "vulnerabilities": [{"package": {"ecosystem": "npm", "name": "bun"},
                                      "vulnerable_version_range": ">= 1.3.14, < 1.4.4",
                                      "patched_versions": "1.4.4, 1.3.20"}]},
                {"ghsa_id": "GHSA-old0-old0-old0", "cve_id": "CVE-2025-1", "summary": "old",
                 "updated_at": "2026-01-01T00:00:00Z", "vulnerabilities": []},
            ],
            gh_url("moby/moby"): FakeFetchError("HTTP 500"),
        })
        result = feeds.poll_due(store, policy, now=NOW, fetch=fetch, only={"github_advisories"})
        self.assertTrue(result.health["github_advisories"].startswith("failed: "))
        self.assertIn("moby/moby", result.health["github_advisories"])
        [sig] = result.new
        self.assertEqual(sig.key, "oven-sh/bun#GHSA-cf8x-9m69-3gg3")
        self.assertEqual(sig.version, "2026-10-24T00:13:31Z")
        self.assertEqual(sig.cves, ())
        self.assertEqual(sig.packages, (model.AdvisoryPackage("npm", "bun", ">= 1.3.14, < 1.4.4", ("1.4.4", "1.3.20")),))
        self.assertEqual([s.key for s in feeds.repo_advisories(store, "oven-sh/bun")], [sig.key])
        self.assertEqual(feeds.repo_advisories(store, "oven-sh/bu"), [])
        self.assertEqual(store.sources["github_advisories"]["consecutive_failures"], 1)


class UsnTests(unittest.TestCase):
    def test_usn_uses_noble_source_packages_and_cve_ids(self):
        payload = {"notices": [
            {"id": "USN-8994-1", "title": "libvips vulnerabilities", "summary": "Fixed libvips.",
             "description": "It was discovered\nthat libvips crashed.", "published": "2026-11-03T17:39:43.471205",
             "cves_ids": ["CVE-2026-33327"], "cves": [{"id": "CVE-2026-33327"}],
             "release_packages": {
                 "noble": [{"name": "vips", "version": "8.15.1-1ubuntu0.1", "is_source": True},
                           {"name": "libvips42t64", "version": "8.15.1-1ubuntu0.1", "is_source": False}],
                 "jammy": [{"name": "vips", "version": "8.12.1-1ubuntu0.1", "is_source": True}]}},
            {"id": "USN-7000-1", "title": "old", "published": "2026-08-01T00:00:00", "cves_ids": [],
             "release_packages": {}},
        ]}
        fetch = FakeFetch({feeds.USN_URL: payload})
        signals, state = feeds.poll_ubuntu_usn({}, fetch, make_policy(), NOW)
        [sig] = signals
        self.assertEqual(sig.key, "USN-8994-1")
        self.assertEqual(sig.cves, ("CVE-2026-33327",))
        self.assertEqual(sig.packages, (model.AdvisoryPackage("Ubuntu:24.04:LTS", "vips", fixed=("8.15.1-1ubuntu0.1",)),))
        self.assertEqual(sig.summary, "Fixed libvips. It was discovered that libvips crashed.")
        self.assertEqual(state["floor"], model.iso(NOW - timedelta(days=30)))


DSA_RDF = """<?xml version="1.0" encoding="UTF-8" ?>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns="http://purl.org/rss/1.0/"
 xmlns:dc="http://purl.org/dc/elements/1.1/">
<channel rdf:about="https://www.debian.org/security/dsa.rdf"><title>Debian Security</title></channel>
<item rdf:about="https://lists.debian.org/debian-security-announce/2026/msg00525.html">
<title>DSA-6606-1 squid - security update</title>
<link>https://lists.debian.org/debian-security-announce/2026/msg00525.html</link>
<dc:date>2026-11-03</dc:date></item>
<item rdf:about="https://lists.debian.org/debian-security-announce/2026/msg00001.html">
<title>DSA-6000-1 old - security update</title>
<link>https://lists.debian.org/debian-security-announce/2026/msg00001.html</link>
<dc:date>2026-01-03</dc:date></item>
</rdf:RDF>"""


class DsaTests(unittest.TestCase):
    def test_dsa_key_parsed_from_title_and_old_items_skipped(self):
        signals, _ = feeds.poll_debian_dsa({}, FakeFetch({feeds.DSA_URL: DSA_RDF}), make_policy(), NOW)
        [sig] = signals
        self.assertEqual(sig.key, "DSA-6606-1")
        self.assertEqual(sig.tier, model.TIER_LEAD)
        self.assertEqual(sig.url, "https://lists.debian.org/debian-security-announce/2026/msg00525.html")
        self.assertEqual(sig.packages, ())


PHP_RSS = """<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0"><channel><title>php.announce</title>
<item><link>https://news-web.php.net/php.announce/510</link>
<title>Upcoming Critical PHP Security Release</title>
<description>&lt;a href=&quot;mailto:x%40php.net&quot;&gt;Release&amp;nbsp;Managers&lt;/a&gt;</description>
<pubDate>Sat, 31 Oct 2026 10:00:00 +0000</pubDate></item>
<item><link>https://news-web.php.net/php.announce/511</link>
<title>PHP 8.4.28 Released (security release)</title>
<pubDate>Mon, 02 Nov 2026 10:00:00 +0000</pubDate></item>
</channel></rss>"""


class PhpTests(unittest.TestCase):
    def test_php_announce_flags_pre_announcements_only(self):
        signals, _ = feeds.poll_php_announce({}, FakeFetch({feeds.PHP_ANNOUNCE_URL: PHP_RSS}), make_policy(), NOW)
        hints = {s.title: s.urgency_hint for s in signals}
        self.assertEqual(hints["Upcoming Critical PHP Security Release"], "pre-announcement")
        self.assertEqual(hints["PHP 8.4.28 Released (security release)"], "")
        self.assertEqual(signals[0].summary, "Release Managers")

    def test_php_releases_store_active_branches_and_signal_recent_versions(self):
        store = FakeStore()
        fetch = FakeFetch({feeds.PHP_ACTIVE_URL: {"8": {
            "8.4": {"version": "8.4.27", "date": "21 Oct 2026", "tags": ["security"], "source": []},
            "8.1": {"version": "8.1.40", "date": "01 Jan 2026", "tags": []}}}})
        result = feeds.poll_due(store, make_policy(), now=NOW, fetch=fetch, only={"php_releases"})
        self.assertEqual(feeds.php_active(store)["8.4"], {"version": "8.4.27", "date": "21 Oct 2026", "tags": ["security"]})
        self.assertIn("8.1", feeds.php_active(store))
        self.assertEqual([s.version for s in result.new], ["8.4.27"])


class NodeTests(unittest.TestCase):
    def test_node_index_newest_first_and_recent_security_releases_signalled(self):
        store = FakeStore()
        fetch = FakeFetch({feeds.NODE_INDEX_URL: [
            {"version": "v24.11.1", "date": "2026-10-21", "security": True, "lts": "Krypton"},
            {"version": "v26.13.0", "date": "2026-10-29", "security": False, "lts": False},
            {"version": "v26.12.1", "date": "2026-10-21", "security": True, "lts": False},
            {"version": "v26.5.1", "date": "2026-07-28", "security": True, "lts": False}]})
        result = feeds.poll_due(store, make_policy(), now=NOW, fetch=fetch, only={"node_releases"})
        index = feeds.node_index(store)
        self.assertEqual([r["version"] for r in index], ["26.13.0", "26.12.1", "26.5.1", "24.11.1"])
        self.assertEqual(index[-1], {"version": "24.11.1", "date": "2026-10-21", "security": True, "lts": "Krypton"})
        self.assertEqual(sorted(s.version for s in result.new), ["24.11.1", "26.12.1"])


class OneCrlTests(unittest.TestCase):
    def test_first_run_seeds_cursor_then_emits_enabled_new_records(self):
        store = FakeStore()
        fetch = FakeFetch({feeds.ONECRL_URL: {"timestamp": 1000, "changes": [
            {"id": "rec-old", "last_modified": 900, "enabled": True, "details": {"name": "Old"}}]}})
        first = feeds.poll_due(store, make_policy(), now=NOW, fetch=fetch, only={"onecrl"})
        self.assertEqual(first.new, [])
        self.assertEqual(store.sources["onecrl"]["state"], {"cursor": 1000})
        fetch.routes[f"{feeds.ONECRL_URL}&_since=1000"] = {"timestamp": 2000, "changes": [
            {"id": "rec-a", "last_modified": 1500, "enabled": True,
             "details": {"bug": "https://bugzilla.mozilla.org/show_bug.cgi?id=1", "why": "<p>Key compromise</p>", "name": ""}},
            {"id": "rec-b", "last_modified": 1600, "enabled": False, "details": {"name": "Disabled"}}]}
        later = feeds.poll_due(store, make_policy(), now=NOW, fetch=fetch, only={"onecrl"}, force=True)
        [sig] = later.new
        self.assertEqual(sig.key, "rec-a")
        self.assertEqual(sig.title, "OneCRL revocation (https://bugzilla.mozilla.org/show_bug.cgi?id=1)")
        self.assertEqual(sig.summary, "Key compromise")
        self.assertEqual(store.sources["onecrl"]["state"], {"cursor": 2000})


class RansomwareTests(unittest.TestCase):
    def test_only_policy_vendor_victims_are_emitted(self):
        fetch = FakeFetch({feeds.RANSOMWARE_URL: [
            {"victim": "Some Bakery", "group": "GroupA", "discovered": "2026-11-03T10:00:00+00:00",
             "domain": "bakery.example", "url": "https://www.ransomware.live/id/one", "description": "x"},
            {"victim": "Proton AG", "group": "GroupB", "discovered": "2026-11-02T10:00:00+00:00",
             "domain": "", "url": "https://www.ransomware.live/id/two", "description": "y" * 500},
        ]})
        signals, _ = feeds.poll_ransomware_live({}, fetch, make_policy(), NOW)
        [sig] = signals
        self.assertEqual(sig.key, "https://www.ransomware.live/id/two")
        self.assertEqual(sig.urgency_hint, "vendor-breach")
        self.assertIn("Proton", sig.summary)
        self.assertIn("GroupB", sig.summary)
        self.assertNotIn("y" * 301, sig.summary)


class PollDueTests(unittest.TestCase):
    def test_sources_match_policy_intervals(self):
        self.assertEqual(set(feeds.SOURCES), set(make_policy().source_intervals))

    def test_due_not_due_and_force(self):
        store = FakeStore()
        policy = make_policy()
        fetch = FakeFetch({feeds.DSA_URL: DSA_RDF})
        self.assertEqual(feeds.poll_due(store, policy, now=NOW, fetch=fetch, only={"debian_dsa"}).health,
                         {"debian_dsa": "ok"})
        soon = NOW + timedelta(seconds=policy.source_intervals["debian_dsa"] - 1)
        self.assertEqual(feeds.poll_due(store, policy, now=soon, fetch=fetch, only={"debian_dsa"}).health,
                         {"debian_dsa": "not-due"})
        self.assertEqual(len(fetch.calls), 1)
        self.assertEqual(feeds.poll_due(store, policy, now=soon, fetch=fetch, only={"debian_dsa"}, force=True).health,
                         {"debian_dsa": "ok"})
        # the forced poll at `soon` is now the last attempt; due again one interval after it
        later = soon + timedelta(seconds=policy.source_intervals["debian_dsa"])
        self.assertEqual(feeds.poll_due(store, policy, now=later, fetch=fetch, only={"debian_dsa"}).health,
                         {"debian_dsa": "ok"})

    def test_failing_source_is_isolated_and_keeps_its_state(self):
        store = FakeStore()
        policy = make_policy()
        fetch = FakeFetch({feeds.ONECRL_URL: {"timestamp": 1000, "changes": []}, feeds.DSA_URL: DSA_RDF})
        feeds.poll_due(store, policy, now=NOW, fetch=fetch, only={"onecrl"})
        # every other source is unmapped and raises; onecrl now fails too
        fetch.routes[f"{feeds.ONECRL_URL}&_since=1000"] = FakeFetchError("HTTP 503")
        result = feeds.poll_due(store, policy, now=NOW + timedelta(days=1), fetch=fetch)
        self.assertEqual(set(result.health), set(feeds.SOURCES))
        self.assertEqual(result.health["debian_dsa"], "ok")
        self.assertEqual(result.health["onecrl"], "failed: FakeFetchError: HTTP 503")
        self.assertTrue(result.health["zero_wire"].startswith("failed: "))
        self.assertEqual([s.key for s in result.new], ["DSA-6606-1"])
        self.assertEqual(store.sources["onecrl"]["state"], {"cursor": 1000})
        self.assertEqual(store.sources["onecrl"]["last_error"], "FakeFetchError: HTTP 503")

    def test_first_run_floor_persists_so_old_items_never_appear_later(self):
        store = FakeStore()
        fetch = FakeFetch({feeds.DSA_URL: DSA_RDF})
        feeds.poll_due(store, make_policy(), now=NOW, fetch=fetch, only={"debian_dsa"})
        later = feeds.poll_due(store, make_policy(), now=NOW + timedelta(days=60), fetch=fetch, only={"debian_dsa"})
        self.assertEqual(later.new, [])
        self.assertEqual(store.sources["debian_dsa"]["state"]["floor"], model.iso(NOW - timedelta(days=30)))


if __name__ == "__main__":
    unittest.main()
