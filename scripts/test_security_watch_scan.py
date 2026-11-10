import json
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

from security_watch import assessments, config, net, resolve, scan  # noqa: E402
from security_watch.config import ComponentSpec, Policy  # noqa: E402
from security_watch.model import (  # noqa: E402
    AdvisoryPackage, Finding, Inventory, Package, Reach, Signal, iso,
)

NOW = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)
CVE = "CVE-2026-111497"
VECTOR_CRITICAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


class FakeStore:
    def __init__(self):
        self.osv: dict[str, tuple[dict, datetime]] = {}
        self.kv: dict = {}
        self.sources: dict[str, dict] = {}

    def osv_get(self, vuln_id):
        return self.osv.get(vuln_id)

    def osv_put(self, vuln_id, record, now):
        self.osv[vuln_id] = (record, now)

    def get_kv(self, key, default=None):
        return self.kv.get(key, default)

    def set_kv(self, key, value):
        self.kv[key] = value

    def source_state(self, name):
        return self.sources.get(name, {"name": name, "last_success": None})


def affected(eco, name, *fixed, introduced="0"):
    events = [{"introduced": introduced}] + [{"fixed": f} for f in fixed]
    return {"package": {"ecosystem": eco, "name": name}, "ranges": [{"type": "ECOSYSTEM", "events": events}]}


def record(vuln_id, *entries, upstream=(), aliases=(), modified="2026-10-31T09:47:25.535412482Z",
           severity=None, summary="Brotli decoder buffer overflow"):
    rec = {"id": vuln_id, "modified": modified, "summary": summary, "affected": list(entries)}
    if upstream:
        rec["upstream"] = list(upstream)
    if aliases:
        rec["aliases"] = list(aliases)
    if severity:
        rec["severity"] = [{"type": "CVSS_V3", "score": severity}]
    return rec


class FakeOSV:
    """Routes querybatch POSTs and /v1/vulns GETs to in-memory payloads."""

    def __init__(self, records=(), hits=None, fail_batch=False, fail_ids=(), page_size=None):
        self.records = {r["id"]: r for r in records}
        self.hits = hits or {}          # (eco, name, version) -> [ids]
        self.fail_batch = fail_batch
        self.fail_ids = set(fail_ids)
        self.page_size = page_size
        self.posts: list[dict] = []
        self.gets: list[str] = []

    def _response(self, url, payload):
        return net.Response(status=200, headers={"content-type": "application/json"},
                            body=json.dumps(payload).encode(), url=url)

    def __call__(self, url, *, method="GET", body=None, headers=None, timeout=20, **_):
        if method == "POST":
            payload = json.loads(body)
            self.posts.append(payload)
            if self.fail_batch:
                raise net.FetchError(url, 503, "service unavailable")
            results = []
            for query in payload["queries"]:
                key = (query["package"]["ecosystem"], query["package"]["name"], query["version"])
                ids = self.hits.get(key, [])
                start = int(query.get("page_token", "0"))
                end = len(ids) if self.page_size is None else start + self.page_size
                vulns = [{"id": i, "modified": self.records.get(i, {}).get("modified", "")} for i in ids[start:end]]
                result = {"vulns": vulns} if vulns else {}
                if end < len(ids):
                    result["next_page_token"] = str(end)
                results.append(result)
            return self._response(url, {"results": results})
        vuln_id = url.rsplit("/", 1)[-1]
        self.gets.append(vuln_id)
        if vuln_id in self.fail_ids:
            raise net.FetchError(url, 500, "internal error")
        if vuln_id not in self.records:
            raise net.FetchError(url, 404, "not found")
        return self._response(url, self.records[vuln_id])


def spec(component_id, exposure="public", **extra):
    return ComponentSpec(id=component_id, kind=extra.pop("kind", "container"), collector="container",
                         exposure=exposure, owner="alert", lock=component_id, extra=extra)


def inventory(component_id, *packages, status="ok", reason=""):
    return Inventory(component_id=component_id, collected_at=NOW, status=status, fingerprint="fp",
                     packages=list(packages), reason=reason)


def policy():
    return Policy(mode="shadow", recipient="carter@example.invalid", max_actions_per_day=3,
                  component_cooldown_hours=12, release_min_age_hours=72, urgent_window_hours=72,
                  urgent_max_per_day=6, tick_budget_seconds=600, inventory_refresh_hours=24,
                  osv_rescan_minutes=60, reach_max_agent_calls_per_tick=2, reach_reachable_p=0.8,
                  reach_not_reachable_p=0.2, jev_deadline_seconds=120, shadow_min_days=14,
                  shadow_min_source_ok_rate=0.95, lock_timeout_seconds=30, vendors=(), upstream_repos=())


BROTLI = Package("Debian:13", "brotli", "1.1.0-2", binary="libbrotli1")


class FeedPatch:
    """Patches the feeds accessors scan uses (kv layout is feeds.py's business)."""

    def __init__(self, kev=(), zero_wire=None, php=None, node=None, repo=None):
        self.patches = [
            mock.patch.object(scan.feeds, "kev_cves", return_value=set(kev)),
            mock.patch.object(scan.feeds, "zero_wire_index", return_value=zero_wire or {}),
            mock.patch.object(scan.feeds, "php_active", return_value=php or {}),
            mock.patch.object(scan.feeds, "node_index", return_value=node or []),
            mock.patch.object(scan.feeds, "repo_advisories", side_effect=lambda store, r: (repo or {}).get(r, [])),
        ]

    def __enter__(self):
        for p in self.patches:
            p.start()
        return self

    def __exit__(self, *exc):
        for p in reversed(self.patches):
            p.stop()


class ScanOsvTests(unittest.TestCase):
    def debian_record(self):
        return record(f"DEBIAN-{CVE}", affected("Debian:12", "brotli", "1.0.9-2+deb12u1"),
                      affected("Debian:13", "brotli", "1.1.0-2+deb13u1"), affected("Debian:14", "brotli"),
                      upstream=[CVE], severity=VECTOR_CRITICAL)

    def test_freshrss_brotli_produces_fixed_finding_with_kev_and_zero_wire(self):
        osv = FakeOSV([self.debian_record()], {("Debian:13", "brotli", "1.1.0-2"): [f"DEBIAN-{CVE}"]})
        store = FakeStore()
        zw = {CVE: [{"slug": "node2shell", "status": "Needs attention", "title": "t", "url": "u"}]}
        with FeedPatch(kev={CVE}, zero_wire=zw):
            result = scan.scan([inventory("freshrss", BROTLI)], {"freshrss": spec("freshrss")},
                               store=store, fetch=osv, now=NOW)
        self.assertEqual([f.key for f in result.findings], [f"freshrss|{CVE}"])
        finding = result.findings[0]
        self.assertEqual(finding.fixed_versions, ["1.1.0-2+deb13u1"])
        self.assertTrue(finding.fix_available)
        self.assertTrue(finding.kev)
        self.assertEqual(finding.zero_wire, ["node2shell"])
        self.assertEqual(finding.severity, "critical")
        self.assertEqual(finding.cves, [CVE])
        self.assertEqual(finding.advisory_ids, [f"DEBIAN-{CVE}"])
        self.assertEqual(finding.package, BROTLI)
        self.assertEqual(result.complete, {"freshrss"})
        self.assertEqual(result.unknown, [])
        self.assertIn(f"DEBIAN-{CVE}", store.osv)

    def test_unfixed_non_kev_record_is_dropped(self):
        rec = record("DEBIAN-CVE-2026-1000", affected("Debian:13", "brotli"), upstream=["CVE-2026-1000"])
        osv = FakeOSV([rec], {("Debian:13", "brotli", "1.1.0-2"): [rec["id"]]})
        with FeedPatch():
            result = scan.scan([inventory("freshrss", BROTLI)], {}, store=FakeStore(), fetch=osv, now=NOW)
        self.assertEqual(result.findings, [])
        self.assertEqual(result.complete, {"freshrss"})

    def test_unfixed_record_kept_when_kev_names_it(self):
        rec = record("DEBIAN-CVE-2026-1000", affected("Debian:13", "brotli"), upstream=["CVE-2026-1000"])
        osv = FakeOSV([rec], {("Debian:13", "brotli", "1.1.0-2"): [rec["id"]]})
        with FeedPatch(kev={"CVE-2026-1000"}):
            result = scan.scan([inventory("freshrss", BROTLI)], {}, store=FakeStore(), fetch=osv, now=NOW)
        self.assertEqual(len(result.findings), 1)
        self.assertFalse(result.findings[0].fix_available)

    def test_querybatch_failure_marks_component_incomplete_and_unknown(self):
        osv = FakeOSV(fail_batch=True)
        with FeedPatch():
            result = scan.scan([inventory("freshrss", BROTLI)], {}, store=FakeStore(), fetch=osv, now=NOW)
        self.assertEqual(result.complete, set())
        self.assertEqual(len(result.unknown), 1)
        self.assertEqual(result.unknown[0]["component"], "freshrss")
        self.assertTrue(result.unknown[0]["reason"].startswith("OSV unavailable: "))

    def test_record_fetch_failure_marks_only_that_component_incomplete(self):
        good = self.debian_record()
        osv = FakeOSV([good], {("Debian:13", "brotli", "1.1.0-2"): [good["id"]],
                               ("Debian:13", "curl", "8.14.1-2"): ["DEBIAN-CVE-2026-2000"]},
                      fail_ids={"DEBIAN-CVE-2026-2000"})
        curl = Package("Debian:13", "curl", "8.14.1-2")
        with FeedPatch():
            result = scan.scan([inventory("freshrss", BROTLI), inventory("open-webui", curl)], {},
                               store=FakeStore(), fetch=osv, now=NOW)
        self.assertEqual(result.complete, {"freshrss"})
        self.assertEqual([u["component"] for u in result.unknown], ["open-webui"])
        self.assertIn("OSV unavailable", result.unknown[0]["reason"])

    def test_inventory_unknown_and_partial_become_unknown_entries(self):
        osv = FakeOSV([self.debian_record()], {("Debian:13", "brotli", "1.1.0-2"): [f"DEBIAN-{CVE}"]})
        with FeedPatch():
            result = scan.scan([inventory("searxng", BROTLI, status="partial", reason="os void has no OSV ecosystem"),
                                inventory("rig", status="unknown", reason="rig offline")],
                               {}, store=FakeStore(), fetch=osv, now=NOW)
        self.assertEqual(result.complete, set())
        self.assertEqual({u["component"]: u["reason"] for u in result.unknown},
                         {"searxng": "os void has no OSV ecosystem", "rig": "rig offline"})
        self.assertEqual([f.key for f in result.findings], [f"searxng|{CVE}"])

    def test_unsupported_ecosystem_is_not_queried_and_unknown(self):
        osv = FakeOSV()
        with FeedPatch():
            result = scan.scan([inventory("searxng", Package("Void", "brotli", "1.1.0_1"))], {},
                               store=FakeStore(), fetch=osv, now=NOW)
        self.assertEqual(osv.posts, [])
        self.assertEqual(result.complete, set())
        self.assertIn("not supported by OSV", result.unknown[0]["reason"])

    def test_records_merge_into_one_finding_per_group(self):
        debian = self.debian_record()
        other = record("DEBIAN-CVE-2026-1050", affected("Debian:13", "brotli", "1.1.0-2+deb13u2"),
                       upstream=[CVE, "CVE-2026-1050"])
        osv = FakeOSV([debian, other], {("Debian:13", "brotli", "1.1.0-2"): [debian["id"], other["id"]]})
        with FeedPatch():
            result = scan.scan([inventory("freshrss", BROTLI)], {}, store=FakeStore(), fetch=osv, now=NOW)
        keys = sorted(f.key for f in result.findings)
        self.assertEqual(keys, ["freshrss|CVE-2026-1050", f"freshrss|{CVE}"])

    def test_scan_caches_trimmed_records_for_the_queried_ecosystems(self):
        debian = self.debian_record()
        debian["affected"][1]["versions"] = ["1.1.0-2"]
        osv = FakeOSV([debian], {("Debian:13", "brotli", "1.1.0-2"): [debian["id"]]})
        store = FakeStore()
        with FeedPatch():
            scan.scan([inventory("freshrss", BROTLI)], {}, store=store, fetch=osv, now=NOW)
            cached, _ = store.osv[debian["id"]]
            self.assertEqual(cached[resolve.TRIMMED_KEY], ["Debian:13"])
            self.assertEqual([a["package"]["ecosystem"] for a in cached["affected"]], ["Debian:13"])
            self.assertNotIn("versions", cached["affected"][0])
            # unchanged modified on a later tick: served from the cache, no refetch
            result = scan.scan([inventory("freshrss", BROTLI)], {}, store=store, fetch=osv,
                               now=NOW + timedelta(days=30))
        self.assertEqual(osv.gets, [debian["id"]])
        self.assertEqual(result.findings[0].fixed_versions, ["1.1.0-2+deb13u1"])

    def test_deadline_leaves_component_incomplete_with_pending_records(self):
        debian = self.debian_record()
        curl_rec = record("DEBIAN-CVE-2026-2000", affected("Debian:13", "curl", "8.14.1-2+deb13u1"),
                          upstream=["CVE-2026-2000"])
        curl = Package("Debian:13", "curl", "8.14.1-2")
        clock = [100.0]

        class SlowBatchOSV(FakeOSV):
            def __call__(self, url, **kw):
                if kw.get("method") == "POST":
                    clock[0] += 50.0      # the querybatch eats the remaining budget
                return super().__call__(url, **kw)

        osv = SlowBatchOSV([debian, curl_rec], {("Debian:13", "brotli", "1.1.0-2"): [debian["id"]],
                                                ("Debian:13", "curl", "8.14.1-2"): [curl_rec["id"]]})
        store = FakeStore()
        store.osv_put(debian["id"], resolve.trim_record(debian, {"Debian:13"}), NOW)
        with FeedPatch(), mock.patch.object(scan, "_monotonic", lambda: clock[0]):
            result = scan.scan([inventory("freshrss", BROTLI, curl)], {}, store=store, fetch=osv, now=NOW,
                               deadline=120.0)
        self.assertEqual(osv.gets, [])
        self.assertEqual([f.key for f in result.findings], [f"freshrss|{CVE}"])
        self.assertEqual(result.complete, set())
        self.assertEqual(result.unknown, [{"component": "freshrss", "reason": "OSV records pending: 1 not yet fetched"}])
        self.assertEqual(result.stats["osv_pending"], 1)


class ScanRuntimeTests(unittest.TestCase):
    def test_bun_runtime_matches_github_advisory_range(self):
        sig = Signal(source="github_advisories", key="oven-sh/bun#GHSA-aaaa-bbbb-cccc", version="1",
                     title="Bun advisory", url="https://github.com/oven-sh/bun/security/advisories",
                     tier="issuer", cves=("CVE-2026-4242",), aliases=("GHSA-aaaa-bbbb-cccc",),
                     packages=(AdvisoryPackage("npm", "bun", ">= 1.0.21, < 1.4.4", ("1.4.4",)),),
                     summary="Bun issue")
        store = FakeStore()
        store.sources["github_advisories"] = {"name": "github_advisories", "last_success": iso(NOW)}
        bun = Package("runtime", "bun", "1.3.14")
        with FeedPatch(repo={"oven-sh/bun": [sig]}):
            result = scan.scan([inventory("bun", bun)],
                               {"bun": spec("bun", exposure="none", kind="runtime", runtime="bun",
                                            advisory_repo="oven-sh/bun")},
                               store=store, fetch=FakeOSV(), now=NOW)
        self.assertEqual([f.key for f in result.findings], ["bun|CVE-2026-4242"])
        self.assertEqual(result.findings[0].fixed_versions, ["1.4.4"])
        self.assertEqual(result.findings[0].advisory_ids, ["GHSA-aaaa-bbbb-cccc"])
        self.assertEqual(result.complete, {"bun"})

    def test_github_advisories_never_fetched_is_unknown(self):
        bun = Package("runtime", "bun", "1.3.14")
        with FeedPatch():
            result = scan.scan([inventory("bun", bun)],
                               {"bun": spec("bun", kind="runtime", runtime="bun", advisory_repo="oven-sh/bun")},
                               store=FakeStore(), fetch=FakeOSV(), now=NOW)
        self.assertEqual(result.complete, set())
        self.assertIn("not fetched", result.unknown[0]["reason"])

    def test_php_branch_security_release(self):
        php = Package("runtime", "php", "8.4.27")
        active = {"8": {"8.4": {"version": "8.4.28", "date": "2026-11-01", "tags": ["security"]},
                        "8.3": {"version": "8.3.40", "date": "2026-11-01", "tags": ["security"]}}}
        with FeedPatch(php=active):
            result = scan.scan([inventory("freshrss", php)], {"freshrss": spec("freshrss")},
                               store=FakeStore(), fetch=FakeOSV(), now=NOW)
        self.assertEqual([f.key for f in result.findings], ["freshrss|PHP-8.4.28"])
        self.assertEqual(result.findings[0].fixed_versions, ["8.4.28"])

    def test_php_branch_without_security_tag_is_clean(self):
        php = Package("runtime", "php", "8.4.27")
        with FeedPatch(php={"8.4": {"version": "8.4.28", "tags": []}}):
            result = scan.scan([inventory("freshrss", php)], {}, store=FakeStore(), fetch=FakeOSV(), now=NOW)
        self.assertEqual(result.findings, [])
        self.assertEqual(result.complete, {"freshrss"})

    def test_node_newer_security_release_on_same_major(self):
        node = Package("runtime", "node", "v26.12.0")
        index = [{"version": "v27.1.0", "security": True, "lts": False},
                 {"version": "v26.14.0", "security": False, "lts": "Krypton"},
                 {"version": "v26.13.0", "security": True, "lts": "Krypton"},
                 {"version": "v26.12.0", "security": False, "lts": "Krypton"}]
        with FeedPatch(node=index):
            result = scan.scan([inventory("node", node)], {}, store=FakeStore(), fetch=FakeOSV(), now=NOW)
        self.assertEqual([f.key for f in result.findings], ["node|NODE-26.13.0"])
        self.assertEqual(result.findings[0].fixed_versions, ["26.14.0"])

    def test_runtime_without_advisory_source_is_unknown_but_complete(self):
        omp = Package("runtime", "omp", "15.2.0")
        with FeedPatch():
            result = scan.scan([inventory("omp", omp)], {"omp": spec("omp", kind="runtime", runtime="omp")},
                               store=FakeStore(), fetch=FakeOSV(), now=NOW)
        self.assertEqual(result.unknown, [{"component": "omp", "reason": "no advisory feed for omp"}])
        self.assertEqual(result.complete, {"omp"})


class ResolveTests(unittest.TestCase):
    def test_querybatch_normalizes_versions_and_names_and_follows_pages(self):
        recs = [record(f"GO-2026-{n}", affected("Go", "stdlib", "1.27.4")) for n in range(1, 4)]
        osv = FakeOSV(recs, {("Go", "stdlib", "1.27.2"): [r["id"] for r in recs],
                             ("PyPI", "jinja2-ext", "2.4"): ["PYSEC-2026-1"]}, page_size=2)
        stdlib = Package("Go", "stdlib", "go1.27.2")
        pypi = Package("PyPI", "Jinja2_Ext", "2.4")
        runtime = Package("runtime", "bun", "1.3.14")
        hits = resolve.querybatch([stdlib, pypi, runtime], fetch=osv)
        self.assertEqual([i for i, _ in hits[stdlib]], ["GO-2026-1", "GO-2026-2", "GO-2026-3"])
        self.assertEqual([i for i, _ in hits[pypi]], ["PYSEC-2026-1"])
        self.assertNotIn(runtime, hits)
        self.assertEqual(osv.posts[1]["queries"][0]["page_token"], "2")

    def test_querybatch_chunks_at_500(self):
        osv = FakeOSV()
        pkgs = [Package("PyPI", f"pkg{n}", "1.0") for n in range(501)]
        resolve.querybatch(pkgs, fetch=osv)
        self.assertEqual([len(p["queries"]) for p in osv.posts], [500, 1])

    def test_get_vuln_caches_and_refetches_when_modified_is_newer(self):
        rec = record("DEBIAN-CVE-2026-7", affected("Debian:13", "brotli", "1.0"))
        osv = FakeOSV([rec])
        store = FakeStore()
        self.assertEqual(resolve.get_vuln(rec["id"], store=store, fetch=osv, now=NOW), rec)
        # querybatch modified equal to the cached one: valid regardless of age
        resolve.get_vuln(rec["id"], store=store, fetch=osv, now=NOW + timedelta(days=30),
                         modified="2026-10-31T09:47:25.535412Z")
        self.assertEqual(len(osv.gets), 1)
        resolve.get_vuln(rec["id"], store=store, fetch=osv, now=NOW, modified="2026-11-01T00:00:00Z")
        self.assertEqual(len(osv.gets), 2)
        # without modified: time-based expiry after 7 days
        resolve.get_vuln(rec["id"], store=store, fetch=osv, now=NOW + timedelta(days=6))
        self.assertEqual(len(osv.gets), 2)
        resolve.get_vuln(rec["id"], store=store, fetch=osv, now=NOW + timedelta(days=8))
        self.assertEqual(len(osv.gets), 3)

    def test_get_vuln_refetches_when_cached_record_lacks_an_ecosystem(self):
        rec = record(f"UBUNTU-{CVE}", affected("Debian:13", "brotli", "1.0"),
                     affected("Ubuntu:24.04:LTS", "brotli", "1.1.0-2ubuntu0.1"))
        osv = FakeOSV([rec])
        store = FakeStore()
        resolve.get_vuln(rec["id"], store=store, fetch=osv, now=NOW, keep_ecosystems={"Debian:13"})
        resolve.get_vuln(rec["id"], store=store, fetch=osv, now=NOW, keep_ecosystems={"Debian:13"})
        self.assertEqual(len(osv.gets), 1)
        widened = resolve.get_vuln(rec["id"], store=store, fetch=osv, now=NOW,
                                   keep_ecosystems={"Ubuntu:24.04:LTS"})
        self.assertEqual(len(osv.gets), 2)
        self.assertEqual(widened[resolve.TRIMMED_KEY], ["Debian:13", "Ubuntu:24.04:LTS"])
        self.assertEqual(resolve.fixed_versions(widened, "Ubuntu:24.04:LTS", "brotli"), ["1.1.0-2ubuntu0.1"])
        # a full (untrimmed-ecosystem) request is never served from a narrowed cache
        resolve.get_vuln(rec["id"], store=store, fetch=osv, now=NOW)
        self.assertEqual(len(osv.gets), 3)

    def test_trim_record_drops_versions_and_foreign_ecosystems(self):
        raw = record(f"UBUNTU-{CVE}",
                     affected("Debian:12", "brotli", "1.0.9-2+deb12u1"),
                     affected("Ubuntu:24.04:LTS", "brotli", "1.1.0-2ubuntu0.1"),
                     upstream=[CVE], severity=VECTOR_CRITICAL)
        raw["affected"][1]["versions"] = ["1.1.0-1", "1.1.0-2"]
        raw["affected"][1]["ranges"].append({"type": "GIT", "repo": "https://example.invalid/brotli",
                                             "events": [{"fixed": "abc"}]})
        raw["affected"][1]["ecosystem_specific"] = {"priority": "high", "binaries": [{"binary_name": "libbrotli1"}]}
        raw["affected"][0]["versions"] = ["1.0.9-2"]
        raw["details"] = "x" * 5000
        raw["related"] = [f"USN-{n}-1" for n in range(60)]
        raw["references"] = [{"type": "WEB", "url": "https://example.invalid"}]
        trimmed = resolve.trim_record(raw, {"Ubuntu:24.04:LTS"})
        self.assertNotIn('"versions"', json.dumps(trimmed))
        self.assertNotIn("references", trimmed)
        self.assertEqual([a["package"]["ecosystem"] for a in trimmed["affected"]], ["Ubuntu:24.04:LTS"])
        self.assertEqual([r["type"] for r in trimmed["affected"][0]["ranges"]], ["ECOSYSTEM"])
        self.assertEqual(trimmed["affected"][0]["ecosystem_specific"], {"priority": "high"})
        self.assertEqual(len(trimmed["details"]), 2000)
        self.assertEqual(len(trimmed["related"]), 50)
        self.assertTrue(resolve.matches_package(trimmed, "Ubuntu:24.04:LTS", "brotli"))
        self.assertFalse(resolve.matches_package(trimmed, "Debian:12", "brotli"))
        self.assertEqual(resolve.fixed_versions(trimmed, "Ubuntu:24.04:LTS", "brotli"), ["1.1.0-2ubuntu0.1"])
        self.assertEqual(resolve.cves_of(trimmed), [CVE])
        self.assertEqual(resolve.severity_of(trimmed), "critical")
        self.assertEqual(resolve.independent_sources_naming([trimmed], "Ubuntu:24.04:LTS", "brotli",
                                                            "1.1.0-2ubuntu0.1"), 1)
        full = resolve.trim_record(raw, None)
        self.assertNotIn(resolve.TRIMMED_KEY, full)
        self.assertEqual(len(full["affected"]), 2)
        self.assertNotIn('"versions"', json.dumps(full))

    def test_get_vuln_404_is_none_and_other_errors_raise(self):
        osv = FakeOSV(fail_ids={"GO-2026-9"})
        self.assertIsNone(resolve.get_vuln("GO-2026-8", store=FakeStore(), fetch=osv, now=NOW))
        with self.assertRaises(net.FetchError):
            resolve.get_vuln("GO-2026-9", store=FakeStore(), fetch=osv, now=NOW)

    def test_resolve_cve_returns_existing_records(self):
        osv = FakeOSV([record(f"UBUNTU-{CVE}"), record(f"DEBIAN-{CVE}")])
        ids = [r["id"] for r in resolve.resolve_cve(CVE, store=FakeStore(), fetch=osv, now=NOW)]
        self.assertEqual(ids, [f"UBUNTU-{CVE}", f"DEBIAN-{CVE}"])

    def test_matches_package_and_fixed_versions(self):
        rec = record("PYSEC-2026-1", affected("PyPI", "Jinja2", "2.11.3", "3.1.5"),
                     affected("PyPI", "jinja2", "3.1.5"),
                     {"package": {"ecosystem": "PyPI", "name": "jinja2"},
                      "ranges": [{"type": "GIT", "events": [{"fixed": "abc"}]}]})
        self.assertTrue(resolve.matches_package(rec, "PyPI", "jinja2"))
        self.assertFalse(resolve.matches_package(rec, "Debian:13", "jinja2"))
        self.assertEqual(resolve.fixed_versions(rec, "PyPI", "JINJA2"), ["2.11.3", "3.1.5"])

    def test_independent_sources_counts_prefixes_not_duplicates(self):
        eco, name, fixed = "Debian:13", "brotli", "1.1.0-2+deb13u1"
        records = [record(f"DEBIAN-{CVE}", affected(eco, name, fixed)),
                   record("DEBIAN-CVE-2026-5", affected(eco, name, fixed)),
                   record(f"UBUNTU-{CVE}", affected(eco, name, fixed)),
                   record("GHSA-xxxx-yyyy-zzzz", affected(eco, name, "9.9"))]
        self.assertEqual(resolve.independent_sources_naming(records, eco, name, fixed), 2)
        self.assertEqual(resolve.independent_sources_naming(records[:2], eco, name, fixed), 1)

    def test_group_of_picks_lowest_cve(self):
        rec = record("GHSA-xxxx-yyyy-zzzz", aliases=["CVE-2026-20000", "CVE-2025-99999", "CVE-2026-3000"])
        self.assertEqual(resolve.group_of(rec), "CVE-2025-99999")
        self.assertEqual(resolve.cves_of(rec), ["CVE-2025-99999", "CVE-2026-3000", "CVE-2026-20000"])
        self.assertEqual(resolve.group_of(record("GO-2026-1")), "GO-2026-1")
        self.assertEqual(resolve.cves_of(record(f"DEBIAN-{CVE}")), [CVE])

    def test_severity_of_sources(self):
        self.assertEqual(resolve.severity_of(record("X-1", severity=VECTOR_CRITICAL)), "critical")
        self.assertEqual(resolve.severity_of(record("X-2", severity="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N")),
                         "medium")
        self.assertEqual(resolve.severity_of({"id": "GHSA-1", "database_specific": {"severity": "MODERATE"}}), "medium")
        ubuntu = {"id": "UBUNTU-1", "affected": [{"package": {}, "ecosystem_specific": {"priority": "high"}}]}
        self.assertEqual(resolve.severity_of(ubuntu), "high")
        self.assertEqual(resolve.severity_of({"id": "GO-1"}), "")

    def test_version_lt_and_github_range(self):
        self.assertTrue(resolve.version_lt("1.3.14", "1.4.4"))
        self.assertTrue(resolve.version_lt("v1.9.0", "1.10.0"))
        self.assertTrue(resolve.version_lt("go1.27.3", "1.27.4"))
        self.assertTrue(resolve.version_lt("1.4.4-beta.1", "1.4.4"))
        self.assertFalse(resolve.version_lt("1.4.4", "1.4.4"))
        self.assertTrue(resolve.in_github_range("1.3.14", ">= 1.0.21, < 1.4.4"))
        self.assertFalse(resolve.in_github_range("1.4.4", ">= 1.0.21, < 1.4.4"))
        self.assertFalse(resolve.in_github_range("1.0.20", ">= 1.0.21, < 1.4.4"))
        self.assertTrue(resolve.in_github_range("1.2.0", "= 1.2.0"))
        self.assertFalse(resolve.in_github_range("1.2.0", ""))


class PrioritizeTests(unittest.TestCase):
    def finding(self, component="freshrss", **kw):
        base = dict(key=f"{component}|{CVE}", component_id=component, group=CVE, package=BROTLI,
                    advisory_ids=[f"DEBIAN-{CVE}"], cves=[CVE], fixed_versions=["1.1.0-2+deb13u1"],
                    fix_available=True, first_seen=iso(NOW - timedelta(hours=1)))
        base.update(kw)
        return Finding(**base)

    def run_prioritize(self, findings, zero_wire=None, stopgaps=(), not_affected=None):
        specs = {"freshrss": spec("freshrss", exposure="public"), "host": spec("host", exposure="lan")}
        with FeedPatch(zero_wire=zero_wire):
            scan.prioritize(findings, specs, policy(), store=FakeStore(), now=NOW,
                            stopgaps=None if stopgaps is None else list(stopgaps),
                            not_affected=not_affected)

    def assessment(self, ok=True, component="freshrss", cves=(CVE,)):
        entry = assessments.NotAffected(
            id="brotli-unused", component=component, cves=tuple(cves), reason="brotli is never loaded",
            verified="2026-11-09", checks=(assessments.Check(argv=("true",), expect=""),))
        verdict = assessments.Verdict(id=entry.id, ok=ok, detail="" if ok else "check 1: true: rc 1")
        return entry, verdict

    def test_verified_not_affected_is_low_even_with_kev_and_zero_wire(self):
        zw = {CVE: [{"slug": "node2shell", "status": "Needs attention"}]}
        f = self.finding(kev=True, zero_wire=["node2shell"], severity="critical", reach=self.reachable())
        self.run_prioritize([f], zero_wire=zw, not_affected=[self.assessment()])
        self.assertEqual(f.urgency, "low")
        self.assertEqual(f.reasons, ["verified not affected: brotli-unused: brotli is never loaded",
                                     "CISA KEV", "Zero Wire: node2shell (Needs attention)",
                                     "reachable (p=0.93), critical"])

    def test_verified_not_affected_wins_over_a_stopgap(self):
        f = self.finding(kev=True)
        self.run_prioritize([f], stopgaps=[self.stopgap()], not_affected=[self.assessment()])
        self.assertEqual(f.urgency, "low")
        self.assertEqual(f.reasons[:2], ["verified not affected: brotli-unused: brotli is never loaded",
                                         "stopgap active: freshrss-brotli-off since 2026-11-03"])

    def test_failed_not_affected_check_fails_closed(self):
        f = self.finding(kev=True)
        self.run_prioritize([f], not_affected=[self.assessment(ok=False)])
        self.assertEqual(f.urgency, "urgent")
        self.assertEqual(f.reasons, ["CISA KEV",
                                     "not-affected check failed: brotli-unused: check 1: true: rc 1"])

    def test_not_affected_does_not_cover_other_components_or_cves(self):
        host = self.finding("host", kev=True)
        other_cve = self.finding(kev=True, cves=["CVE-2026-9999"])
        self.run_prioritize([host, other_cve], not_affected=[self.assessment(), self.assessment(ok=False)])
        self.assertEqual((host.urgency, host.reasons), ("urgent", ["CISA KEV"]))
        self.assertEqual((other_cve.urgency, other_cve.reasons), ("urgent", ["CISA KEV"]))

    def test_not_affected_none_and_empty_change_nothing(self):
        for value in (None, []):
            f = self.finding(kev=True)
            self.run_prioritize([f], not_affected=value)
            self.assertEqual((f.urgency, f.reasons), ("urgent", ["CISA KEV"]))

    def stopgap(self, component="freshrss", cves=(CVE,)):
        return config.Stopgap(id="freshrss-brotli-off", component=component, cves=tuple(cves),
                              description="brotli decoding disabled in curl", since="2026-11-03",
                              remove="when brotli is fixed", doc="")

    def test_stopgap_caps_kev_and_zero_wire_finding_at_normal(self):
        zw = {CVE: [{"slug": "node2shell", "status": "Needs attention"}]}
        f = self.finding(kev=True, zero_wire=["node2shell"])
        self.run_prioritize([f], zero_wire=zw, stopgaps=[self.stopgap()])
        self.assertEqual(f.urgency, "normal")
        self.assertEqual(f.reasons, ["stopgap active: freshrss-brotli-off since 2026-11-03", "CISA KEV",
                                     "Zero Wire: node2shell (Needs attention)"])

    def test_stopgap_does_not_cover_other_components_or_cves(self):
        host = self.finding("host", kev=True)
        other_cve = self.finding(kev=True, cves=["CVE-2026-9999"])
        self.run_prioritize([host, other_cve], stopgaps=[self.stopgap()])
        self.assertEqual((host.urgency, host.reasons), ("urgent", ["CISA KEV"]))
        self.assertEqual((other_cve.urgency, other_cve.reasons), ("urgent", ["CISA KEV"]))

    def test_stopgap_keeps_low_findings_low(self):
        f = self.finding(fixed_versions=[], fix_available=False)
        self.run_prioritize([f], stopgaps=[self.stopgap()])
        self.assertEqual(f.urgency, "low")
        self.assertEqual(f.reasons[0], "stopgap active: freshrss-brotli-off since 2026-11-03")

    def test_explicit_empty_stopgap_list_disables_the_ledger(self):
        f = self.finding(kev=True)
        with mock.patch.object(scan.config, "load_stopgaps", return_value=[self.stopgap()]) as load:
            self.run_prioritize([f], stopgaps=[])
        load.assert_not_called()
        self.assertEqual(f.urgency, "urgent")

    def test_stopgaps_none_loads_the_ledger(self):
        f = self.finding(kev=True)
        with mock.patch.object(scan.config, "load_stopgaps", return_value=[self.stopgap()]) as load:
            self.run_prioritize([f], stopgaps=None)
        load.assert_called_once_with()
        self.assertEqual(f.urgency, "normal")

    def reachable(self, p=0.93):
        return Reach(verdict="reachable", method="agent+jev", p=p)

    def test_public_medium_finding_is_normal_not_urgent(self):
        f = self.finding(severity="medium")
        self.run_prioritize([f])
        self.assertEqual((f.urgency, f.reasons), ("normal", ["fix available", "public surface"]))

    def test_public_surface_not_reachable_is_low(self):
        f = self.finding(severity="high", reach=Reach(verdict="not_reachable", method="govulncheck"))
        self.run_prioritize([f])
        self.assertEqual((f.urgency, f.reasons), ("low", ["not reachable per govulncheck"]))

    def test_kev_zero_wire_and_reachable_reasons(self):
        zw = {CVE: [{"slug": "node2shell", "status": "Needs attention"}]}
        f = self.finding("host", kev=True, zero_wire=["node2shell"], severity="high", reach=self.reachable())
        self.run_prioritize([f], zero_wire=zw)
        self.assertEqual(f.urgency, "urgent")
        self.assertEqual(f.reasons, ["CISA KEV", "Zero Wire: node2shell (Needs attention)",
                                     "reachable (p=0.93), high"])

    def test_zero_wire_needs_attention_is_urgent_and_reference_is_not(self):
        f = self.finding("host", zero_wire=["node2shell"])
        self.run_prioritize([f], zero_wire={CVE: [{"slug": "node2shell", "status": "Needs attention"}]})
        self.assertEqual((f.urgency, f.reasons), ("urgent", ["Zero Wire: node2shell (Needs attention)"]))
        g = self.finding("host", zero_wire=["old-item"])
        self.run_prioritize([g], zero_wire={CVE: [{"slug": "old-item", "status": "Reference"}]})
        self.assertEqual(g.urgency, "low")

    def test_kev_stays_urgent_outside_the_window(self):
        f = self.finding(kev=True, first_seen=iso(NOW - timedelta(hours=100)))
        self.run_prioritize([f])
        self.assertEqual((f.urgency, f.reasons), ("urgent", ["CISA KEV"]))

    def test_kev_wins_over_a_not_reachable_verdict(self):
        # Rule: CISA KEV (and Zero Wire "Needs attention") make an affected finding urgent
        # even when reachability judged it not reachable -- KEV wins.
        f = self.finding("host", kev=True, reach=Reach(verdict="not_reachable", method="agent+jev", p=0.05))
        self.run_prioritize([f])
        self.assertEqual(f.urgency, "urgent")
        self.assertEqual(f.reasons, ["CISA KEV", "not reachable per agent+jev"])

    def test_reachable_high_within_window_is_urgent(self):
        f = self.finding("host", severity="high", reach=self.reachable())
        self.run_prioritize([f])
        self.assertEqual((f.urgency, f.reasons), ("urgent", ["reachable (p=0.93), high"]))

    def test_reachable_high_outside_window_is_normal(self):
        f = self.finding("host", severity="high", reach=self.reachable(),
                         first_seen=iso(NOW - timedelta(hours=100)))
        self.run_prioritize([f])
        self.assertEqual(f.urgency, "normal")
        self.assertEqual(f.reasons, ["fix available, high", "reachable (p=0.93), high",
                                     "first seen more than 72h ago"])

    def test_reachable_medium_is_not_urgent(self):
        f = self.finding(severity="medium", reach=self.reachable())
        self.run_prioritize([f])
        self.assertEqual(f.urgency, "normal")

    def test_high_fix_on_unexposed_component_is_normal(self):
        f = self.finding("host", severity="critical")
        self.run_prioritize([f])
        self.assertEqual((f.urgency, f.reasons), ("normal", ["fix available, critical"]))

    def test_medium_fix_on_unexposed_component_is_low(self):
        f = self.finding("host", severity="medium")
        self.run_prioritize([f])
        self.assertEqual(f.urgency, "low")

    def test_no_fix_is_low(self):
        f = self.finding(severity="critical", fixed_versions=[], fix_available=False)
        self.run_prioritize([f])
        self.assertEqual((f.urgency, f.reasons), ("low", ["no fix available"]))

    def test_not_affected_is_low_even_with_kev(self):
        f = self.finding(kev=True, status="unknown")
        self.run_prioritize([f])
        self.assertEqual(f.urgency, "low")


if __name__ == "__main__":
    unittest.main()
