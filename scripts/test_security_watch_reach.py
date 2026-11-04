import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import dataclasses
import json
import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from security_watch import config, reach
from security_watch.model import Finding, Inventory, Package, Reach

NOW = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)


class FakeStore:
    def __init__(self, osv=None):
        self.reach = {}
        self.puts = []
        self.osv = osv or {}
        self.kv = {}

    def get_kv(self, key, default=None):
        return self.kv.get(key, default)

    def set_kv(self, key, value):
        self.kv[key] = value

    def get_reach(self, key):
        return self.reach.get(key)

    def put_reach(self, key, value, now):
        self.reach[key] = value
        self.puts.append(key)

    def osv_get(self, vuln_id):
        record = self.osv.get(vuln_id)
        return (record, NOW) if record else None


class FakeJev:
    def __init__(self, untrusted=0.9, loaded=0.9, error=None):
        self.untrusted = untrusted
        self.loaded = loaded
        self.error = error
        self.calls = []

    def ask(self, purpose, state, questions):
        self.calls.append((purpose, state, questions))
        if self.error:
            raise self.error
        return {"untrusted_reaches": {"type": "noul", "noul": self.untrusted},
                "loaded": {"type": "noul", "noul": self.loaded}}


class FakeUnavailable(RuntimeError):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def make_spec(cid="web", exposure="public", untrusted="public HTTP requests", **extra):
    return config.ComponentSpec(id=cid, kind="container", collector="container", exposure=exposure,
                                owner="alert", lock=cid, description="test service",
                                untrusted_input=untrusted, extra=extra)


def make_finding(cid="web", group="CVE-2026-1111", eco="PyPI", name="brotli", ids=("GHSA-test-0001",),
                 cves=("CVE-2026-1111",), location="", status="affected", severity="high", kev=False):
    return Finding(key=f"{cid}|{group}", component_id=cid, group=group,
                   package=Package(eco, name, "1.0.0", location=location),
                   advisory_ids=list(ids), cves=list(cves), fixed_versions=["1.0.1"],
                   fix_available=True, status=status, severity=severity, kev=kev)


def govulncheck_stream(*objects):
    return "\n".join(json.dumps(obj, indent=2) for obj in objects)


def osv_obj(vid, *aliases):
    return {"osv": {"id": vid, "aliases": list(aliases), "summary": "x"}}


def finding_obj(vid, module, package=None, function=None):
    frame = {"module": module, "version": "v1.0.0"}
    if package:
        frame["package"] = package
    if function:
        frame["function"] = function
    return {"finding": {"osv": vid, "fixed_version": "v1.0.1", "trace": [frame]}}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.home = root / "home"
        self.home.mkdir()
        state = root / "state"
        patcher = mock.patch.dict(os.environ, {"HOME": str(self.home), "SECURITY_WATCH_STATE_DIR": str(state)})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)
        self.policy = dataclasses.replace(config.load_policy(), reach_max_agent_calls_per_tick=2,
                                          reach_reachable_p=0.8, reach_not_reachable_p=0.2)


class GovulncheckTests(Base):
    def setUp(self):
        super().setUp()
        self.binary = self.home / "bin" / "svc"
        self.binary.parent.mkdir()
        self.binary.write_bytes(b"\x7fELF")
        self.inv = Inventory("gosvc", NOW, "ok", "fp-1",
                             meta={"binaries": [{"path": str(self.binary), "sha256": "s"}]})
        self.spec = make_spec("gosvc")
        self.calls = []

    def runner(self, stdout, returncode=0):
        def run(argv, **kwargs):
            self.calls.append((argv, kwargs))
            return subprocess.CompletedProcess(argv, returncode, stdout, "boom" if returncode else "")
        return run

    def assess_go(self, finding, stdout, returncode=0, store=None):
        store = store or FakeStore()
        result = reach.assess([finding], {"gosvc": self.inv}, {"gosvc": self.spec}, store=store,
                              policy=self.policy, now=NOW, run=self.runner(stdout, returncode),
                              omp_call=lambda p: self.fail("agent must not run"), load_jev=False)
        return result[finding.key], store

    def test_parse_handles_indented_stream(self):
        text = govulncheck_stream({"config": {"scanner_name": "govulncheck"}},
                                  osv_obj("GO-2026-0001", "CVE-2026-1111"),
                                  finding_obj("GO-2026-0001", "golang.org/x/net", "golang.org/x/net/http2", "Read"))
        osvs, findings = reach.parse_govulncheck(text)
        self.assertEqual(osvs["GO-2026-0001"], {"GO-2026-0001", "CVE-2026-1111"})
        self.assertEqual(len(findings), 1)

    def test_symbol_level_hit_is_reachable_and_cached(self):
        finding = make_finding("gosvc", eco="Go", name="golang.org/x/net", ids=("GHSA-test-0002",))
        stdout = govulncheck_stream(osv_obj("GO-2026-0001", "CVE-2026-1111", "GHSA-test-0002"),
                                    finding_obj("GO-2026-0001", "golang.org/x/net"),
                                    finding_obj("GO-2026-0001", "golang.org/x/net", "golang.org/x/net/http2",
                                                "Framer.ReadFrame"))
        result, store = self.assess_go(finding, stdout)
        self.assertEqual((result.verdict, result.p, result.method), ("reachable", 1.0, "govulncheck"))
        self.assertIs(finding.reach, result)
        self.assertEqual(store.puts, [reach.cache_key(self.inv, finding)])
        argv, kwargs = self.calls[0]
        self.assertEqual(argv[1:5], ["run", "golang.org/x/vuln/cmd/govulncheck@v1.8.0", "-mode=binary", "-json"])
        self.assertEqual(argv[-1], str(self.binary))
        self.assertEqual(kwargs["env"]["GOTOOLCHAIN"], "local")

    def test_module_level_only_is_not_reachable(self):
        finding = make_finding("gosvc", eco="Go", name="stdlib")
        stdout = govulncheck_stream(osv_obj("GO-2026-0003", "CVE-2026-1111"),
                                    finding_obj("GO-2026-0003", "stdlib"),
                                    finding_obj("GO-2026-0003", "stdlib", "net/http"))
        result, store = self.assess_go(finding, stdout)
        self.assertEqual((result.verdict, result.p), ("not_reachable", 0.0))
        self.assertTrue(result.summary)
        self.assertEqual(len(store.puts), 1)

    def test_alias_mapping_ignores_other_advisories(self):
        finding = make_finding("gosvc", eco="Go", name="stdlib", ids=("GO-2026-0009",), cves=("CVE-2026-2222",))
        stdout = govulncheck_stream(osv_obj("GO-2026-0003", "CVE-2026-1111"),
                                    finding_obj("GO-2026-0003", "stdlib", "net/http", "Serve"))
        result, store = self.assess_go(finding, stdout)
        self.assertEqual(result.verdict, "unknown")
        self.assertEqual(len(store.puts), 1)
        self.assertEqual(reach.unknown_retry_after(result), timedelta(hours=24))

    def test_alias_mapping_matches_cve_alias(self):
        osvs, findings = reach.parse_govulncheck(govulncheck_stream(
            osv_obj("GO-2026-0003", "CVE-2026-2222"),
            finding_obj("GO-2026-0003", "stdlib", "net/http", "Serve")))
        finding = make_finding(eco="Go", name="stdlib", ids=("DEBIAN-CVE-2026-2222",), cves=("CVE-2026-2222",))
        self.assertEqual(reach.govulncheck_level(osvs, findings, finding), "symbol")

    def test_tool_failure_is_unknown_and_retried_after_an_hour(self):
        finding = make_finding("gosvc", eco="Go", name="stdlib")
        result, store = self.assess_go(finding, "", returncode=1)
        self.assertEqual((result.verdict, result.method), ("unknown", "govulncheck"))
        self.assertIn("failed", result.summary)
        self.assertEqual(len(store.puts), 1)
        self.assertEqual(reach.unknown_retry_after(result), timedelta(hours=1))
        self.assertFalse(reach.cache_fresh(result, NOW + timedelta(hours=2)))


class AgentBase(Base):
    def setUp(self):
        super().setUp()
        app = self.home / "app"
        app.mkdir()
        self.lines = ["import brotli", "", "def handle(request):", "    body = request.read()",
                      "    return brotli.decompress(body)", ""]
        (app / "server.py").write_text("\n".join(self.lines))
        (app / ".env").write_text("SETTING=1\n")
        (app / "api_token.txt").write_text("nothing\n")
        self.spec = make_spec("web", reach_host_paths=["~/app"])
        self.inv = Inventory("web", NOW, "ok", "fp-web")
        self.prompts = []

    def reply(self, evidence, verdict="reachable"):
        return "Here you go:\n" + json.dumps({"verdict": verdict, "untrusted_sources": ["HTTP body"],
                                              "evidence": evidence, "summary": "body is decompressed"})

    def omp(self, evidence):
        def call(prompt):
            self.prompts.append(prompt)
            tree = Path(prompt.split("TREE=", 1)[1].splitlines()[0])
            self.assertTrue((tree / "host/app/server.py").is_file())
            self.assertFalse((tree / "host/app/.env").exists())
            self.assertFalse((tree / "host/app/api_token.txt").exists())
            return self.reply(evidence)
        return call

    def good_evidence(self):
        return [{"file": "host/app/server.py", "line": 5, "quote": "return brotli.decompress(body)",
                 "why": "decompresses request body"}]


class CitationTests(AgentBase):
    def test_invalid_citations_are_dropped(self):
        tree = Path(self.tmp.name) / "tree"
        (tree / "src").mkdir(parents=True)
        (tree / "src/a.py").write_text("\n".join(self.lines))
        outside = Path(self.tmp.name) / "outside.py"
        outside.write_text("\n".join(self.lines))
        items = [
            {"file": "../outside.py", "line": 5, "quote": "return brotli.decompress(body)", "why": "x"},
            {"file": str(outside), "line": 5, "quote": "return brotli.decompress(body)", "why": "x"},
            {"file": "src/a.py", "line": 99, "quote": "return brotli.decompress(body)", "why": "x"},
            {"file": "src/a.py", "line": 1, "quote": "return brotli.decompress(body)", "why": "x"},
            {"file": "src/a.py", "line": 5, "quote": "eval(body)", "why": "x"},
            {"file": "src/a.py", "line": 5, "why": "no quote"},
            {"file": "src/missing.py", "line": 1, "quote": "import brotli", "why": "x"},
            {"file": "src/a.py", "line": 4, "quote": "return   brotli.decompress(body)", "why": "ok"},
            {"file": str(tree / "src/a.py"), "line": 1, "quote": "import brotli", "why": "ok"},
        ]
        kept = reach.validate_evidence(items, tree)
        self.assertEqual([(e["file"], e["line"]) for e in kept], [("src/a.py", 4), ("src/a.py", 1)])

    def test_secret_bearing_evidence_is_dropped(self):
        tree = Path(self.tmp.name) / "tree"
        tree.mkdir()
        credential = "Bear" + "er " + "k7Pq" * 6
        (tree / "a.py").write_text(f"headers = {{'Authorization': '{credential}'}}\nimport brotli\n")
        items = [{"file": "a.py", "line": 1, "quote": credential, "why": "auth header"},
                 {"file": "a.py", "line": 2, "quote": "import brotli", "why": "loads it"}]
        kept = reach.validate_evidence(items, tree)
        self.assertEqual([e["line"] for e in kept], [2])

    def test_build_tree_skips_secret_names(self):
        tree = Path(self.tmp.name) / "t"
        tree.mkdir()
        reach.build_tree(self.spec, tree, run=None)
        self.assertTrue((tree / "host/app/server.py").is_file())
        self.assertFalse((tree / "host/app/.env").exists())
        self.assertFalse((tree / "host/app/api_token.txt").exists())


class JevTests(AgentBase):
    def run_agent(self, jev_client=None, load_jev=True, evidence=None):
        store = FakeStore(osv={"GHSA-test-0001": {"summary": "brotli decompression bomb", "details": ""}})
        finding = make_finding()
        result = reach.assess([finding], {"web": self.inv}, {"web": self.spec}, store=store, policy=self.policy,
                              now=NOW, omp_call=self.omp(self.good_evidence() if evidence is None else evidence),
                              jev_client=jev_client, load_jev=load_jev)
        return result[finding.key], store

    def test_thresholds_map_to_verdicts(self):
        self.assertEqual(reach.jev_verdict(0.85, 0.7, self.policy), "reachable")
        self.assertEqual(reach.jev_verdict(0.85, 0.5, self.policy), "unknown")
        self.assertEqual(reach.jev_verdict(0.5, 0.9, self.policy), "unknown")
        self.assertEqual(reach.jev_verdict(0.2, 0.9, self.policy), "not_reachable")

    def test_jev_reachable_is_cached_with_evidence(self):
        client = FakeJev(0.9, 0.8)
        result, store = self.run_agent(jev_client=client)
        self.assertEqual((result.verdict, result.method, result.p), ("reachable", "agent+jev", 0.9))
        self.assertEqual(result.evidence[0]["file"], "host/app/server.py")
        self.assertEqual(len(store.puts), 1)
        purpose, state, questions = client.calls[0]
        self.assertEqual(purpose, "security-watch-reach")
        self.assertEqual(set(questions), {"untrusted_reaches", "loaded"})
        self.assertIn("brotli decompression bomb", state["advisory_summary"])
        self.assertIn("brotli decompression bomb", self.prompts[0])

    def test_jev_low_probability_is_not_reachable(self):
        result, store = self.run_agent(jev_client=FakeJev(0.1, 0.9))
        self.assertEqual(result.verdict, "not_reachable")
        self.assertEqual(len(store.puts), 1)

    def test_jev_unavailable_is_unknown_and_retried_after_an_hour(self):
        result, store = self.run_agent(jev_client=FakeJev(error=FakeUnavailable("rate")))
        self.assertEqual(result.verdict, "unknown")
        self.assertEqual(result.summary, "Jev unavailable: rate")
        self.assertEqual(len(store.puts), 1)
        self.assertEqual(reach.unknown_retry_after(result), timedelta(hours=1))

    def test_jev_missing_is_unknown(self):
        result, store = self.run_agent(jev_client=None, load_jev=False)
        self.assertEqual(result.verdict, "unknown")
        self.assertTrue(result.summary.startswith("Jev unavailable"))
        self.assertEqual(len(store.puts), 1)

    def test_jev_middle_band_is_unknown_and_retried_after_a_day(self):
        result, store = self.run_agent(jev_client=FakeJev(0.5, 0.9))
        self.assertEqual(result.verdict, "unknown")
        self.assertEqual(len(store.puts), 1)
        self.assertEqual(reach.unknown_retry_after(result), timedelta(hours=24))

    def test_no_valid_evidence_is_unknown_without_jev(self):
        client = FakeJev()
        bad = [{"file": "host/app/server.py", "line": 1, "quote": "os.system(body)", "why": "x"}]
        result, store = self.run_agent(jev_client=client, evidence=bad)
        self.assertEqual(result.verdict, "unknown")
        self.assertEqual(client.calls, [])
        self.assertEqual(len(store.puts), 1)
        self.assertEqual(reach.unknown_retry_after(result), timedelta(hours=24))


class FactsTests(AgentBase):
    def setUp(self):
        super().setUp()
        self.spec = make_spec("web", container="freshrss", reach_host_paths=["~/app"], reach_facts={
            "php_curl_version": ["php", "-r", "var_export(curl_version());"],
            "leaky": ["printenv", "API_HEADER"],
        })
        self.runs = []
        self.fact_text = ""

    def fake_run(self, argv, **kwargs):
        self.runs.append((argv, kwargs))
        if argv[3] == "php":
            out = "array (\n  'version' => '8.14.1',\n  'brotli_version' => '1.1.0',\n)\n"
        else:
            out = "Authorization: " + "Bear" + "er " + "k7Pq" * 6 + "\n"
        return subprocess.CompletedProcess(argv, 0, out, "")

    def omp_reading_facts(self, prompt):
        tree = Path(prompt.split("TREE=", 1)[1].splitlines()[0])
        self.fact_text = (tree / "FACTS.txt").read_text()
        self.prompts.append(prompt)
        return self.reply(self.good_evidence() + [
            {"file": "FACTS.txt", "line": 3, "quote": "'brotli_version' => '1.1.0',", "why": "curl links brotli"}])

    def test_facts_written_secret_dropped_and_sent_to_jev(self):
        client = FakeJev(0.9, 0.9)
        finding = make_finding()
        result = reach.assess([finding], {"web": self.inv}, {"web": self.spec}, store=FakeStore(),
                              policy=self.policy, now=NOW, run=self.fake_run, omp_call=self.omp_reading_facts,
                              jev_client=client)
        self.assertEqual(result[finding.key].verdict, "reachable")
        self.assertIn((["docker", "exec", "freshrss", "php", "-r", "var_export(curl_version());"],
                       {"timeout": 30}), self.runs)
        self.assertTrue(self.fact_text.startswith("## php_curl_version\narray ("))
        self.assertNotIn("leaky", self.fact_text)
        self.assertNotIn("Authorization", self.fact_text)
        self.assertIn("FACTS.txt", self.prompts[0])
        state = client.calls[0][1]
        self.assertEqual(state["facts"], self.fact_text)
        self.assertIn("FACTS.txt", [e["file"] for e in state["evidence"]])

    def test_facts_change_the_cache_key(self):
        finding = make_finding()
        plain = reach.cache_key(self.inv, finding)
        one = reach.cache_key(self.inv, finding, "## a\n1\n")
        two = reach.cache_key(self.inv, finding, "## a\n2\n")
        self.assertEqual(len({plain, one, two}), 3)


class SchedulingTests(AgentBase):
    def test_agent_cap_defers_rest_uncached(self):
        findings = [make_finding(group=f"CVE-2026-100{i}", cves=(f"CVE-2026-100{i}",)) for i in range(3)]
        store = FakeStore()
        result = reach.assess(findings, {"web": self.inv}, {"web": self.spec}, store=store, policy=self.policy,
                              now=NOW, omp_call=self.omp(self.good_evidence()), jev_client=FakeJev(0.9, 0.9))
        self.assertEqual(len(self.prompts), 2)
        verdicts = [result[f.key].verdict for f in findings]
        self.assertEqual(verdicts, ["reachable", "reachable", "unknown"])
        self.assertEqual(result[findings[2].key].summary, "deferred")
        self.assertEqual(len(store.puts), 2)
        self.assertNotIn(reach.cache_key(self.inv, findings[2]), store.reach)

    def assess_batch(self, findings, store, policy, now=NOW):
        return reach.assess(findings, {"web": self.inv}, {"web": self.spec}, store=store, policy=policy,
                            now=now, omp_call=self.omp(self.good_evidence()), jev_client=FakeJev(0.9, 0.9))

    def test_below_threshold_finding_is_not_sent_to_agent(self):
        finding = make_finding(severity="medium")
        store = FakeStore()
        result = reach.assess([finding], {"web": self.inv}, {"web": self.spec}, store=store, policy=self.policy,
                              now=NOW, omp_call=lambda p: self.fail("no agent"), load_jev=False)
        got = result[finding.key]
        self.assertEqual((got.verdict, got.method, got.summary),
                         ("unknown", "none", "not assessed: below agent threshold"))
        self.assertEqual(store.puts, [])
        self.assertEqual(store.kv, {})

    def test_daily_cap_persists_within_day_and_resets_next_day(self):
        policy = dataclasses.replace(self.policy, reach_max_agent_calls_per_day=3)
        store = FakeStore()

        def batch(tag):
            return [make_finding(group=f"CVE-2026-{tag}{i}", cves=(f"CVE-2026-{tag}{i}",)) for i in range(3)]

        first = batch("11")
        self.assess_batch(first, store, policy)
        self.assertEqual(len(self.prompts), 2)
        self.assertEqual(store.kv["reach_agent_calls"], {"date": "2026-11-03", "count": 2})

        second = batch("22")
        result = self.assess_batch(second, store, policy, now=NOW + timedelta(hours=1))
        self.assertEqual(len(self.prompts), 3)
        self.assertEqual(store.kv["reach_agent_calls"], {"date": "2026-11-03", "count": 3})
        self.assertEqual([result[f.key].summary for f in second][1:], ["deferred", "deferred"])
        for f in second[1:]:
            self.assertNotIn(reach.cache_key(self.inv, f), store.reach)

        third = batch("33")
        self.assess_batch(third, store, policy, now=NOW + timedelta(days=1))
        self.assertEqual(len(self.prompts), 5)
        self.assertEqual(store.kv["reach_agent_calls"], {"date": "2026-11-04", "count": 2})

    def test_ordering_puts_kev_first(self):
        policy = dataclasses.replace(self.policy, reach_max_agent_calls_per_tick=1)
        findings = [
            make_finding(group="CVE-2026-3001", cves=("CVE-2026-3001",), severity="high"),
            make_finding(group="CVE-2026-3002", cves=("CVE-2026-3002",), severity="critical"),
            make_finding(group="CVE-2026-3003", cves=("CVE-2026-3003",), severity="low", kev=True),
        ]
        result = self.assess_batch(findings, FakeStore(), policy)
        self.assertEqual(len(self.prompts), 1)
        self.assertIn("CVE-2026-3003", self.prompts[0])
        self.assertEqual(result[findings[2].key].verdict, "reachable")
        self.assertEqual([result[f.key].summary for f in findings[:2]], ["deferred", "deferred"])
        ranked = sorted(findings[:2], key=lambda f: reach._priority((f, self.spec)))
        self.assertEqual([f.severity for f in ranked], ["critical", "high"])

    def test_cache_hit_skips_work(self):
        finding = make_finding()
        store = FakeStore()
        cached = Reach("not_reachable", "agent+jev", p=0.05, summary="cached")
        store.reach[reach.cache_key(self.inv, finding)] = cached
        result = reach.assess([finding], {"web": self.inv}, {"web": self.spec}, store=store, policy=self.policy,
                              now=NOW, run=lambda *a, **k: self.fail("no run"),
                              omp_call=lambda p: self.fail("no agent"), jev_client=FakeJev())
        self.assertEqual(result[finding.key].summary, "cached")
        self.assertIs(finding.reach, cached)
        self.assertEqual(store.puts, [])

    def assess_with_cached(self, cached):
        finding = make_finding()
        store = FakeStore()
        store.reach[reach.cache_key(self.inv, finding)] = cached
        result = reach.assess([finding], {"web": self.inv}, {"web": self.spec}, store=store, policy=self.policy,
                              now=NOW, omp_call=self.omp(self.good_evidence()), jev_client=FakeJev(0.9, 0.9))
        return result[finding.key], store

    def test_cached_unknown_within_backoff_is_reused(self):
        cached = Reach("unknown", "agent+jev", summary="agent cited no verifiable evidence",
                       assessed_at=(NOW - timedelta(hours=2)).isoformat())
        result, store = self.assess_with_cached(cached)
        self.assertIs(result, cached)
        self.assertEqual(self.prompts, [])
        self.assertEqual(store.puts, [])

    def test_cached_unknown_past_backoff_is_reassessed(self):
        cached = Reach("unknown", "agent+jev", summary="agent cited no verifiable evidence",
                       assessed_at=(NOW - timedelta(hours=25)).isoformat())
        result, store = self.assess_with_cached(cached)
        self.assertEqual(result.verdict, "reachable")
        self.assertEqual(len(self.prompts), 1)
        self.assertEqual(len(store.puts), 1)

    def test_cached_transient_unknown_is_retried_after_an_hour(self):
        cached = Reach("unknown", "agent+jev", summary="Jev unavailable: rate",
                       assessed_at=(NOW - timedelta(hours=2)).isoformat())
        result, store = self.assess_with_cached(cached)
        self.assertEqual(result.verdict, "reachable")
        self.assertEqual(len(self.prompts), 1)

    def test_unexposed_component_is_not_assessed(self):
        finding = make_finding()
        spec = make_spec(exposure="loopback", untrusted="")
        result = reach.assess([finding], {"web": self.inv}, {"web": spec}, store=FakeStore(), policy=self.policy,
                              now=NOW, omp_call=lambda p: self.fail("no agent"), load_jev=False)
        self.assertEqual((result[finding.key].verdict, result[finding.key].method), ("unknown", "none"))

    def test_expired_deadline_defers(self):
        finding = make_finding()
        store = FakeStore()
        result = reach.assess([finding], {"web": self.inv}, {"web": self.spec}, store=store, policy=self.policy,
                              now=NOW, omp_call=lambda p: self.fail("no agent"), load_jev=False, deadline=0.0)
        self.assertEqual(result[finding.key].summary, "deferred")
        self.assertEqual(store.puts, [])


if __name__ == "__main__":
    unittest.main()
