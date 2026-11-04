import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import contextlib
import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest import mock

import deploy_lock
from security_watch import config, model, playbooks_ops
from security_watch.model import Finding, Inventory, Package, Plan, Refusal
from steward import toolchains as steward_toolchains
from steward import updates as steward_updates

NOW = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)


def digest(ch: str) -> str:
    return "sha256:" + ch * 64


def sha(ch: str) -> str:
    return ch * 40


class FakeRun:
    """argv-prefix rules; the first matching rule answers (callable or (rc, stdout))."""

    def __init__(self):
        self.rules = []
        self.calls = []

    def on(self, prefix, answer):
        self.rules.append((tuple(prefix), answer))

    def __call__(self, argv, *, timeout=120, input=None, env=None, cwd=None):
        argv = [str(a) for a in argv]
        self.calls.append(argv)
        for prefix, answer in self.rules:
            if tuple(argv[:len(prefix)]) == prefix:
                if callable(answer):
                    answer = answer(argv)
                rc, out = answer
                return subprocess.CompletedProcess(argv, rc, out, "")
        return subprocess.CompletedProcess(argv, 0, "", "")

    def called(self, prefix):
        return [c for c in self.calls if tuple(c[:len(prefix)]) == tuple(prefix)]


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def json(self):
        return self.payload


class FakeFetch:
    def __init__(self, routes):
        self.routes = routes
        self.urls = []

    def __call__(self, url, **kwargs):
        self.urls.append(url)
        if url not in self.routes:
            raise RuntimeError(f"unexpected fetch {url}")
        return FakeResponse(self.routes[url])


class FakeStore:
    def __init__(self, inventories=None):
        self.inventories = inventories or {}

    def get_inventory(self, component_id):
        return self.inventories.get(component_id)


def fake_lock(calls, *, busy=False):
    @contextlib.contextmanager
    def lock(key="host", *, timeout=None, holder=""):
        calls.append((key, timeout, holder))
        if busy:
            raise deploy_lock.LockTimeout(key, {"holder": "steward:p1"})
        yield
    return lock


def make_ctx(*, run=None, fetch=None, specs=None, findings=(), store=None, busy=False):
    lock_calls = []
    ctx = SimpleNamespace(
        store=store or FakeStore(),
        policy=SimpleNamespace(lock_timeout_seconds=5, release_min_age_hours=72),
        specs=specs or {},
        now=NOW,
        run=run or FakeRun(),
        fetch=fetch or FakeFetch({}),
        lock=fake_lock(lock_calls, busy=busy),
        host_lock=fake_lock(lock_calls, busy=busy),
        steward_active=lambda: False,
        rescan=lambda component: [],
        findings={f.key: f for f in findings},
    )
    ctx.lock_calls = lock_calls
    return ctx


def spec(**fields):
    base = {"id": "x", "kind": "container", "collector": "container", "exposure": "public",
            "owner": "alert", "lock": "x"}
    base.update(fields)
    core = {k: base.pop(k) for k in list(base) if k in config._SPEC_FIELDS}
    if "health" in core:
        core["health"] = tuple(core["health"])
    return config.ComponentSpec(**core, extra=base)


def finding(component, eco, name, version, fixed, ids=("ADV-1",)):
    return Finding(key=f"{component}|CVE-2026-1", component_id=component, group="CVE-2026-1",
                   package=Package(eco, name, version), advisory_ids=list(ids), cves=["CVE-2026-1"],
                   fixed_versions=list(fixed), fix_available=bool(fixed))


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def sleep(self, seconds):
        self.t += seconds

    def __call__(self):
        return self.t


class TempHomeCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.state = self.home / "state"
        patcher = mock.patch.dict(os.environ, {"HOME": str(self.home),
                                               "SECURITY_WATCH_STATE_DIR": str(self.state)})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)
        self.clock = FakeClock()

    def pb(self, cls, **kwargs):
        return cls(sleep=self.clock.sleep, clock=self.clock, **kwargs)


class StewardImageTests(TempHomeCase):
    def test_freshrss_plan_refuses_when_candidate_equals_current(self):
        compose = self.home / "freshrss" / "docker-compose.yml"
        compose.parent.mkdir()
        compose.write_text(f"services:\n  freshrss:\n    image: freshrss/freshrss:1.30.4@{digest('a')}\n")
        up = SimpleNamespace(
            FRESHRSS_COMPOSE=compose, FRESHRSS_UP=compose.parent / "up.sh",
            FRESHRSS_TAGS_API=steward_updates.FRESHRSS_TAGS_API,
            _FRESHRSS_PIN_RE=steward_updates._FRESHRSS_PIN_RE,
            _select_freshrss_tag=steward_updates._select_freshrss_tag)
        fetch = FakeFetch({up.FRESHRSS_TAGS_API: {"results": [
            {"name": "1.30.4", "digest": digest("a"), "last_updated": "2026-10-01T00:00:00Z"},
            {"name": "latest", "digest": digest("a"), "last_updated": "2026-10-01T00:00:00Z"}]}})
        f = finding("freshrss", "Debian:13", "brotli", "1.1.0-2", ["1.1.0-2+deb13u1"])
        sp = spec(id="freshrss", owner="steward-freshrss", lock="freshrss")
        result = self.pb(playbooks_ops.StewardFreshRSS, updates=up).plan([f], sp, make_ctx(fetch=fetch))
        self.assertIsInstance(result, Refusal)
        self.assertTrue(result.alert)
        self.assertEqual(result.reason, "no newer upstream FreshRSS release; current image 1.30.4 "
                                        "still ships brotli 1.1.0-2")

    def test_freshrss_lock_timeout_is_refused_without_touching_production(self):
        f = finding("freshrss", "Debian:13", "brotli", "1.1.0-2", ["1.1.0-2+deb13u1"])
        sp = spec(id="freshrss", owner="steward-freshrss", lock="freshrss")
        run = FakeRun()
        called = []
        up = SimpleNamespace(_p1_freshrss_update=lambda **kw: called.append(kw) or {"status": "bumped"})
        ctx = make_ctx(run=run, specs={"freshrss": sp}, findings=[f], busy=True)
        plan = Plan(playbook="steward-freshrss", component_id="freshrss", finding_keys=[f.key],
                    target="freshrss 1.30.5", lock_keys=["freshrss"], steps=[], undo="",
                    state={"image": "freshrss/freshrss:1.30.5@" + digest("b"),
                           "item": {"name": "1.30.5", "digest": digest("b")}})
        outcome = self.pb(playbooks_ops.StewardFreshRSS, updates=up).apply(plan, ctx)
        self.assertEqual(outcome.status, "refused")
        self.assertIs(outcome.state["production_touched"], False)
        self.assertEqual(ctx.lock_calls, [("freshrss", 5, "security-watch:steward-freshrss")])
        self.assertEqual(run.calls, [])
        self.assertEqual(called, [])

    def test_searxng_young_tag_sets_min_age_zero_and_release_published(self):
        compose = self.home / "searxng" / "docker-compose.yml"
        compose.parent.mkdir()
        compose.write_text(f"services:\n  searxng:\n    image: docker.io/searxng/searxng@{digest('c')}\n")
        up = SimpleNamespace(
            HOME=self.home, SEARXNG_TAGS_API=steward_updates.SEARXNG_TAGS_API,
            _searxng_tag_date=steward_updates._searxng_tag_date,
            _select_mature_searxng_tag=steward_updates._select_mature_searxng_tag)
        published = NOW - timedelta(days=1)
        fetch = FakeFetch({up.SEARXNG_TAGS_API: {"results": [
            {"name": "2026.11.2-abc1234", "digest": digest("d"),
             "last_updated": published.isoformat().replace("+00:00", "Z")},
            {"name": "2026.10.20-def5678", "digest": digest("c"), "last_updated": "2026-10-20T08:00:00Z"}]}})
        run = FakeRun()
        run.on(["docker", "inspect", "searxng"], (0, "2026.10.20-def5678\n"))
        f = finding("searxng", "PyPI", "lxml", "6.0.0", ["6.0.1"])
        sp = spec(id="searxng", owner="steward-searxng", lock="searxng")
        plan = self.pb(playbooks_ops.StewardSearXNG, updates=up).plan([f], sp, make_ctx(run=run, fetch=fetch))
        self.assertIsInstance(plan, Plan)
        self.assertEqual(plan.state["min_age_days"], 0)
        self.assertEqual(plan.release_published, model.iso(published))
        self.assertEqual(plan.state["image"], "docker.io/searxng/searxng@" + digest("d"))
        self.assertEqual(plan.fixed_version, "6.0.1")


class ToolchainTests(TempHomeCase):
    def test_toolchain_refuses_fix_on_another_minor_line(self):
        f = finding("go-root", "Go", "stdlib", "1.26.10", ["1.27.4"])
        sp = spec(id="go-root", kind="runtime", owner="steward-toolchain", lock="toolchain-go-root",
                  toolchain="go_root")
        pb = self.pb(playbooks_ops.StewardToolchain, toolchains=steward_toolchains,
                     releases=lambda name, store: [{"version": "1.27.4"}, {"version": "1.26.10"}])
        result = pb.plan([f], sp, make_ctx())
        self.assertIsInstance(result, Refusal)
        self.assertTrue(result.alert)
        self.assertIn("another line", result.reason)

    def test_toolchain_plans_same_line_release(self):
        f = finding("go-user", "Go", "stdlib", "1.27.3", ["1.26.11", "1.27.4"])
        sp = spec(id="go-user", kind="runtime", owner="steward-toolchain", lock="toolchain-go-user",
                  toolchain="go_user")
        pb = self.pb(playbooks_ops.StewardToolchain, toolchains=steward_toolchains,
                     releases=lambda name, store: [{"version": "1.27.4"}, {"version": "1.26.11"}])
        plan = pb.plan([f], sp, make_ctx())
        self.assertIsInstance(plan, Plan)
        self.assertEqual(plan.state["step"], "toolchain_go_user")
        self.assertEqual(plan.fixed_version, "1.27.4")


class ReleaseRebuildTests(TempHomeCase):
    def setUp(self):
        super().setUp()
        (self.home / ".local/go").mkdir(parents=True)
        (self.home / ".local/go/VERSION").write_text("go1.27.4\ntime 2026-10-30\n")
        self.repo = self.home / "dev" / "opencode-go-proxy"
        (self.repo / ".git").mkdir(parents=True)
        self.binary = self.home / ".local/bin/opencode-go-proxy"
        self.binary.parent.mkdir(parents=True)
        self.binary.write_bytes(b"old-binary")
        self.spec = spec(id="opencode-go-proxy", kind="host-binary", collector="go-binary",
                         owner="release-rebuild", lock="opencode-go-proxy", repo="opencode-go-proxy",
                         binaries=["~/.local/bin/opencode-go-proxy"], release=["bash", "release.sh"],
                         transactional=False, units=["opencode-go-proxy.service"],
                         health=["http://127.0.0.1:8082/health"])
        self.finding = finding("opencode-go-proxy", "Go", "stdlib", "1.27.3", ["1.26.11", "1.27.4"])
        self.head = sha("1")

    def store(self, revision=None):
        inv = Inventory(component_id="opencode-go-proxy", collected_at=NOW, status="ok", fingerprint="f",
                        meta={"binaries": [{"path": str(self.binary), "go_version": "go1.27.3",
                                            "vcs_revision": revision or self.head}]})
        return FakeStore({"opencode-go-proxy": inv})

    def git_run(self, *, dirty="", branch="main", origin=None):
        run = FakeRun()
        run.on(["git", "-C", str(self.repo), "status"], (0, dirty))
        run.on(["git", "-C", str(self.repo), "branch"], (0, branch + "\n"))
        run.on(["git", "-C", str(self.repo), "fetch"], (0, ""))
        run.on(["git", "-C", str(self.repo), "rev-parse", "HEAD"], (0, self.head + "\n"))
        run.on(["git", "-C", str(self.repo), "rev-parse", "origin/main"], (0, (origin or self.head) + "\n"))
        return run

    def plan(self, run, store=None):
        pb = self.pb(playbooks_ops.ReleaseRebuild)
        return pb, pb.plan([self.finding], self.spec, make_ctx(run=run, store=store or self.store(),
                                                                 specs={self.spec.id: self.spec},
                                                                 findings=[self.finding]))

    def test_refuses_dirty_tree(self):
        _, result = self.plan(self.git_run(dirty=" M main.go\n"))
        self.assertIsInstance(result, Refusal)
        self.assertTrue(result.alert)
        self.assertIn("uncommitted changes", result.reason)

    def test_refuses_head_not_origin_main(self):
        _, result = self.plan(self.git_run(origin=sha("2")))
        self.assertIsInstance(result, Refusal)
        self.assertTrue(result.alert)
        self.assertIn("origin/main", result.reason)

    def test_refuses_binary_revision_mismatch(self):
        _, result = self.plan(self.git_run(), store=self.store(revision=sha("3")))
        self.assertIsInstance(result, Refusal)
        self.assertTrue(result.alert)
        self.assertIn("would ship new code", result.reason)

    def test_refuses_when_host_go_is_affected(self):
        (self.home / ".local/go/VERSION").write_text("go1.27.3\n")
        run = self.git_run()
        _, result = self.plan(run)
        self.assertIsInstance(result, Refusal)
        self.assertFalse(result.alert)
        self.assertEqual(result.reason, "host Go 1.27.3 is affected; the go-user toolchain fix comes first")
        self.assertEqual(run.calls, [])

    def test_non_transactional_health_failure_restores_snapshot_and_restarts_units(self):
        run = self.git_run()

        def release(argv):
            self.binary.write_bytes(b"new-binary")
            return 0, "built"

        run.on(["bash", "release.sh"], release)
        pb, plan = self.plan(run)
        self.assertIsInstance(plan, Plan)
        pb.probe = lambda url, host: 200 if self.binary.read_bytes() == b"old-binary" else 503
        ctx = make_ctx(run=run, store=self.store(), specs={self.spec.id: self.spec}, findings=[self.finding])
        outcome = pb.apply(plan, ctx)
        self.assertEqual(outcome.status, "rolled_back", outcome.detail)
        self.assertIs(outcome.state["production_touched"], True)
        self.assertEqual(self.binary.read_bytes(), b"old-binary")
        self.assertEqual(run.called(["systemctl", "--user", "restart"]),
                         [["systemctl", "--user", "restart", "opencode-go-proxy.service"]])
        snapshots = list((self.state / "rollback" / "opencode-go-proxy").glob("*/opencode-go-proxy"))
        self.assertEqual(len(snapshots), 1)
        self.assertEqual(snapshots[0].read_bytes(), b"old-binary")
        self.assertIn(str(snapshots[0]), outcome.undo)
        self.assertEqual(ctx.lock_calls, [("opencode-go-proxy", 5, "security-watch:release-rebuild")])


class ComposeDigestTests(TempHomeCase):
    def setUp(self):
        super().setUp()
        self.compose = self.home / "news" / "docker-compose.yml"
        self.compose.parent.mkdir()
        self.old = f"    image: nginx:1.31.7-alpine@{digest('a')}"
        self.text = f"name: carter-news\n\nservices:\n  web:\n{self.old}\n    container_name: carter-news\n"
        self.compose.write_text(self.text)
        self.spec = spec(id="news", owner="compose-digest", lock="news", compose="~/news/docker-compose.yml",
                         up=["bash", "~/news/up.sh"], health=["http://127.0.0.1:30144/healthz"])
        self.finding = finding("news", "Alpine:v3.24", "brotli", "1.2.0-r1", ["1.2.0-r2"],
                               ids=("ALPINE-CVE-2026-1",))
        base = "https://hub.docker.com/v2/repositories/library/nginx/tags"
        self.fetch = FakeFetch({
            f"{base}/1.31.7-alpine": {"name": "1.31.7-alpine", "digest": digest("a"),
                                      "last_updated": "2026-10-15T16:51:32.549484Z"},
            f"{base}?name=1.31.&page_size=100": {"next": None, "results": [
                {"name": "1.31.8-perl", "digest": digest("e"), "last_updated": "2026-11-03T04:51:37Z"},
                {"name": "1.31.8-alpine3.24", "digest": digest("b"), "last_updated": "2026-10-28T22:51:25Z"},
                {"name": "1.31.8-alpine", "digest": digest("b"), "last_updated": "2026-10-28T22:51:19Z"},
                {"name": "1.31.7-alpine", "digest": digest("a"), "last_updated": "2026-10-15T16:51:32Z"}]},
        })
        self.run = FakeRun()
        self.run.on(["docker", "pull"], (0, ""))
        self.run.on(["docker", "run"], (0, "brotli-libs-1.2.0-r2 x86_64 {brotli} (MIT) [installed]\n"
                                           "musl-1.2.5-r10 x86_64 {musl} (MIT) [installed]\n"))
        self.ups = []
        self.run.on(["bash", str(self.home / "news/up.sh")],
                    lambda argv: self.ups.append(self.compose.read_text()) or (0, "up"))
        self.queried = []

    def querybatch(self, packages, *, fetch):
        self.queried.extend(packages)
        return {}

    def make(self):
        pb = self.pb(playbooks_ops.ComposeDigest, querybatch=self.querybatch)
        ctx = make_ctx(run=self.run, fetch=self.fetch, specs={"news": self.spec}, findings=[self.finding])
        plan = pb.plan([self.finding], self.spec, ctx)
        self.assertIsInstance(plan, Plan)
        return pb, ctx, plan

    def test_plan_picks_newest_same_minor_alpine_patch(self):
        _, _, plan = self.make()
        self.assertEqual(plan.state["image"], "nginx:1.31.8-alpine@" + digest("b"))
        self.assertEqual(plan.release_published, "2026-10-28T22:51:19+00:00")

    def test_apply_rewrites_only_the_image_line(self):
        pb, ctx, plan = self.make()
        pb.probe = lambda url, host: 200
        outcome = pb.apply(plan, ctx)
        self.assertEqual(outcome.status, "done", outcome.detail)
        expected = self.text.replace(self.old, "    image: nginx:1.31.8-alpine@" + digest("b"))
        self.assertEqual(self.compose.read_text(), expected)
        self.assertEqual(self.queried, [Package("Alpine:v3.24", "brotli", "1.2.0-r2")])
        self.assertIs(outcome.state["production_touched"], True)

    def test_health_failure_restores_original_compose(self):
        pb, ctx, plan = self.make()
        pb.probe = lambda url, host: 503 if digest("b") in self.compose.read_text() else 200
        outcome = pb.apply(plan, ctx)
        self.assertEqual(outcome.status, "rolled_back", outcome.detail)
        self.assertEqual(len(self.ups), 2)
        self.assertIn(digest("b"), self.ups[0])
        self.assertEqual(self.ups[1], self.text)
        self.assertEqual(self.compose.read_text(), self.text)
        self.assertIs(outcome.state["production_touched"], True)

    def test_candidate_still_affected_is_refused_before_switching(self):
        pb, ctx, plan = self.make()
        pb.querybatch = lambda packages, fetch: {p: [("ALPINE-CVE-2026-1", "x")] for p in packages}
        outcome = pb.apply(plan, ctx)
        self.assertEqual(outcome.status, "refused")
        self.assertIs(outcome.state["production_touched"], False)
        self.assertEqual(self.compose.read_text(), self.text)
        self.assertEqual(self.ups, [])


class AptSecurityTests(TempHomeCase):
    @staticmethod
    def compare(argv):
        a, op, b = argv[2], argv[3], argv[4]
        assert op == "ge"
        return (0 if a and a >= b else 1), ""

    def test_refuses_without_fixed_candidate(self):
        run = FakeRun()
        run.on(["dpkg-query", "-W"], (0, "ii \topenssl\tlibssl3t64\t3.0.13-0ubuntu3.4\n"
                                         "ii \topenssl\topenssl\t3.0.13-0ubuntu3.4\n"
                                         "ii \tbash\tbash\t5.2.21-2ubuntu4\n"))
        run.on(["apt-cache", "policy"], (0, "libssl3t64:\n  Installed: 3.0.13-0ubuntu3.4\n"
                                            "  Candidate: 3.0.13-0ubuntu3.4\n  Version table:\n"
                                            "openssl:\n  Installed: 3.0.13-0ubuntu3.4\n"
                                            "  Candidate: 3.0.13-0ubuntu3.4\n"))
        run.on(["dpkg", "--compare-versions"], self.compare)
        f = finding("host", "Ubuntu:24.04:LTS", "openssl", "3.0.13-0ubuntu3.4", ["3.0.13-0ubuntu3.5"])
        sp = spec(id="host", kind="host", collector="host-dpkg", owner="apt-security", lock="host")
        result = self.pb(playbooks_ops.AptSecurity).plan([f], sp, make_ctx(run=run))
        self.assertIsInstance(result, Refusal)
        self.assertTrue(result.alert)
        self.assertIn("no apt candidate >= fixed 3.0.13-0ubuntu3.5", result.reason)
        self.assertEqual(run.called(["sudo"]), [])

    def test_plans_upgrade_when_candidate_is_fixed(self):
        run = FakeRun()
        run.on(["dpkg-query", "-W"], (0, "ii \topenssl\tlibssl3t64\t3.0.13-0ubuntu3.4\n"))
        run.on(["apt-cache", "policy"], (0, "libssl3t64:\n  Installed: 3.0.13-0ubuntu3.4\n"
                                            "  Candidate: 3.0.13-0ubuntu3.5\n"))
        run.on(["dpkg", "--compare-versions"], self.compare)
        f = finding("host", "Ubuntu:24.04:LTS", "openssl", "3.0.13-0ubuntu3.4", ["3.0.13-0ubuntu3.5"])
        sp = spec(id="host", kind="host", collector="host-dpkg", owner="apt-security", lock="host")
        plan = self.pb(playbooks_ops.AptSecurity).plan([f], sp, make_ctx(run=run))
        self.assertIsInstance(plan, Plan)
        self.assertEqual(plan.state["packages"], ["libssl3t64"])
        self.assertEqual(plan.undo, "sudo apt-get install --allow-downgrades libssl3t64=3.0.13-0ubuntu3.4")


class RegistryTests(unittest.TestCase):
    def test_registry_has_every_ops_playbook_single_tick(self):
        self.assertEqual(set(playbooks_ops.PLAYBOOKS), {
            "apt-security", "steward-freshrss", "steward-openwebui", "steward-searxng", "steward-omp",
            "steward-herdr", "steward-toolchain", "release-rebuild", "compose-digest"})
        for key, pb in playbooks_ops.PLAYBOOKS.items():
            self.assertEqual(pb.id, key)
            self.assertFalse(pb.multi_tick)


if __name__ == "__main__":
    unittest.main()
