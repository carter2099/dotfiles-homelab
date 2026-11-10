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
from security_watch import config, inventory, model, playbooks_ops
from security_watch.model import Finding, Inventory, Package, Plan, Refusal, Signal
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
    def __init__(self, inventories=None, signals=None):
        self.inventories = inventories or {}
        self.signals = signals or {}   # (source, key) -> (Signal, first_seen)

    def get_inventory(self, component_id):
        return self.inventories.get(component_id)

    def signal(self, source, key):
        hit = self.signals.get((source, key))
        return hit[0] if hit else None

    def signals_since(self, since, *, sources=None):
        return [(sig, first, first) for (source, _), (sig, first) in self.signals.items()
                if sources is None or source in sources]


def go_signal(version, published=None):
    return Signal(source="go_releases", key=f"go{version}", version=version, title=f"Go {version} released",
                  url="https://go.dev/doc/devel/release", tier="issuer", published=published)


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


def finding(component, eco, name, version, fixed, ids=("ADV-1",), group="CVE-2026-1", **extra):
    return Finding(key=f"{component}|{group}", component_id=component, group=group,
                   package=Package(eco, name, version), advisory_ids=list(ids), cves=[group],
                   fixed_versions=list(fixed), fix_available=bool(fixed), **extra)


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


class EnvRun(FakeRun):
    """FakeRun that also records the env each argv[0] was run with."""

    def __init__(self):
        super().__init__()
        self.envs = {}

    def __call__(self, argv, **kwargs):
        self.envs[str(argv[0])] = kwargs.get("env")
        return super().__call__(argv, **kwargs)


class StewardImageTests(TempHomeCase):
    FRESHRSS_PIN = f"freshrss/freshrss:1.30.4@{digest('a')}"
    STAMP = "20261103T120000Z"
    ROLLBACK = "freshrss-local:rollback-20261103T120000Z"
    CANDIDATE = "freshrss-local:candidate-20261103T120000Z"
    RUNNING = digest("e")

    def freshrss_up(self, *, derived=True):
        compose = self.home / "freshrss" / "docker-compose.yml"
        compose.parent.mkdir(exist_ok=True)
        if derived:
            compose.write_text(
                "services:\n  freshrss:\n    build:\n      context: .\n      args:\n"
                f"        FRESHRSS_BASE: {self.FRESHRSS_PIN}\n"
                "        SECURITY_REFRESH: ${SECURITY_REFRESH:-0}\n"
                "    image: freshrss-local:current\n    container_name: freshrss\n")
        else:
            compose.write_text(f"services:\n  freshrss:\n    image: {self.FRESHRSS_PIN}\n")
        return SimpleNamespace(
            FRESHRSS_COMPOSE=compose, FRESHRSS_UP=compose.parent / "up.sh",
            FRESHRSS_TAGS_API=steward_updates.FRESHRSS_TAGS_API,
            _FRESHRSS_PIN_RE=steward_updates._FRESHRSS_PIN_RE,
            _select_freshrss_tag=steward_updates._select_freshrss_tag,
            _p1_freshrss_update=mock.Mock(side_effect=AssertionError("tag path must not run")))

    @staticmethod
    def freshrss_fetch(up):
        return FakeFetch({up.FRESHRSS_TAGS_API: {"results": [
            {"name": "1.30.4", "digest": digest("a"), "last_updated": "2026-10-01T00:00:00Z"},
            {"name": "latest", "digest": digest("a"), "last_updated": "2026-10-01T00:00:00Z"}]}})

    @staticmethod
    def freshrss_spec():
        return spec(id="freshrss", owner="steward-freshrss", lock="freshrss", container="freshrss",
                    health=["http://127.0.0.1:30149/i/"])

    @staticmethod
    def brotli():
        return finding("freshrss", "Debian:13", "brotli", "1.1.0-2", ["1.1.0-2+deb13u1"])

    def freshrss_run(self, candidate_brotli="1.1.0-2+deb13u1", up_rc=0):
        run = EnvRun()
        run.on(["docker", "build"], (0, ""))
        run.on(["docker", "run"], (0, f"brotli\t{candidate_brotli}\nzlib\t1.3\n"))
        run.on(["docker", "inspect"], (0, self.RUNNING + "\n"))
        run.on([str(self.home / "freshrss" / "up.sh")], (up_rc, ""))
        return run

    @staticmethod
    def osv(vulnerable):
        def querybatch(packages, *, fetch):
            return {p: [("ADV-1", None)] for p in packages if p.version in vulnerable}
        return querybatch

    def refresh_plan(self, up):
        f = self.brotli()
        plan = self.pb(playbooks_ops.StewardFreshRSS, updates=up).plan(
            [f], self.freshrss_spec(), make_ctx(fetch=self.freshrss_fetch(up)))
        self.assertIsInstance(plan, Plan)
        return f, plan

    def test_freshrss_plan_refreshes_derived_image_when_upstream_has_no_newer_tag(self):
        up = self.freshrss_up()
        _, plan = self.refresh_plan(up)
        self.assertEqual(plan.target, "freshrss derived image refresh (Debian security updates for brotli)")
        self.assertIsNone(plan.release_published)
        self.assertEqual(plan.fixed_version, "1.1.0-2+deb13u1")
        self.assertEqual(plan.lock_keys, ["freshrss"])
        self.assertEqual(plan.state["refresh"], self.STAMP)
        self.assertEqual(plan.state["rollback"], self.ROLLBACK)
        self.assertEqual(plan.undo, f"docker tag {self.ROLLBACK} freshrss-local:current && "
                                    f"cd {up.FRESHRSS_COMPOSE.parent} && "
                                    "docker compose up -d --no-build --force-recreate")

    def test_freshrss_plan_refuses_when_no_newer_tag_and_not_a_debian_package(self):
        up = self.freshrss_up()
        f = finding("freshrss", "Packagist", "guzzlehttp/guzzle", "7.0.0", ["7.0.1"])
        result = self.pb(playbooks_ops.StewardFreshRSS, updates=up).plan(
            [f], self.freshrss_spec(), make_ctx(fetch=self.freshrss_fetch(up)))
        self.assertIsInstance(result, Refusal)
        self.assertTrue(result.alert)
        self.assertEqual(result.reason, "no newer upstream FreshRSS release; current image 1.30.4 "
                                        "still ships guzzlehttp/guzzle 7.0.0")

    def test_freshrss_plan_refuses_refresh_without_the_derived_build(self):
        up = self.freshrss_up(derived=False)
        result = self.pb(playbooks_ops.StewardFreshRSS, updates=up).plan(
            [self.brotli()], self.freshrss_spec(), make_ctx(fetch=self.freshrss_fetch(up)))
        self.assertIsInstance(result, Refusal)
        self.assertIn("is not the derived build", result.reason)

    def test_freshrss_refresh_builds_verifies_and_deploys_candidate(self):
        up = self.freshrss_up()
        f, plan = self.refresh_plan(up)
        run = self.freshrss_run()
        ctx = make_ctx(run=run, specs={"freshrss": self.freshrss_spec()}, findings=[f])
        pb = self.pb(playbooks_ops.StewardFreshRSS, updates=up, querybatch=self.osv({"1.1.0-2"}),
                     probe=lambda url, host: 200)
        outcome = pb.apply(plan, ctx)
        self.assertEqual(outcome.status, "done", outcome.detail)
        self.assertIs(outcome.state["production_touched"], True)
        self.assertEqual(outcome.undo, plan.undo)
        up_sh = str(up.FRESHRSS_UP)
        self.assertEqual(run.called(["docker", "build"]), [[
            "docker", "build", "--build-arg", f"FRESHRSS_BASE={self.FRESHRSS_PIN}",
            "--build-arg", f"SECURITY_REFRESH={self.STAMP}", "-t", self.CANDIDATE,
            str(up.FRESHRSS_COMPOSE.parent)]])
        self.assertIn(["docker", "run", "--rm", "--network", "none", "--entrypoint", "dpkg-query",
                       self.CANDIDATE], [c[:8] for c in run.calls])
        order = [c[0] if c[0] != "docker" else " ".join(c[:2]) for c in run.calls]
        self.assertEqual(order, ["docker build", "docker run", "docker inspect", "docker tag", up_sh,
                                 "docker image"])
        self.assertEqual(run.called(["docker", "tag"]), [["docker", "tag", self.RUNNING, self.ROLLBACK]])
        self.assertEqual(run.envs[up_sh]["SECURITY_REFRESH"], self.STAMP)
        self.assertEqual(run.called(["docker", "image", "rm"]), [["docker", "image", "rm", self.CANDIDATE]])
        self.assertEqual(ctx.lock_calls, [("freshrss", 5, "security-watch:steward-freshrss")])
        up._p1_freshrss_update.assert_not_called()
        self.assertEqual(outcome.state["verified_keys"], [f.key])

    def test_freshrss_refresh_refuses_candidate_that_still_ships_the_vulnerable_version(self):
        up = self.freshrss_up()
        f, plan = self.refresh_plan(up)
        run = self.freshrss_run(candidate_brotli="1.1.0-2")
        ctx = make_ctx(run=run, specs={"freshrss": self.freshrss_spec()}, findings=[f])
        pb = self.pb(playbooks_ops.StewardFreshRSS, updates=up, querybatch=self.osv({"1.1.0-2"}),
                     probe=lambda url, host: 200)
        outcome = pb.apply(plan, ctx)
        self.assertEqual(outcome.status, "refused")
        self.assertIs(outcome.state["production_touched"], False)
        self.assertIn("still ships brotli 1.1.0-2 affected by ADV-1", outcome.detail)
        self.assertEqual(run.called([str(up.FRESHRSS_UP)]), [])
        self.assertEqual(run.called(["docker", "tag"]), [])
        self.assertEqual(run.called(["docker", "image", "rm"]), [["docker", "image", "rm", self.CANDIDATE]])

    def test_freshrss_refresh_rolls_back_on_health_failure(self):
        up = self.freshrss_up()
        f, plan = self.refresh_plan(up)
        run = self.freshrss_run()
        restore = ["docker", "tag", self.ROLLBACK, "freshrss-local:current"]
        probe = lambda url, host: 200 if run.called(restore) else 503
        ctx = make_ctx(run=run, specs={"freshrss": self.freshrss_spec()}, findings=[f])
        pb = self.pb(playbooks_ops.StewardFreshRSS, updates=up, querybatch=self.osv({"1.1.0-2"}),
                     probe=probe)
        outcome = pb.apply(plan, ctx)
        self.assertEqual(outcome.status, "rolled_back", outcome.detail)
        self.assertIs(outcome.state["production_touched"], True)
        self.assertIn("health failed", outcome.detail)
        self.assertIn("docker compose up -d --no-build --force-recreate", outcome.undo)
        self.assertEqual(run.called(restore), [restore])
        self.assertEqual(run.called(["docker", "compose"]), [[
            "docker", "compose", "-f", str(up.FRESHRSS_COMPOSE), "up", "-d", "--no-build",
            "--force-recreate"]])

    def test_freshrss_refresh_failed_when_rollback_stays_unhealthy(self):
        up = self.freshrss_up()
        f, plan = self.refresh_plan(up)
        run = self.freshrss_run(up_rc=1)
        ctx = make_ctx(run=run, specs={"freshrss": self.freshrss_spec()}, findings=[f])
        pb = self.pb(playbooks_ops.StewardFreshRSS, updates=up, querybatch=self.osv({"1.1.0-2"}),
                     probe=lambda url, host: 0)
        outcome = pb.apply(plan, ctx)
        self.assertEqual(outcome.status, "failed")
        self.assertIs(outcome.state["production_touched"], True)
        self.assertIn("exited 1", outcome.detail)
        self.assertEqual(outcome.undo, plan.undo)

    def test_freshrss_lock_timeout_is_refused_without_touching_production(self):
        f = self.brotli()
        sp = self.freshrss_spec()
        up = self.freshrss_up()
        _, refresh = self.refresh_plan(up)
        bump = Plan(playbook="steward-freshrss", component_id="freshrss", finding_keys=[f.key],
                    target="freshrss 1.30.5", lock_keys=["freshrss"], steps=[], undo="",
                    state={"image": "freshrss/freshrss:1.30.5@" + digest("b"),
                           "item": {"name": "1.30.5", "digest": digest("b")}})
        for plan in (bump, refresh):
            with self.subTest(target=plan.target):
                run = FakeRun()
                ctx = make_ctx(run=run, specs={"freshrss": sp}, findings=[f], busy=True)
                outcome = self.pb(playbooks_ops.StewardFreshRSS, updates=up).apply(plan, ctx)
                self.assertEqual(outcome.status, "refused")
                self.assertIs(outcome.state["production_touched"], False)
                self.assertEqual(ctx.lock_calls, [("freshrss", 5, "security-watch:steward-freshrss")])
                self.assertEqual(run.calls, [])
                up._p1_freshrss_update.assert_not_called()

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

    def test_openwebui_skip_after_container_stop_is_failed_touched(self):
        f = finding("open-webui", "PyPI", "authlib", "1.7.2", ["1.9.0"])
        sp = spec(id="open-webui", owner="steward-openwebui", lock="open-webui")
        up = SimpleNamespace(_p1_openwebui=mock.Mock(return_value={
            "step": "openwebui_update", "status": "skipped",
            "reason": "baseline: offline backup failed: disk full; old container restarted and verified"}))
        run = FakeRun()
        run.on(["docker", "run"], (0, "authlib\t1.9.0\n"))
        plan = Plan(playbook="steward-openwebui", component_id="open-webui", finding_keys=[f.key],
                    target="open-webui 0.13.4", lock_keys=["open-webui"], steps=[], undo="steward rollback",
                    state={"image": "ghcr.io/open-webui/open-webui:0.13.4", "release": {"tag_name": "v0.13.4"}})
        ctx = make_ctx(run=run, specs={"open-webui": sp}, findings=[f])
        outcome = self.pb(playbooks_ops.StewardOpenWebUI, updates=up, querybatch=self.osv(set())).apply(plan, ctx)
        self.assertEqual(outcome.status, "failed", outcome.detail)
        self.assertIs(outcome.state["production_touched"], True)
        self.assertIn("stopped open-webui", outcome.detail)
        self.assertEqual(outcome.state["verified_keys"], [f.key])

    def searxng_case(self, fixed_in):
        """Running 10-01; tags: 1 day (too young for act's gate), 4 days (past 72 h, not 7-day
        mature), 14 days (mature).  ``fixed_in`` = the tag names whose venv has lxml 6.0.1."""
        compose = self.home / "searxng" / "docker-compose.yml"
        compose.parent.mkdir()
        compose.write_text(f"services:\n  searxng:\n    image: docker.io/searxng/searxng@{digest('a')}\n")
        stamp = lambda days: (NOW - timedelta(days=days)).isoformat().replace("+00:00", "Z")
        tags = [{"name": "2026.11.2-ddd4444", "digest": digest("d"), "last_updated": stamp(1)},
                {"name": "2026.10.30-ccc3333", "digest": digest("c"), "last_updated": stamp(4)},
                {"name": "2026.10.20-bbb2222", "digest": digest("b"), "last_updated": stamp(14)},
                {"name": "2026.10.1-aaa1111", "digest": digest("a"), "last_updated": stamp(33)}]
        up = SimpleNamespace(
            HOME=self.home, SEARXNG_TAGS_API=steward_updates.SEARXNG_TAGS_API,
            _searxng_tag_date=steward_updates._searxng_tag_date,
            _select_mature_searxng_tag=steward_updates._select_mature_searxng_tag,
            _p1_searxng_update=mock.Mock(return_value={"step": "searxng", "status": "ok"}))
        by_digest = {t["digest"]: t["name"] for t in tags}
        run = FakeRun()
        run.on(["docker", "inspect", "searxng"], (0, "2026.10.1-aaa1111\n"))
        run.on(["docker", "run"], lambda argv: (0, "lxml\t" + (
            "6.0.1" if by_digest[argv[7].split("@", 1)[1]] in fixed_in else "6.0.0") + "\n"))
        f = finding("searxng", "PyPI", "lxml", "6.0.0", ["6.0.1"])
        sp = spec(id="searxng", owner="steward-searxng", lock="searxng")
        pb = self.pb(playbooks_ops.StewardSearXNG, updates=up, querybatch=self.osv({"6.0.0"}))
        ctx = make_ctx(run=run, fetch=FakeFetch({up.SEARXNG_TAGS_API: {"results": tags}}),
                       specs={"searxng": sp}, findings=[f])
        plan = pb.plan([f], sp, ctx)
        self.assertIsInstance(plan, Plan)
        return pb, ctx, plan, up, tags, f

    def test_searxng_picks_younger_tag_when_mature_one_lacks_the_fix(self):
        pb, ctx, plan, up, tags, f = self.searxng_case(fixed_in={"2026.10.30-ccc3333"})
        self.assertEqual([c["item"]["name"] for c in plan.state["candidates"]],
                         ["2026.10.30-ccc3333", "2026.10.20-bbb2222"])
        self.assertEqual(plan.state["image"], "docker.io/searxng/searxng@" + digest("c"))
        self.assertEqual(plan.state["min_age_days"], 0)
        self.assertEqual(plan.release_published, model.iso(NOW - timedelta(days=4)))
        outcome = pb.apply(plan, ctx)
        self.assertEqual(outcome.status, "done", outcome.detail)
        self.assertEqual(outcome.state["verified_keys"], [f.key])
        kwargs = up._p1_searxng_update.call_args.kwargs
        self.assertEqual([t["name"] for t in kwargs["tags"]], ["2026.10.30-ccc3333", "2026.10.1-aaa1111"])
        self.assertEqual(kwargs["min_age_days"], 0)

    def test_searxng_falls_back_to_older_candidate_newest_first(self):
        pb, ctx, plan, up, tags, f = self.searxng_case(fixed_in={"2026.10.20-bbb2222"})
        outcome = pb.apply(plan, ctx)
        self.assertEqual(outcome.status, "done", outcome.detail)
        self.assertIn("chose searxng 2026.10.20-bbb2222", outcome.detail)
        self.assertIn(digest("b"), outcome.undo)
        kwargs = up._p1_searxng_update.call_args.kwargs
        self.assertEqual(kwargs["tags"][0]["name"], "2026.10.20-bbb2222")
        self.assertNotIn("min_age_days", kwargs)

    def test_searxng_refuses_with_alert_when_no_candidate_clears(self):
        pb, ctx, plan, up, tags, f = self.searxng_case(fixed_in=set())
        outcome = pb.apply(plan, ctx)
        self.assertEqual(outcome.status, "refused")
        self.assertIs(outcome.state["alert"], True)
        self.assertIs(outcome.state["production_touched"], False)
        up._p1_searxng_update.assert_not_called()


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
        store = FakeStore(signals={("go_releases", "go1.27.4"): (go_signal("1.27.4", "2026-10-30T18:00:00Z"),
                                                                 "2026-10-31T00:00:00+00:00")})
        plan = pb.plan([f], sp, make_ctx(store=store))
        self.assertIsInstance(plan, Plan)
        self.assertEqual(plan.state["step"], "toolchain_go_user")
        self.assertEqual(plan.fixed_version, "1.27.4")
        self.assertEqual(plan.release_published, "2026-10-30T18:00:00+00:00")

    def go_user(self, store):
        f = finding("go-user", "Go", "stdlib", "1.27.3", ["1.27.4"])
        sp = spec(id="go-user", kind="runtime", owner="steward-toolchain", lock="toolchain-go-user",
                  toolchain="go_user")
        pb = self.pb(playbooks_ops.StewardToolchain, toolchains=steward_toolchains,
                     releases=lambda name, store: [{"version": "1.27.4"}])
        return pb.plan([f], sp, make_ctx(store=store))

    def test_toolchain_go_release_date_falls_back_to_signal_first_seen(self):
        store = FakeStore(signals={("go_releases", "go1.27.4"): (go_signal("1.27.4"), "2026-11-01T06:00:00+00:00")})
        plan = self.go_user(store)
        self.assertIsInstance(plan, Plan)
        self.assertEqual(plan.release_published, "2026-11-01T06:00:00+00:00")

    def test_toolchain_refuses_when_release_date_unknown(self):
        result = self.go_user(FakeStore())
        self.assertIsInstance(result, Refusal)
        self.assertFalse(result.alert)
        self.assertIn("release date of go_user 1.27.4 is unknown", result.reason)

    def test_toolchain_node_release_published_is_the_newest_release_date(self):
        f = finding("node", "runtime", "node", "22.11.0", ["22.12.0"])
        sp = spec(id="node", kind="runtime", owner="steward-toolchain", lock="toolchain-node", toolchain="node")
        pb = self.pb(playbooks_ops.StewardToolchain, toolchains=steward_toolchains,
                     releases=lambda name, store: [{"version": "22.13.0", "date": "2026-11-02"},
                                                   {"version": "22.12.0", "date": "2026-10-20"}])
        plan = pb.plan([f], sp, make_ctx())
        self.assertIsInstance(plan, Plan)
        self.assertEqual(plan.state["target"], "22.13.0")
        self.assertEqual(plan.release_published, "2026-11-02T00:00:00+00:00")

    def test_toolchain_warning_touched_only_when_active_version_changed(self):
        sp = spec(id="go-user", kind="runtime", owner="steward-toolchain", lock="toolchain-go-user",
                  toolchain="go_user")
        plan = Plan(playbook="steward-toolchain", component_id="go-user", finding_keys=["go-user|CVE-2026-1"],
                    target="go_user 1.27.4", lock_keys=["toolchain-go-user"], steps=[], undo="switch back",
                    state={"step": "toolchain_go_user", "fixed": "1.27.4", "installed": "1.27.3",
                           "target": "1.27.4"})
        for active, touched in (("1.27.3", False), ("1.27.4", True), ("", True)):
            with self.subTest(active=active):
                tc = SimpleNamespace(
                    p1_toolchain=lambda step, **kw: {"status": "warning", "error": "OSError: state save failed"},
                    Ctx=lambda **kw: None,
                    drivers=lambda ctx, active=active: {"toolchain_go_user": SimpleNamespace(current=lambda: active)})
                outcome = self.pb(playbooks_ops.StewardToolchain, toolchains=tc).apply(
                    plan, make_ctx(specs={"go-user": sp}))
                self.assertEqual(outcome.status, "failed")
                self.assertIs(outcome.state["production_touched"], touched)


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

    def store(self, revision=None, modified=False):
        inv = Inventory(component_id="opencode-go-proxy", collected_at=NOW, status="ok", fingerprint="f",
                        meta={"binaries": [{"path": str(self.binary), "go_version": "go1.27.3",
                                            "vcs_revision": revision or self.head, "vcs_modified": modified}]})
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

    def apply_ctx(self, run, **fields):
        ctx = make_ctx(run=run, store=self.store(), specs={self.spec.id: self.spec}, findings=[self.finding])
        for key, value in fields.items():
            setattr(ctx, key, value)
        return ctx

    def test_release_failure_with_unchanged_binaries_is_failed_untouched_without_restart(self):
        run = self.git_run()
        run.on(["bash", "release.sh"], (1, "go test ./...: FAIL"))
        pb, plan = self.plan(run)
        pb.probe = lambda url, host: 200
        outcome = pb.apply(plan, self.apply_ctx(run))
        self.assertEqual(outcome.status, "failed", outcome.detail)
        self.assertIs(outcome.state["production_touched"], False)
        self.assertIn("every binary unchanged and healthy", outcome.detail)
        self.assertEqual(run.called(["systemctl", "--user", "restart"]), [])
        self.assertEqual(self.binary.read_bytes(), b"old-binary")

    def test_release_failure_with_changed_binary_restores_snapshot_even_when_transactional(self):
        self.spec = spec(**{**{k: getattr(self.spec, k) for k in ("id", "kind", "collector", "exposure", "owner",
                                                                  "lock", "repo", "health")},
                            **self.spec.extra, "transactional": True})
        run = self.git_run()

        def release(argv):
            self.binary.write_bytes(b"half-installed")
            return 1, "promotion failed; rollback failed"

        run.on(["bash", "release.sh"], release)
        pb, plan = self.plan(run)
        pb.probe = lambda url, host: 200
        outcome = pb.apply(plan, self.apply_ctx(run))
        self.assertEqual(outcome.status, "rolled_back", outcome.detail)
        self.assertIs(outcome.state["production_touched"], True)
        self.assertEqual(self.binary.read_bytes(), b"old-binary")
        self.assertEqual(run.called(["systemctl", "--user", "restart"]),
                         [["systemctl", "--user", "restart", "opencode-go-proxy.service"]])

    def test_apply_rechecks_tree_and_head_under_the_lock(self):
        pb, plan = self.plan(self.git_run())
        self.assertIsInstance(plan, Plan)
        for label, run, alert in (("dirty", self.git_run(dirty=" M main.go\n"), True),
                                  ("moved", FakeRun(), None)):
            with self.subTest(label):
                if label == "moved":
                    run.on(["git", "-C", str(self.repo), "status"], (0, ""))
                    run.on(["git", "-C", str(self.repo), "rev-parse", "HEAD"], (0, sha("4") + "\n"))
                outcome = pb.apply(plan, self.apply_ctx(run))
                self.assertEqual(outcome.status, "refused", outcome.detail)
                self.assertIs(outcome.state["production_touched"], False)
                self.assertEqual(outcome.state.get("alert"), alert)
                self.assertEqual(run.called(["bash", "release.sh"]), [])

    def test_refuses_binary_built_from_modified_tree(self):
        _, result = self.plan(self.git_run(), store=self.store(modified=True))
        self.assertIsInstance(result, Refusal)
        self.assertTrue(result.alert)
        self.assertIn("vcs.modified=true", result.reason)

    def test_plans_only_the_stdlib_findings_the_host_go_fixes(self):
        later = finding("opencode-go-proxy", "Go", "stdlib", "1.27.3", ["1.27.5"], group="CVE-2026-2")
        pb = self.pb(playbooks_ops.ReleaseRebuild)
        plan = pb.plan([self.finding, later], self.spec, make_ctx(run=self.git_run(), store=self.store()))
        self.assertIsInstance(plan, Plan)
        self.assertEqual(plan.finding_keys, [self.finding.key])
        self.assertEqual(plan.fixed_version, "1.27.4")

    def test_homelab_backup_refused_near_its_nightly_run_or_while_active(self):
        backup = spec(id="homelab-backup", kind="host-binary", collector="go-binary", owner="release-rebuild",
                      lock="homelab-backup", repo="opencode-go-proxy",
                      binaries=["~/.local/bin/opencode-go-proxy"], release=["bash", "release.sh"])
        pb = self.pb(playbooks_ops.ReleaseRebuild)
        at = lambda h, m: datetime(2026, 11, 3, h, m, tzinfo=timezone.utc)
        # Window = 03:00 minus (RELEASE_TIMEOUT + 5 min) .. 03:00 + 15 min = 02:25..03:15 today.
        self.assertEqual(playbooks_ops.RELEASE_TIMEOUT, 1800)
        for label, now in (("lead edge", at(2, 25)), ("release would overlap", at(2, 40)),
                           ("just before", at(2, 59)), ("trailing edge", at(3, 15))):
            with self.subTest(label):
                run = self.git_run()
                ctx = make_ctx(run=run, store=self.store())
                ctx.now = now
                result = pb.plan([self.finding], backup, ctx)
                self.assertIsInstance(result, Refusal)
                self.assertFalse(result.alert)
                self.assertIn("03:00 UTC homelab-backup run window (35 min before to 15 min after)", result.reason)
                self.assertEqual(run.calls, [])
        for label, now in (("before window", at(2, 24)), ("after window", at(3, 16))):
            with self.subTest(label):
                run = self.git_run()
                run.on(["systemctl", "--user", "is-active"], (0, "inactive\ninactive\n"))
                ctx = make_ctx(run=run, store=self.store())
                ctx.now = now
                result = pb.plan([self.finding], backup, ctx)
                self.assertNotIn("run window", getattr(result, "reason", ""))
                self.assertEqual(run.called(["systemctl", "--user", "is-active"]),
                                 [["systemctl", "--user", "is-active", "homelab-backup.service",
                                   "homelab-backup-restore-drill.service"]])
        with self.subTest("active"):
            run = self.git_run()
            run.on(["systemctl", "--user", "is-active"], (0, "active\ninactive\n"))
            result = pb.plan([self.finding], backup, make_ctx(run=run, store=self.store()))
            self.assertIsInstance(result, Refusal)
            self.assertFalse(result.alert)
            self.assertIn("homelab-backup.service is running", result.reason)

    def test_build_holds_shared_go_toolchain_lock_and_rechecks_steward(self):
        events = []

        @contextlib.contextmanager
        def service_lock(key, *, timeout=None, shared=False, holder=""):
            events.append(("take", key, shared))
            try:
                yield
            finally:
                events.append(("release", key))

        run = self.git_run()
        run.on(["bash", "release.sh"], lambda argv: events.append(("release.sh",)) or (0, "ok"))
        pb, plan = self.plan(run)
        pb.probe = lambda url, host: 200
        with mock.patch.object(playbooks_ops.deploy_lock, "service_lock", service_lock):
            outcome = pb.apply(plan, self.apply_ctx(run))
            self.assertEqual(outcome.status, "done", outcome.detail)
            self.assertEqual(events, [("take", "toolchain-go-user", True), ("release.sh",),
                                      ("release", "toolchain-go-user")])
            events.clear()
            outcome = pb.apply(plan, self.apply_ctx(run, steward_active=lambda: True))
        self.assertEqual(outcome.status, "refused")
        self.assertIs(outcome.state["production_touched"], False)
        self.assertNotIn(("release.sh",), events)


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
        self.assertIs(outcome.state["alert"], True)

    def test_news_candidate_clearing_38_of_39_findings_applies_with_verified_keys(self):
        # 2026-11-09: nginx:1.31.8-alpine fixes the KEV brotli finding but still ships zlib 1.3.2-r1.
        findings = [finding("news", "Alpine:v3.24", f"pkg{i}", "1.0-r0", ["1.0-r1"],
                            ids=(f"ALPINE-CVE-2026-{100 + i}",), group=f"CVE-2026-{100 + i}") for i in range(38)]
        zlib = finding("news", "Alpine:v3.24", "zlib", "1.3.2-r1", ["1.3.2-r2"],
                       ids=("ALPINE-CVE-2026-4738",), group="CVE-2026-4738")
        findings.append(zlib)
        listing = "".join(f"pkg{i}-1.0-r1 x86_64 {{pkg{i}}} (MIT) [installed]\n" for i in range(38))
        self.run.rules.insert(0, (("docker", "run"), (0, listing + "zlib-1.3.2-r1 x86_64 {zlib} (Zlib) [installed]\n")))
        pb = self.pb(playbooks_ops.ComposeDigest,
                     querybatch=lambda packages, fetch: {p: [("ALPINE-CVE-2026-4738", None)]
                                                         for p in packages if p.name == "zlib"},
                     probe=lambda url, host: 200)
        ctx = make_ctx(run=self.run, fetch=self.fetch, specs={"news": self.spec}, findings=findings)
        plan = pb.plan(findings, self.spec, ctx)
        self.assertEqual(len(plan.finding_keys), 39)
        outcome = pb.apply(plan, ctx)
        self.assertEqual(outcome.status, "done", outcome.detail)
        self.assertEqual(outcome.state["verified_keys"], [f.key for f in findings[:38]])
        self.assertNotIn(zlib.key, outcome.state["verified_keys"])
        self.assertIn("38 of 39", outcome.detail)
        self.assertIn("zlib 1.3.2-r1 affected by ALPINE-CVE-2026-4738", outcome.detail)
        self.assertEqual(len(self.run.called(["docker", "run"])), 1)

    def test_osv_failure_refuses_without_alert(self):
        pb, ctx, plan = self.make()

        def broken(packages, *, fetch):
            raise RuntimeError("api.osv.dev unreachable")

        pb.querybatch = broken
        outcome = pb.apply(plan, ctx)
        self.assertEqual(outcome.status, "refused")
        self.assertFalse(outcome.state.get("alert"))
        self.assertEqual(self.ups, [])


class CandidateVerificationTests(unittest.TestCase):
    def test_candidate_listing_runs_once_per_ecosystem(self):
        run = FakeRun()
        run.on(["docker", "run", "--rm", "--network", "none", "--entrypoint", "dpkg-query"],
               (0, "openssl\t3.0.17-1\nzlib\t1:1.3.dfsg-3\n"))
        run.on(["docker", "run", "--rm", "--network", "none", "--entrypoint", "python3"],
               (0, "PyJWT\t2.14.0\nauthlib\t1.9.0\n"))
        findings = [finding("x", "Debian:13", "openssl", "3.0.16-1", ["3.0.17-1"], group="CVE-2026-1"),
                    finding("x", "Debian:13", "zlib", "1:1.3.dfsg-2", ["1:1.3.dfsg-3"], group="CVE-2026-2"),
                    finding("x", "PyPI", "pyjwt", "2.13.0", ["2.14.0"], group="CVE-2026-3"),
                    finding("x", "PyPI", "Authlib", "1.7.2", ["1.9.0"], group="CVE-2026-4")]
        check = playbooks_ops.verify_candidate(make_ctx(run=run), "img:new", findings, spec(),
                                               querybatch=lambda packages, fetch: {})
        self.assertEqual(check.keys, [f.key for f in findings])
        self.assertEqual(len(run.called(["docker", "run"])), 2)


class RunGroupTests(unittest.TestCase):
    def test_production_runner_uses_the_process_group_runner(self):
        done = subprocess.CompletedProcess(["bash", "release.sh"], 0, "", "")
        with mock.patch.object(inventory, "run_group", create=True, return_value=done) as run_group:
            out = playbooks_ops._run_group(SimpleNamespace(run=inventory.default_run), ["bash", "release.sh"],
                                           timeout=5, cwd="/tmp")
        self.assertIs(out, done)
        run_group.assert_called_once_with(["bash", "release.sh"], timeout=5, env=None, cwd="/tmp")

    def test_other_runners_are_called_as_is(self):
        run = FakeRun()
        playbooks_ops._run_group(SimpleNamespace(run=run), ["bash", "release.sh"], timeout=5)
        self.assertEqual(run.calls, [["bash", "release.sh"]])


class AptSecurityTests(TempHomeCase):
    @staticmethod
    def compare(argv):
        a, op, b = argv[2], argv[3], argv[4]
        assert op == "ge"
        return (0 if a and a >= b else 1), ""

    def setUp(self):
        super().setUp()
        self.stamp = self.home / "update-success-stamp"
        self.stamp.touch()
        self.lists_age(60)
        patcher = mock.patch.object(playbooks_ops, "APT_FRESHNESS_PATHS", (self.stamp,))
        patcher.start()
        self.addCleanup(patcher.stop)

    def lists_age(self, seconds):
        when = NOW.timestamp() - seconds
        os.utime(self.stamp, (when, when))

    HOST = dict(id="host", kind="host", collector="host-dpkg", owner="apt-security", lock="host",
                system_units=["ssh.service", "docker.service", "cloudflared.service"],
                health=["http://127.0.0.1:30144/healthz"])

    def apt_run(self, *, busy="inactive\ninactive\n", fuser=(1, ""), update=(0, ""),
                sim=(0, "Inst libssl3t64 [3.0.13-0ubuntu3.4] (3.0.13-0ubuntu3.5 Ubuntu:24.04/noble-security)\n"),
                install=(0, ""), units="active\nactive\nactive\n", candidate_after_update=None):
        run = FakeRun()
        state = {"installed": False, "updated": False}

        def dpkg(argv):
            version = "3.0.13-0ubuntu3.5" if state["installed"] else "3.0.13-0ubuntu3.4"
            return 0, f"ii \topenssl\tlibssl3t64\t{version}\n"

        def policy(argv):
            cand = candidate_after_update if candidate_after_update and not state["updated"] else "3.0.13-0ubuntu3.5"
            return 0, f"libssl3t64:\n  Installed: 3.0.13-0ubuntu3.4\n  Candidate: {cand}\n"

        def do_update(argv):
            state["updated"] = update[0] == 0
            return update

        def do_install(argv):
            state["installed"] = install[0] == 0
            return install

        run.on(["dpkg-query", "-W"], dpkg)
        run.on(["apt-cache", "policy"], policy)
        run.on(["dpkg", "--compare-versions"], self.compare)
        run.on(["systemctl", "is-active", "apt-daily.service"], (0, busy))
        run.on(["systemctl", "is-active", "ssh.service"], (0, units))
        run.on(["sudo", "-n", "fuser"], fuser)
        run.on(["sudo", "-n", "apt-get", "update"], do_update)
        run.on(["apt-get", "-s", "install"], sim)
        run.on(["sudo", "-n", "apt-get", "install"], do_install)
        return run

    def apt_apply(self, run, *, probe=lambda url, host: 200):
        f = finding("host", "Ubuntu:24.04:LTS", "openssl", "3.0.13-0ubuntu3.4", ["3.0.13-0ubuntu3.5"])
        sp = spec(**self.HOST)
        pb = self.pb(playbooks_ops.AptSecurity, probe=probe)
        ctx = make_ctx(run=run, specs={"host": sp}, findings=[f])
        plan = pb.plan([f], sp, ctx)
        self.assertIsInstance(plan, Plan)
        return plan, pb.apply(plan, ctx)

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

    def test_arch_qualified_package_reads_unqualified_policy_header(self):
        # dpkg reports "libsoup-3.0-0:amd64"; `apt-cache policy` prints the header as
        # "libsoup-3.0-0:", which once made every multi-arch package look candidate-less.
        run = FakeRun()
        run.on(["dpkg-query", "-W"], (0, "ii \tlibsoup3\tlibsoup-3.0-0:amd64\t3.4.4-5ubuntu0.8\n"))
        run.on(["apt-cache", "policy"], (0, "libsoup-3.0-0:\n  Installed: 3.4.4-5ubuntu0.8\n"
                                            "  Candidate: 3.4.4-5ubuntu0.9\n"))
        run.on(["dpkg", "--compare-versions"], self.compare)
        f = finding("host", "Ubuntu:24.04:LTS", "libsoup3", "3.4.4-5ubuntu0.8", ["3.4.4-5ubuntu0.9"])
        sp = spec(id="host", kind="host", collector="host-dpkg", owner="apt-security", lock="host")
        plan = self.pb(playbooks_ops.AptSecurity).plan([f], sp, make_ctx(run=run))
        self.assertIsInstance(plan, Plan)
        self.assertEqual(plan.state["packages"], ["libsoup-3.0-0:amd64"])

    def test_apply_simulates_then_installs_with_no_remove_and_health_gates(self):
        run = self.apt_run()
        plan, outcome = self.apt_apply(run)
        self.assertEqual(outcome.status, "done", outcome.detail)
        self.assertIs(outcome.state["production_touched"], True)
        install = run.called(["sudo", "-n", "apt-get", "install"])
        self.assertEqual(len(install), 1)
        self.assertIn("--no-remove", install[0])
        order = [i for i, c in enumerate(run.calls) if c[:3] in (["apt-get", "-s", "install"],
                                                                   ["sudo", "-n", "apt-get"])]
        self.assertEqual([run.calls[i][:4] for i in order],
                         [["sudo", "-n", "apt-get", "update"], ["apt-get", "-s", "install", "--only-upgrade"],
                          ["sudo", "-n", "apt-get", "install"]])
        self.assertEqual(run.called(["systemctl", "is-active", "ssh.service"]),
                         [["systemctl", "is-active", "ssh.service", "docker.service", "cloudflared.service"]])

    def test_busy_apt_is_refused_untouched(self):
        for label, kwargs in (("apt-daily", {"busy": "inactive\nactivating\n"}),
                              ("lock held", {"fuser": (0, " 4242")})):
            with self.subTest(label):
                run = self.apt_run(**kwargs)
                _, outcome = self.apt_apply(run)
                self.assertEqual(outcome.status, "refused", outcome.detail)
                self.assertIs(outcome.state["production_touched"], False)
                self.assertFalse(outcome.state.get("alert"))
                self.assertEqual(run.called(["sudo", "-n", "apt-get"]), [])

    def test_simulated_removal_is_refused(self):
        run = self.apt_run(sim=(0, "Remv libfoo1 [1.0-1]\nInst libssl3t64 [3.0.13-0ubuntu3.4] (3.0.13-0ubuntu3.5)\n"))
        _, outcome = self.apt_apply(run)
        self.assertEqual(outcome.status, "refused")
        self.assertIs(outcome.state["alert"], True)
        self.assertIs(outcome.state["production_touched"], False)
        self.assertIn("would remove libfoo1", outcome.detail)
        self.assertEqual(run.called(["sudo", "-n", "apt-get", "install"]), [])

    def test_install_lock_error_is_refused_untouched(self):
        run = self.apt_run(install=(100, "E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 4242"))
        _, outcome = self.apt_apply(run)
        self.assertEqual(outcome.status, "refused", outcome.detail)
        self.assertIs(outcome.state["production_touched"], False)

    def test_health_gate_failure_is_failed_touched(self):
        for label, kwargs, probe, text in (
                ("unit", {"units": "active\ninactive\nactive\n"}, lambda url, host: 200, "docker.service inactive"),
                ("origin", {}, lambda url, host: 502, "health: http://127.0.0.1:30144/healthz answered 502")):
            with self.subTest(label):
                _, outcome = self.apt_apply(self.apt_run(**kwargs), probe=probe)
                self.assertEqual(outcome.status, "failed", outcome.detail)
                self.assertIs(outcome.state["production_touched"], True)
                self.assertIn(text, outcome.detail)
                self.assertTrue(outcome.undo.startswith("sudo apt-get install --allow-downgrades"))

    def test_apt_update_failure_is_refused_not_failed(self):
        run = self.apt_run(update=(100, "E: The repository 'https://example.invalid noble Release' has no Release file."))
        _, outcome = self.apt_apply(run)
        self.assertEqual(outcome.status, "refused", outcome.detail)
        self.assertIs(outcome.state["production_touched"], False)
        self.assertIs(outcome.state["alert"], True)
        self.assertEqual(run.called(["sudo", "-n", "apt-get", "install"]), [])

    def test_stale_lists_are_refreshed_during_plan(self):
        self.lists_age(2 * 3600)
        run = self.apt_run(candidate_after_update="3.0.13-0ubuntu3.4")
        f = finding("host", "Ubuntu:24.04:LTS", "openssl", "3.0.13-0ubuntu3.4", ["3.0.13-0ubuntu3.5"])
        ctx = make_ctx(run=run)
        plan = self.pb(playbooks_ops.AptSecurity).plan([f], spec(**self.HOST), ctx)
        self.assertIsInstance(plan, Plan)
        self.assertEqual(len(run.called(["sudo", "-n", "apt-get", "update"])), 1)
        self.assertEqual(ctx.lock_calls, [("host", 5, "security-watch:apt-security")])
        self.assertEqual(plan.state["packages"], ["libssl3t64"])

    def test_stale_lists_update_failure_in_plan_is_refused(self):
        self.lists_age(2 * 3600)
        run = self.apt_run(candidate_after_update="3.0.13-0ubuntu3.4", update=(100, "E: GPG error"))
        f = finding("host", "Ubuntu:24.04:LTS", "openssl", "3.0.13-0ubuntu3.4", ["3.0.13-0ubuntu3.5"])
        result = self.pb(playbooks_ops.AptSecurity).plan([f], spec(**self.HOST), make_ctx(run=run))
        self.assertIsInstance(result, Refusal)
        self.assertTrue(result.alert)
        self.assertIn("apt-get update failed", result.reason)


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
