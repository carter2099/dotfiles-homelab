import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import base64  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import subprocess  # noqa: E402
import unittest  # noqa: E402
from datetime import timedelta  # noqa: E402

from security_watch import config, inventory, model, net, rubysec, scan  # noqa: E402
from security_watch.model import Finding, Package, Plan, Refusal  # noqa: E402
from security_watch.playbooks_repo import RepoPrPlaybook, gem_target, replace_ruby_mentions  # noqa: E402
from test_security_watch_playbooks_repo import (  # noqa: E402
    BLOG_DOCKERFILE, GREEN_RUNS, NOW, SPECS, FakeRun, FakeStore, TempHomeTestCase, json_response, make_ctx,
)
from test_security_watch_scan import FakeOSV, FeedPatch, inventory as make_inventory, policy, spec  # noqa: E402

SHA = "a" * 40
NET_SSH = Package("RubyGems", "net-ssh", "7.3.0", location="blog-web-1:/rails/Gemfile.lock")


def audit_result(gem, version, ghsa, patched, criticality=None, cve=None):
    return {"type": "unpatched_gem", "gem": {"name": gem, "version": version},
            "advisory": {"id": f"GHSA-{ghsa}", "cve": cve, "ghsa": ghsa, "criticality": criticality,
                         "patched_versions": patched, "title": f"{gem} flaw"}}


def gem_finding(component, name, version, fixed, group, urgency="normal"):
    return Finding(key=f"{component}|{group}", component_id=component, group=group,
                   package=Package("RubyGems", name, version), advisory_ids=[group], cves=[],
                   fixed_versions=list(fixed), fix_available=True, urgency=urgency)


def ruby_finding(component, version, fixed, group):
    return Finding(key=f"{component}|{group}", component_id=component, group=group,
                   package=Package(model.RUNTIME_ECOSYSTEM, "ruby", version), advisory_ids=[group], cves=[],
                   fixed_versions=list(fixed), fix_available=True, severity="critical")


def lock(**gems):
    specs = "".join(f"    {name.replace('_', '-')} ({version})\n" for name, version in gems.items())
    return f"GEM\n  remote: https://rubygems.org/\n  specs:\n{specs}\nPLATFORMS\n  ruby\n\nBUNDLED WITH\n   2.6.9\n"


def versions(*entries):
    return [{"number": n, "prerelease": pre, "created_at": at, "platform": "ruby"} for n, pre, at in entries]


NET_SSH_VERSIONS = versions(("8.2.0", False, "2026-11-25T21:43:19.823Z"), ("8.1.2", False, "2026-11-08T07:59:54.867Z"),
                            ("8.0.0.rc2", True, "2024-01-01T00:00:00Z"), ("7.3.10", False, "2026-11-08T08:00:21.063Z"),
                            ("7.3.9", False, "2026-11-06T15:26:36.315Z"), ("7.3.0", False, "2024-10-01T00:00:00Z"))


class RubysecTests(TempHomeTestCase):
    def test_fixed_versions_take_each_requirement_lower_bound(self):
        self.assertEqual(rubysec.fixed_versions(["~> 7.3, >= 7.3.5", ">= 8.0.0.rc2", "~> 7.3.10", "< 2.0"]),
                         ["7.3.5", "8.0.0.rc2", "7.3.10"])

    def test_audit_checks_a_lockfile_of_the_gems_and_keeps_only_unpatched_gems(self):
        head = self.home / ".local/share/ruby-advisory-db/.git/FETCH_HEAD"
        head.parent.mkdir(parents=True)
        head.write_text("fresh")
        seen = {}

        def run(argv, **kw):
            seen["argv"], seen["env"] = argv, kw["env"]
            seen["lock"] = Path(kw["cwd"], "Gemfile.lock").read_text()
            out = {"results": [audit_result("net-ssh", "7.3.0", "hjwv-j52r-xcg7", ["~> 7.3.9", ">= 8.1.1"], "high"),
                               {"type": "insecure_source", "source": "http://example.invalid"}]}
            return subprocess.CompletedProcess(argv, 1, json.dumps(out), "")

        with unittest.mock.patch.dict(os.environ, {"RBENV_VERSION": "3.4.11", "BUNDLE_FROZEN": "true"}):
            results = rubysec.audit([NET_SSH, Package("PyPI", "requests", "2.0")], run=run)
        self.assertEqual([r["gem"]["name"] for r in results], ["net-ssh"])
        self.assertEqual(seen["argv"][:5], ["bundle-audit", "check", "--format", "json", "--gemfile-lock"])
        self.assertIn("    net-ssh (7.3.0)\n", seen["lock"])
        self.assertNotIn("requests", seen["lock"])
        self.assertNotIn("RBENV_VERSION", seen["env"])
        self.assertNotIn("BUNDLE_FROZEN", seen["env"])

    def test_audit_failure_raises_instead_of_reading_clean(self):
        head = self.home / ".local/share/ruby-advisory-db/.git/FETCH_HEAD"
        head.parent.mkdir(parents=True)
        head.write_text("fresh")
        run = lambda argv, **kw: subprocess.CompletedProcess(argv, 127, "", "bundle-audit: not found")  # noqa: E731
        with self.assertRaises(RuntimeError):
            rubysec.audit([NET_SSH], run=run)


class ScanRubysecTests(unittest.TestCase):
    def scan(self, audit):
        with FeedPatch():
            return scan.scan([make_inventory("blog", NET_SSH)], {"blog": spec("blog")}, store=FakeStore(),
                             fetch=FakeOSV([], {}), now=NOW, audit=audit)

    def test_advisories_osv_lacks_become_findings(self):
        result = self.scan(lambda pkgs: [audit_result("net-ssh", "7.3.0", "hjwv-j52r-xcg7",
                                                      ["~> 7.3.9", ">= 8.1.1"], "High")])
        [finding] = result.findings
        self.assertEqual(finding.key, "blog|GHSA-hjwv-j52r-xcg7")
        self.assertEqual(finding.package, NET_SSH)
        self.assertEqual(finding.fixed_versions, ["7.3.9", "8.1.1"])
        self.assertEqual(finding.severity, "high")
        self.assertIn("blog", result.complete)

    def test_audit_failure_keeps_the_component_incomplete(self):
        def audit(pkgs):
            raise RuntimeError("bundle-audit check exited 127")
        result = self.scan(audit)
        self.assertNotIn("blog", result.complete)
        self.assertIn("bundler-audit unavailable", result.unknown[0]["reason"])


class CiGatedPrioritizeTests(unittest.TestCase):
    def rate(self, exposure, gated, **kw):
        f = gem_finding("dn", "net-ssh", "7.3.0", ["7.3.10"], "GHSA-qcf4-j55x-72hv")
        f.severity = kw.get("severity", "medium")
        f.reach = kw.get("reach")
        extra = {"ci_gated": True} if gated else {}
        with FeedPatch():
            scan.prioritize([f], {"dn": spec("dn", exposure=exposure, **extra)}, policy(), store=FakeStore(),
                            now=NOW, stopgaps=[], not_affected=None)
        return f

    def test_gem_finding_that_fails_ci_is_fixed_even_unexposed(self):
        self.assertEqual(self.rate("none", gated=False).urgency, "low")
        gated = self.rate("none", gated=True)
        self.assertEqual(gated.urgency, "normal")
        self.assertIn("fails the repo's CI security gate", gated.reasons)

    def test_not_reachable_gem_on_a_gated_repo_stays_normal(self):
        reach = model.Reach(verdict="not_reachable", p=0.05, method="agent")
        self.assertEqual(self.rate("public", gated=False, severity="high", reach=reach).urgency, "low")
        self.assertEqual(self.rate("public", gated=True, severity="high", reach=reach).urgency, "normal")


class RepoCollectorTests(TempHomeTestCase):
    def collect(self, files):
        def responder(argv, kw):
            if "rev-parse" in argv:
                return 0, SHA + "\n"
            if "show" in argv:
                path = argv[-1].split(":", 1)[1]
                return (0, files[path]) if path in files else (128, "")
            return None
        return inventory.collect(SPECS["delta-neutral"], run=FakeRun(responder), now=NOW)

    def test_origin_main_gems_and_pinned_ruby(self):
        inv = self.collect({"Gemfile.lock": lock(net_ssh="7.3.8", httpx="1.7.2"), ".ruby-version": "3.4.12\n"})
        self.assertEqual(inv.status, "ok", inv.reason)
        self.assertEqual(inv.fingerprint, SHA)
        self.assertIn(Package("RubyGems", "httpx", "1.7.2", location=f"delta_neutral@{SHA[:7]}:Gemfile.lock"),
                      inv.packages)
        self.assertIn(Package(model.RUNTIME_ECOSYSTEM, "ruby", "3.4.12",
                              location=f"delta_neutral@{SHA[:7]}:.ruby-version"), inv.packages)

    def test_missing_ruby_version_is_partial(self):
        inv = self.collect({"Gemfile.lock": lock(net_ssh="7.3.8")})
        self.assertEqual(inv.status, "partial")
        self.assertIn("runtime ruby", inv.reason)


class GemUpdatePlanTests(TempHomeTestCase):
    def plan(self, findings, gemfile, gem_versions):
        def responder(argv, kw):
            if "show" in argv:
                return (0, gemfile) if argv[-1] == "origin/main:Gemfile.lock" else (0, BLOG_DOCKERFILE)
            return None
        self.fetched = []

        def fetch(url, **kw):
            self.fetched.append(url)
            name = url.rsplit("/", 1)[1][:-5]
            return json_response(url, gem_versions[name])
        return RepoPrPlaybook().plan(findings, SPECS["blog"], make_ctx(FakeRun(responder), fetch))

    def test_net_ssh_moves_to_the_newest_patch_of_its_minor_line(self):
        group = [gem_finding("blog", "net-ssh", "7.3.0", ["7.3.5", "8.0.0.rc2"], "GHSA-3x7f-q7wf-fp73"),
                 gem_finding("blog", "net-ssh", "7.3.0", ["7.3.10", "8.1.2"], "GHSA-qcf4-j55x-72hv")]
        result = self.plan(group, lock(net_ssh="7.3.0", kamal="2.12.0"), {"net-ssh": NET_SSH_VERSIONS})
        self.assertIsInstance(result, Plan, getattr(result, "reason", ""))
        self.assertEqual(result.state["edit"], "gem-update")
        self.assertEqual(result.state["params"], {"gems": [["net-ssh", "7.3.0", "7.3.10", "patch", "7.3.10"]]})
        self.assertEqual(result.target, "blog: Gemfile.lock net-ssh 7.3.0 -> 7.3.10")
        self.assertEqual(sorted(result.finding_keys), ["blog|GHSA-3x7f-q7wf-fp73", "blog|GHSA-qcf4-j55x-72hv"])
        self.assertEqual(result.release_published, "2026-11-08T08:00:21+00:00")
        self.assertEqual(self.fetched, ["https://rubygems.org/api/v1/versions/net-ssh.json"])

    def test_fix_on_a_later_minor_uses_the_minor_strategy(self):
        httpx = versions(("1.9.2", False, "2026-11-25T13:32:20Z"), ("1.9.1", False, "2026-11-13T16:39:28Z"),
                         ("1.8.4", False, "2026-09-11T11:32:38Z"), ("2.0.0", False, "2026-11-26T00:00:00Z"))
        result = self.plan([gem_finding("blog", "httpx", "1.7.2", ["1.9.1"], "CVE-2026-129784")],
                           lock(httpx="1.7.2"), {"httpx": httpx})
        self.assertEqual(result.state["params"], {"gems": [["httpx", "1.7.2", "1.9.2", "minor", "1.9.1"]]})

    def test_a_fix_only_in_the_next_major_is_left_for_carter(self):
        result = self.plan([gem_finding("blog", "net-ssh", "7.3.0", ["8.1.2"], "GHSA-x")],
                           lock(net_ssh="7.3.0"), {"net-ssh": NET_SSH_VERSIONS})
        self.assertIsInstance(result, Refusal)
        self.assertTrue(result.alert)
        self.assertIn("needs a major upgrade from 7.3.0", result.reason)

    def test_gem_target_ignores_prereleases(self):
        self.assertEqual(gem_target("net-ssh", "7.3.0", "7.3.5", NET_SSH_VERSIONS)[:2], ("7.3.10", "patch"))
        self.assertIsInstance(gem_target("x", "7.3.0", "9.0.0", NET_SSH_VERSIONS), str)


class GemUpdateApplyTests(TempHomeTestCase):
    def apply(self, resolved):
        plan = Plan(playbook="repo-pr", component_id="blog", finding_keys=["blog|GHSA-qcf4-j55x-72hv"],
                    target="blog: Gemfile.lock net-ssh 7.3.0 -> 7.3.10", lock_keys=["app-blog"], steps=["edit"],
                    undo="", state={"edit": "gem-update", "path": "Gemfile.lock", "repo": "blog",
                                    "github": "carter2099/blog", "group": "GHSA-qcf4-j55x-72hv",
                                    "params": {"gems": [["net-ssh", "7.3.0", "7.3.10", "patch", "7.3.10"]]}})
        self.worktree = None

        def respond(argv, kw):
            if "worktree" in argv and "add" in argv:
                self.worktree = Path(argv[6])
                self.worktree.mkdir(exist_ok=True)
                (self.worktree / "Gemfile.lock").write_text(lock(net_ssh="7.3.0"))
                (self.worktree / ".ruby-version").write_text("3.4.13\n")
                (self.worktree / ".github" / "workflows").mkdir(parents=True)
                (self.worktree / ".github" / "workflows" / "ci.yml").write_text("on: push\n")
                return None
            if argv[:2] == ["rbenv", "versions"]:
                return 0, "3.4.11\n4.0.10\nsystem\n"
            if argv[:2] == ["bundle", "lock"]:
                (Path(kw["cwd"]) / "Gemfile.lock").write_text(lock(net_ssh=resolved))
                return None
            if "status" in argv:
                return 0, " M Gemfile.lock\n"
            if "rev-parse" in argv:
                return 0, "headsha1\n"
            if argv[:3] == ["gh", "pr", "list"]:
                return 0, "[]"
            if argv[:3] == ["gh", "pr", "create"]:
                return 0, "https://github.com/carter2099/blog/pull/43\n"
            return None
        run = FakeRun(respond)
        return RepoPrPlaybook().apply(plan, make_ctx(run)), run

    def test_bundle_lock_stays_on_the_patch_line_with_a_same_minor_ruby(self):
        outcome, run = self.apply("7.3.10")
        self.assertEqual(outcome.status, "pending", outcome.detail)
        [(argv, kw)] = run.find("bundle", "lock")
        self.assertEqual(argv, ["bundle", "lock", "--update", "net-ssh", "--conservative", "--patch", "--strict"])
        self.assertEqual(kw["env"]["RBENV_VERSION"], "3.4.11")
        self.assertTrue(run.find("add", "--", "Gemfile.lock"))

    def test_a_resolution_below_the_fix_pushes_nothing(self):
        outcome, run = self.apply("7.3.8")
        self.assertEqual(outcome.status, "failed")
        self.assertIn("net-ssh resolves 7.3.8 after bundle lock; the fix needs 7.3.10", outcome.detail)
        self.assertEqual(run.find("push"), [])


class RubyVersionPlanTests(TempHomeTestCase):
    def plan(self, findings, *, hub_status=200, setup_versions=("3.4.12", "3.4.13")):
        def responder(argv, kw):
            if "show" in argv:
                return (0, "3.4.11\n") if argv[-1] == "origin/main:.ruby-version" else (0, BLOG_DOCKERFILE)
            if "grep" in argv:
                return 0, ""
            return None
        self.fetched = []

        def fetch(url, **kw):
            self.fetched.append(url)
            if "hub.docker.com" in url:
                if hub_status != 200:
                    raise net.FetchError(url, hub_status, "not found")
                return json_response(url, {"name": url.rsplit("/", 1)[1]})
            if "setup-ruby" in url:
                content = base64.b64encode(json.dumps({"ruby": list(setup_versions)}).encode()).decode()
                return json_response(url, {"encoding": "base64", "content": content})
            return json_response(url, {"tag_name": "v3_4_13", "published_at": "2026-11-18T23:39:39Z"})
        return RepoPrPlaybook().plan(findings, SPECS["blog"], make_ctx(FakeRun(responder), fetch))

    def findings(self):
        return [ruby_finding("blog", "3.4.11", ["3.3.14", "3.4.13", "4.0.10"], "GHSA-34m4-m9fh-gqp5"),
                ruby_finding("blog", "3.4.11", ["3.3.13", "3.4.12", "4.0.9"], "CVE-2026-110264")]

    def test_moves_to_the_newest_fix_on_the_minor_line(self):
        result = self.plan(self.findings())
        self.assertIsInstance(result, Plan, getattr(result, "reason", ""))
        self.assertEqual(result.state["edit"], "ruby-version")
        self.assertEqual(result.state["params"], {"version": "3.4.13", "from": "3.4.11", "dockerfile": "Dockerfile",
                                                  "mentions": ["AGENTS.md", "config/deploy.yml"]})
        self.assertEqual(result.release_published, "2026-11-18T23:39:39+00:00")
        self.assertIn("https://hub.docker.com/v2/repositories/library/ruby/tags/3.4.13-slim-bookworm", self.fetched)

    def test_waits_for_the_image_and_for_setup_ruby(self):
        missing_image = self.plan(self.findings(), hub_status=404)
        self.assertIsInstance(missing_image, Refusal)
        self.assertFalse(missing_image.alert)
        self.assertIn("ruby:3.4.13-slim-bookworm is not on Docker Hub yet", missing_image.reason)
        no_setup = self.plan(self.findings(), setup_versions=("3.4.12",))
        self.assertIsInstance(no_setup, Refusal)
        self.assertFalse(no_setup.alert)
        self.assertIn("ruby/setup-ruby cannot install Ruby 3.4.13", no_setup.reason)

    def test_no_fix_on_the_minor_line_alerts(self):
        result = self.plan([ruby_finding("blog", "3.4.11", ["3.3.14", "4.0.10"], "GHSA-x")])
        self.assertIsInstance(result, Refusal)
        self.assertTrue(result.alert)
        self.assertIn("no fixed Ruby on the 3.4 line", result.reason)

    def test_mentions_change_only_on_ruby_lines(self):
        text = "Ruby 3.4.11 base\nRUBY_VERSION: 3.4.11\nsqlite 3.4.11\nRuby 3.4.110\n"
        self.assertEqual(replace_ruby_mentions(text, "3.4.11", "3.4.13"),
                         "Ruby 3.4.13 base\nRUBY_VERSION: 3.4.13\nsqlite 3.4.11\nRuby 3.4.110\n")


DN_DOCKERFILE = "# syntax=docker/dockerfile:1\nARG RUBY_VERSION=3.4.12\nFROM docker.io/library/ruby:$RUBY_VERSION-slim AS base\n"
DN_CHANGELOG = ("# Changelog\n\nThe format is based on Keep a Changelog.\n\n"
                "## [0.1.41] - 2026-11-26\n\n### Changed\n- Bumped rack from 3.2.8 to 3.2.9\n")


class TagReleaseTests(TempHomeTestCase):
    def apply_ruby(self):
        finding = ruby_finding("delta-neutral", "3.4.12", ["3.4.13"], "GHSA-34m4-m9fh-gqp5")
        plan = Plan(playbook="repo-pr", component_id="delta-neutral", finding_keys=[finding.key],
                    target="delta-neutral: Ruby 3.4.12 -> 3.4.13", lock_keys=["repo-delta-neutral"], steps=["edit"],
                    undo="", state={"edit": "ruby-version", "path": ".ruby-version", "repo": "delta_neutral",
                                    "github": "carter2099/delta_neutral", "group": finding.group,
                                    "params": {"version": "3.4.13", "from": "3.4.12", "dockerfile": "Dockerfile",
                                               "mentions": ["README.md", "config/deploy.yml"]}})
        self.committed = {}

        def respond(argv, kw):
            if "worktree" in argv and "add" in argv:
                self.worktree = tree = Path(argv[6])
                (tree / "config").mkdir(parents=True)
                (tree / ".github" / "workflows").mkdir(parents=True)
                (tree / ".github" / "workflows" / "ci.yml").write_text("on: push\n")
                (tree / ".ruby-version").write_text("3.4.12\n")
                (tree / "Dockerfile").write_text(DN_DOCKERFILE)
                (tree / "README.md").write_text("- **Ruby 3.4.12** (see `.ruby-version`)\n")
                (tree / "config" / "deploy.yml").write_text("  #   RUBY_VERSION: 3.4.12\n")
                (tree / "config" / "version.rb").write_text('module DeltaNeutral\n  VERSION = "0.1.41"\nend\n')
                (tree / "CHANGELOG.md").write_text(DN_CHANGELOG)
                return None
            if "add" in argv and "--" in argv:
                files = argv[argv.index("--") + 1:]
                self.committed = {f: (self.worktree / f).read_text() for f in files}
                return None
            if "status" in argv:
                return 0, " M .ruby-version\n"
            if "rev-parse" in argv:
                return 0, "headsha1\n"
            if argv[:3] == ["gh", "pr", "list"]:
                return 0, "[]"
            if argv[:3] == ["gh", "pr", "create"]:
                return 0, "https://github.com/carter2099/delta_neutral/pull/119\n"
            return None
        ctx = make_ctx(FakeRun(respond))
        ctx.findings = {finding.key: finding}
        return RepoPrPlaybook().apply(plan, ctx)

    def test_ruby_bump_pr_carries_the_release_version_and_changelog(self):
        outcome = self.apply_ruby()
        self.assertEqual(outcome.status, "pending", outcome.detail)
        self.assertEqual(outcome.state["release_version"], "0.1.42")
        self.assertEqual(sorted(self.committed), [".ruby-version", "CHANGELOG.md", "Dockerfile", "README.md",
                                                  "config/deploy.yml", "config/version.rb"])
        self.assertEqual(self.committed[".ruby-version"], "3.4.13\n")
        self.assertIn("ARG RUBY_VERSION=3.4.13\nFROM docker.io/library/ruby:$RUBY_VERSION-slim", self.committed["Dockerfile"])
        self.assertEqual(self.committed["README.md"], "- **Ruby 3.4.13** (see `.ruby-version`)\n")
        self.assertIn('VERSION = "0.1.42"', self.committed["config/version.rb"])
        self.assertIn("The format is based on Keep a Changelog.\n\n## [0.1.42] - 2026-11-03\n\n### Security\n"
                      "- Bumped Ruby from 3.4.12 to 3.4.13 (`.ruby-version` and the Dockerfile's `RUBY_VERSION`) "
                      "for GHSA-34m4-m9fh-gqp5.\n\n## [0.1.41] - 2026-11-26", self.committed["CHANGELOG.md"])

    def deploy(self, *, tag_sha=None, ci=GREEN_RUNS):
        sha = "m" * 40

        def respond(argv, kw):
            if argv[:2] == ["gh", "api"]:
                if argv[2].endswith("check-runs?per_page=100"):
                    return 0, json.dumps({"total_count": len(ci), "check_runs": ci})
                return 0, json.dumps({"statuses": []})
            if "show" in argv:
                return 0, 'module DeltaNeutral\n  VERSION = "0.1.42"\nend\n'
            if "rev-parse" in argv:
                return (0, tag_sha + "\n") if tag_sha else (1, "")
            return None
        run = FakeRun(respond)
        action = {"id": 9, "component_id": "delta-neutral",
                  "state": {"stage": "deploy", "repo": "delta_neutral", "github": "carter2099/delta_neutral",
                            "merge_sha": sha, "has_ci": True, "merged_at": model.iso(NOW - timedelta(minutes=5)),
                            "created_at": model.iso(NOW - timedelta(hours=1)), "production_touched": False}}
        store = FakeStore()
        return RepoPrPlaybook().advance(action, make_ctx(run, store=store)), run, store, sha

    def test_green_merge_commit_is_tagged_and_pushed(self):
        outcome, run, store, sha = self.deploy()
        self.assertEqual(outcome.status, "done", outcome.detail)
        self.assertTrue(outcome.verify)
        repo = str(config.expand("~/dev/delta_neutral"))
        self.assertTrue(run.find("git", "-C", repo, "tag", "v0.1.42", sha))
        self.assertTrue(run.find("push", "origin", "refs/tags/v0.1.42"))
        self.assertEqual(store.updates[0][1]["state"]["stage"], "deploying")

    def test_pending_ci_or_a_foreign_tag_never_tags(self):
        pending, run, _, _ = self.deploy(ci=[{"name": "test", "status": "in_progress", "conclusion": None}])
        self.assertEqual(pending.status, "pending")
        self.assertEqual(run.find("tag", "v0.1.42"), [])
        foreign, run, _, _ = self.deploy(tag_sha="f" * 40)
        self.assertEqual(foreign.status, "failed")
        self.assertIn("already exists on another commit", foreign.detail)
        self.assertEqual(run.find("push"), [])


if __name__ == "__main__":
    unittest.main()
