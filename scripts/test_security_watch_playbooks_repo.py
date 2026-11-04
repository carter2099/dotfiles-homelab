import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import contextlib
import json
import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest import mock

from security_watch import config, model, net, playbooks_repo
from security_watch.model import Finding, Outcome, Package, Plan, Refusal
from security_watch.playbooks_repo import (
    RepoPrPlaybook, bump_go_toolchain, bump_golang_from, bump_pip_pin, escape_module_path,
    is_go_pseudo_version, refresh_arg, resolve_go_tag,
)

NOW = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)
OLD_DIGEST = "sha256:" + "f2" * 32
NEW_DIGEST = "sha256:" + "d2" * 32

BLOG_DOCKERFILE = f"""ARG RUBY_VERSION=3.4.11
FROM docker.io/library/ruby:$RUBY_VERSION-slim-bookworm AS base

WORKDIR /rails

# Install base packages and apply Debian security updates
RUN apt-get update -qq && \\
    apt-get upgrade -y --no-install-recommends && \\
    apt-get install --no-install-recommends -y ca-certificates curl libjemalloc2 libvips sqlite3 && \\
    rm -rf /var/lib/apt/lists /var/cache/apt/archives

ENV RAILS_ENV="production"

FROM docker.io/library/golang:1.27.3-alpine@{OLD_DIGEST} AS thrust
COPY Gemfile.lock ./
RUN CGO_ENABLED=0 GOBIN=/usr/local/bin go install -trimpath "github.com/basecamp/thruster/cmd/thrust@v1.0.0"

FROM base AS build
RUN apt-get update -qq && \\
    apt-get install --no-install-recommends -y build-essential git libyaml-dev pkg-config && \\
    rm -rf /var/lib/apt/lists /var/cache/apt/archives
COPY Gemfile Gemfile.lock ./
RUN bundle install

FROM base
COPY --from=build /rails /rails
USER 1000:1000
CMD ./bin/rails server -p $PORT
"""

BEATZ_DOCKERFILE = """FROM golang:1.26.10-alpine AS build

WORKDIR /src
COPY go.mod ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/beatz .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/beatz /beatz
ENTRYPOINT ["/beatz"]
"""

DASHBOARD_DOCKERFILE = f"""FROM golang:1.26.10-alpine@{OLD_DIGEST} AS go-build
ARG REVISION=dev
WORKDIR /src
RUN mkdir /out && chown 65534:65534 /out
RUN go build -o /out/homelab-dashboard-collector ./cmd/collector

FROM scratch AS collector
COPY --from=go-build /out/homelab-dashboard-collector /homelab-dashboard-collector

FROM oven/bun:1.3.14-alpine AS web-build
RUN bun install --frozen-lockfile --ignore-scripts

FROM nginx:1.31.6-alpine AS web
ARG REVISION=dev
# The nginx base trails Alpine security fixes; pick them up at build time.
RUN apk upgrade --no-cache
COPY deploy/nginx.conf /etc/nginx/nginx.conf
ENTRYPOINT ["nginx"]
"""

HERDR_GO_MOD = """module github.com/carter2099/herdr-web-client

go 1.27.0

toolchain go1.27.3

require (
\tgithub.com/creack/pty v1.1.24
\tgithub.com/gorilla/websocket v1.5.3
\tgolang.org/x/term v0.47.0
)

require golang.org/x/sys v0.49.0 // indirect
"""

PROMPT_GUARD_REQUIREMENTS = """fastapi==0.139.2
uvicorn==0.51.0
torch==2.13.0
transformers==5.14.1
pydantic==2.13.4
certifi==2026.10.19
"""

SPECS = {spec.id: spec for spec in config.load_components()}


def finding(component, ecosystem, name, version, fixed, group="CVE-2026-111497", urgency="normal"):
    return Finding(
        key=f"{component}|{group}", component_id=component, group=group,
        package=Package(ecosystem, name, version), advisory_ids=[f"OSV-{group}"],
        cves=[group] if group.startswith("CVE-") else [], fixed_versions=list(fixed),
        fix_available=bool(fixed), urgency=urgency)


def completed(argv, rc=0, out=""):
    return subprocess.CompletedProcess(argv, rc, out, "")


class FakeRun:
    def __init__(self, responder=None):
        self.calls = []
        self.responder = responder or (lambda argv, kw: None)

    def __call__(self, argv, **kwargs):
        argv = list(argv)
        self.calls.append((argv, kwargs))
        result = self.responder(argv, kwargs)
        if result is None:
            return completed(argv)
        rc, out = result
        return completed(argv, rc, out)

    def find(self, *parts):
        return [(argv, kw) for argv, kw in self.calls if all(p in argv for p in parts)]


def json_response(url, payload, status=200):
    return net.Response(status=status, headers={}, body=json.dumps(payload).encode(), url=url)


def make_ctx(run, fetch=None, locks=None):
    held = locks if locks is not None else []

    @contextlib.contextmanager
    def lock(key, *, timeout=None, holder=""):
        held.append(key)
        yield

    def no_fetch(url, **kwargs):
        raise AssertionError(f"unexpected fetch {url}")

    return SimpleNamespace(
        store=None, policy=SimpleNamespace(lock_timeout_seconds=5), specs=SPECS, now=NOW,
        run=run, fetch=fetch or no_fetch, lock=lock, host_lock=None,
        steward_active=lambda: False, rescan=None, findings={})


class TempHomeTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.home = Path(self._tmp.name)
        patcher = mock.patch.dict(os.environ, {"HOME": str(self.home),
                                               "SECURITY_WATCH_STATE_DIR": str(self.home / "state")})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self._tmp.cleanup)


class RefreshArgTests(unittest.TestCase):
    def test_inserts_before_the_upgrade_run_of_the_blog_base_stage(self):
        out = refresh_arg(BLOG_DOCKERFILE, "202611031200")
        lines = out.splitlines()
        index = lines.index("ARG SECURITY_REFRESH=202611031200")
        self.assertEqual(lines[index + 1], "RUN apt-get update -qq && \\")
        self.assertLess(index, lines.index(f"FROM docker.io/library/golang:1.27.3-alpine@{OLD_DIGEST} AS thrust"))
        self.assertEqual(out.count("SECURITY_REFRESH"), 1)
        self.assertEqual(out.replace(lines[index - 1] + "\n" + lines[index] + "\n", ""), BLOG_DOCKERFILE)

    def test_updates_an_existing_arg_in_place(self):
        seeded = BLOG_DOCKERFILE.replace("RUN apt-get update -qq && \\\n    apt-get upgrade",
                                         "ARG SECURITY_REFRESH=202601010000\nRUN apt-get update -qq && \\\n    apt-get upgrade", 1)
        out = refresh_arg(seeded, "202611031200")
        self.assertIn("ARG SECURITY_REFRESH=202611031200\nRUN apt-get update -qq", out)
        self.assertNotIn("202601010000", out)
        self.assertEqual(out.count("SECURITY_REFRESH"), 1)
        self.assertEqual(len(out.splitlines()), len(seeded.splitlines()))

    def test_inserts_in_the_dashboard_nginx_stage_with_apk_upgrade(self):
        out = refresh_arg(DASHBOARD_DOCKERFILE, "202611031200")
        lines = out.splitlines()
        index = lines.index("ARG SECURITY_REFRESH=202611031200")
        self.assertEqual(lines[index + 1], "RUN apk upgrade --no-cache")
        self.assertGreater(index, lines.index("FROM nginx:1.31.6-alpine AS web"))

    def test_returns_none_without_a_package_run(self):
        self.assertIsNone(refresh_arg(BEATZ_DOCKERFILE, "202611031200"))


class BumpTests(unittest.TestCase):
    def test_golang_from_keeps_prefix_stage_and_replaces_pinned_digest(self):
        out = bump_golang_from(BLOG_DOCKERFILE, "1.27.4", NEW_DIGEST)
        self.assertIn(f"FROM docker.io/library/golang:1.27.4-alpine@{NEW_DIGEST} AS thrust\n", out)
        self.assertNotIn(OLD_DIGEST, out)
        self.assertEqual(out.replace(f"1.27.4-alpine@{NEW_DIGEST}", f"1.27.3-alpine@{OLD_DIGEST}"),
                         BLOG_DOCKERFILE)

    def test_golang_from_does_not_add_a_digest_to_an_unpinned_line(self):
        out = bump_golang_from(BEATZ_DOCKERFILE, "1.26.11", NEW_DIGEST)
        self.assertTrue(out.startswith("FROM golang:1.26.11-alpine AS build\n"))
        self.assertNotIn("@sha256", out)

    def test_golang_from_refuses_pinned_line_without_digest_and_noop(self):
        self.assertIsNone(bump_golang_from(BLOG_DOCKERFILE, "1.27.4", None))
        self.assertIsNone(bump_golang_from(BEATZ_DOCKERFILE, "1.26.10", None))
        self.assertIsNone(bump_golang_from("FROM scratch\n", "1.27.4", None))

    def test_go_toolchain_bumps_only_the_toolchain_line(self):
        out = bump_go_toolchain(HERDR_GO_MOD, "1.27.4")
        self.assertEqual(out, HERDR_GO_MOD.replace("toolchain go1.27.3", "toolchain go1.27.4"))
        self.assertIn("\ngo 1.27.0\n", out)
        self.assertIsNone(bump_go_toolchain(HERDR_GO_MOD, "1.27.3"))
        self.assertIsNone(bump_go_toolchain("module x\n\ngo 1.27.0\n", "1.27.4"))

    def test_pip_pin_changes_exactly_the_named_pin(self):
        out = bump_pip_pin(PROMPT_GUARD_REQUIREMENTS, "transformers", "5.14.2")
        self.assertEqual(out, PROMPT_GUARD_REQUIREMENTS.replace("transformers==5.14.1", "transformers==5.14.2"))
        self.assertEqual(bump_pip_pin(PROMPT_GUARD_REQUIREMENTS, "Torch", "2.13.1"),
                         PROMPT_GUARD_REQUIREMENTS.replace("torch==2.13.0", "torch==2.13.1"))

    def test_pip_pin_uses_pep503_names_and_keeps_extras_and_markers(self):
        text = "PyYAML==6.0.1\nuvicorn[standard]==0.51.0 ; python_version >= '3.12'  # server\n"
        self.assertEqual(bump_pip_pin(text, "pyyaml", "6.0.2"), text.replace("6.0.1", "6.0.2"))
        self.assertEqual(bump_pip_pin(text, "Uvicorn", "0.51.1"), text.replace("0.51.0", "0.51.1"))

    def test_pip_pin_ignores_non_exact_pins_and_missing_names(self):
        self.assertIsNone(bump_pip_pin("requests>=2.31.0\n", "requests", "2.32.0"))
        self.assertIsNone(bump_pip_pin(PROMPT_GUARD_REQUIREMENTS, "numpy", "2.0.0"))


class PlanTests(TempHomeTestCase):
    def test_refuses_an_ecosystem_with_a_pin_owner(self):
        run = FakeRun()
        result = RepoPrPlaybook().plan(
            [finding("blog", "RubyGems", "rack", "3.1.0", ["3.1.1"])], SPECS["blog"], make_ctx(run))
        self.assertIsInstance(result, Refusal)
        self.assertTrue(result.alert)
        self.assertIn("dependabot-webhook", result.reason)
        self.assertEqual(run.calls, [])

    def test_refuses_an_edit_the_component_does_not_allow(self):
        run = FakeRun()
        result = RepoPrPlaybook().plan(
            [finding("beatz", "Debian:12", "brotli", "1.0.9-2", ["1.0.9-2+deb12u1"])], SPECS["beatz"], make_ctx(run))
        self.assertIsInstance(result, Refusal)
        self.assertTrue(result.alert)
        self.assertIn("base-refresh", result.reason)
        self.assertEqual(run.calls, [])

    def test_plans_a_base_refresh_from_origin_main(self):
        def responder(argv, kw):
            if "show" in argv:
                self.assertEqual(argv[-1], "origin/main:Dockerfile")
                return 0, BLOG_DOCKERFILE
            return None
        run = FakeRun(responder)
        result = RepoPrPlaybook().plan(
            [finding("blog", "Debian:12", "brotli", "1.0.9-2", ["1.0.9-2+deb12u1"])], SPECS["blog"], make_ctx(run))
        self.assertIsInstance(result, Plan)
        self.assertEqual(result.target, "blog: Dockerfile ARG SECURITY_REFRESH (Debian security updates for brotli)")
        self.assertEqual(result.lock_keys, ["app-blog"])
        self.assertEqual(result.state["edit"], "base-refresh")
        self.assertEqual(result.state["params"], {"stamp": "202611031200"})
        self.assertTrue(run.find("fetch"))

    def test_plans_go_builder_on_the_same_minor_line(self):
        def responder(argv, kw):
            return (0, BEATZ_DOCKERFILE) if "show" in argv else None
        fetched = []

        def fetch(url, **kw):
            fetched.append(url)
            return json_response(url, {"name": "1.26.11-alpine", "digest": NEW_DIGEST})
        result = RepoPrPlaybook().plan(
            [finding("beatz", "Go", "stdlib", "1.26.10", ["1.26.11", "1.27.4"], group="GO-2026-4001")],
            SPECS["beatz"], make_ctx(FakeRun(responder), fetch))
        self.assertIsInstance(result, Plan)
        self.assertEqual(result.target, "beatz: Dockerfile golang 1.26.10 -> 1.26.11")
        self.assertEqual(result.state["params"], {"version": "1.26.11", "digest": None})
        self.assertEqual(result.fixed_version, "1.26.11")
        self.assertEqual(fetched, ["https://hub.docker.com/v2/repositories/library/golang/tags/1.26.11-alpine"])


CRYPTO = "golang.org/x/crypto"
PSEUDO = "0.58.1-0.20261009181718-" + "2f1f" * 3
BACKUP_GO_MOD = f"""module github.com/carter2099/homelab-backup

go 1.27.0

require (
\t{CRYPTO} v0.57.0
\tgithub.com/BurntSushi/toml v1.4.0
)
"""


def proxy_fetch(listing, fetched):
    def fetch(url, **kw):
        fetched.append(url)
        return net.Response(status=200, headers={}, body=listing.encode(), url=url)
    return fetch


class GoModuleVersionTests(TempHomeTestCase):
    def plan_backup(self, fixed, listing, fetched):
        def responder(argv, kw):
            return (0, BACKUP_GO_MOD) if "show" in argv else None
        return RepoPrPlaybook().plan(
            [finding("homelab-backup", "Go", CRYPTO, "0.57.0", fixed)], SPECS["homelab-backup"],
            make_ctx(FakeRun(responder), proxy_fetch(listing, fetched) if listing is not None else None))

    def test_recognises_pseudo_version_forms(self):
        self.assertTrue(is_go_pseudo_version("v" + PSEUDO))
        self.assertTrue(is_go_pseudo_version(PSEUDO))
        self.assertTrue(is_go_pseudo_version("v1.2.3-rc.1.0.20261009181718-" + "2f1f" * 3))
        self.assertTrue(is_go_pseudo_version("v0.0.0-20261009181718-" + "2f1f" * 3))
        self.assertFalse(is_go_pseudo_version("v0.58.1"))
        self.assertFalse(is_go_pseudo_version("v0.59.0-rc.1"))

    def test_pseudo_version_resolves_to_the_next_tag(self):
        fetched = []
        listing = "v0.57.0\nv0.58.0\nv0.59.0-rc.1\nv0.59.0\nv0.60.0\n"
        self.assertEqual(resolve_go_tag(CRYPTO, PSEUDO, proxy_fetch(listing, fetched)), "0.59.0")
        self.assertEqual(fetched, ["https://proxy.golang.org/golang.org/x/crypto/@v/list"])
        self.assertEqual(resolve_go_tag(CRYPTO, PSEUDO, proxy_fetch("v0.58.1\nv0.59.0\n", [])), "0.58.1")

    def test_plan_pins_the_tag_instead_of_the_pseudo_version(self):
        fetched = []
        result = self.plan_backup([PSEUDO], "v0.57.0\nv0.58.0\nv0.59.0\n", fetched)
        self.assertIsInstance(result, Plan)
        self.assertEqual(result.state["params"], {"modules": [[CRYPTO, "0.59.0"]]})
        self.assertEqual(result.target, f"homelab-backup: go.mod {CRYPTO} v0.57.0 -> v0.59.0")
        self.assertNotIn(PSEUDO, " ".join(result.steps))
        self.assertEqual(len(fetched), 1)

    def test_no_newer_tag_is_an_alert_refusal(self):
        result = self.plan_backup([PSEUDO], "v0.57.0\nv0.58.0\nv0.59.0-rc.1\n", [])
        self.assertIsInstance(result, Refusal)
        self.assertTrue(result.alert)
        self.assertEqual(result.reason, f"fix for {CRYPTO} exists only at an untagged commit (v{PSEUDO}); "
                                        "waiting for a tagged release")

    def test_tagged_fixed_version_skips_the_proxy(self):
        result = self.plan_backup(["0.58.0"], None, [])
        self.assertIsInstance(result, Plan)
        self.assertEqual(result.state["params"], {"modules": [[CRYPTO, "0.58.0"]]})

    def test_module_path_escapes_upper_case_letters(self):
        self.assertEqual(escape_module_path("github.com/BurntSushi/toml"), "github.com/!burnt!sushi/toml")
        fetched = []
        resolve_go_tag("github.com/BurntSushi/toml", "1.4.1-0.20261009181718-" + "2f1f" * 3,
                       proxy_fetch("v1.4.0\nv1.5.0\n", fetched))
        self.assertEqual(fetched, ["https://proxy.golang.org/github.com/!burnt!sushi/toml/@v/list"])


def blog_plan():
    return Plan(playbook="repo-pr", component_id="blog", finding_keys=["blog|CVE-2026-111497"],
                target="blog: Dockerfile ARG SECURITY_REFRESH (Debian security updates for brotli)",
                lock_keys=["app-blog"], steps=["edit"], undo="gh pr close",
                state={"edit": "base-refresh", "path": "Dockerfile", "params": {"stamp": "202611031200"},
                       "repo": "blog", "github": "carter2099/blog", "cves": ["CVE-2026-111497"],
                       "group": "CVE-2026-111497", "packages": ["brotli"]})


class ApplyTests(TempHomeTestCase):
    def responder(self, dockerfile):
        self.worktree = None
        self.committed = None

        def respond(argv, kw):
            if "worktree" in argv and "add" in argv:
                self.worktree = Path(argv[6])
                (self.worktree / "Dockerfile").write_text(dockerfile)
                (self.worktree / ".github" / "workflows").mkdir(parents=True)
                (self.worktree / ".github" / "workflows" / "ci.yml").write_text("on: push\n")
                return None
            if "status" in argv:
                return 0, " M Dockerfile\n"
            if "add" in argv and "--" in argv:
                self.committed = (self.worktree / "Dockerfile").read_text()
                return None
            if "rev-parse" in argv:
                return 0, "headsha1\n"
            if argv[:3] == ["gh", "pr", "create"]:
                return 0, "https://github.com/carter2099/blog/pull/42\n"
            return None
        return respond

    def test_opens_a_labelled_pr_and_removes_the_worktree(self):
        run = FakeRun(self.responder(BLOG_DOCKERFILE))
        outcome = RepoPrPlaybook().apply(blog_plan(), make_ctx(run))
        self.assertEqual(outcome.status, "pending", outcome.detail)
        self.assertEqual(outcome.state["stage"], "ci")
        self.assertEqual(outcome.state["pr"], 42)
        self.assertEqual(outcome.state["branch"], "secwatch/blog-cve-2026-111497-202611031200")
        self.assertFalse(outcome.state["production_touched"])
        self.assertTrue(outcome.state["has_ci"])
        self.assertIn("ARG SECURITY_REFRESH=202611031200\nRUN apt-get update -qq", self.committed)
        commit = run.find("commit")[0][0]
        self.assertIn("security: base-refresh for CVE-2026-111497", commit)
        self.assertTrue(run.find("push", "origin", "HEAD:refs/heads/secwatch/blog-cve-2026-111497-202611031200"))
        create = run.find("gh", "pr", "create")[0][0]
        self.assertEqual(create[create.index("--label") + 1], "security-watch")
        self.assertTrue(run.find("worktree", "remove", "--force", str(self.worktree)))
        self.assertFalse(self.worktree.exists())

    def test_removes_the_worktree_when_the_edit_fails(self):
        run = FakeRun(self.responder(BEATZ_DOCKERFILE))
        outcome = RepoPrPlaybook().apply(blog_plan(), make_ctx(run))
        self.assertEqual(outcome.status, "failed")
        self.assertFalse(outcome.state["production_touched"])
        self.assertTrue(run.find("worktree", "remove", "--force", str(self.worktree)))
        self.assertFalse(self.worktree.exists())
        self.assertEqual(run.find("push"), [])
        self.assertEqual(run.find("gh", "pr", "create"), [])


def pr_json(*, state="OPEN", labels=(), rollup=None, mergeable="MERGEABLE", head="headsha1", merge_oid=None):
    return json.dumps({
        "state": state, "mergeable": mergeable, "mergeStateStatus": "CLEAN", "headRefOid": head,
        "labels": [{"name": name} for name in labels],
        "statusCheckRollup": rollup if rollup is not None else [
            {"__typename": "CheckRun", "name": "test", "status": "COMPLETED", "conclusion": "SUCCESS"}],
        "mergeCommit": {"oid": merge_oid} if merge_oid else None,
    })


def action(component="blog", **state):
    base = {"stage": "ci", "repo": component, "github": f"carter2099/{component}", "branch": "secwatch/x",
            "pr": 42, "url": "https://github.com/carter2099/x/pull/42", "edit": "base-refresh",
            "head": "headsha1", "has_ci": True, "created_at": model.iso(NOW - timedelta(hours=1)),
            "production_touched": False}
    base.update(state)
    return {"id": 7, "component_id": component, "state": base}


class AdvanceTests(TempHomeTestCase):
    def setUp(self):
        super().setUp()
        self.deploys = []

        def app_deploy(service, spec, dry_run=False, *, sleep):
            self.deploys.append((service, spec, dry_run))
            return self.deploy_row
        self.deploy_row = {"status": "ok", "reason": "CI-green origin/main", "revert": "git revert it"}
        self.registry = {"blog": {"repo": "~/dev/blog", "github": "carter2099/blog"}}
        self.playbook = RepoPrPlaybook(app_deploy=app_deploy, deploy_registry=self.registry,
                                       auto_merge_repos={"blog"}, sleep=lambda seconds: None)

    def gh(self, view, repo_view=None):
        def respond(argv, kw):
            if argv[:3] == ["gh", "pr", "view"]:
                return 0, view
            if argv[:3] == ["gh", "repo", "view"]:
                return 0, repo_view or json.dumps(
                    {"rebaseMergeAllowed": True, "squashMergeAllowed": True, "mergeCommitAllowed": True})
            return None
        return FakeRun(respond)

    def test_hold_label_refuses(self):
        outcome = self.playbook.advance(action(), make_ctx(self.gh(pr_json(labels=["hold"]))))
        self.assertEqual(outcome.status, "refused")
        self.assertIn("held by Carter", outcome.detail)

    def test_failed_check_fails_without_touching_production(self):
        rollup = [{"__typename": "CheckRun", "name": "test", "status": "COMPLETED", "conclusion": "FAILURE"}]
        outcome = self.playbook.advance(action(), make_ctx(self.gh(pr_json(rollup=rollup))))
        self.assertEqual(outcome.status, "failed")
        self.assertFalse(outcome.state["production_touched"])

    def test_pending_checks_wait_then_give_up_after_a_day(self):
        rollup = [{"__typename": "CheckRun", "name": "test", "status": "IN_PROGRESS", "conclusion": ""}]
        run = self.gh(pr_json(rollup=rollup))
        self.assertEqual(self.playbook.advance(action(), make_ctx(run)).status, "pending")
        late = action(created_at=model.iso(NOW - timedelta(hours=25)))
        self.assertEqual(self.playbook.advance(late, make_ctx(run)).status, "failed")
        self.assertEqual(run.find("merge"), [])

    def test_green_pr_merges_with_the_allowed_method(self):
        run = self.gh(pr_json(), json.dumps(
            {"rebaseMergeAllowed": False, "squashMergeAllowed": True, "mergeCommitAllowed": True}))
        outcome = self.playbook.advance(action(), make_ctx(run))
        self.assertEqual(outcome.status, "pending")
        self.assertEqual(outcome.state["stage"], "merging")
        merge = run.find("gh", "pr", "merge")[0][0]
        self.assertIn("--squash", merge)
        self.assertIn("--auto", merge)
        self.assertNotIn("--admin", merge)
        self.assertEqual(merge[merge.index("--match-head-commit") + 1], "headsha1")

    def test_merge_without_auto_outside_the_candidates(self):
        run = self.gh(pr_json())
        outcome = self.playbook.advance(action("beatz"), make_ctx(run))
        self.assertEqual(outcome.state["stage"], "merging")
        merge = run.find("gh", "pr", "merge")[0][0]
        self.assertIn("--rebase", merge)
        self.assertNotIn("--auto", merge)

    def test_merged_pr_moves_to_deploy(self):
        run = self.gh(pr_json(state="MERGED", merge_oid="mergesha1"))
        outcome = self.playbook.advance(action(stage="merging", merge_requested_at=model.iso(NOW)), make_ctx(run))
        self.assertEqual(outcome.status, "pending")
        self.assertEqual(outcome.state["stage"], "deploy")
        self.assertEqual(outcome.state["merge_sha"], "mergesha1")
        self.assertIn("revert --no-edit mergesha1", outcome.undo)

    def test_deploy_runs_steward_app_deploy_under_the_lock(self):
        locks = []
        fetch = lambda url, **kw: net.Response(status=200, headers={}, body=b"ok", url=url)
        outcome = self.playbook.advance(
            action(stage="deploy", merge_sha="mergesha1", merged_at=model.iso(NOW)),
            make_ctx(FakeRun(), fetch, locks))
        self.assertEqual(outcome.status, "done", outcome.detail)
        self.assertTrue(outcome.verify)
        self.assertTrue(outcome.state["production_touched"])
        self.assertEqual(locks, ["app-blog"])
        self.assertEqual(self.deploys, [("blog", self.registry["blog"], False)])
        self.assertEqual(outcome.undo, "git revert it")

    def test_deploy_skipped_until_ci_is_green_stays_pending(self):
        self.deploy_row = {"status": "skipped", "reason": "origin/main abc1234 is not CI-green: pending"}
        outcome = self.playbook.advance(
            action(stage="deploy", merge_sha="mergesha1", merged_at=model.iso(NOW)), make_ctx(FakeRun()))
        self.assertEqual(outcome.status, "pending")
        self.assertFalse(outcome.state["production_touched"])

    def test_rolled_back_app_deploy_is_reported(self):
        self.deploy_row = {"status": "rolled_back", "error": "deploy exited 1; production verified back"}
        outcome = self.playbook.advance(
            action(stage="deploy", merge_sha="mergesha1", merged_at=model.iso(NOW)), make_ctx(FakeRun()))
        self.assertEqual(outcome.status, "rolled_back")
        self.assertTrue(outcome.state["production_touched"])

    def test_release_deploy_pulls_and_runs_the_script(self):
        def respond(argv, kw):
            if "symbolic-ref" in argv:
                return 0, "main\n"
            return None
        run = FakeRun(respond)
        fetch = lambda url, **kw: net.Response(status=200, headers={}, body=b"ok", url=url)
        locks = []
        outcome = self.playbook.advance(
            action("beatz", stage="deploy", merge_sha="mergesha1", merged_at=model.iso(NOW)),
            make_ctx(run, fetch, locks))
        self.assertEqual(outcome.status, "done", outcome.detail)
        self.assertTrue(outcome.state["production_touched"])
        self.assertEqual(locks, ["app-beatz"])
        self.assertTrue(run.find("pull", "--ff-only", "origin", "main"))
        bash = run.find("bash", "release.sh")[0]
        self.assertEqual(bash[1]["cwd"], str(self.home / "dev" / "beatz"))
        self.assertEqual(bash[1]["timeout"], 1800)
        self.assertTrue(bash[1]["env"]["PATH"].startswith(str(self.home / ".local/go/bin") + ":"))

    def test_release_deploy_waits_for_a_dirty_checkout(self):
        def respond(argv, kw):
            if "symbolic-ref" in argv:
                return 0, "main\n"
            if "status" in argv:
                return 0, " M notes.txt\n"
            return None
        run = FakeRun(respond)
        outcome = self.playbook.advance(
            action("beatz", stage="deploy", merge_sha="mergesha1", merged_at=model.iso(NOW)), make_ctx(run))
        self.assertEqual(outcome.status, "pending")
        self.assertFalse(outcome.state["production_touched"])
        self.assertEqual(run.find("bash"), [])


class RegistryTests(unittest.TestCase):
    def test_exports_the_multi_tick_repo_pr_playbook(self):
        playbook = playbooks_repo.PLAYBOOKS["repo-pr"]
        self.assertEqual(playbook.id, "repo-pr")
        self.assertTrue(playbook.multi_tick)


if __name__ == "__main__":
    unittest.main()
