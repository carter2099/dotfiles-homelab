#!/usr/bin/env python3
"""dotfiles-commit: commit exact paths to the private dotfiles repo, showing publish scope.

    dotfiles-commit -m MSG PATH...   stage exactly PATHs, secret-scan (block on hit),
                                     show each path's public-showcase scope, commit, push
    dotfiles-commit --classify PATH...  show scopes only (dry run: nothing staged or recorded)
    dotfiles-commit --publish [--dry-run]  run the public showcase publisher now

Scope comes from ~/system-config/dotfiles-publish.toml; ambiguous paths are
decided by Jev (after the secret scan) and recorded in
~/system-config/dotfiles-publish-decisions.json, which is committed alongside.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from steward import dotfiles, showcase  # noqa: E402

HOME = Path.home()
GIT_DIR = HOME / ".dotfiles-homelab"
BRANCH = "main"


def git(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    cp = subprocess.run(
        ["git", "--literal-pathspecs", f"--git-dir={GIT_DIR}", f"--work-tree={HOME}", *args],
        capture_output=True, text=True, timeout=180,
    )
    if check and cp.returncode != 0:
        raise SystemExit(f"dotfiles-commit: git {args[0]} failed: {cp.stderr.strip()[:500]}")
    return cp


def home_relative(raw: str) -> str:
    path = Path(os.path.abspath(os.path.expanduser(raw)))
    try:
        rel = path.relative_to(HOME).as_posix()
    except ValueError:
        raise SystemExit(f"dotfiles-commit: {raw} is outside {HOME}")
    if rel in {"", "."} or rel.split("/")[0] == ".dotfiles-homelab":
        raise SystemExit(f"dotfiles-commit: refusing {raw}")
    if path.is_dir() and not path.is_symlink():
        raise SystemExit(f"dotfiles-commit: {raw} is a directory; name the files to commit")
    return rel


def read_content(rel: str) -> bytes | None:
    path = HOME / rel
    if path.is_symlink():
        return os.readlink(path).encode()
    if path.is_file():
        return path.read_bytes()
    return None


def classify(paths: list[str], *, record: bool) -> list[str]:
    """Print each path's scope; returns extra paths to commit (the decisions file)."""
    policy = showcase.load_policy(showcase.POLICY_PATH)
    decisions = showcase.load_decisions(showcase.DECISIONS_PATH)
    client: list = []

    def get_client():
        if not client:
            client.append(showcase._load_jev_client())
        return client[0]

    recorded = {}
    for rel in paths:
        content = read_content(rel)
        if content is None:
            print(f"  {rel}: deleted (removed from the showcase on next publish)")
            continue
        d = showcase.decide(rel, content, policy=policy, decisions={**decisions, **recorded},
                            client=get_client)
        if d.record:
            recorded[rel] = d.record
        print(f"  {rel}: {d.scope} ({d.by}: {d.reason})")
    if recorded and record:
        showcase.save_decisions(showcase.DECISIONS_PATH,
                                {**showcase.load_decisions(showcase.DECISIONS_PATH), **recorded})
        print(f"  recorded {len(recorded)} Jev decision(s) in {showcase.DECISIONS_PATH}")
        return [showcase.DECISIONS_PATH.relative_to(HOME).as_posix()]
    return []


def commit(message: str, paths: list[str], push: bool) -> int:
    policy = showcase.load_policy(showcase.POLICY_PATH)
    git("add", "--all", "--", *paths)
    diff = git("diff", "--cached", "--no-color", "--", *paths).stdout
    findings = showcase.scan_diff(diff, policy, mac=False)
    if findings:
        git("reset", "--quiet", "--", *paths)
        print("dotfiles-commit: secret scan blocked the commit (paths unstaged):", file=sys.stderr)
        for f in findings[:50]:
            print(f"  {f['path']}:{f['line']} {f['rule']}", file=sys.stderr)
        return 1
    if not diff.strip():
        print("dotfiles-commit: nothing to commit for these paths")
        return 0
    print("Publish scope:")
    extra = classify(paths, record=True)
    all_paths = paths + [p for p in extra if p not in paths]
    if extra:
        git("add", "--", *extra)
    git("commit", "--quiet", "-m", message, "--", *all_paths)
    head = git("rev-parse", "--short", "HEAD").stdout.strip()
    print(f"committed {head}: {', '.join(all_paths)}")
    if not push:
        return 0
    origin_error = dotfiles._origin_matches(GIT_DIR, HOME)
    if origin_error:
        print(f"dotfiles-commit: push blocked: {origin_error}", file=sys.stderr)
        return 1
    git("fetch", "--quiet", "origin", BRANCH)
    outgoing = git("diff", "--no-color", "FETCH_HEAD", "HEAD").stdout
    findings = showcase.scan_diff(outgoing, policy, mac=False)
    if findings:
        print("dotfiles-commit: secret scan blocked the push (commit kept locally):", file=sys.stderr)
        for f in findings[:50]:
            print(f"  {f['path']}:{f['line']} {f['rule']}", file=sys.stderr)
        return 1
    git("push", "--quiet", "origin", f"HEAD:refs/heads/{BRANCH}")
    print(f"pushed to origin/{BRANCH}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dotfiles-commit", description=__doc__.split("\n\n")[0])
    parser.add_argument("-m", "--message")
    parser.add_argument("--classify", action="store_true", help="show publish scope only")
    parser.add_argument("--publish", action="store_true", help="run the showcase publisher now")
    parser.add_argument("--dry-run", action="store_true", help="with --publish: compute only")
    parser.add_argument("--no-push", action="store_true", help="commit without pushing")
    parser.add_argument("paths", nargs="*")
    args = parser.parse_args(argv)
    if args.publish:
        result = showcase.publish(dry_run=args.dry_run)
        print(f"showcase {result['status']}: {result['published_count']} public, "
              f"{len(result['held'])} held, {len(result['blocked'])} blocked")
        for key in ("added", "updated", "removed", "held", "blocked"):
            for row in result[key]:
                print(f"  {key}: {row['path']} ({row['reason']})")
        if result.get("reason"):
            print(f"  reason: {result['reason']}")
        return 0 if result["status"] in {"published", "unchanged", "dry_run"} else 1
    if not args.paths:
        parser.error("PATH required")
    paths = list(dict.fromkeys(home_relative(p) for p in args.paths))
    if args.classify:
        print("Publish scope (dry run, nothing recorded):")
        classify(paths, record=False)
        return 0
    if not args.message:
        parser.error("-m MSG required to commit")
    return commit(args.message, paths, push=not args.no_push)


if __name__ == "__main__":
    sys.exit(main())
