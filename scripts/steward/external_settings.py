"""Expected-state snapshots of external settings (GitHub repos, Cloudflare).

Tracked files under ``~/system-config/external/`` hold the normalized, sorted
settings the homelab's automation relies on: repo merge settings, rulesets,
branch protection, Dependabot security updates, vulnerability alerts, webhooks
and labels for every repo the automation touches; the homelab tunnel's ingress,
the zone's DNS records and the zone's Access apps and policies.  Volatile
fields (ids, timestamps, counters, API links) are dropped and the Cloudflare
account/zone/tunnel ids are replaced by placeholders, so a diff means a setting
changed.

``--write`` refreshes the files (explicit only; a secret-scan hit or any API
failure aborts before anything is written: ``system-config/**`` is published
to the public dotfiles mirror).  ``--check`` compares live against tracked; the
steward's P3a runs it report-only.  An endpoint that refuses for permission
reasons (HTTP 403/404) is recorded as ``{"unreadable": ...}``; anything else
(network, timeout, 5xx, auth) is an error, never a clean result.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from .config import (
    AUTO_MERGE_CANDIDATES,
    AUTO_MERGE_EXCLUDED,
    DEPENDABOT_AGENT_OWNED_REPOS,
    DEPENDABOT_WEBHOOK_BUNDLER_REPOS,
    DEPLOY_REGISTRY,
    DOTFILES_REPO,
    GITHUB_OWNER,
    HOME,
    STEWARD_PATH,
)
from .runtime import atomic_write_text

SNAPSHOT_DIR = HOME / "system-config" / "external"
CLOUDFLARE_DIR = HOME / ".config" / "cloudflare"
CLOUDFLARE_API = "https://api.cloudflare.com/client/v4"
COMPONENTS_TOML = HOME / "scripts" / "security_watch" / "components.toml"
DEPENDABOT_REPOS_YAML = HOME / "dev" / "dependabot-webhook" / "repos.yaml"
EXTRA_REPOS = ("dotfiles-homelab-private", "dotfiles-homelab", "notes")
REFRESH_COMMAND = "python3 ~/scripts/steward_external_settings.py --write"
CHECK_COMMAND = "python3 ~/scripts/steward_external_settings.py --check"
CALL_TIMEOUT = 20      # seconds per API call
BUDGET_SECONDS = 150   # whole collection (P3a stays bounded)
WORKERS = 8

_HTTP_STATUS = re.compile(r"\(HTTP (\d{3})\)")
_VOLATILE = frozenset({
    "id", "node_id", "uid", "url", "html_url", "_links", "created_at", "updated_at",
    "created_on", "modified_on", "comment_modified_on", "contexts_url",
    "current_user_can_bypass", "version",
})


class CollectError(Exception):
    """An API call failed for a reason other than permissions."""


# ── helpers ──────────────────────────────────────────────────────────

def _strip(value: Any, drop=_VOLATILE) -> Any:
    """Drop volatile keys at every depth."""
    if isinstance(value, dict):
        return {k: _strip(v, drop) for k, v in value.items() if k not in drop}
    if isinstance(value, list):
        return [_strip(v, drop) for v in value]
    return value


def _fingerprint(value: str) -> str:
    return "sha256:" + hashlib.sha256(str(value).encode()).hexdigest()[:12]


def _redact(value: Any, ids: dict[str, str]) -> Any:
    """Replace account/zone/tunnel ids anywhere in strings with placeholders."""
    if isinstance(value, dict):
        return {k: _redact(v, ids) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(v, ids) for v in value]
    if isinstance(value, str):
        for secret, placeholder in ids.items():
            if secret:
                value = value.replace(secret, placeholder)
    return value


def _remaining(deadline: float) -> float:
    left = deadline - time.monotonic()
    if left <= 0:
        raise CollectError(f"time budget of {BUDGET_SECONDS}s exceeded")
    return min(CALL_TIMEOUT, left)


def render(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


# ── GitHub ───────────────────────────────────────────────────────────

def _repo_name(name: str) -> str:
    name = name.strip().lstrip(".")
    return name if "/" in name else f"{GITHUB_OWNER}/{name}"


def github_repos() -> list[str]:
    """Every repo the automation touches. Raises CollectError when a source is unreadable."""
    names = {str(v["github"]) for v in DEPLOY_REGISTRY.values() if v.get("github")}
    names |= set(AUTO_MERGE_CANDIDATES) | set(DEPENDABOT_WEBHOOK_BUNDLER_REPOS)
    names |= set(DEPENDABOT_AGENT_OWNED_REPOS) | set(AUTO_MERGE_EXCLUDED)
    names |= {DOTFILES_REPO, *EXTRA_REPOS}
    try:
        components = tomllib.loads(COMPONENTS_TOML.read_text(encoding="utf-8"))
        yaml_text = DEPENDABOT_REPOS_YAML.read_text(encoding="utf-8")
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise CollectError(f"repo list source unreadable: {e}") from e
    for component in components.get("component") or []:
        for key in ("repo", "github"):
            if isinstance(component.get(key), str):
                names.add(component[key])
    names |= set(re.findall(r"(?m)^  ([\w.-]+/[\w.-]+):\s*$", yaml_text))
    return sorted({_repo_name(n) for n in names})


def _gh(path: str, deadline: float, paginate: bool = False) -> tuple[int, Any, str]:
    """(status, json-or-None, message). 403/404 come back; other failures raise."""
    cmd = ["gh", "api", "-H", "Accept: application/vnd.github+json", path]
    if paginate:
        cmd.insert(2, "--paginate")
    env = {**os.environ, "PATH": f"{STEWARD_PATH}:{os.environ.get('PATH', '')}",
           "GH_PROMPT_DISABLED": "1", "NO_COLOR": "1"}
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True,
                            timeout=_remaining(deadline), env=env)
    except subprocess.TimeoutExpired as e:
        raise CollectError(f"gh api {path}: timed out") from e
    except OSError as e:
        raise CollectError(f"gh api {path}: {e.strerror or e}") from e
    if cp.returncode == 0:
        text = cp.stdout.strip()
        if not text:
            return 204, None, ""
        if paginate:  # --paginate concatenates one JSON array per page
            text = re.sub(r"\]\s*\[", ",", text)
        try:
            return 200, json.loads(text), ""
        except json.JSONDecodeError as e:
            raise CollectError(f"gh api {path}: invalid JSON ({e.msg})") from e
    match = _HTTP_STATUS.search(cp.stderr or "")
    status = int(match.group(1)) if match else 0
    message = ""
    try:
        message = str(json.loads(cp.stdout).get("message") or "")
    except (json.JSONDecodeError, AttributeError):
        pass
    if status in (403, 404):
        return status, None, message or "no message"
    detail = (cp.stderr or "").strip().splitlines()
    raise CollectError(f"gh api {path}: {detail[-1][:200] if detail else f'rc={cp.returncode}'}")


def _unreadable(status: int, message: str) -> dict[str, str]:
    return {"unreadable": f"HTTP {status}: {message[:200]}"}


_REPO_KEYS = (
    "visibility", "default_branch", "archived", "allow_auto_merge", "allow_merge_commit",
    "allow_squash_merge", "allow_rebase_merge", "allow_update_branch",
    "delete_branch_on_merge",
)


def github_snapshot(repo: str, deadline: float) -> dict[str, Any]:
    status, data, msg = _gh(f"repos/{repo}", deadline)
    if data is None:
        return {"repo": repo, "settings": _unreadable(status, msg)}
    settings = {k: data.get(k) for k in _REPO_KEYS}
    security = data.get("security_and_analysis")
    if isinstance(security, dict):
        settings["security_and_analysis"] = {
            k: v.get("status") for k, v in security.items() if isinstance(v, dict)}
    snap: dict[str, Any] = {"repo": repo, "settings": settings}

    status, data, msg = _gh(f"repos/{repo}/rulesets", deadline)
    if data is None:
        snap["rulesets"] = _unreadable(status, msg)
    else:
        rulesets = []
        for row in data:
            status, detail, msg = _gh(f"repos/{repo}/rulesets/{row['id']}", deadline)
            if detail is None:
                rulesets.append({"name": row.get("name"), **_unreadable(status, msg)})
                continue
            rulesets.append(_strip({k: detail.get(k) for k in (
                "name", "target", "enforcement", "conditions", "rules", "bypass_actors")}))
        snap["rulesets"] = sorted(rulesets, key=lambda r: str(r.get("name")))

    branch = settings.get("default_branch") or "main"
    status, data, msg = _gh(f"repos/{repo}/branches/{branch}/protection", deadline)
    if data is not None:
        snap["branch_protection"] = _strip(data)
    elif status == 404 and "not protected" in msg.lower():
        snap["branch_protection"] = None
    else:
        snap["branch_protection"] = _unreadable(status, msg)

    status, data, msg = _gh(f"repos/{repo}/automated-security-fixes", deadline)
    snap["dependabot_security_updates"] = (
        data if isinstance(data, dict) else _unreadable(status, msg))

    # GitHub answers 204 when alerts are enabled and 404 when they are not.
    status, _data, msg = _gh(f"repos/{repo}/vulnerability-alerts", deadline)
    snap["vulnerability_alerts"] = (
        {"enabled": True} if status == 204 else
        {"enabled": False} if status == 404 else _unreadable(status, msg))

    status, data, msg = _gh(f"repos/{repo}/hooks", deadline, paginate=True)
    if data is None:
        snap["webhooks"] = _unreadable(status, msg)
    else:
        hooks = []
        for hook in data:
            config = hook.get("config") or {}
            hooks.append({
                "name": hook.get("name"), "active": hook.get("active"),
                "events": sorted(hook.get("events") or []),
                "config": {k: config.get(k) for k in ("url", "content_type", "insecure_ssl")},
            })
        snap["webhooks"] = sorted(hooks, key=lambda h: (str(h["config"]["url"]), str(h["name"])))

    status, data, msg = _gh(f"repos/{repo}/labels?per_page=100", deadline, paginate=True)
    snap["labels"] = (sorted(str(label.get("name")) for label in data)
                      if data is not None else _unreadable(status, msg))
    return snap


def github_path(repo: str) -> str:
    return "github/" + repo.replace("/", "__") + ".json"


# ── Cloudflare ───────────────────────────────────────────────────────

def _cf_ids() -> dict[str, str]:
    try:
        return {name: (CLOUDFLARE_DIR / name).read_text(encoding="utf-8").strip()
                for name in ("api-token", "account-id", "zone-id", "homelab-tunnel-id")}
    except OSError as e:
        raise CollectError(f"Cloudflare credentials unreadable: {e.strerror or e}") from e


def _cf(path: str, ids: dict[str, str], deadline: float, label: str) -> tuple[int, Any, str]:
    """(status, result, message); 403/404 come back, other failures raise.

    The label, never the URL (it embeds account/zone ids), names the call in errors.
    """
    request = urllib.request.Request(
        CLOUDFLARE_API + path, headers={"Authorization": f"Bearer {ids['api-token']}"})
    try:
        with urllib.request.urlopen(request, timeout=_remaining(deadline)) as response:
            body = json.load(response)
    except urllib.error.HTTPError as e:
        try:
            errors = json.loads(e.read() or b"{}").get("errors") or []
        except (json.JSONDecodeError, AttributeError):
            errors = []
        message = "; ".join(str(err.get("message")) for err in errors if isinstance(err, dict))
        if e.code in (403, 404):
            return e.code, None, message or "no message"
        raise CollectError(f"Cloudflare {label}: HTTP {e.code} {message[:160]}") from e
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as e:
        reason = getattr(e, "reason", None) or type(e).__name__
        raise CollectError(f"Cloudflare {label}: {str(reason)[:160]}") from e
    if not body.get("success", False):
        raise CollectError(f"Cloudflare {label}: API reported failure")
    return 200, body, ""


def _cf_pages(path: str, ids, deadline, label) -> tuple[int, list | None, str]:
    rows, page = [], 1
    while True:
        sep = "&" if "?" in path else "?"
        status, body, msg = _cf(f"{path}{sep}page={page}", ids, deadline, label)
        if body is None:
            return status, None, msg
        rows.extend(body.get("result") or [])
        info = body.get("result_info") or {}
        if page >= int(info.get("total_pages") or 1):
            return 200, rows, ""
        page += 1


_ACCESS_VOLATILE = frozenset({"id", "uid", "created_at", "updated_at"})


def cloudflare_snapshots(deadline: float) -> dict[str, Any]:
    ids = _cf_ids()
    placeholders = {ids["account-id"]: "<account-id>", ids["zone-id"]: "<zone-id>",
                    ids["homelab-tunnel-id"]: "<homelab-tunnel-id>"}
    acct, zone, tunnel = ids["account-id"], ids["zone-id"], ids["homelab-tunnel-id"]
    out: dict[str, Any] = {}

    status, body, msg = _cf(f"/accounts/{acct}/cfd_tunnel/{tunnel}/configurations",
                            ids, deadline, "tunnel configuration")
    if body is None:
        out["cloudflare/tunnel.json"] = _unreadable(status, msg)
    else:
        config = (body.get("result") or {}).get("config") or {}
        ingress = [_fingerprint_aud(rule) for rule in config.get("ingress") or []]
        tunnel_snap = {"tunnel": "homelab", "ingress": ingress}
        if "originRequest" in config:
            tunnel_snap["originRequest"] = _fingerprint_aud(config["originRequest"])
        out["cloudflare/tunnel.json"] = tunnel_snap

    status, rows, msg = _cf_pages(f"/zones/{zone}/dns_records?per_page=100", ids, deadline,
                                  "DNS records")
    if rows is None:
        out["cloudflare/dns.json"] = _unreadable(status, msg)
    else:
        records = []
        for r in rows:
            record = {k: r.get(k) for k in ("type", "name", "content", "proxied", "ttl")}
            if r.get("priority") is not None:
                record["priority"] = r["priority"]
            records.append(record)
        out["cloudflare/dns.json"] = {"records": sorted(records, key=lambda r: (
            str(r["name"]), str(r["type"]), str(r["content"])))}

    access: dict[str, Any] = {}
    status, rows, msg = _cf_pages(f"/zones/{zone}/access/apps", ids, deadline, "Access apps")
    if rows is None:
        access["apps"] = {"unreadable": f"HTTP {status}: {msg[:160]} (token lacks {_ACCESS_READ})"}
    else:
        apps = []
        for app in rows:
            # Top level only: nested include/exclude rules reference groups/IdPs by id.
            app = _fingerprint_aud({k: v for k, v in app.items() if k not in _ACCESS_VOLATILE})
            app["policies"] = sorted(
                ({k: v for k, v in p.items() if k not in _ACCESS_VOLATILE}
                 for p in app.get("policies") or [] if isinstance(p, dict)),
                key=lambda p: (p.get("precedence") or 0, str(p.get("name"))))
            apps.append(app)
        access["apps"] = sorted(apps, key=lambda a: (str(a.get("domain")), str(a.get("name"))))
    status, rows, msg = _cf_pages(f"/zones/{zone}/access/groups", ids, deadline, "Access groups")
    access["groups"] = (sorted(({k: v for k, v in g.items() if k not in _ACCESS_VOLATILE}
                                for g in rows), key=lambda g: str(g.get("name")))
                        if rows is not None else
                        {"unreadable": f"HTTP {status}: {msg[:160]} (token lacks Access: "
                                       "Organizations, Identity Providers, and Groups Read)"})
    out["cloudflare/access.json"] = access
    return _redact(out, placeholders)


def _fingerprint_aud(value: Any) -> Any:
    """Access application audience tags as short fingerprints (still diffable)."""
    if isinstance(value, dict):
        return {k: (_fingerprint_list(v) if k in ("aud", "audTag") else _fingerprint_aud(v))
                for k, v in value.items()}
    if isinstance(value, list):
        return [_fingerprint_aud(v) for v in value]
    return value


def _fingerprint_list(value: Any) -> Any:
    if isinstance(value, list):
        return [_fingerprint(v) for v in value]
    return _fingerprint(value)


# ── collect / diff / check / write ───────────────────────────────────

def collect(budget: float = BUDGET_SECONDS) -> tuple[dict[str, Any], list[str]]:
    """({relative path: snapshot}, [errors]). A failed source contributes an error, no file."""
    deadline = time.monotonic() + budget
    files: dict[str, Any] = {}
    errors: list[str] = []
    try:
        repos = github_repos()
    except CollectError as e:
        repos, errors = [], [str(e)]

    def one_repo(repo):
        return github_snapshot(repo, deadline)

    def cloudflare():
        return cloudflare_snapshots(deadline)

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        cf_future = pool.submit(cloudflare)
        futures = {repo: pool.submit(one_repo, repo) for repo in repos}
        for repo, future in futures.items():
            try:
                files[github_path(repo)] = future.result()
            except CollectError as e:
                errors.append(f"{repo}: {e}")
        try:
            files.update(cf_future.result())
        except CollectError as e:
            errors.append(str(e))
    return files, errors


def _keyed(rows: list) -> dict | None:
    """A list of named dicts as {name: row} for readable diff paths, else None."""
    for key in ("name", "hostname", "repo"):
        if rows and all(isinstance(r, dict) and key in r for r in rows):
            names = [str(r[key]) for r in rows]
            if len(set(names)) == len(names):
                return dict(zip(names, rows))
    return None


def diff_paths(old: Any, new: Any, path: str = "") -> list[dict[str, str]]:
    """[{"path", "change": changed|added|removed}] between two snapshots."""
    if old == new:
        return []
    if isinstance(old, list) and isinstance(new, list):
        old_k, new_k = _keyed(old), _keyed(new)
        if old_k is not None and new_k is not None:
            old, new = old_k, new_k
    if isinstance(old, dict) and isinstance(new, dict):
        out = []
        for key in sorted(set(old) | set(new), key=str):
            sub = f"{path}.{key}" if path else str(key)
            if key not in old:
                out.append({"path": sub, "change": "added"})
            elif key not in new:
                out.append({"path": sub, "change": "removed"})
            else:
                out.extend(diff_paths(old[key], new[key], sub))
        return out
    return [{"path": path or "(whole file)", "change": "changed"}]


def _tracked(snapshot_dir: Path) -> dict[str, Any]:
    tracked = {}
    for path in sorted(snapshot_dir.glob("**/*.json")):
        rel = path.relative_to(snapshot_dir).as_posix()
        try:
            tracked[rel] = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            tracked[rel] = {"_invalid": str(e)[:200]}
    return tracked


def compare(live: dict[str, Any], tracked: dict[str, Any], errors=()) -> dict[str, Any]:
    """Structured diff of live snapshots vs tracked files."""
    failed = {e.split(":", 1)[0] for e in errors}
    github_unknown = any(e.startswith("repo list") for e in errors)
    cloudflare_failed = any(e.startswith("Cloudflare") for e in errors)
    files = []
    for rel in sorted(set(live) | set(tracked)):
        if rel not in live:
            # A source that errored is not evidence the file went stale.
            repo = rel.removeprefix("github/").removesuffix(".json").replace("__", "/")
            if rel.startswith("github/") and (github_unknown or repo in failed):
                continue
            if rel.startswith("cloudflare/") and cloudflare_failed:
                continue
            files.append({"path": rel, "status": "stale",
                          "changes": [{"path": "(whole file)", "change": "no longer produced"}]})
        elif rel not in tracked:
            files.append({"path": rel, "status": "new",
                          "changes": [{"path": "(whole file)", "change": "not tracked yet"}]})
        else:
            changes = diff_paths(tracked[rel], live[rel])
            if changes:
                files.append({"path": rel, "status": "changed", "changes": changes})
    status = "error" if errors else ("drift" if files else "ok")
    return {"status": status, "files": files, "errors": list(errors),
            "checked": len(live), "refresh": REFRESH_COMMAND}


def check(snapshot_dir: Path | None = None, budget: float = BUDGET_SECONDS) -> dict[str, Any]:
    """Report-only comparison for P3a; never raises, never writes."""
    snapshot_dir = Path(snapshot_dir or SNAPSHOT_DIR)
    base = {"snapshot_dir": str(snapshot_dir), "refresh": REFRESH_COMMAND}
    if os.environ.get("STEWARD_OFFLINE") == "1":
        return {**base, "status": "error", "files": [], "errors": ["offline (STEWARD_OFFLINE=1)"]}
    if not snapshot_dir.is_dir():
        return {**base, "status": "attention_needed", "files": [], "errors": [],
                "reason": "no tracked snapshots; run the refresh command"}
    try:
        live, errors = collect(budget)
    except Exception as e:  # noqa: BLE001 - P3a reports, never crashes
        return {**base, "status": "error", "files": [], "errors": [f"{type(e).__name__}: {e}"[:300]]}
    return {**base, **compare(live, _tracked(snapshot_dir), errors)}


def secret_findings(files: dict[str, Any], snapshot_dir: Path) -> list[str]:
    """P9c's deterministic scanner over every rendered snapshot (path and rule only)."""
    from .public_dotfiles import scan

    hits = []
    for rel, data in sorted(files.items()):
        path = snapshot_dir / rel
        try:
            home_rel = path.relative_to(HOME).as_posix()
        except ValueError:
            home_rel = path.as_posix()
        reason = scan(home_rel, render(data).encode("utf-8"), entropy=True)
        if reason:
            hits.append(f"{rel}: {reason}")
    return hits


def write(snapshot_dir: Path | None = None, budget: float = BUDGET_SECONDS) -> dict[str, Any]:
    """Refresh the tracked files. Any API error or secret-scan hit aborts before writing."""
    snapshot_dir = Path(snapshot_dir or SNAPSHOT_DIR)
    live, errors = collect(budget)
    if errors:
        return {"status": "aborted", "reason": "API errors; nothing written", "errors": errors}
    hits = secret_findings(live, snapshot_dir)
    if hits:
        return {"status": "aborted", "reason": "secret scan hit; nothing written", "errors": hits}
    written, removed = [], []
    for rel, data in sorted(live.items()):
        path = snapshot_dir / rel
        text = render(data)
        if not path.exists() or path.read_text(encoding="utf-8") != text:
            path.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_text(path, text)
            path.chmod(0o644)
            written.append(rel)
    for rel in _tracked(snapshot_dir):
        if rel not in live:
            (snapshot_dir / rel).unlink()
            removed.append(rel)
    return {"status": "ok", "files": len(live), "written": written, "removed": removed}


def summary_line(row: dict[str, Any], limit: int = 6) -> str:
    """'rulesets.x.enforcement changed, labels changed (+2 more)' for one file."""
    changes = row.get("changes") or []
    parts = [f"{c.get('path')} {c.get('change')}" for c in changes[:limit]]
    more = f" (+{len(changes) - limit} more)" if len(changes) > limit else ""
    return ", ".join(parts) + more


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true", help="refresh the tracked snapshots")
    mode.add_argument("--check", action="store_true", help="compare live vs tracked (exit 1 drift, 2 error)")
    parser.add_argument("--json", action="store_true", help="print the structured result")
    args = parser.parse_args(argv)
    result = write() if args.write else check()
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    elif args.write:
        print(f"{result['status']}: " + (
            f"{result['files']} snapshots, written {result['written'] or 'none'}, "
            f"removed {result['removed'] or 'none'}" if result["status"] == "ok"
            else f"{result['reason']}\n  " + "\n  ".join(result["errors"])))
    else:
        print(f"{result['status']}: {result.get('checked', 0)} snapshots checked")
        for row in result.get("files") or []:
            print(f"  {row['status']}: {row['path']}: {summary_line(row)}")
        for error in result.get("errors") or []:
            print(f"  error: {error}")
        if result.get("reason"):
            print(f"  {result['reason']}")
    if args.write:
        return 0 if result["status"] == "ok" else 2
    return {"ok": 0, "drift": 1}.get(result["status"], 2)


if __name__ == "__main__":
    sys.exit(main())
