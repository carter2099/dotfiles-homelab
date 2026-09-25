"""Evidence collectors and worker/judge audit workflow."""
from __future__ import annotations

from .config import (
    AUDIT_MAX_WORKERS,
    AUTO_PKGS,
    DEFAULT_TEMPLATE,
    DEPENDABOT_UNIT,
    DIGEST_SCRIPT,
    CLEANUP_PATTERNS,
    DEPLOY_REGISTRY,
    ENDPOINTS,
    FIX_MAX_ITERS,
    FINDING_ACTIONS,
    FINDING_SEVERITIES,
    GH_API,
    HOME,
    IDEAS_DIR,
    LLAMA_CPP_RELEASES_API,
    LOW_DEFAULT_SEVERITY_SECTIONS,
    LLAMA_CPP_UPDATE_SCRIPT,
    MAX_WORKERS,
    OPENWEBUI_COMPOSE,
    P7B_REPORT_ONLY_SECTIONS,
    PENDING_PATH,
    PLANS_DIR,
    PROXY_HEALTH,
    Path,
    RIG_APT_TIMEOUT,
    RIG_BOOT_ENTRY,
    RIG_DISK_MAX_PERCENT,
    RIG_MODEL_ENDPOINT,
    RIG_REBOOT_WAIT_TIMEOUT,
    RIG_REMOTE_PATH,
    RIG_REQUIRED_MODEL_IDS,
    RIG_SSH_ALIAS,
    RIG_SSH_COMMAND_TIMEOUT,
    RIG_SSH_CONNECT_TIMEOUT,
    RIG_UPDATE_TIMEOUT,
    RUNS_LOG,
    RUN_DIR_BASE,
    SEARXNG_TAGS_API,
    SECRET_PATTERNS,
    SESSION_ACTIVE_MINUTES,
    SESSION_DIR,
    SESSION_INTERACTIVE_DIR,
    SESSION_MEMOIR_DIR,
    SESSION_MEMORY_CONTEXT_DAYS,
    SESSION_MEMORY_CONTEXT_MAX,
    STEWARD_MODEL,
    STEWARD_PATH,
    TEMPLATE_PATH,
    ThreadPoolExecutor,
    UPDATE_MIN_AGE_DAYS,
    WORKFLOW_POLICY_VERSION,
    VERSION_REGISTRY,
    WORKFLOW_SCHEMA_VERSION,
    _FNM_NODE_DIRS,
    argparse,
    as_completed,
    datetime,
    hashlib,
    html,
    json,
    os,
    re,
    shlex,
    subprocess,
    sys,
    time,
    timedelta,
    timezone,
    urllib,
)
from .runtime import (
    NO_TOOLS,
    READ_ONLY_TOOLS,
    _assistant_text_from_message,
    _balanced_json_slice,
    _call_omp_p,
    _date_context,
    _evidence_hash,
    _extract_json,
    _load_prev_artifact,
    _message_error_str,
    _ndjson_looks_like_event_stream,
    _reboot_if_needed,
    apt_installed_version,
    apt_upgradable,
    extract_from_ndjson,
    parse_previous_summary,
    prev_workday,
    read_json,
    run,
    run_capture,
    run_capture_ok,
    run_ok,
    user_env,
    write_json,
)

def _audit_collector_1_agents_md():
    """Collector: AGENTS.md truth-check evidence."""
    agents_path = HOME / "AGENTS.md"
    sha = hashlib.sha256(agents_path.read_bytes()).hexdigest() if agents_path.exists() else "missing"
    ip_addr = run_capture(["ip", "-4", "addr", "show", "enp3s0f0"])
    docker_ps = run_capture(["docker", "ps", "--format", "{{.Names}}\t{{.Image}}\t{{.Ports}}\t{{.Status}}"])
    ufw_rules = run_capture(["sudo", "-n", "ufw", "show", "added"])
    user_timers = run_capture(["systemctl", "--user", "list-timers", "--all"], env=user_env())
    return {
        "agents_md_sha256": sha,
        "ip_addr_enp3s0f0": ip_addr,
        "docker_ps": docker_ps,
        "ufw_rules_added": ufw_rules,
        "user_timers": user_timers,
    }


def _upstream_versions():
    """Latest upstream releases, fetched by the collector (agents have no network)."""
    upstream = {}

    def _fetch(url):
        req = urllib.request.Request(url, headers={"Accept": "application/json",
                                                   "User-Agent": "homelab-steward"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())

    for name in ("go", "nodejs", "ruby", "traefik"):
        try:
            cycles = _fetch(f"https://endoflife.date/api/{name}.json")[:4]
            upstream[name] = [
                {"cycle": c.get("cycle"), "latest": c.get("latest"),
                 "lts": c.get("lts"), "eol": c.get("eol")}
                for c in cycles
            ]
        except Exception as error:
            upstream[name] = {"error": str(error)[:200]}
    for name, repo in (("neovim", "neovim/neovim"),):
        try:
            upstream[name] = _fetch(
                f"https://api.github.com/repos/{repo}/releases/latest").get("tag_name")
        except Exception as error:
            upstream[name] = {"error": str(error)[:200]}
    return upstream


def _audit_collector_2_versions():
    """Collector: current version strings plus latest upstream releases."""
    return {
        "go": run_capture(["go", "version"]),
        "node": run_capture(["node", "-v"]),
        "rbenv": run_capture(["rbenv", "versions"]),
        "nvim": run_capture(["nvim", "--version"]).split("\n", 1)[0],
        "docker_images": run_capture(
            ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}\t{{.CreatedAt}}"]),
        "upstream": _upstream_versions(),
    }


def _audit_collector_3_digest_quality():
    """Collector: digest quality metrics over trailing 7 days."""
    evidence = {"topics": {}, "placeholder_leakage": 0, "fallback_count": 0}
    topics = ["ai-tech", "agentic-platform", "ai-hardware", "gaming-digest", "world-digest"]
    now = datetime.now()
    for topic in topics:
        topic_dir = HOME / "digests" / topic
        tev = {"exists": topic_dir.exists(), "runs": []}
        if topic_dir.exists():
            for d in sorted(topic_dir.iterdir(), reverse=True):
                if not d.is_dir():
                    continue
                try:
                    d_date = datetime.strptime(d.name, "%Y-%m-%d")
                except ValueError:
                    continue
                if (now - d_date).days > 7:
                    continue
                artifacts = sorted([f.name for f in d.iterdir() if f.is_file()])
                html_files = [f for f in artifacts if f.endswith(".html")]
                placeholder_count = 0
                for hf in html_files:
                    html = (d / hf).read_text()
                    placeholder_count += len(re.findall(r"\{\{[A-Z_]+\}\}", html))
                # Phase 9 archival copy (top-level YYYY-MM-DD.md, digest_md_path) lives
                # outside the run dir and was never scanned — it has hidden fabricated
                # example.com stories and raw prompt echoes (digest-quality audit gap).
                top_md = topic_dir / f"{d.name}.md"
                if top_md.exists():
                    top_text = top_md.read_text()
                    placeholder_count += len(re.findall(r"\{\{[A-Z_]+\}\}", top_text))
                    placeholder_count += len(re.findall(r"https?://example\.com\b", top_text))
                    placeholder_count += len(re.findall(
                        r"Any notable stories or angles that were missed today", top_text))
                tev["runs"].append({
                    "date": d.name,
                    "artifacts": artifacts,
                    "placeholder_leaks": placeholder_count,
                    "attention_artifact": "02b-attention.json" in artifacts,
                    "standfirst_artifact": "07-standfirst.json" in artifacts,
                })
                evidence["placeholder_leakage"] += placeholder_count
        evidence["topics"][topic] = tev
    # Published-site contract: every completed date has one durable JSON artifact
    # per category, an atomically activated static build, one mail marker, and a
    # configured target in the existing R2 backup.
    news_root = HOME / "digests" / "news"
    publications_dir = news_root / "publications"
    publication_dates = []
    if publications_dir.exists():
        dated_dirs = [
            path for path in sorted(publications_dir.iterdir(), reverse=True)
            if path.is_dir() and re.fullmatch(r"\d{4}-\d{2}-\d{2}", path.name)
        ]
        for date_dir in dated_dirs[:2]:
            entries = {}
            for slug in ("ai-tech", "agents", "ai-hardware", "gaming", "world"):
                path = date_dir / f"{slug}.json"
                entry = {"exists": path.exists(), "valid": False, "stories": 0}
                if path.exists():
                    try:
                        publication_text = path.read_text()
                        publication = json.loads(publication_text)
                        stories = (
                            publication.get("fresh", [])
                            + publication.get("ongoing", [])
                        )
                        standfirst = publication.get("standfirst", "")
                        attention_path = (
                            news_root / "attention" / date_dir.name / f"{slug}.json"
                        )
                        entry.update({
                            "valid": (
                                publication.get("date") == date_dir.name
                                and publication.get("slug") == slug
                                and publication.get("schema_version") == 2
                                and (
                                    date_dir.name < "2026-08-25"
                                    or publication.get("ranking_schema_version") == 3
                                )
                            ),
                            "status": publication.get("status", ""),
                            "stories": len(stories),
                            "ranking_schema_version": publication.get(
                                "ranking_schema_version"
                            ),
                            "significance_complete": all(
                                story.get("editorial_significance")
                                in {"high", "medium", "low"}
                                for story in stories
                            ),
                            "high_evidence_complete": (
                                date_dir.name < "2026-08-25"
                                or all(
                                    story.get("editorial_significance") != "high"
                                    or (
                                        isinstance(story.get("significance_evidence"), dict)
                                        and story.get("significance_validation", {}).get("status")
                                        == "accepted"
                                    )
                                    for story in (
                                        publication.get("fresh", [])
                                        + publication.get("ongoing", [])
                                    )
                                )
                            ),
                            "priority_complete": all(
                                isinstance(story.get("priority_score"), (int, float))
                                for story in stories
                            ),
                            "attention_complete": (
                                date_dir.name < "2026-08-25"
                                or all(
                                    isinstance(story.get("attention"), dict)
                                    and story["attention"].get("status")
                                    in {"ok", "no_matches", "unavailable", "out_of_scope"}
                                    for story in stories
                                )
                            ),
                            "attention_failure_semantics_valid": (
                                date_dir.name < "2026-08-25"
                                or all(
                                    (
                                        story.get("attention", {}).get("status") != "no_matches"
                                        or (
                                            story["attention"].get("attention_now") == 0
                                            and story["attention"].get("digest_prominence") == 0
                                        )
                                    )
                                    and (
                                        story.get("attention", {}).get("status") != "unavailable"
                                        or story["attention"].get("confidence") == 0
                                    )
                                    for story in stories
                                )
                            ),
                            "attention_artifact_exists": (
                                date_dir.name < "2026-08-25" or attention_path.exists()
                            ),
                            "standfirst_complete": (
                                isinstance(standfirst, str)
                                and 40 <= len(standfirst) <= 900
                                and bool(re.search(r"""[.!?…]["'’”)]*$""", standfirst))
                                and not bool(re.search(
                                    r"today[’']s digest|digest leads|read on|also in focus",
                                    standfirst,
                                    re.IGNORECASE,
                                ))
                            ),
                            "placeholder_leaks": len(re.findall(
                                r"\{\{[A-Z_]+\}\}|https?://example\.com\b",
                                publication_text,
                            )),
                        })
                    except (json.JSONDecodeError, OSError) as error:
                        entry["error"] = str(error)
                entries[slug] = entry
            publication_dates.append({
                "date": date_dir.name,
                "categories": entries,
                "summary_email_sent": (
                    news_root / "mail" / f"{date_dir.name}.sent.json"
                ).exists(),
            })
    current_site = news_root / "current"
    build_path = current_site / "build.json"
    try:
        build = json.loads(build_path.read_text()) if build_path.exists() else {}
    except (json.JSONDecodeError, OSError):
        build = {}
    backup_config_path = HOME / "homelab-backup" / "config.yaml"
    try:
        backup_config = backup_config_path.read_text()
    except OSError:
        backup_config = ""
    evidence["publication"] = {
        "contract_started": "2026-08-25",
        "dates": publication_dates,
        "site_current_is_symlink": current_site.is_symlink(),
        "site_index_exists": (current_site / "index.html").exists(),
        "build": build,
        "r2_target_configured": (
            "name: daily-news-data" in backup_config
            and "source: /home/carter/digests/news" in backup_config
        ),
        "backup_config_mtime": (
            datetime.fromtimestamp(
                backup_config_path.stat().st_mtime, timezone.utc
            ).isoformat()
            if backup_config_path.exists() else ""
        ),
    }

    # llm-proxy fallback count in digest window
    fallback_log = run_capture(
        ["journalctl", "--user", "-u", "llm-proxy",
         "--since", "7 days ago", "--no-pager", "-q"],
        env=user_env(),
    )
    evidence["fallback_count"] = fallback_log.count("X-Fallback: true")

    # Per-topic durations from .digests.log
    digests_log = HOME / "digests" / ".digests.log"
    if digests_log.exists():
        evidence["durations"] = digests_log.read_text()[-2000:]
    return evidence


# Known scanner files to skip in commit diff scan (avoid self-flagging).
_SKIP_SCANNER_FILES = {
    "scripts/steward_runner.py",
}

def _gather_repo_secrets():
    """Scan repos for uncommitted secret files and recent secret-commits in git history.

    Pure Python, deterministic, no LLM. Returns a dict with:
      - repos_scanned: int
      - working_tree_issues: list of dicts
      - commit_issues: list of dicts
      - findings_summary: str
    """
    issues_wt = []
    issues_commit = []
    repos_scanned = 0

    repo_candidates = []

    # ~/dev/*/ directories
    dev_dir = HOME / "dev"
    if dev_dir.is_dir():
        for d in sorted(dev_dir.iterdir()):
            if d.is_dir():
                repo_candidates.append(("dev/" + d.name, d, False))

    # Specific repos
    for name, path, is_bare in [
        ("homelab-backup", HOME / "homelab-backup", False),
        ("notes", HOME / "notes", False),
    ]:
        if path.is_dir():
            repo_candidates.append((name, path, is_bare))

    # Dotfiles bare repo
    dotfiles_git_dir = HOME / ".dotfiles-homelab"
    if dotfiles_git_dir.is_dir():
        repo_candidates.append(("dotfiles", dotfiles_git_dir, True))

    for name, path, is_bare in repo_candidates:
        # Verify git repo
        if is_bare:
            git_base = ["--git-dir", str(path)]
        else:
            git_base = ["-C", str(path)]

        check = run_capture_ok(["git"] + git_base + ["rev-parse", "--git-dir"])
        if check[2] != 0:
            continue

        remotes = run_capture(["git"] + git_base + ["remote", "-v"])
        if not remotes:
            continue

        repos_scanned += 1

        # Working tree scan (skip bare repos — P9b handles dotfiles)
        if not is_bare:
            status_out = run_capture(["git"] + git_base + ["status", "--short"])
            if status_out:
                for line in status_out.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    xy = line[:2]
                    filepath = line[3:].strip()
                    for pat in SECRET_PATTERNS:
                        if pat.match(filepath) or pat.match(Path(filepath).name):
                            issue_type = "untracked" if xy == "??" else "modified"
                            issues_wt.append({
                                "repo": name,
                                "path": filepath,
                                "issue": f"{issue_type} secret file",
                                "status": xy,
                            })
                            break

        # Recent commit scan
        log_cmd = ["git"] + git_base + ["log", "--all", "--since=24 hours ago", "-p", "--", "."]
        log_out, log_err, log_rc = run_capture_ok(log_cmd)
        if log_out:
            current_commit = ""
            current_date = ""
            current_file = ""
            skip_file = False  # skip content lines when inside a known scanner file
            findings = 0

            for line in log_out.splitlines():
                if line.startswith("commit "):
                    current_commit = line.split()[1][:8]
                    current_date = ""
                    current_file = ""
                    skip_file = False
                    continue
                if line.startswith("Date:"):
                    current_date = line[5:].strip()
                    continue
                if line.startswith("diff --git a/"):
                    parts = line.split(" b/")
                    current_file = parts[-1] if len(parts) > 1 else ""
                    stripped_file = current_file.lstrip("/")
                    skip_file = stripped_file in _SKIP_SCANNER_FILES
                    continue
                if skip_file:
                    continue
                if line.startswith("---") or line.startswith("+++") or line.startswith("@@"):
                    continue
                if line.startswith("index ") or line.startswith("new file ") or line.startswith("deleted file "):
                    continue

                if not line.startswith("+"):
                    continue
                if line.startswith("+++"):
                    continue

                content = line[1:]

                found_issue = None
                if re.search(r"AKIA[0-9A-Z]{16}", content):
                    found_issue = "possible AWS access key in diff"
                elif re.search(r"ghp_[0-9a-zA-Z]{36}|gho_[0-9a-zA-Z]{36}|ghu_[0-9a-zA-Z]{36}|ghs_[0-9a-zA-Z]{36}|ghr_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82,}", content):
                    found_issue = "possible GitHub token in diff"
                elif re.search(r"-----BEGIN\s?(?:RSA|DSA|EC|OPENSSH|PGP)\s?PRIVATE KEY-----", content):
                    found_issue = "possible private key in diff"
                elif re.search(r"hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24,}", content):
                    found_issue = "possible Slack webhook in diff"
                elif re.search(r"-----BEGIN CERTIFICATE-----", content):
                    found_issue = "possible certificate in diff"

                if found_issue and findings < 20:
                    issues_commit.append({
                        "repo": name,
                        "commit": current_commit,
                        "date": current_date,
                        "path": current_file,
                        "issue": found_issue,
                    })
                    findings += 1

    total_issues = len(issues_wt) + len(issues_commit)
    if total_issues == 0:
        findings_summary = "clean \u2014 no secrets detected"
    else:
        repo_count = len({i["repo"] for i in issues_wt + issues_commit})
        findings_summary = f"{total_issues} issues across {repo_count} repos scanned"

    return {
        "repos_scanned": repos_scanned,
        "working_tree_issues": issues_wt,
        "commit_issues": issues_commit,
        "findings_summary": findings_summary,
    }

# Bound for UFW rule text embedded in the docs-accuracy packet. The live
# ruleset is ~1.6 KB; the cap only stops a runaway ruleset from crowding out
# the rest of the evidence.
_DOCS_UFW_STATUS_MAX = 4000


def _ufw_status():
    """Read-only privileged UFW rule listing (parent collector only)."""
    return run_capture(["sudo", "ufw", "status"])


_CF_API = "https://api.cloudflare.com/client/v4"
_CF_ZONE = "carter2099.com"


def _cf_get(path, token):
    """GET one Cloudflare API path; returns the decoded `result` or raises."""
    req = urllib.request.Request(
        f"{_CF_API}{path}",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        payload = json.loads(resp.read().decode())
    if not payload.get("success", False):
        errors = [e.get("message", "") for e in payload.get("errors") or [] if isinstance(e, dict)]
        raise RuntimeError("; ".join(errors) or "Cloudflare API reported failure")
    return payload.get("result")


def _cloudflare_facts():
    """Deterministic Cloudflare facts for audit evidence (collector only).

    The API token is read here at runtime and never logged, returned, or put in
    a prompt; agents get only the facts below.
    """
    cf_dir = HOME / ".config" / "cloudflare"

    def _read(name):
        path = cf_dir / name
        return path.read_text().strip() if path.exists() else ""

    token, account, tunnel = _read("api-token"), _read("account-id"), _read("homelab-tunnel-id")
    if not (token and account and tunnel):
        return {"error": "Cloudflare token/account/tunnel id file missing"}
    facts = {}

    def _collect(key, fn):
        try:
            facts[key] = fn()
        except Exception as error:  # HTTPError text never includes request headers
            facts[key] = {"error": str(error)[:300]}

    def _ingress():
        config = (_cf_get(f"/accounts/{account}/cfd_tunnel/{tunnel}/configurations", token)
                  or {}).get("config") or {}
        return {
            "ingress": [
                {"hostname": rule.get("hostname", "(catch-all)"), "service": rule.get("service"),
                 "access_protected": bool((rule.get("originRequest") or {}).get("access"))}
                for rule in config.get("ingress") or []
            ],
            "warp_routing": config.get("warp-routing"),
        }

    def _tunnel():
        info = _cf_get(f"/accounts/{account}/cfd_tunnel/{tunnel}", token) or {}
        conns = info.get("connections") or []
        return {
            "name": info.get("name"),
            "status": info.get("status"),
            "connections": len(conns),
        }

    def _routes():
        routes = _cf_get(f"/accounts/{account}/teamnet/routes?is_deleted=false", token) or []
        return [{"network": r.get("network"), "tunnel_id": r.get("tunnel_id")} for r in routes]

    def _dns():
        zones = _cf_get(f"/zones?name={_CF_ZONE}", token) or []
        if not zones:
            raise RuntimeError(f"zone {_CF_ZONE} not visible to token")
        records = _cf_get(f"/zones/{zones[0]['id']}/dns_records?per_page=100", token) or []
        return [
            {"name": r.get("name"), "type": r.get("type"),
             "content": r.get("content"), "proxied": r.get("proxied")}
            for r in records
        ]

    _collect("tunnel_ingress", _ingress)
    _collect("tunnel_status", _tunnel)
    _collect("private_routes", _routes)
    _collect("dns_records", _dns)
    return facts


def _audit_collector_4_security():
    """Collector: security posture evidence."""
    # RDAP domain expiry
    rdap_expiry = ""
    try:
        req = urllib.request.Request(
            "https://rdap.verisign.com/com/v1/domain/carter2099.com",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            rdap_data = json.loads(resp.read().decode())
            for event in rdap_data.get("events", []):
                if event.get("eventAction") == "expiration":
                    rdap_expiry = event.get("eventDate", "")
    except Exception as e:
        rdap_expiry = f"error: {e}"

    cloudflare = _cloudflare_facts()
    incident_doc = HOME / "notes" / "docs" / "homelab" / "opencode-go-proxy.md"
    incident_read_error = ""
    try:
        incident_text = incident_doc.read_text()
    except OSError as error:
        incident_text = ""
        incident_read_error = str(error)
    if "Known credential incident: unresolved." in incident_text:
        incident_status = "unresolved"
    elif "Known credential incident: resolved." in incident_text:
        incident_status = "resolved"
    else:
        incident_status = "unverifiable"
    known_credential_incident = {
        "status": incident_status,
        "source": str(incident_doc),
        "read_error": incident_read_error,
        "detail": (
            "A credential remains in public git history unless explicit provider "
            "revocation/cancellation is recorded. Do not inspect or reproduce it."
        ),
    }

    return {
        "listeners": run_capture(["ss", "-tlnp"]),
        "ufw_status": _ufw_status(),
        "unattended_upgrades": run_capture(["systemctl", "is-active", "unattended-upgrades"]),
        "rdap_expiry": rdap_expiry,
        "cloudflare": {k: cloudflare.get(k) for k in ("tunnel_ingress", "tunnel_status", "private_routes", "error") if k in cloudflare},
        "ssh_failures": run_capture(
            ["bash", "-c",
             "journalctl -u ssh --since '24 hours ago' 2>/dev/null | grep -c 'Failed password' || echo 0"]),
        "repo_secrets": _gather_repo_secrets(),
        "known_credential_incident": known_credential_incident,
    }


def _audit_collector_5_config_drift():
    """Collector: config vs tracked drift."""
    dotfiles_status = run_capture(
        ["/usr/bin/git", "--git-dir", str(HOME / ".dotfiles-homelab"),
         "--work-tree", str(HOME), "status", "--short"])
    notes_status = run_capture(["git", "-C", str(HOME / "notes"), "status", "--short"])

    deploy_repos = {}
    for name, path in [
        ("blog", HOME / "blog" / "blog"),
        ("homelab-backup", HOME / "homelab-backup"),
    ]:
        if path.exists():
            run_capture(["git", "-C", str(path), "fetch"], timeout=30)
            deploy_repos[name] = run_capture(["git", "-C", str(path), "status", "-sb"])

    # Parse notes INDEX.md for cross-reference with disk
    indexed = set()
    index_path = HOME / "notes" / "INDEX.md"
    if index_path.exists():
        for line in index_path.read_text().splitlines():
            # Skip format template lines - the literal example "path/to/file.md"
            if line.strip().startswith("Format:") or "path/to/" in line:
                continue
            m = re.search(r"\]\(([^)]+\.md)\)", line)
            if m:
                indexed.add(m.group(1))

    notes_dir = HOME / "notes"
    on_disk = set()
    if notes_dir.exists():
        for md in notes_dir.rglob("*.md"):
            if "sessions" in md.parts:
                continue
            rel = str(md.relative_to(notes_dir))
            # Never flag the index itself or repo boilerplate
            if rel in ("INDEX.md", "README.md"):
                continue
            on_disk.add(rel)

    return {
        "dotfiles_status": dotfiles_status,
        "notes_status": notes_status,
        "deploy_repos": deploy_repos,
        "notes_in_index_not_on_disk": sorted(list(indexed - on_disk)),
        "notes_on_disk_not_in_index": sorted(list(on_disk - indexed)),
    }


def _audit_collector_6_notes_resources():
    """Collector: resource trends + OOM/exit-255 hunt."""
    # Scan the whole current boot's kernel log, not a rolling 24h window:
    # a daily steward run can otherwise miss an OOM event that happened
    # >24h before it (e.g. Aug 05 17:52 UTC event unseen by Aug 06 21:00 run).
    oom_hunt = run_capture(
        ["journalctl", "-k", "-b", "--no-pager", "-q"])
    oom_count = oom_hunt.lower().count("out of memory") if oom_hunt else 0
    exit_255 = run_capture(
        ["docker", "ps", "-a", "--filter", "status=exited",
         "--format", "{{.Names}}\t{{.Status}}\t{{.Image}}"])

    # R2 size
    r2_list = run_capture(
        [str(HOME / "homelab-backup" / "homelab-backup"), "list"])
    news_state_sizes = {}
    news_root = HOME / "digests" / "news"
    for name in ("publications", "attention", "mail"):
        root = news_root / name
        total = 0
        if root.exists():
            for path in root.rglob("*"):
                try:
                    if path.is_file():
                        total += path.stat().st_size
                except OSError:
                    pass
        news_state_sizes[name] = total

    return {
        "disk_df": run_capture(["df", "-h", "/"]),
        "docker_system_df": run_capture(["docker", "system", "df"]),
        "oom_count": oom_count,
        "exit_255_containers": exit_255,
        "r2_list_tail": "\n".join(r2_list.splitlines()[-20:]) if r2_list else "",
        "daily_news_state_bytes": news_state_sizes,
        "journal_size": run_capture(
            ["journalctl", "--disk-usage"]),
    }


def _audit_collector_7_agent_fleet():
    """Collector: other unattended agents' recent runs."""
    env = user_env()
    hyperliquid_log = run_capture(
        ["journalctl", "--user", "-u", "hyperliquid-sdk",
         "--since", "4 days ago", "--no-pager", "-n", "100"],
        env=env,
    )
    dependabot_errors = run_capture(
        ["journalctl", "--user", "-u", "dependabot-webhook",
         "--since", "7 days ago", "--no-pager"],
        env=env,
    )
    return {
        "hyperliquid_sdk_recent": hyperliquid_log[:3000],
        "dependabot_errors": dependabot_errors[:2000],
    }

def _audit_collector_8_docs_accuracy():
    """Collector: docs/ file content + related system state for fact-checking."""
    docs_dir = HOME / "notes" / "docs"
    # Firewall rules and Cloudflare facts come first: agent prompts truncate the
    # serialized evidence, and the agents have no shell, sudo, or network tools.
    ufw_status = _ufw_status()
    evidence = {
        "firewall": {
            "source": "sudo ufw status (root, read-only, collected by the steward)",
            "ufw_status": ufw_status[:_DOCS_UFW_STATUS_MAX],
            "truncated": len(ufw_status) > _DOCS_UFW_STATUS_MAX,
        },
        "cloudflare": _cloudflare_facts(),
        "doc_files": {},
        "system_state": {},
    }

    # Doc file hashes (for delta gate — skip if no prior run to compare)
    if docs_dir.exists():
        for md_file in sorted(docs_dir.rglob("*.md")):
            rel = md_file.relative_to(docs_dir)
            evidence["doc_files"][str(rel)] = {
                "sha256": hashlib.sha256(md_file.read_bytes()).hexdigest(),
                "size": md_file.stat().st_size,
            }
    else:
        evidence["doc_files"]["_missing"] = True

    # System state that docs reference
    evidence["system_state"] = {
        "docker_ps": run_capture(
            ["docker", "ps", "--format", "{{.Names}}\t{{.Image}}\t{{.Ports}}\t{{.Status}}"]),
        "listening_ports": run_capture(
            ["sudo", "ss", "-tlnp", "--no-header"]),
        "user_services": run_capture(
            ["systemctl", "--user", "list-units", "--type=service", "--all", "--no-legend"],
            env=user_env()),
        "user_timers": run_capture(
            ["systemctl", "--user", "list-timers", "--all"], env=user_env()),
        "docker_images": run_capture(
            ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}\t{{.CreatedAt}}"]),
        "ip_addr": run_capture(["ip", "-4", "addr", "show", "enp3s0f0"]),
    }
    return evidence


AUDIT_SECTIONS = [
    {
        "name": "agents-md-truth",
        "collector": _audit_collector_1_agents_md,
        "artifact": "07-audit-1-agents-md.json",
        "timeout": 600,
        "guidance": (
            "Truth-check /home/carter/AGENTS.md against the live host. READ the file first. "
            "Verify (1) pointer targets still resolve (paths, commands it cites) and (2) structural/"
            "semantic facts: IP roles (.92 is the static netplan address; the "
            "DHCP address is dynamic and must not be depended on; blog is loopback-only), "
            "enp3s0f0 as primary + wlp6s0 down, FreshRSS as the Docker Compose stack in ~/freshrss (loopback 127.0.0.1:30149), "
            "service+timer names and schedules, "
            "ufw rules (evidence ufw_rules_added must match ~/system-config/ufw-expected-rules.txt, "
            "applied by ~/system-config/ufw-rebuild.sh; steward P3a only reports drift: there are no cni0 or "
            "flannel.1 rules, and "
            "Open WebUI reaches 8081/8082 only via the fixed bridge br-owui — no per-ID br-<id> "
            "rules; a doc telling operators to add blanket cni0/flannel.1 or br-<id> allows is DRIFT), "
            "sole docker daemon at /var/lib/docker, "
            "documented ports. Do NOT re-add intentionally-removed version pins. "
            "For every DRIFT propose an exact OLD_TEXT -> NEW_TEXT edit as action doc_fix with "
            "target.doc /home/carter/AGENTS.md. Prefer UNVERIFIABLE over guessing — "
            "you have only read/grep/glob, so cite file contents or collected evidence."
        ),
    },
    {
        "name": "version-currency",
        "collector": _audit_collector_2_versions,
        "artifact": "07-audit-2-versions.json",
        "timeout": 600,
        "guidance": (
            "Compare current versions (in evidence) against latest upstream stable for components NOT "
            "auto-updated by P1: Go, Node, Ruby (rbenv), neovim, and the traefik docker image. "
            "Do NOT report freshrss, open-webui, herdr, omp, the pinned searxng image, or llama.cpp "
            "on the gaming rig — P1 updates those earlier in the same run after their safety gates. "
            "Report per component: current / latest / status (current | behind | behind-major). "
            "Do NOT exec into containers — the docker images evidence IS the current version. "
            "Latest upstream releases are in evidence.upstream (collected by the steward; you "
            "have no network or shell tools). An upstream entry with an error is UNVERIFIABLE. "
            "Routing: use action report_only for every finding in this section."
        ),
    },
    {
        "name": "digest-quality",
        "collector": _audit_collector_3_digest_quality,
        "artifact": "07-audit-3-digests.json",
        "timeout": 600,
        "guidance": (
            "Judge Daily News over the last 48 hours plus systemic regressions: completeness, "
            "freshness, duplication, tracker hygiene, five schema-v2/ranking-v3 publications, "
            "complete standfirsts, and active front page. Every high significance must have "
            "accepted source-grounded evidence; routine deprecations without demonstrated broad "
            "impact must be downgraded. `no_matches` must score attention/prominence 0; "
            "`unavailable` and `out_of_scope` must have confidence 0 so observed attention cannot "
            "move priority (priority is then editorial significance plus any Jev importance); sources "
            "not fully collected are left out and listed in evidence.sources_excluded. Check deterministic "
            "priority fields, durable attention records, one mail marker after the 2026-08-25 "
            "cutover, and the daily-news-data R2 target. Do not reopen known historical empty days. "
            "Judge from the evidence and local files only; you cannot fetch web pages."
        ),
    },
    {
        "name": "security-posture",
        "collector": _audit_collector_4_security,
        "artifact": "07-audit-4-security.json",
        "timeout": 600,
        "guidance": (
            "Judge the security posture from the evidence: listening sockets vs the documented set "
            "(loopback-only: open-webui 48100, searxng 8080, prompt-guard 8090, news 30144, herdr-web 30145, freshrss 30149, "
            "beatz 30142, blog 33099; "
            "ufw-gated: llm-proxy 8081 and opencode-go-proxy 8082; exact-host LAN allow: gaming rig "
            "192.168.4.103 to opencode-go-proxy 8082), ufw ruleset matches "
            "~/system-config/ufw-expected-rules.txt (the only source of truth; steward P3a reports "
            "drift, never mutates): cni0 allows only tcp 6443,10250 from pods, no flannel.1 rule, "
            "Open WebUI reaches 8081/8082 only via the fixed bridge br-owui (host.docker.internal="
            "172.31.250.1), and a blanket cni0/flannel.1 or per-ID br-<id> allow is unexpected; "
            "unattended-upgrades active, carter2099.com RDAP expiry "
            "(>30d out = ok), CF tunnel ingress (evidence.cloudflare.tunnel_ingress) vs expected hostnames (chat, hooks, freshrss, blog, "
            "ssh, beatz, rig, news, remote), SSH failed-password volume. The tunnel's enabled WARP "
            "routing with an empty private-route inventory is documented and inert; flag it only if "
            "routes appear or documentation differs. Flag anything else unexpected. "
            "For dependabot-webhook, use dependabot_maintenance evidence: maintenance-stopped "
            "means this run successfully stopped a previously active service; its absent 9099 "
            "listener and hooks HTTP 502 are expected until cleanup. This exception covers only "
            "that owned pause, never an unhealthy running service, unexpected/unverifiable states, "
            "unrelated endpoints, bind exposure, or failed restoration after a completed run. "
            "For repo_secrets: working_tree_issues means secret-pattern files are uncommitted in a "
            "repo — flag each as ATTENTION; commit_issues means a secret-pattern string appeared in "
            "recent diffs — flag as ATTENTION with the commit SHA. No findings = PASS for this sub-check. "
            "Routing: needs_carter when Carter must choose (credentials, network exposure), "
            "otherwise report_only."
        ),
    },
    {
        "name": "config-doc-drift",
        "collector": _audit_collector_5_config_drift,
        "artifact": "07-audit-5-config.json",
        "timeout": 600,
        "guidance": (
            "Judge drift significance from the evidence: "
            "dotfiles repo should be clean except files an interactive session is actively editing; notes repo "
            "should be clean; deploy dirs (blog, homelab-backup) should match origin/main "
            "(commit-before-deploy rule). Distinguish real drift from in-flight session work — when unsure, "
            "mark ATTENTION with reasoning rather than DRIFT. "
            "Routing: a registry service's production checkout behind merged origin code -> deploy; "
            "generated junk files matching the cleanup patterns -> cleanup; a maintained doc "
            "contradicted by the live config -> doc_fix; anything else -> needs_carter."
        ),
    },
    {
        "name": "notes-resources",
        "collector": _audit_collector_6_notes_resources,
        "artifact": "07-audit-6-resources.json",
        "timeout": 600,
        "guidance": (
            "Interpret the resource evidence: disk usage/growth, docker reclaimable space, journal "
            "size, R2 archive growth, Daily News publication/attention/mail growth, OOM kills, and "
            "exited containers (known intermittent exit-255; flag repeats on one container). Report "
            "ATTENTION only for actionable trends such as disk >80%, sustained week-over-week "
            "attention-history growth that threatens R2 limits, or recurring OOM."
        ),
    },
    {
        "name": "agent-fleet-review",
        "collector": _audit_collector_7_agent_fleet,
        "artifact": "07-audit-7-fleet.json",
        "timeout": 600,
        "guidance": (
            "Review the other unattended agents' recent runs from the evidence: hyperliquid-sdk (Mon/Thu timer — "
            "did it fire? outcome? errors?), dependabot-webhook (jobs, failures). Use the "
            "dependabot_maintenance assessment: only maintenance-stopped is an expected current "
            "run pause. Already-inactive, failed, or unverifiable services are not exempt. "
            "Cleanup and systemd ExecStopPost restore the webhook; a completed prior run's "
            "failed restoration is still a finding. "
            "Also read recent session files in ~/.omp/agent/sessions-automated if you need outcomes the journal "
            "lacks. Flag failed or silently-skipped runs."
        ),
    },
    {
        "name": "docs-accuracy",
        "collector": _audit_collector_8_docs_accuracy,
        "artifact": "07-audit-8-docs.json",
        "timeout": 600,
        "guidance": (
            "Truth-check the doc files in ~/notes/docs/ against the live host. "
            "Read each .md file that has changed (check evidence doc_files sha256 vs prior run) "
            "and verify factual claims: port numbers, paths, service names, process names, "
            "URLs, config file locations, IP addresses, command syntax. "
            "For every DRIFT propose exact OLD_TEXT -> NEW_TEXT edits as action doc_fix "
            "(target.doc = the absolute doc path). "
            "For firewall/ufw claims use evidence firewall.ufw_status (root-collected live "
            "rules). For Cloudflare claims (tunnel ingress, tunnel status, private routes, DNS "
            "records) use evidence.cloudflare, collected by the steward; you have no shell or "
            "network tools and must not look for API credentials. "
            "Prefer UNVERIFIABLE over guessing. "
            "Files to check: docs/homelab/hardware.md, deployment.md, freshrss.md, blog.md, "
            "hyperliquid-sdk.md, dependabot-webhook.md, open-webui.md, searxng.md, "
            "cloudflare.md, opencode-go-proxy.md, local-llm-gaming-rig.md, email-digests.md, "
            "homelab-steward.md, homelab-backup.md."
        ),
    },
]

# Complete worker+judge verdicts. The delta cache further restricts these to PASS.
_REAL_VERDICTS = {"PASS", "DRIFT", "ATTENTION", "UNVERIFIABLE"}


def _session_memory_context(days=SESSION_MEMORY_CONTEXT_DAYS,
                            max_chars=SESSION_MEMORY_CONTEXT_MAX):
    """Recent session memoirs (last N day-folders) as a compact markdown block."""
    if not SESSION_MEMOIR_DIR.is_dir():
        return "(no session memory yet)"
    day_dirs = sorted([d for d in SESSION_MEMOIR_DIR.iterdir()
                       if d.is_dir() and re.match(r"^\d{4}-\d{2}-\d{2}$", d.name)],
                      reverse=True)
    parts, total = [], 0
    for d in day_dirs[:days]:
        for f in sorted(d.glob("*.md")):
            try:
                txt = f.read_text(errors="replace").strip()
            except OSError:
                continue
            snippet = txt[:1200]
            parts.append(f"### {d.name}/{f.name}\n{snippet}")
            total += len(snippet)
            if total > max_chars:
                parts.append("…(truncated)")
                break
        if total > max_chars:
            break
    return "\n\n".join(parts) if parts else "(no session memory yet)"


_AUDIT_VERDICTS = {"PASS", "DRIFT", "ATTENTION", "UNVERIFIABLE"}


def _final_audit_verdict(worker_verdict, judge_packet):
    """Use the judge's explicit verdict; never hide confirmed problems behind PASS."""
    if judge_packet.get("judge_error"):
        return "judge-failed"
    candidate = str(judge_packet.get("verdict") or "").upper()
    if candidate not in _AUDIT_VERDICTS:
        return "UNVERIFIABLE"
    return candidate

def _validate_prepared_audit_worker_packet(packet):
    """Validate steward-assigned finding IDs and mutation-relevant worker fields."""
    if not isinstance(packet, dict) or packet.get("verdict") not in _AUDIT_VERDICTS:
        raise ValueError("invalid prepared audit worker packet")
    findings = packet.get("findings")
    if not isinstance(findings, list):
        raise ValueError("prepared audit worker findings must be a list")
    for index, item in enumerate(findings, 1):
        if not isinstance(item, dict) or item.get("id") != f"finding-{index}":
            raise ValueError("prepared audit worker IDs must be unique and sequential")
        for key in ("claim", "evidence", "fix"):
            if not isinstance(item.get(key), str) or not item[key].strip():
                raise ValueError(f"prepared audit worker finding missing {key}")
    return packet


# Finding schema v2 routing fields. Workers propose them, the judge may set
# severity and downgrade the action, and steward.routing validates the rest.
# Normalization never raises: a bad routing field degrades to a safe default
# instead of invalidating the whole worker packet.
_FINDING_V2_KEYS = ("severity", "action", "target", "decision", "routing_note")
_JUDGE_DOWNGRADE_ACTIONS = ("needs_carter", "report_only")
_NO_ROUTE_NOTE = "no route proposed"

_SEVERITY_RUBRIC = """\
  - high: data loss or backup/restore failure; security exposure or credential risk; a
    production service down or silently wrong; automation silently failing its core job.
  - medium: user-visible defects without data risk (wrong or duplicate content), stale
    production deploys, maintenance automation failing with a workaround.
  - low: documentation drift, version currency, cosmetic, hygiene."""

_WORKER_PACKET_SCHEMA = """\
{"verdict": "PASS"|"DRIFT"|"ATTENTION"|"UNVERIFIABLE",
 "findings": [{"claim": "...", "evidence": "...", "fix": "...",
   "severity": "high"|"medium"|"low",
   "action": "code_fix"|"doc_fix"|"deploy"|"version_update"|"cleanup"|"needs_carter"|"report_only",
   "target": {"repo": "/home/carter/dev/<repo>", "paths": ["relative/file.py"],
              "doc": "/home/carter/notes/docs/homelab/x.md", "old_text": "...",
              "new_text": "...", "service": "blog"},
   "decision": "one sentence: the choice Carter must make (needs_carter only)"}]}"""

_WORKER_ROUTING_GUIDE = f"""\
FINDING ROUTING (every finding carries severity, action, and target; include only the
target keys that apply; `repo` and `doc` are absolute /home/carter/... paths):
- severity:
{_SEVERITY_RUBRIC}
- action (exactly one; the steward validates it and anything invalid goes to Carter):
  - code_fix: an app-code defect in a ~/dev repo. target.repo = the repo,
    target.paths = repo-relative files to change.
  - doc_fix: a statement in a maintained doc (~/notes/docs/**, ~/AGENTS.md) contradicted by
    live evidence. target.doc; target.old_text copied EXACTLY from the file (it must occur
    once); target.new_text grounded in the evidence.
  - deploy: production is behind merged code of a registry service. target.service
    ({", ".join(sorted(DEPLOY_REGISTRY))}).
  - version_update: a registry service has an update. target.service
    ({", ".join(sorted(VERSION_REGISTRY))}).
  - cleanup: generated junk files matching known patterns
    ({", ".join(CLEANUP_PATTERNS)}). target.paths = home-relative paths.
  - needs_carter: ONLY a policy choice (credentials, spending, deleting data, network
    exposure, new public repos) or when no bounded route above applies. Always add
    `decision`: one sentence naming the choice Carter must make.
  - report_only: informational; nothing should change automatically.
- Never guess a target. If you cannot name one exactly, use needs_carter."""


def _valid_finding_severity(value):
    """Return a recognised severity, or None."""
    if isinstance(value, str) and value.strip().lower() in FINDING_SEVERITIES:
        return value.strip().lower()
    return None


def _default_finding_severity(section_name):
    return "low" if section_name in LOW_DEFAULT_SEVERITY_SECTIONS else "medium"


def _normalize_finding_action(value):
    """Return a recognised action, or None."""
    if isinstance(value, str) and value.strip().lower() in FINDING_ACTIONS:
        return value.strip().lower()
    return None


def _normalize_finding_target(value):
    """Keep only well-typed target keys; old_text/new_text stay byte-exact."""
    if not isinstance(value, dict):
        return {}
    target = {}
    for key in ("repo", "doc", "service"):
        item = value.get(key)
        if isinstance(item, str) and item.strip():
            target[key] = item.strip()
    old_text = value.get("old_text")
    if isinstance(old_text, str) and old_text:
        target["old_text"] = old_text
    new_text = value.get("new_text")
    if isinstance(new_text, str):
        target["new_text"] = new_text
    paths = value.get("paths")
    if isinstance(paths, str):
        paths = [paths]
    if isinstance(paths, list):
        clean = [path.strip() for path in paths if isinstance(path, str) and path.strip()]
        if clean:
            target["paths"] = clean
    return target


def _normalize_finding_v2(finding, section_name=None):
    """Return a copy of ``finding`` with normalized schema-v2 routing fields.

    Idempotent. severity -> medium (low for LOW_DEFAULT_SEVERITY_SECTIONS);
    action -> needs_carter with routing_note "no route proposed"; target ->
    well-typed keys only; decision is kept only for needs_carter.
    """
    item = dict(finding)
    severity = _valid_finding_severity(item.get("severity"))
    action = _normalize_finding_action(item.get("action"))
    decision = item.get("decision")
    note = item.get("routing_note")
    for key in _FINDING_V2_KEYS:
        item.pop(key, None)
    item["severity"] = severity or _default_finding_severity(section_name)
    item["action"] = action or "needs_carter"
    item["target"] = _normalize_finding_target(finding.get("target"))
    if item["action"] == "needs_carter":
        item["decision"] = decision.strip() if isinstance(decision, str) else ""
    if action is None:
        item["routing_note"] = _NO_ROUTE_NOTE
    elif isinstance(note, str) and note.strip():
        item["routing_note"] = note.strip()
    return item


def _prepare_audit_worker_packet(packet, section_name=None):
    """Validate worker JSON, normalize v2 routing fields, and assign finding IDs."""
    if not isinstance(packet, dict):
        raise ValueError("audit worker packet must be an object")
    verdict = packet.get("verdict")
    findings = packet.get("findings")
    if verdict not in _AUDIT_VERDICTS or not isinstance(findings, list):
        raise ValueError("audit worker packet has invalid verdict/findings")
    prepared = dict(packet)
    prepared_findings = []
    for index, finding in enumerate(findings, 1):
        if not isinstance(finding, dict):
            raise ValueError("audit worker findings must be objects")
        item = _normalize_finding_v2(finding, section_name)
        for key in ("claim", "evidence", "fix"):
            if not isinstance(item.get(key), str) or not item[key].strip():
                raise ValueError(f"audit worker finding missing {key}")
        item["id"] = f"finding-{index}"
        prepared_findings.append(item)
    prepared["findings"] = prepared_findings
    return _validate_prepared_audit_worker_packet(prepared)


def _validate_audit_judge_packet(packet, worker_packet, section_name=None):
    """Validate ID dispositions and restore worker-owned claim/fix/route fields.

    Confirmed items take the judge's severity when valid (else the normalized
    worker severity) and may downgrade the worker action to needs_carter or
    report_only; the target always comes from the worker.
    """
    if not isinstance(packet, dict):
        raise ValueError("audit judge packet must be an object")
    _validate_prepared_audit_worker_packet(worker_packet)
    verdict = packet.get("verdict")
    if verdict not in _AUDIT_VERDICTS:
        raise ValueError(f"invalid audit judge verdict: {verdict!r}")
    worker_by_id = {
        item["id"]: item for item in worker_packet.get("findings", [])
        if isinstance(item, dict) and item.get("id")
    }
    seen = set()
    normalized = dict(packet)
    for key in ("confirmed", "rejected"):
        value = packet.get(key)
        if not isinstance(value, list):
            raise ValueError(f"audit judge {key} must be a list")
        normalized_items = []
        for item in value:
            if not isinstance(item, dict):
                raise ValueError(f"audit judge {key} items must be objects")
            finding_id = item.get("id")
            worker_finding = worker_by_id.get(finding_id)
            if worker_finding is None or finding_id in seen:
                raise ValueError(f"audit judge returned invalid/duplicate id: {finding_id!r}")
            detail_key = "evidence" if key == "confirmed" else "reason"
            if not isinstance(item.get(detail_key), str) or not item[detail_key].strip():
                raise ValueError(f"audit judge {key} item missing {detail_key}")
            canonical = dict(item)
            canonical["claim"] = worker_finding["claim"]
            if key == "confirmed":
                canonical["fix"] = worker_finding["fix"]
                canonical = _canonical_confirmed_route(
                    canonical, item, worker_finding, section_name
                )
            normalized_items.append(canonical)
            seen.add(finding_id)
        normalized[key] = normalized_items
    if seen != set(worker_by_id):
        raise ValueError("audit judge did not disposition every worker finding")
    confirmed_count = len(normalized["confirmed"])
    if verdict in ("PASS", "UNVERIFIABLE") and confirmed_count:
        raise ValueError(f"audit judge {verdict} cannot confirm problems")
    if verdict in ("DRIFT", "ATTENTION") and not confirmed_count:
        normalized["verdict_normalized_from"] = verdict
        normalized["verdict"] = "PASS"
    return normalized


def _canonical_confirmed_route(canonical, judge_item, worker_finding, section_name):
    """Apply worker-owned route fields plus the judge's severity/downgrade."""
    routed = _normalize_finding_v2(worker_finding, section_name)
    for key in _FINDING_V2_KEYS:
        canonical.pop(key, None)
    canonical["severity"] = (
        _valid_finding_severity(judge_item.get("severity")) or routed["severity"]
    )
    canonical["action"] = routed["action"]
    canonical["target"] = routed["target"]
    if "decision" in routed:
        canonical["decision"] = routed["decision"]
    if "routing_note" in routed:
        canonical["routing_note"] = routed["routing_note"]
    judge_action = _normalize_finding_action(judge_item.get("action"))
    if judge_action in _JUDGE_DOWNGRADE_ACTIONS and judge_action != routed["action"]:
        note = judge_item.get("routing_note")
        canonical["action"] = judge_action
        canonical["judge_downgraded_from"] = routed["action"]
        canonical["routing_note"] = (
            note.strip() if isinstance(note, str) and note.strip()
            else f"judge downgraded route from {routed['action']}"
        )
        if judge_action == "needs_carter":
            decision = judge_item.get("decision")
            canonical["decision"] = (
                decision.strip() if isinstance(decision, str) and decision.strip()
                else canonical["routing_note"]
            )
        else:
            canonical.pop("decision", None)
    return canonical


def _apply_deterministic_audit_guards(section_name, evidence, verdict, confirmed):
    """Surface persistent manual incidents even when an LLM misses them."""
    confirmed = list(confirmed or [])
    if verdict.endswith("-failed"):
        return verdict, confirmed
    incident = evidence.get("known_credential_incident", {})
    if (
        section_name == "security-posture"
        and incident.get("status") in ("unresolved", "unverifiable")
    ):
        claim = "Known public-history credential incident remains unresolved"
        if not any(
            item.get("claim") == claim for item in confirmed if isinstance(item, dict)
        ):
            confirmed.append({
                "claim": claim,
                "evidence": (
                    f"Nonsecret status is unresolved in {incident.get('source', 'runbook')}; "
                    "provider revocation/cancellation is not verified."
                ),
                "severity": "high",
                "action": "needs_carter",
                "target": {},
                "decision": (
                    "Revoke or cancel the exposed credential with its provider, then mark "
                    "the incident resolved in the opencode-go-proxy runbook."
                ),
            })
        return "ATTENTION", confirmed
    return verdict, confirmed


def _run_audit_agent_pair(section, evidence, current_hash, session_memory=""):
    """Worker + judge for one audit section. Returns the section result dict."""
    section_name = section["name"]
    worker_prompt = f"""
You are a homelab audit agent for section '{section_name}'.

SECTION GUIDANCE:
{section["guidance"]}

Rules:
- Ground every claim in the collected evidence or in files you read yourself
  (cite specific file:line or evidence key).
- Your only tools are read, grep, and glob. You cannot run commands, use the
  network, or change anything; when a fact is neither in the evidence nor in a
  readable file, mark it UNVERIFIABLE instead of guessing.
- Put only unresolved problem findings in `findings`. Healthy/current observations are
  evidence for your verdict, not findings. A PASS packet has an empty findings list.
- Return a fenced ```json packet:
{_WORKER_PACKET_SCHEMA}

{_WORKER_ROUTING_GUIDE}

- CRITICAL: every assistant turn that yields must include that fenced ```json block.
  If the advisor requests changes, emit a REVISED ```json packet — never a prose-only
  ack like "you're right" / "updated above". The JSON is the only durable output.
- If the investigation is incomplete or you must stop early, your FINAL turn must still
  emit the fenced ```json packet — verdict "UNVERIFIABLE" with a finding describing what
  could not be verified. Never end on prose.

{_date_context()}

COLLECTED EVIDENCE:
{json.dumps(evidence, indent=2, default=str)[:20000]}

RECENT SESSION MEMORY (Carter's recent interactive omp sessions — context for interpreting homelab state):
{session_memory}
"""

    def _run_worker(prompt_text, label):
        raw = _call_omp_p(
            prompt_text, model=STEWARD_MODEL, timeout=section["timeout"], mode="json",
            tools=READ_ONLY_TOOLS,
        )
        return _prepare_audit_worker_packet(_extract_json(raw, label), section_name)

    try:
        worker_packet = _run_worker(worker_prompt, f"worker-{section_name}")
    except Exception as e:
        # Worker ended without a JSON packet (truncated run / prose-only ack).
        # Retry once with a packet-only continuation so an interrupted worker
        # still yields a verdict — never persist worker-failed on the first miss.
        retry_prompt = f"""
Your audit run for section '{section_name}' ended without the required fenced
```json packet. Emit ONLY the fenced ```json packet now, reflecting whatever you
verified:

{_WORKER_PACKET_SCHEMA}

- If the investigation was incomplete, verdict "UNVERIFIABLE" with a finding noting
  what could not be verified.
- This turn contains the JSON packet and nothing else.
"""
        try:
            worker_packet = _run_worker(retry_prompt, f"worker-{section_name}-retry")
        except Exception as e2:
            return {
                "name": section_name,
                "verdict": "worker-failed",
                "error": f"{e}; retry also failed: {e2}",
                "evidence_hash": current_hash,
                "judge_rejected": [],
                "confirmed_findings": [],
            }

    judge_prompt = f"""
You are a skeptical judge reviewing a homelab audit agent's findings. Independently
re-verify each finding against the collected evidence and the worker's citations.
You have no tools: everything you may rely on is inlined below. Keep only findings
the evidence confirms.

SECTION: {section_name}

SECTION GUIDANCE:
{section["guidance"]}

COLLECTED EVIDENCE:
{json.dumps(evidence, indent=2, default=str)[:20000]}

WORKER VERDICT + FINDINGS:
{json.dumps(worker_packet, indent=2)}

RECENT SESSION MEMORY (context for interpreting the state the findings describe):
{session_memory}

Return a fenced ```json packet:
{{"verdict": "PASS"|"DRIFT"|"ATTENTION"|"UNVERIFIABLE",
 "confirmed": [{{"id": "finding-1", "evidence": "independent verification",
                "severity": "high"|"medium"|"low"}}],
 "rejected": [{{"id": "finding-2", "reason": "why it is not an unresolved problem"}}]}}
- Return every worker finding ID exactly once across `confirmed` and `rejected`.
- Refer to findings by ID; do not repeat or rewrite the worker's claim or fix.
- `confirmed` contains unresolved problem findings only, never healthy-state confirmations.
- `PASS` requires an empty `confirmed` list. Use `ATTENTION` for unresolved manual/security
  action and `DRIFT` for a concrete state/config mismatch.
- For every confirmed item set `severity` by this rubric; you may override the worker's:
{_SEVERITY_RUBRIC}
- Route: the worker's `action`/`target`/`decision` stand unless unsafe or unsupported by
  the evidence. Then you may only downgrade: add `"action": "needs_carter"` (with a
  one-sentence `decision` naming the choice Carter must make) or `"action": "report_only"`,
  plus a `routing_note` saying why. Never propose another action and never add or change
  a `target`; the steward keeps the worker's target verbatim.
- CRITICAL: every yielding turn must include the fenced ```json block. If the advisor
  requests changes, emit a REVISED ```json packet — never a prose-only ack.
"""

    def _run_judge(prompt_text, label):
        raw = _call_omp_p(prompt_text, timeout=section["timeout"], mode="json",
                          tools=NO_TOOLS)
        return _validate_audit_judge_packet(
            _extract_json(raw, label),
            worker_packet,
            section_name,
        )

    judge_attempts = 1
    judge_retry_errors = []
    try:
        judge_packet = _run_judge(judge_prompt, f"judge-{section_name}")
    except Exception as e:
        judge_attempts = 2
        judge_retry_errors.append(str(e))
        retry_prompt = (
            f"{judge_prompt}\n\n"
            f"Your previous response failed steward validation: {str(e)[:500]}\n"
            "Return a corrected fenced JSON packet only. Disposition every listed finding ID "
            "exactly once; do not repeat claim or fix text."
        )
        try:
            judge_packet = _run_judge(retry_prompt, f"judge-{section_name}-retry")
        except Exception as e2:
            judge_retry_errors.append(str(e2))
            judge_packet = {
                "confirmed": [],
                "rejected": [],
                "judge_error": f"{e}; retry also failed: {e2}",
            }

    confirmed = judge_packet.get("confirmed", [])
    rejected = judge_packet.get("rejected", [])
    worker_verdict = worker_packet.get("verdict", "UNVERIFIABLE")
    final_verdict = _final_audit_verdict(worker_verdict, judge_packet)
    final_verdict, confirmed = _apply_deterministic_audit_guards(
        section_name, evidence, final_verdict, confirmed
    )
    return {
        "name": section_name,
        "verdict": final_verdict,
        "worker_verdict": worker_verdict,
        "judge_verdict": judge_packet.get("verdict", ""),
        "judge_error": judge_packet.get("judge_error", ""),
        "judge_attempts": judge_attempts,
        "judge_retry_errors": judge_retry_errors,
        "evidence_hash": current_hash,
        "worker_findings": worker_packet.get("findings", []),
        "judge_confirmed": confirmed,
        "judge_rejected": rejected,
    }


def _audit_artifact_cacheable(artifact):
    """Cache only artifacts with a complete, provenance-valid judge disposition."""
    if artifact.get("judge_error"):
        return False
    base_verdict = str(artifact.get("verdict", "")).removeprefix("cached-")
    if base_verdict != "PASS":
        # Re-check unresolved/inconclusive sections every run. Carrying their
        # pre-fix verdict forward can resurrect an item P7b or Carter resolved.
        return False
    if base_verdict not in _REAL_VERDICTS:
        return False
    worker_packet = {
        "verdict": artifact.get("worker_verdict"),
        "findings": artifact.get("worker_findings", []),
    }
    judge_packet = {
        "verdict": artifact.get("judge_verdict"),
        "confirmed": artifact.get("judge_confirmed", []),
        "rejected": artifact.get("judge_rejected", []),
    }
    try:
        _validate_prepared_audit_worker_packet(worker_packet)
        _validate_audit_judge_packet(judge_packet, worker_packet, artifact.get("name"))
    except ValueError:
        return False
    return _final_audit_verdict(worker_packet["verdict"], judge_packet) == base_verdict


def _dependabot_maintenance_evidence(run_dir, setup_data):
    """Distinguish an owned maintenance stop from an unrelated service failure."""
    recorded = setup_data.get("dependabot", {})
    owned_stop = (
        setup_data.get("run_dir") == str(run_dir)
        and setup_data.get("phase_status") == "succeeded"
        and not setup_data.get("dry_run")
        and isinstance(recorded, dict)
        and recorded.get("was_active") is True
        and recorded.get("stopped") is True
        and not recorded.get("error")
    )
    stdout, stderr, code = run_capture_ok(
        ["systemctl", "--user", "show", DEPENDABOT_UNIT,
         "--property=LoadState,ActiveState,SubState,Result"],
        env=user_env(), timeout=15,
    )
    state = dict(
        line.split("=", 1) for line in stdout.splitlines() if "=" in line
    )
    assessment = "unverifiable"
    if code == 0 and state.get("LoadState") == "loaded":
        if state.get("ActiveState") == "active" and state.get("SubState") == "running":
            assessment = "running"
        elif (
            owned_stop
            and state.get("ActiveState") == "inactive"
            and state.get("SubState") == "dead"
            and state.get("Result") == "success"
        ):
            assessment = "maintenance-stopped"
        else:
            assessment = "unexpected"
    return {
        "unit": DEPENDABOT_UNIT,
        "assessment": assessment,
        "owned_stop": owned_stop,
        "state": state,
        "check_error": stderr if code else "",
        "restoration": "current-run cleanup and systemd ExecStopPost",
    }


def phase_7_audit(run_dir, setup_data, dry_run=False):
    """Phase 7: audit sections — collector -> delta gate -> parallel worker+judge."""
    print("[P7] audit")
    prev_date_str = setup_data.get("prev_date", "")

    all_results = []
    to_fire = []
    dependabot_maintenance = None

    for section in AUDIT_SECTIONS:
        section_name = section["name"]
        artifact_name = section["artifact"]
        print(f"  [{section_name}] collector...")

        try:
            evidence = section["collector"]()
        except Exception as e:
            print(f"    collector FAILED: {e}")
            result = {"name": section_name, "verdict": "collector-failed",
                      "error": str(e), "judge_rejected": [], "confirmed_findings": []}
            write_json(run_dir / artifact_name, result)
            all_results.append(result)
            continue

        if section_name in ("security-posture", "agent-fleet-review"):
            if dependabot_maintenance is None:
                dependabot_maintenance = _dependabot_maintenance_evidence(run_dir, setup_data)
            evidence = {"dependabot_maintenance": dependabot_maintenance, **evidence}

        write_json(run_dir / f"{artifact_name}.evidence.json", evidence)
        current_hash = _evidence_hash(evidence)

        # Delta gate: cache only when yesterday produced a REAL verdict on identical evidence
        prev_artifact = _load_prev_artifact(run_dir, prev_date_str, artifact_name)
        if prev_artifact:
            prev_hash = prev_artifact.get("evidence_hash")
            prev_verdict = str(prev_artifact.get("verdict", ""))
            base_verdict = prev_verdict.removeprefix("cached-")
            if prev_hash == current_hash and _audit_artifact_cacheable(prev_artifact):
                print(f"    delta-gate: unchanged -> cached-{base_verdict}")
                result = {
                    "name": section_name,
                    "verdict": f"cached-{base_verdict}",
                    "worker_verdict": prev_artifact.get("worker_verdict", ""),
                    "judge_verdict": prev_artifact.get("judge_verdict", ""),
                    "judge_error": "",
                    "evidence_hash": current_hash,
                    "worker_findings": prev_artifact.get("worker_findings", []),
                    "judge_confirmed": prev_artifact.get("judge_confirmed", []),
                    "judge_rejected": prev_artifact.get("judge_rejected", []),
                }
                write_json(run_dir / artifact_name, result)
                all_results.append(result)
                continue

        if dry_run:
            print("    dry-run: collector only")
            result = {"name": section_name, "verdict": "dry-run-collector-only",
                      "evidence_hash": current_hash, "judge_rejected": [],
                      "confirmed_findings": []}
            write_json(run_dir / artifact_name, result)
            all_results.append(result)
            continue

        to_fire.append((section, evidence, current_hash, artifact_name))

    session_memory = _session_memory_context()

    # Fan out worker+judge pairs in parallel (cloud model, staggered via pool)
    if to_fire:
        print(f"  fanning out {len(to_fire)} sections (max_workers={AUDIT_MAX_WORKERS})")
        with ThreadPoolExecutor(max_workers=AUDIT_MAX_WORKERS) as pool:
            futures = {
                pool.submit(_run_audit_agent_pair, section, evidence, chash, session_memory): (section, artifact_name)
                for (section, evidence, chash, artifact_name) in to_fire
            }
            for fut in as_completed(futures):
                section, artifact_name = futures[fut]
                try:
                    result = fut.result()
                except Exception as e:
                    result = {"name": section["name"], "verdict": "worker-failed",
                              "error": str(e), "judge_rejected": [],
                              "confirmed_findings": []}
                write_json(run_dir / artifact_name, result)
                all_results.append(result)
                print(f"    {section['name']}: {result['verdict']}, "
                      f"confirmed={len(result.get('judge_confirmed', []))}, "
                      f"rejected={len(result.get('judge_rejected', []))}")

    # Master artifact in canonical section order
    order = {s["name"]: i for i, s in enumerate(AUDIT_SECTIONS)}
    all_results.sort(key=lambda r: order.get(r["name"], 99))
    master = {"sections": all_results}
    write_json(run_dir / "07-audit.json", master)
    print(f"[P7] done -> {run_dir / '07-audit.json'}")
    return master

