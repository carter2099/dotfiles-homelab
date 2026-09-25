"""Ideas and plans work queue reconciliation."""
from __future__ import annotations

from .config import (
    AUTO_PKGS,
    DEFAULT_TEMPLATE,
    DEPENDABOT_UNIT,
    DIGEST_SCRIPT,
    ENDPOINTS,
    FIX_MAX_ITERS,
    GH_API,
    HOME,
    IDEAS_DIR,
    LLAMA_CPP_RELEASES_API,
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
    NO_TOOLS,
)

_PATH_REF = re.compile(r"(?<![\w/.~-])(~/[\w./@+-]+|/(?:home|etc|opt|srv|usr/local)/[\w./@+-]+)")


def _referenced_path_evidence(body, limit=20):
    """Existence of host paths a queue item references (inlined no-tools evidence)."""
    evidence = {}
    for match in _PATH_REF.finditer(body or ""):
        raw = match.group(1).rstrip(".,;:)")
        if raw in evidence:
            continue
        path = Path(raw.replace("~", str(HOME), 1)) if raw.startswith("~/") else Path(raw)
        try:
            evidence[raw] = "exists" if path.exists() else "missing"
        except OSError:
            evidence[raw] = "unreadable"
        if len(evidence) >= limit:
            break
    return evidence

def _scan_md_files(directory, default_status="idea"):
    """Scan a directory for .md files, parse Status header + first heading + first paragraph."""
    results = []
    if not directory.exists():
        return results
    for f in sorted(directory.iterdir()):
        if not f.is_file() or not f.suffix == ".md":
            continue
        if f.name == "README.md":
            continue
        text = f.read_text()
        # Parse Status
        status_m = re.search(r"\*\*Status:\*\*\s*(.+)$", text, re.MULTILINE)
        # Normalize to first word, lowercase: "implementing (approved by …)" -> "implementing"
        status = (status_m.group(1).strip().split()[0].lower().rstrip(",")
                  if status_m else default_status)
        # Idea backlink (plans may declare one): **Idea:** `~/ideas/foo.md`
        idea_m = re.search(r"\*\*Idea:\*\*\s*`?([^`\s]+)", text)
        idea_link = idea_m.group(1) if idea_m else None
        # Parse Priority
        prio_m = re.search(r"\*\*Priority:\*\*\s*(\d+)$", text, re.MULTILINE)
        priority = int(prio_m.group(1)) if prio_m else 99
        # Parse Approved date
        approved_m = re.search(r"\*\*Approved:\*\*\s*(\S+)$", text, re.MULTILINE)
        approved = approved_m.group(1).strip() if approved_m else None
        # Parse urgent
        urgent_m = re.search(r"\*\*urgent:\*\*\s*(true|false)", text, re.MULTILINE)
        urgent = urgent_m.group(1).strip().lower() == "true" if urgent_m else False
        # Parse deploy
        deploy_m = re.search(r"\*\*deploy:\*\*\s*(true|false)", text, re.MULTILINE)
        deploy = deploy_m.group(1).strip().lower() == "true" if deploy_m else False
        # First heading
        heading_m = re.search(r"^#\s+(.+)$", text, re.MULTILINE)
        heading = heading_m.group(1).strip() if heading_m else f.stem
        # First paragraph (after frontmatter/heading, non-empty, <=160 chars)
        # Strip YAML frontmatter if present
        body = text
        if body.startswith("---"):
            end = body.find("---", 3)
            if end != -1:
                body = body[end + 3:]
        # Skip the first heading line
        lines = body.splitlines()
        para = ""
        in_para = False
        for line in lines:
            stripped = line.strip()
            if not in_para and stripped and not stripped.startswith("#"):
                in_para = True
            if in_para:
                if not stripped:
                    break
                para += stripped + " "
        para = para.strip()[:160]
        mtime = datetime.fromtimestamp(f.stat().st_mtime)
        results.append({
            "file": f.name,
            "stem": f.stem,
            "status": status,
            "idea_link": idea_link,
            "priority": priority,
            "approved": approved,
            "urgent": urgent,
            "deploy": deploy,
            "heading": heading,
            "summary": para,
            "mtime": mtime.isoformat(),
            "age_days": (datetime.now() - mtime).days,
        })
    return results


def _item_abs_path(item, kind):
    """Resolve absolute path for a scanned idea/plan item (open dirs only)."""
    base = IDEAS_DIR if kind == "idea" else PLANS_DIR
    return base / item["file"]


def _set_status_line(path, status_value):
    """Rewrite **Status:** line (or insert after first heading). Returns new text."""
    text = path.read_text()
    if re.search(r"^\*\*Status:\*\*", text, re.MULTILINE):
        return re.sub(
            r"^\*\*Status:\*\*\s*.+$",
            f"**Status:** {status_value}",
            text,
            count=1,
            flags=re.MULTILINE,
        )
    # Insert after first H1
    m = re.search(r"^#\s+.+$", text, re.MULTILINE)
    if m:
        insert_at = m.end()
        return text[:insert_at] + f"\n\n**Status:** {status_value}\n" + text[insert_at:].lstrip("\n")
    return f"**Status:** {status_value}\n\n" + text


def _apply_queue_status_update(update, dry_run=False):
    """Apply one judge-confirmed status update. Returns result dict."""
    kind = update.get("kind", "idea")
    rel = update.get("file") or update.get("path") or ""
    # Accept absolute or bare filename
    path = Path(rel).expanduser() if rel.startswith("/") or rel.startswith("~") else None
    if path is None:
        base = IDEAS_DIR if kind == "idea" else PLANS_DIR
        path = base / Path(rel).name
    if not path.exists():
        # Maybe already moved
        done_path = (IDEAS_DIR if kind == "idea" else PLANS_DIR) / "done" / path.name
        if done_path.exists():
            return {"file": path.name, "kind": kind, "status": "already_done",
                    "path": str(done_path)}
        return {"file": path.name, "kind": kind, "status": "missing", "path": str(path)}

    new_status = (update.get("new_status") or "").strip().lower()
    reason = (update.get("reason") or "").strip()
    move_to_done = bool(update.get("move_to_done")) or new_status == "done"

    # Status line value — keep a short human note for done
    if new_status == "done":
        today = datetime.now().strftime("%Y-%m-%d")
        status_value = f"DONE ({today})"
        if reason:
            status_value += f" — {reason[:120]}"
    elif new_status in ("planned", "idea", "scrapped", "draft", "approved",
                        "implementing"):
        status_value = new_status
        if reason and new_status == "scrapped":
            status_value += f" — {reason[:120]}"
    else:
        return {"file": path.name, "kind": kind, "status": "rejected_status",
                "new_status": new_status}

    if dry_run:
        return {
            "file": path.name, "kind": kind, "status": "dry_run",
            "would_set": status_value, "would_move": move_to_done and new_status == "done",
            "path": str(path),
        }

    new_text = _set_status_line(path, status_value)
    path.write_text(new_text)

    final_path = path
    if move_to_done and new_status == "done":
        done_dir = (IDEAS_DIR if kind == "idea" else PLANS_DIR) / "done"
        done_dir.mkdir(parents=True, exist_ok=True)
        dest = done_dir / path.name
        if dest.exists() and dest.resolve() != path.resolve():
            # Prefer not to clobber; leave updated file in place
            return {
                "file": path.name, "kind": kind, "status": "updated_exists_in_done",
                "path": str(path), "dest_exists": str(dest),
            }
        if dest.resolve() != path.resolve():
            path.rename(dest)
            final_path = dest

    return {
        "file": path.name, "kind": kind, "status": "updated",
        "new_status": new_status, "path": str(final_path),
        "moved_to_done": move_to_done and new_status == "done",
        "reason": reason[:200],
    }


def _reconcile_queue_statuses(ideas_outstanding, plans_open, dry_run=False):
    """Agent checks each open idea/plan; judge verifies; apply confirmed updates.

    Returns {updates_proposed, updates_confirmed, applied, judge, error?}.
    """
    candidates = []
    for item in ideas_outstanding:
        p = _item_abs_path(item, "idea")
        if p.exists():
            candidates.append({
                "kind": "idea",
                "file": item["file"],
                "path": str(p),
                "status": item["status"],
                "heading": item.get("heading", ""),
                "summary": item.get("summary", ""),
                "age_days": item.get("age_days"),
            })
    for item in plans_open:
        p = _item_abs_path(item, "plan")
        if p.exists():
            candidates.append({
                "kind": "plan",
                "file": item["file"],
                "path": str(p),
                "status": item["status"],
                "heading": item.get("heading", ""),
                "summary": item.get("summary", ""),
                "age_days": item.get("age_days"),
            })

    if not candidates:
        return {"updates_proposed": [], "updates_confirmed": [], "applied": [],
                "judge": {"verdict": "skip", "reason": "no open items"}}

    # The status agent and judge run with --no-tools: inline the evidence.
    for c in candidates:
        try:
            body = Path(c["path"]).read_text()[:2500]
        except OSError:
            body = ""
        c["body_preview"] = body
        c["referenced_paths"] = _referenced_path_evidence(body)

    agent_prompt = f"""You are the Homelab Steward work-queue status agent.

For each open idea/plan below, decide whether its **Status** is stale relative to
reality on disk. You have NO tools: rely only on the evidence inlined below (file
body preview, and existence checks for every host path the body references). Only
propose a status change when that evidence is strong.

Valid idea statuses: idea | planned | done | scrapped
Valid plan statuses: draft | approved | implementing | done | scrapped

Rules:
- If the work described is clearly already implemented on the host, set new_status
  to "done" and move_to_done=true.
- If an idea is still raw thought with no implementation, leave it (omit from updates).
- Do NOT mark something done just because the markdown body talks in past tense —
  the inlined path evidence must corroborate it; otherwise leave the item unchanged.
- Do NOT invent new work. Status hygiene only.
- Prefer fewer, high-confidence updates.

CANDIDATES:
{json.dumps(candidates, indent=2)}

Return ONLY fenced JSON:
```json
{{
  "updates": [
    {{
      "kind": "idea"|"plan",
      "file": "filename.md",
      "path": "/home/carter/ideas/filename.md",
      "current_status": "planned",
      "new_status": "done",
      "move_to_done": true,
      "reason": "short why",
      "evidence": ["concrete evidence strings"]
    }}
  ],
  "unchanged": [{{"file": "...", "reason": "still open because..."}}]
}}
```
"""

    print(f"  status agent: checking {len(candidates)} open item(s)")
    try:
        agent_raw = _call_omp_p(agent_prompt, model=STEWARD_MODEL, timeout=600,
                                mode="json", tools=NO_TOOLS)
        agent_packet = _extract_json(agent_raw, "queue-status-agent")
    except Exception as e:
        print(f"  status agent failed: {e}")
        return {
            "updates_proposed": [], "updates_confirmed": [], "applied": [],
            "error": str(e), "judge": {"verdict": "agent_failed"},
        }

    proposed = agent_packet.get("updates") or []
    if not isinstance(proposed, list):
        proposed = []
    # Keep only well-formed updates with a real status change
    clean_proposed = []
    for u in proposed:
        if not isinstance(u, dict):
            continue
        if not u.get("file") and not u.get("path"):
            continue
        ns = (u.get("new_status") or "").strip().lower()
        cs = (u.get("current_status") or "").strip().lower()
        if ns and ns != cs:
            clean_proposed.append(u)

    if not clean_proposed:
        print("  status agent: no status changes proposed")
        return {
            "updates_proposed": [], "updates_confirmed": [], "applied": [],
            "unchanged": agent_packet.get("unchanged", []),
            "judge": {"verdict": "nothing_to_do"},
        }

    judge_prompt = f"""You are a skeptical judge reviewing work-queue status changes
proposed by another agent on Carter's homelab.

For each proposed update, independently check the claim against the inlined
evidence below (you have NO tools). Confirm only if the evidence shows the item's
status should change. Reject weak, unverifiable, or wrong claims.

PROPOSED UPDATES:
{json.dumps(clean_proposed, indent=2)}

Open candidates with evidence:
{json.dumps([{k: c[k] for k in ('kind','file','path','status','heading','body_preview','referenced_paths')} for c in candidates], indent=2)}

Return ONLY fenced JSON:
```json
{{
  "verdict": "pass"|"partial"|"fail",
  "confirmed": [
    {{
      "kind": "idea"|"plan",
      "file": "filename.md",
      "path": "...",
      "current_status": "...",
      "new_status": "done",
      "move_to_done": true,
      "reason": "..."
    }}
  ],
  "rejected": [{{"file": "...", "reason": "why rejected"}}],
  "summary": "one sentence"
}}
```
"""

    print(f"  status judge: reviewing {len(clean_proposed)} proposal(s)")
    try:
        judge_raw = _call_omp_p(judge_prompt, model=STEWARD_MODEL, timeout=600,
                                mode="json", tools=NO_TOOLS)
        judge_packet = _extract_json(judge_raw, "queue-status-judge")
    except Exception as e:
        print(f"  status judge failed: {e}")
        return {
            "updates_proposed": clean_proposed, "updates_confirmed": [], "applied": [],
            "error": f"judge failed: {e}",
            "judge": {"verdict": "judge_failed", "summary": str(e)},
        }

    confirmed = judge_packet.get("confirmed") or []
    if not isinstance(confirmed, list):
        confirmed = []

    applied = []
    for u in confirmed:
        # Force kind/file from proposal when missing
        if not u.get("kind") and u.get("file"):
            for p in clean_proposed:
                if p.get("file") == u.get("file"):
                    u.setdefault("kind", p.get("kind", "idea"))
                    u.setdefault("path", p.get("path"))
                    break
        result = _apply_queue_status_update(u, dry_run=dry_run)
        applied.append(result)
        print(f"    {result.get('kind')} {result.get('file')}: {result.get('status')}"
              f" -> {result.get('new_status', result.get('would_set', ''))}")

    return {
        "updates_proposed": clean_proposed,
        "updates_confirmed": confirmed,
        "applied": applied,
        "rejected": judge_packet.get("rejected", []),
        "unchanged": agent_packet.get("unchanged", []),
        "judge": {
            "verdict": judge_packet.get("verdict", "unknown"),
            "summary": judge_packet.get("summary", ""),
        },
    }


def phase_5_work_queue(run_dir, dry_run=False):
    """Phase 5: scan ideas/plans, reconcile stale statuses, consistency checks."""
    print("[P5] work queue scan")

    ideas = _scan_md_files(IDEAS_DIR, default_status="idea")
    plans = _scan_md_files(PLANS_DIR, default_status="draft")

    # Also scan done subdirectories
    ideas_done = _scan_md_files(IDEAS_DIR / "done", default_status="done")
    plans_done = _scan_md_files(PLANS_DIR / "done", default_status="done")

    # Buckets (pre-reconcile)
    ideas_outstanding = [i for i in ideas if i["status"] not in ("done", "scrapped")]
    plans_draft = [p for p in plans if p["status"] == "draft"]
    plans_approved = [p for p in plans if p["status"] == "approved"]
    plans_implementing = [p for p in plans if p["status"] == "implementing"]
    plans_open = plans_draft + plans_approved + plans_implementing

    # Agent + judge: mark completed ideas/plans done when evidence supports it
    reconcile = {"updates_proposed": [], "updates_confirmed": [], "applied": [],
                 "judge": {"verdict": "skipped"}}
    if ideas_outstanding or plans_open:
        if dry_run:
            print("  DRY RUN — status reconcile will not mutate files")
        try:
            reconcile = _reconcile_queue_statuses(
                ideas_outstanding, plans_open, dry_run=dry_run
            )
        except Exception as e:
            print(f"  status reconcile failed: {e}")
            reconcile = {
                "updates_proposed": [], "updates_confirmed": [], "applied": [],
                "error": str(e), "judge": {"verdict": "error"},
            }

        # Re-scan after mutations so the email reflects new reality
        if any(a.get("status") in ("updated", "dry_run") for a in reconcile.get("applied", [])):
            ideas = _scan_md_files(IDEAS_DIR, default_status="idea")
            plans = _scan_md_files(PLANS_DIR, default_status="draft")
            ideas_done = _scan_md_files(IDEAS_DIR / "done", default_status="done")
            plans_done = _scan_md_files(PLANS_DIR / "done", default_status="done")
            ideas_outstanding = [i for i in ideas if i["status"] not in ("done", "scrapped")]
            plans_draft = [p for p in plans if p["status"] == "draft"]
            plans_approved = [p for p in plans if p["status"] == "approved"]
            plans_implementing = [p for p in plans if p["status"] == "implementing"]

    plans_done_this_week = [
        p for p in plans_done
        if (datetime.now() - datetime.fromisoformat(p["mtime"])).days <= 7
    ]
    # Ideas moved to done today also surface under a lightweight note in inconsistencies? No —
    # keep queue clean. Applied updates live in reconcile artifact field.

    # Consistency checks (linkage via a plan's **Idea:** backlink, not filename)
    inconsistencies = []
    for idea in ideas_outstanding:
        # An idea still marked 'idea' while a plan links to it -> should be 'planned'
        linking = [p for p in plans
                   if p.get("idea_link") and idea["file"] in p["idea_link"]]
        if linking and idea["status"] == "idea":
            inconsistencies.append({
                "type": "idea_not_updated",
                "idea": idea["file"],
                "detail": f"Idea status is 'idea' but plan exists: {linking[0]['file']} (set idea to 'planned')",
            })

    for plan in plans_done:
        # Only flag plans that DECLARE an idea link; standalone plans are fine
        if plan.get("idea_link"):
            matching_idea = [i for i in ideas_done if i["file"] in plan["idea_link"]]
            # Also accept idea still in open dir only if status already done (mid-move)
            if not matching_idea:
                open_match = [i for i in ideas if i["file"] in plan["idea_link"]
                              and i["status"] == "done"]
                if not open_match:
                    inconsistencies.append({
                        "type": "plan_done_idea_not",
                        "plan": plan["file"],
                        "detail": f"Plan done but linked idea ({plan['idea_link']}) not in ideas/done/",
                    })

    for plan in plans_implementing:
        lock_path = PLANS_DIR / ".steward-lock"
        if not lock_path.exists():
            age = (datetime.now() - datetime.fromisoformat(plan["mtime"])).days
            if age > 2:
                inconsistencies.append({
                    "type": "implementing_no_lock",
                    "plan": plan["file"],
                    "detail": f"Status implementing but no lock file exists; stale for {age} days",
                })

    data = {
        "ideas": {
            "outstanding": ideas_outstanding,
            "total_outstanding": len(ideas_outstanding),
        },
        "plans": {
            "draft": plans_draft,
            "approved": plans_approved,
            "implementing": plans_implementing,
            "done_this_week": plans_done_this_week,
        },
        "inconsistencies": inconsistencies,
        "status_reconcile": reconcile,
    }
    write_json(run_dir / "05-queue.json", data)
    print(f"[P5] done -> {run_dir / '05-queue.json'}")
    print(f"  ideas outstanding: {len(ideas_outstanding)}")
    print(f"  plans: {len(plans_draft)} draft, {len(plans_approved)} approved, "
          f"{len(plans_implementing)} implementing, {len(plans_done_this_week)} done this week")
    print(f"  inconsistencies: {len(inconsistencies)}")
    applied_n = len([a for a in reconcile.get("applied", [])
                     if a.get("status") in ("updated", "dry_run")])
    print(f"  status reconcile: judge={reconcile.get('judge', {}).get('verdict')} "
          f"applied={applied_n}")
    return data

