"""Confirmed audit finding remediation and fix/judge loops."""
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
    _date_context,
    _evidence_hash,
    _load_prev_artifact,
    _reboot_if_needed,
    apt_installed_version,
    apt_upgradable,
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
from .audit import (
    AUDIT_SECTIONS,
    _AUDIT_VERDICTS,
    _REAL_VERDICTS,
    _SKIP_SCANNER_FILES,
    _apply_deterministic_audit_guards,
    _audit_artifact_cacheable,
    _audit_collector_1_agents_md,
    _audit_collector_2_versions,
    _audit_collector_3_digest_quality,
    _audit_collector_4_security,
    _audit_collector_5_config_drift,
    _audit_collector_6_notes_resources,
    _audit_collector_7_agent_fleet,
    _audit_collector_8_docs_accuracy,
    _final_audit_verdict,
    _gather_repo_secrets,
    _prepare_audit_worker_packet,
    _run_audit_agent_pair,
    _session_memory_context,
    _validate_audit_judge_packet,
    _validate_prepared_audit_worker_packet,
    phase_7_audit,
)
from .worker import publish_validated_result, run_isolated_fix
from . import routing


def _parse_fix_markdown_table(raw_text, section_name, original_error):
    """Fallback: try to extract fixes from plain text when JSON parsing fails.
    Handles markdown tables OR simple 'PASS' / 'all current' text."""
    text_lower = raw_text.lower()

    # If the agent just said everything is fine / PASS
    if re.search(r"(?i)(all|everything).*(pass|current|fine|ok|clean|up to date|no finding|nothing to)", text_lower):
        return {
            "fixes_applied": [],
            "summary": "All findings already current or clean — no fixes needed.",
            "status": "no_action",
        }

    lines = raw_text.strip().splitlines()
    # Find a markdown table (line with |---| pattern)
    table_start = None
    for i, line in enumerate(lines):
        if re.search(r"\|---\|.*\|---\|", line):
            table_start = i + 1  # data starts after header separator
            break
    if table_start is None or table_start >= len(lines):
        return {"fixes_applied": [], "summary": original_error, "error": original_error}

    fixes = []
    summary_parts = []
    for line in lines[table_start:]:
        line = line.strip()
        if not line or not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.split("|")[1:-1]]
        if len(cells) < 3:
            continue
        finding = re.sub(r"\*\*(.*?)\*\*", r"\1", cells[0]).strip()
        action = re.sub(r"`(.*?)`", r"\1", cells[1]).strip()
        status_cell = cells[2].strip().lower()
        if "fixed" in status_cell or "check" in status_cell or "✅" in status_cell:
            status = "fixed"
        elif "defer" in status_cell or "skip" in status_cell:
            status = "deferred"
        elif "fail" in status_cell:
            status = "failed"
        else:
            status = "fixed"
        fixes.append({"finding": finding, "action": action, "commit": "N/A", "status": status})
        summary_parts.append(finding[:60])

    if fixes:
        summary = "Extracted from markdown table: " + "; ".join(summary_parts[:3])
        return {"fixes_applied": fixes, "summary": summary}
    return {"fixes_applied": [], "summary": original_error, "error": original_error}


def _finding_key(item):
    """Stable key across worker findings, fix rows, and judge reviews."""
    if not isinstance(item, dict):
        return re.sub(r"\s+", " ", str(item or "").strip().lower())[:200]
    raw = (
        item.get("claim")
        or item.get("finding")
        or item.get("evidence")
        or item.get("action")
        or ""
    )
    return re.sub(r"\s+", " ", str(raw).strip().lower())[:200]


def _is_unfixable_note(note):
    """True when judge/fix text says human/deferred/unfixable — don't retry."""
    return bool(re.search(
        r"(?i)\b(unfixable|cannot fix|can't fix|needs? human|manual(ly)?|"
        r"deferred|out of scope|not actionable|unverifiable|"
        r"requires? (carter|human|manual)|correctly deferred)\b",
        note or "",
    ))


def _index_by_finding_key(items):
    """Map finding_key -> item (last write wins). Skips empty keys."""
    out = {}
    for it in items or []:
        if not isinstance(it, dict):
            continue
        k = _finding_key(it)
        if k:
            out[k] = it
    return out


def _remaining_after_judge(findings, judge_packet, fixes_applied):
    """Findings still needing work after a judge pass.

    Keeps only items the judge marked ok=false (or failed fixes with no
    positive review). Drops pass/deferred/unfixable. Unmatched judge
    reviews are returned separately for artifact logging.
    """
    reviewed = judge_packet.get("reviewed") or []
    if not isinstance(reviewed, list):
        reviewed = []
    verdict = str(judge_packet.get("verdict") or "").lower()
    if verdict == "pass":
        return [], [r for r in reviewed if isinstance(r, dict)]

    review_by_key = _index_by_finding_key(reviewed)
    fix_by_key = _index_by_finding_key(fixes_applied)
    matched_review_keys = set()
    remaining = []

    for f in findings or []:
        if not isinstance(f, dict):
            continue
        key = _finding_key(f)
        if not key:
            continue
        rev = review_by_key.get(key)
        fix = fix_by_key.get(key)
        if rev is not None:
            matched_review_keys.add(key)
            ok = rev.get("ok")
            note = str(rev.get("note") or "")
            if ok is True or str(ok).lower() in ("true", "yes", "pass"):
                continue
            if _is_unfixable_note(note):
                continue
            # ok=false (or missing/ambiguous) → retry with judge note
            retry = dict(f)
            retry["prior_judge_note"] = note[:400]
            if fix and fix.get("action"):
                retry["prior_fix_action"] = str(fix.get("action"))[:400]
            if fix and fix.get("status"):
                retry["prior_fix_status"] = fix.get("status")
            remaining.append(retry)
            continue

        # No matching review row — use fix status + overall verdict.
        status = str((fix or {}).get("status") or "").lower()
        if status == "deferred" or _is_unfixable_note(str((fix or {}).get("action") or "")):
            continue
        if status == "fixed" and verdict in ("partial", ""):
            # Judge didn't call this one out; treat as accepted on partial.
            continue
        if status == "failed" or verdict == "fail":
            retry = dict(f)
            if fix and fix.get("action"):
                retry["prior_fix_action"] = str(fix.get("action"))[:400]
            retry["prior_fix_status"] = status or "unknown"
            retry["prior_judge_note"] = str(judge_packet.get("summary") or "judge fail / fix failed")[:400]
            remaining.append(retry)

    unmatched_reviews = [
        r for k, r in review_by_key.items() if k not in matched_review_keys
    ]
    return remaining, unmatched_reviews


def _merge_fixes_applied(iterations):
    """Collapse per-iteration fixes; last write wins per finding key."""
    merged = {}
    order = []
    for it in iterations:
        for fix in it.get("fixes_applied") or []:
            if not isinstance(fix, dict):
                continue
            k = _finding_key(fix) or f"anon-{len(order)}"
            if k not in merged:
                order.append(k)
            row = dict(fix)
            row["iteration"] = it.get("n")
            merged[k] = row
    return [merged[k] for k in order]


def _fix_one_section(section_name, confirmed_findings, dry_run, run_dir=None):
    """Run one bounded fix↔judge iteration through the isolated worker.

    The worker owns a disposable snapshot and executes all model/tool/test
    activity there.  Carter's process receives only a versioned packet and a
    path-bounded diff; the deterministic publisher creates an isolated review
    ref only after the existing judge returns ``pass``. The checked-out branch,
    index, and running application remain unchanged.
    """
    if dry_run:
        return {
            "section": section_name,
            "status": "dry-run",
            "findings_count": len(confirmed_findings),
            "fixes_applied": [],
            "judge_verdict": "dry-run",
            "iterations": [],
            "iteration_count": 0,
            "max_iters": FIX_MAX_ITERS,
            "publication_policy": "local-review-ref",
            "runtime_effect": "not_deployed",
        }

    if not confirmed_findings:
        return {
            "section": section_name,
            "status": "skipped",
            "reason": "no actionable findings",
            "findings_count": 0,
            "fixes_applied": [],
            "iterations": [],
            "iteration_count": 0,
            "max_iters": FIX_MAX_ITERS,
            "publication_policy": "local-review-ref",
            "runtime_effect": "not_deployed",
        }

    remaining = [dict(f) for f in confirmed_findings if isinstance(f, dict)]
    iterations = []
    stop_reason = "max_iters"
    final_judge = {"verdict": "unknown", "summary": "", "reviewed": []}
    published_commits = []

    def _finding_text(value):
        return str(value.get("claim") or value.get("finding") or value.get("evidence") or "").strip()

    def _canonical_rows(rows):
        """Map worker id/claim aliases back to the audit finding claim keys."""
        by_id = {
            str(f.get("id")): f
            for f in remaining
            if isinstance(f, dict) and f.get("id")
        }
        by_key = {_finding_key(f): f for f in remaining if _finding_key(f)}
        normalized = []
        for row in rows if isinstance(rows, list) else []:
            if not isinstance(row, dict):
                continue
            token = str(row.get("finding") or row.get("id") or "").strip()
            source = by_id.get(token) or by_key.get(_finding_key({"finding": token}))
            item = dict(row)
            if source is not None:
                item["finding"] = _finding_text(source)
            normalized.append(item)
        return normalized

    for n in range(1, FIX_MAX_ITERS + 1):
        worker_result = run_isolated_fix(
            section_name,
            remaining,
            run_dir=Path(run_dir) if run_dir is not None else None,
            iteration=n,
        )
        raw_fix = worker_result.get("fix_packet") if isinstance(worker_result, dict) else {}
        raw_judge = worker_result.get("judge_packet") if isinstance(worker_result, dict) else {}
        fix_packet = dict(raw_fix) if isinstance(raw_fix, dict) else {}
        judge_packet = dict(raw_judge) if isinstance(raw_judge, dict) else {}
        fixes_applied = fix_packet.get("fixes_applied") or []
        if not isinstance(fixes_applied, list):
            fixes_applied = []
        fixes_applied = _canonical_rows(fixes_applied)
        fix_packet["fixes_applied"] = fixes_applied
        judge_packet["reviewed"] = _canonical_rows(judge_packet.get("reviewed") or [])
        worker_status = str(worker_result.get("status") or "").lower()

        # Isolation failures are a hard boundary, not a reason to retry an
        # unconfined model call.  Keep the packet reviewable and stop this
        # section immediately.
        if worker_status != "ok":
            proposal_rows = [
                row
                for row in fixes_applied
                if isinstance(row, dict) and row.get("proposal") is True
            ]
            if worker_status == "policy-rejected" and proposal_rows:
                fixes_applied = proposal_rows
                fix_packet["fixes_applied"] = fixes_applied
            else:
                fixes_applied = []
                fix_packet["fixes_applied"] = []
            judge_packet = {
                "verdict": "fail",
                "reviewed": [
                    {
                        "finding": _finding_text(f),
                        "ok": False,
                        "note": (
                            "isolated worker did not run; no source change was accepted: "
                            + str(worker_result.get("error") or worker_status or "unknown worker failure")
                        )[:500],
                    }
                    for f in remaining
                ],
                "summary": str(worker_result.get("error") or "isolated worker unavailable")[:500],
            }
            final_judge = judge_packet
            iter_rec = {
                "n": n,
                "input_findings_count": len(remaining),
                "fixes_applied": fixes_applied,
                "fix_summary": str(fix_packet.get("summary") or ""),
                "judge_verdict": "fail",
                "judge_summary": judge_packet["summary"],
                "remaining_after": len(remaining),
                "worker_status": worker_status,
                "publication": {"status": "not_attempted"},
            }
            iterations.append(iter_rec)
            stop_reason = (
                "policy-rejected"
                if worker_status == "policy-rejected"
                else "worker-unavailable"
            )
            break

        # Never publish a partial/failing judge packet.  If a candidate diff
        # exists, make every finding retryable so an accepted row is never
        # reported while its sibling changes were discarded.
        has_diff = any(
            isinstance(repo, dict) and bool(str(repo.get("diff") or "").strip())
            for repo in worker_result.get("repositories") or []
        )
        if str(judge_packet.get("verdict") or "").lower() != "pass" and has_diff:
            judge_packet = {
                "verdict": "fail",
                "reviewed": [
                    {
                        "finding": _finding_text(f),
                        "ok": False,
                        "note": "candidate diff withheld because the existing judge did not return pass",
                    }
                    for f in remaining
                ],
                "summary": str(judge_packet.get("summary") or "judge did not pass")[:500],
            }

        publication = {"status": "not_attempted"}
        if str(judge_packet.get("verdict") or "").lower() == "pass":
            publication = publish_validated_result(worker_result, section_name)
            for commit in publication.get("commits") or []:
                if commit.get("commit"):
                    published_commits.append(dict(commit))
            if publication.get("status") != "published":
                reason = str(publication.get("error") or "trusted publisher rejected candidate")
                # A judge cannot override a publisher rejection.  Convert the
                # packet into explicit failures so the bounded loop can retry.
                judge_packet = {
                    "verdict": "fail",
                    "reviewed": [
                        {
                            "finding": _finding_text(f),
                            "ok": False,
                            "note": f"trusted publisher rejected candidate: {reason}"[:500],
                        }
                        for f in remaining
                    ],
                    "summary": reason[:500],
                }
                for row in fixes_applied:
                    if row.get("status") == "fixed":
                        row["status"] = "failed"
                        row["action"] = (
                            str(row.get("action") or "")
                            + f" Source publication rejected: {reason}"
                        )[:1200]
            else:
                commit_names = [
                    str(commit["commit"])
                    for commit in publication.get("commits") or []
                    if commit.get("commit")
                ]
                commit_text = ", ".join(commit_names) or "no source diff"
                for row in fixes_applied:
                    if row.get("status") == "fixed":
                        row["status"] = "deferred"
                        row["commit"] = commit_text
                        row["action"] = (
                            str(row.get("action") or "")
                            + f" Reviewed source repair stored locally ({commit_text}); checkout unchanged, review required, not deployed."
                        )[:1200]
                        row["runtime_effect"] = "not_deployed"

        next_remaining, unmatched_reviews = _remaining_after_judge(
            remaining, judge_packet, fixes_applied
        )
        iter_rec = {
            "n": n,
            "input_findings_count": len(remaining),
            "fixes_applied": fixes_applied,
            "fix_summary": fix_packet.get("summary", ""),
            "judge_verdict": judge_packet.get("verdict", "unknown"),
            "judge_summary": judge_packet.get("summary", ""),
            "judge_reviewed": judge_packet.get("reviewed") or [],
            "remaining_after": len(next_remaining),
            "worker_status": worker_status,
            "publication": publication,
            "validation": [
                {
                    "repository": repo.get("source"),
                    "records": repo.get("validation") or [],
                }
                for repo in worker_result.get("repositories") or []
                if isinstance(repo, dict)
            ],
        }
        if unmatched_reviews:
            iter_rec["unmatched_judge_reviews"] = unmatched_reviews
        iterations.append(iter_rec)
        final_judge = judge_packet

        print(
            f"    {section_name} iter {n}/{FIX_MAX_ITERS}: "
            f"judge={iter_rec['judge_verdict']} "
            f"fixes={len(fixes_applied)} remaining={len(next_remaining)}"
        )

        if str(judge_packet.get("verdict") or "").lower() == "pass":
            stop_reason = "pass"
            remaining = []
            break
        if not next_remaining:
            stop_reason = "no_remaining"
            remaining = []
            break

        prev_keys = sorted(_finding_key(f) for f in remaining)
        next_keys = sorted(_finding_key(f) for f in next_remaining)
        if next_keys == prev_keys and n > 1:
            stop_reason = "no_progress"
            remaining = next_remaining
            break
        if n > 1 and not fixes_applied:
            stop_reason = "empty_fix"
            remaining = next_remaining
            break
        remaining = next_remaining
    else:
        stop_reason = "max_iters"

    merged_fixes = _merge_fixes_applied(iterations)
    last = iterations[-1] if iterations else {}
    return {
        "section": section_name,
        "status": "review-required" if published_commits else (
            "fix-failed" if stop_reason == "worker-unavailable" else "completed"
        ),
        "findings_count": len(confirmed_findings),
        "actionable_count": len(confirmed_findings),
        "fixes_applied": merged_fixes,
        "fix_summary": last.get("fix_summary", ""),
        "judge_verdict": last.get("judge_verdict", final_judge.get("verdict", "unknown")),
        "judge_summary": last.get("judge_summary", final_judge.get("summary", "")),
        "judge_reviewed": last.get("judge_reviewed", final_judge.get("reviewed") or []),
        "iterations": iterations,
        "iteration_count": len(iterations),
        "max_iters": FIX_MAX_ITERS,
        "stop_reason": stop_reason,
        "remaining_unfixed": len(remaining) + sum(bool(row.get("commit")) for row in merged_fixes),
        "source_repair_commits": published_commits,
        "publication_policy": "local-review-ref",
        "runtime_effect": "not_deployed",
    }


def _confirmed_worker_findings(section):
    """Return worker findings whose stable IDs the judge confirmed."""
    confirmed_ids = {
        finding.get("id")
        for finding in section.get("judge_confirmed", [])
        if isinstance(finding, dict) and finding.get("id")
    }
    return [
        finding
        for finding in section.get("worker_findings", [])
        if isinstance(finding, dict) and finding.get("id") in confirmed_ids
    ]


def _p7b_fix_candidates(sections):
    """Split auto-fixable findings from sections that are report-only by policy."""
    to_fix = []
    report_only = []
    for section in sections:
        verdict = str(section.get("verdict", "")).removeprefix("cached-")
        confirmed = section.get("judge_confirmed", [])
        if verdict not in ("DRIFT", "ATTENTION") or not confirmed:
            continue
        name = section.get("name", "")
        if name in P7B_REPORT_ONLY_SECTIONS:
            report_only.append({
                "section": name,
                "status": "report-only",
                "findings_count": len(confirmed),
            })
            continue
        actionable = _confirmed_worker_findings(section)
        if actionable:
            to_fix.append((name, actionable))
    return to_fix, report_only


def phase_7b_fix(run_dir, dry_run=False, route_context=None):
    """Phase 7b: route every confirmed finding; only code_fix reaches the worker.

    ``routes`` (one row per confirmed finding) is the report's source of
    truth. ``sections`` keeps the legacy per-section worker results, and
    ``report_only`` the legacy report-only section list.
    """
    print("[P7b] route + auto-fix")
    audit_path = run_dir / "07-audit.json"
    if not audit_path.exists():
        print("  skipped — no audit data")
        result = {"sections": [], "routes": [], "status": "no_audit"}
        write_json(run_dir / "07b-fixes.json", result)
        return result

    audit = read_json(audit_path)
    sections = audit.get("sections", [])
    applied_path = run_dir / "01-applied.json"
    applied = {}
    if applied_path.exists():
        try:
            applied = read_json(applied_path)
        except (OSError, ValueError):
            applied = {}
    _, report_only = _p7b_fix_candidates(sections)

    ctx = route_context or routing.RouteContext()
    ctx.dry_run = dry_run
    ctx.run_dir = run_dir
    if ctx.fix_section is None:
        ctx.fix_section = _fix_one_section
    routed = routing.route_findings(sections, applied, ctx)
    fix_results = routed["sections"]
    routes = routed["routes"]

    # Sort to canonical section order
    order = {s["name"]: i for i, s in enumerate(AUDIT_SECTIONS)}
    fix_results.sort(key=lambda r: order.get(r.get("section", ""), 99))

    master = {
        "sections": fix_results,
        "report_only": report_only,
        "routes": routes,
        "status": "done" if routes else "nothing_to_fix",
    }
    write_json(run_dir / "07b-fixes.json", master)

    counts = {}
    for row in routes:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    for row in routes:
        print(f"    {row['section']}/{row['finding_id']}: {row['action']} -> {row['status']}")
    summary = ", ".join(f"{n} {s}" for s, n in sorted(counts.items())) or "no findings"
    print(f"[P7b] done -> {run_dir / '07b-fixes.json'} ({summary}; "
          f"{len(fix_results)} worker sections{', DRY RUN' if dry_run else ''})")
    return master

