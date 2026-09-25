"""Setup and interactive-session memory maintenance."""
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
    NO_TOOLS,
    READ_ONLY_TOOLS,
    DeadlinePassed,
    atomic_write_text,
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

def phase_0_setup(args, run_dir=None):
    """Create run dir, snapshot usage, stop dependabot, load prev-summary delta."""
    current = datetime.now()
    if run_dir is None:
        run_dir = RUN_DIR_BASE / current.strftime("%Y-%m-%d")
    else:
        run_dir = Path(run_dir)
    date_str = run_dir.name
    run_date = datetime.strptime(date_str, "%Y-%m-%d")
    run_dir.mkdir(parents=True, exist_ok=True)

    prev_date = prev_workday(run_date)
    prev_date_str = prev_date.strftime("%Y-%m-%d")
    prev_md = RUN_DIR_BASE / prev_date_str / "summary.md"
    prev_summary = parse_previous_summary(prev_md)

    # Usage report — snapshot proxy health (no gating, just reporting)
    usage = {"accounts": [], "proxy_error": None}
    try:
        req = urllib.request.Request(PROXY_HEALTH)
        with urllib.request.urlopen(req, timeout=10) as resp:
            proxy_health = json.loads(resp.read().decode())
    except Exception as e:
        proxy_health = {"error": str(e)}
        usage["proxy_error"] = str(e)

    if "accounts" in proxy_health:
        for acct in proxy_health["accounts"]:
            rolling = acct.get("rolling") or {}
            weekly = acct.get("weekly") or {}
            monthly = acct.get("monthly") or {}
            usage["accounts"].append({
                "name": acct.get("name", "?"),
                "tier": acct.get("tier", "unknown"),
                "rolling_pct": rolling.get("pct", 0),
                "weekly_pct": weekly.get("pct", 0),
                "monthly_pct": monthly.get("pct", 0),
                "rolling_reset_in": rolling.get("reset_in") or "",
                "weekly_reset_in": weekly.get("reset_in") or "",
                "monthly_reset_in": monthly.get("reset_in") or "",
                "usage_fresh": bool(acct.get("usage_fresh")),
            })

    # Dependabot management — stop the webhook so it doesn't race our executor
    dep = {"was_active": False, "stopped": False, "error": None}
    if not args.dry_run:
        try:
            active = run_capture(
                ["systemctl", "--user", "is-active", DEPENDABOT_UNIT],
                env=user_env(),
            ).strip()
            dep["was_active"] = (active == "active")
            if dep["was_active"]:
                run(["systemctl", "--user", "stop", DEPENDABOT_UNIT], env=user_env())
                dep["stopped"] = True
                print("  dependabot: stopped for steward run")
            else:
                print("  dependabot: already inactive")
        except Exception as e:
            dep["error"] = str(e)
            print(f"  dependabot: stop failed — {e}")
    data = {
        "date": date_str,
        "run_dir": str(run_dir),
        "prev_date": prev_date_str,
        "prev_summary_exists": prev_md.exists(),
        "dry_run": args.dry_run,
        "resume": args.resume,
        "usage": usage,
        "dependabot": dep,
    }
    artifact = run_dir / "00-setup.json"
    write_json(artifact, data)

    # Print usage summary
    acct_lines = []
    for a in usage["accounts"]:
        extra = "" if a.get("usage_fresh") else ", usage API STALE"
        resets = []
        if a.get("rolling_reset_in"):
            resets.append(f"5h→{a['rolling_reset_in']}")
        if a.get("weekly_reset_in"):
            resets.append(f"7d→{a['weekly_reset_in']}")
        if a.get("monthly_reset_in"):
            resets.append(f"30d→{a['monthly_reset_in']}")
        reset_s = f" [{', '.join(resets)}]" if resets else ""
        acct_lines.append(
            f"    {a['name']} ({a['tier']}): "
            f"5h={a['rolling_pct']}%, weekly={a['weekly_pct']}%, "
            f"monthly={a['monthly_pct']}%{extra}{reset_s}"
        )
    print(f"[P0] setup -> {artifact}")
    if usage["proxy_error"]:
        print(f"  proxy: UNREACHABLE ({usage['proxy_error']})")
    else:
        print(f"  usage ({len(usage['accounts'])} accounts):")
        for line in acct_lines:
            print(line)
    return data


# ── P0b: session memory ───────────────────────────────────────────────

def _session_header(path):
    """Parse session metadata from a session jsonl (type=session|title lines)."""
    remembered = None
    try:
        with open(path, "r", errors="replace") as fh:
            for i, line in enumerate(fh):
                if i > 20:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(obj, dict):
                    continue
                if obj.get("type") == "session":
                    return obj
                if remembered is None and obj.get("type") == "title" and obj.get("title"):
                    remembered = {"id": None, "timestamp": None, "cwd": None,
                                  "title": obj.get("title")}
    except Exception:
        pass
    return remembered or {}


def _iter_interactive_sessions(cutoff_ts):
    """Yield (project, path, mtime, header) for interactive session transcripts >= cutoff.

    Interactive sessions live in ~/.omp/agent/sessions/<project>/; headless invocations
    go to sessions-automated/ via --session-dir and are intentionally excluded.
    """
    if not SESSION_INTERACTIVE_DIR.exists():
        return
    for proj_dir in sorted(SESSION_INTERACTIVE_DIR.iterdir()):
        if not proj_dir.is_dir():
            continue
        project = proj_dir.name
        for f in sorted(proj_dir.glob("*.jsonl")):
            try:
                mtime = datetime.fromtimestamp(f.stat().st_mtime, tz=timezone.utc)
            except OSError:
                continue
            if mtime < cutoff_ts:
                continue
            yield project, f, mtime, _session_header(f)


def _session_date_str(header, mtime):
    ts = header.get("timestamp")
    if ts:
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00")).strftime("%Y-%m-%d")
        except Exception:
            pass
    return mtime.strftime("%Y-%m-%d")


def _existing_memoir_for(session_id, source_path, date_str):
    """Find a memoir whose frontmatter matches this session (session_id or source path)."""
    day_dir = SESSION_MEMOIR_DIR / date_str
    if not day_dir.is_dir():
        return None
    for f in sorted(day_dir.glob("*.md")):
        try:
            txt = f.read_text(errors="replace")
        except OSError:
            continue
        m = re.search(r"^session_id:\s*(\S+)", txt, re.MULTILINE)
        if m and m.group(1) == session_id:
            return f
        m = re.search(r"^source:\s*(\S+)", txt, re.MULTILINE)
        if m and m.group(1) == str(source_path):
            return f
    return None


def _session_excerpt(path, head=2500, tail=800):
    """Compact transcript excerpt (head + tail) for the filter judge."""
    try:
        txt = path.read_text(errors="replace")
    except OSError:
        return ""
    if len(txt) <= head + tail:
        return txt
    return txt[:head] + "\n…[truncated]…\n" + txt[-tail:]


MEMOIR_CHUNK_CHARS = 24000   # one map call's transcript slice (split at message boundaries)
MEMOIR_MAX_CHUNKS = 80       # whole-session mapping cap (new memoirs); beyond: skipped
MEMOIR_MAX_DELTA_CHUNKS = 40 # cap on the part of a session a stale memoir is missing
MEMOIR_MAP_WORKERS = 4       # concurrent map calls per session
MEMOIR_NOTE_CHARS = 3000     # cap on one chunk's (or one merge's) notes
MEMOIR_NOTES_BUDGET = 60000  # notes the reduce call may see; above it, merge a level first
MEMOIR_TAIL_CHARS = 6000     # raw end of the transcript given to the reduce call
MEMOIR_MAX_MEMOIR_CHARS = 20000  # an existing memoir longer than this is left to Carter
MEMOIR_CHUNK_TIMEOUT = 180   # seconds per chunk/merge call
MEMOIR_FINAL_TIMEOUT = 600   # seconds per summarize/extend call
P0B_DEADLINE_SECONDS = 2400  # whole P0b budget; later sessions are skipped_deadline
P0B_PROBLEM_ACTIONS = ("skipped_deadline", "error", "judge_error", "summarizer_failed")


class _TranscriptTooLong(Exception):
    pass


def _session_messages(path):
    """Condensed transcript as one text block per message, with message times.

    User/assistant text in full, tool calls and results trimmed. No truncation: long
    sessions are chunked (_session_evidence) because P0b model calls run --no-tools.
    Returns (blocks, stamps, last_message_ts or None); stamps[i] is block i's time or None.
    """
    blocks, stamps, last_ts = [], [], None
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            for raw in handle:
                try:
                    item = json.loads(raw)
                except ValueError:
                    continue
                msg = item.get("message") if isinstance(item, dict) else None
                if not isinstance(msg, dict):
                    continue
                ts, parsed = item.get("timestamp"), None
                if isinstance(ts, str):
                    try:
                        parsed = _parse_iso(ts)
                        if not parsed.tzinfo:
                            parsed = None
                        elif last_ts is None or parsed > last_ts:
                            last_ts = parsed
                    except ValueError:
                        pass
                role = msg.get("role") or "?"
                content = msg.get("content")
                if isinstance(content, str):
                    content = [{"type": "text", "text": content}]
                if not isinstance(content, list):
                    continue
                lines = []
                for part in content:
                    if not isinstance(part, dict):
                        continue
                    kind = part.get("type")
                    if kind == "text" and part.get("text"):
                        text = part["text"].strip()
                        if role == "toolResult":
                            text = text[:300] + ("…" if len(text) > 300 else "")
                            lines.append(f"[tool result] {text}")
                        else:
                            lines.append(f"{role}: {text}")
                    elif kind == "toolCall":
                        args = json.dumps(part.get("arguments"), ensure_ascii=False)
                        lines.append(f"[tool call {part.get('name')}] {args[:300]}")
                if lines:
                    blocks.append("\n".join(lines))
                    stamps.append(parsed)
    except OSError:
        return [], [], None
    return blocks, stamps, last_ts


def _blocks_after(blocks, stamps, since):
    """The messages from the first one stamped after `since` to the end."""
    for i, ts in enumerate(stamps):
        if ts is not None and ts > since:
            return blocks[i:]
    return []


def _chunk_blocks(blocks, limit=MEMOIR_CHUNK_CHARS):
    """Ordered chunks of <= limit chars, split at message boundaries.
    A single message longer than limit is split by characters."""
    chunks, cur, size = [], [], 0
    for block in blocks:
        pieces = [block[i:i + limit] for i in range(0, len(block), limit)] or [block]
        for piece in pieces:
            if cur and size + 1 + len(piece) > limit:
                chunks.append("\n".join(cur))
                cur, size = [], 0
            cur.append(piece)
            size += len(piece) + (1 if size else 0)
    if cur:
        chunks.append("\n".join(cur))
    return chunks


def _map_chunk(path, index, total, chunk, deadline=None):
    raw = _call_omp_p(
        MEMOIR_CHUNK_NOTES_PROMPT.format(path=path, index=index, total=total, chunk=chunk,
                                         max_chars=MEMOIR_NOTE_CHARS),
        model=STEWARD_MODEL, timeout=MEMOIR_CHUNK_TIMEOUT, mode="json", tools=NO_TOOLS,
        deadline=deadline)
    notes = _extract_json(raw, "session-memoir-chunk").get("notes")
    if not isinstance(notes, str):
        raise ValueError(f"chunk {index}/{total}: packet without notes")
    return notes.strip()[:MEMOIR_NOTE_CHARS] or "(nothing durable)"


def _merge_notes(path, group, deadline=None):
    raw = _call_omp_p(
        MEMOIR_NOTES_MERGE_PROMPT.format(path=path, notes="\n\n".join(group),
                                         max_chars=MEMOIR_NOTE_CHARS),
        model=STEWARD_MODEL, timeout=MEMOIR_CHUNK_TIMEOUT, mode="json", tools=NO_TOOLS,
        deadline=deadline)
    notes = _extract_json(raw, "session-memoir-merge").get("notes")
    if not isinstance(notes, str) or not notes.strip():
        raise ValueError("notes merge returned no notes")
    return notes.strip()[:MEMOIR_NOTE_CHARS]


def _session_evidence(path, blocks, max_chunks, scope="TRANSCRIPT", deadline=None):
    """Transcript evidence for a no-tools memoir call.

    Short transcript: the whole condensed text. Long: map every <=24k chunk to bounded
    notes (bounded concurrency), merge levels until the notes fit the reduce budget,
    then append the raw end. Any chunk failure raises (the caller leaves the memoir
    unchanged); more than max_chunks raises _TranscriptTooLong; passing the deadline
    raises DeadlinePassed. Returns (evidence_text, n_chunks).
    """
    text = "\n".join(blocks)
    if len(text) <= MEMOIR_CHUNK_CHARS:
        return text, 1
    chunks = _chunk_blocks(blocks)
    total = len(chunks)
    if total > max_chunks:
        raise _TranscriptTooLong(f"{total} chunks > {max_chunks}")
    with ThreadPoolExecutor(max_workers=MEMOIR_MAP_WORKERS) as pool:
        notes = list(pool.map(lambda ic: _map_chunk(path, ic[0], total, ic[1], deadline),
                              enumerate(chunks, 1)))
    notes = [f"[chunk {i}/{total}]\n{n}" for i, n in enumerate(notes, 1)]
    while sum(len(n) + 2 for n in notes) > MEMOIR_NOTES_BUDGET:
        groups, cur, size = [], [], 0
        for n in notes:
            if cur and size + len(n) + 2 > MEMOIR_CHUNK_CHARS:
                groups.append(cur)
                cur, size = [], 0
            cur.append(n)
            size += len(n) + 2
        groups.append(cur)
        if len(groups) >= len(notes):
            raise ValueError("chunk notes cannot be merged below the reduce budget")
        with ThreadPoolExecutor(max_workers=MEMOIR_MAP_WORKERS) as pool:
            notes = list(pool.map(lambda g: _merge_notes(path, g, deadline), groups))
    evidence = (
        f"NOTES FROM ALL {total} {scope} CHUNKS, in session order:\n\n"
        + "\n\n".join(notes)
        + f"\n\nRAW END OF THE {scope} (last {MEMOIR_TAIL_CHARS} chars):\n"
        + text[-MEMOIR_TAIL_CHARS:]
    )
    return evidence, total


def _memoir_covers_until(memoir_path, content):
    """When the memoir was last brought up to date: the earlier of its frontmatter
    `updated:`/`timestamp:` and its file mtime (UTC); None if neither is known."""
    times = []
    fm = re.match(r"---\n(.*?)\n---", content, re.DOTALL)
    if fm:
        for key in ("updated", "timestamp"):
            m = re.search(rf"^{key}:\s*(\S+)", fm.group(1), re.MULTILINE)
            if m:
                try:
                    ts = _parse_iso(m.group(1))
                    if ts.tzinfo:
                        times.append(ts)
                        break
                except ValueError:
                    pass
    try:
        times.append(datetime.fromtimestamp(memoir_path.stat().st_mtime, timezone.utc))
    except OSError:
        pass
    return min(times) if times else None


def _sanitize_slug(s, maxlen=48):
    s = re.sub(r"[^a-z0-9-]+", "-", (s or "").lower()).strip("-")
    s = re.sub(r"-{2,}", "-", s)
    return (s[:maxlen].rstrip("-")) or "session"


def _parse_iso(ts):
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _memoir_path(date_str, hhmm, slug):
    day_dir = SESSION_MEMOIR_DIR / date_str
    day_dir.mkdir(parents=True, exist_ok=True)
    base = f"{hhmm}-{slug}"
    p = day_dir / f"{base}.md"
    n = 2
    while p.exists():
        p = day_dir / f"{base}-{n}.md"
        n += 1
    return p


def _write_memoir(path, date_str, project, header, body, source_path, session_id,
                  updated=None):
    """Deterministic frontmatter + H1; LLM body. path is the target file.
    updated: last session message time the body covers (read by _memoir_covers_until)."""
    title = (header.get("title") or "session").strip()[:80] or "session"
    hhmm = "0000"
    ts = header.get("timestamp")
    if ts:
        try:
            hhmm = _parse_iso(ts).strftime("%H%M")
        except Exception:
            pass
    fm = (
        "---\n"
        f"title: {title}\n"
        f"source: {source_path}\n"
        f"session_id: {session_id}\n"
        f"project: {project}\n"
        f"date: {date_str}\n"
        + (f"updated: {updated.isoformat()}\n" if updated else "")
        + "---\n"
    )
    h1 = f"# Session: {date_str} {hhmm[:2]}:{hhmm[2:]} — {title}"
    atomic_write_text(path, fm + h1 + "\n\n" + body.strip() + "\n")


FILTER_JUDGE_PROMPT = """You are a light filter judge for Carter's session-memory vault.

Decide whether this interactive omp session is worth documenting in the homelab memory
bank. SKIP only sessions that are clearly not worth recording:
- test / scratch / throwaway runs (e.g. in /tmp, trying a flag, playing around)
- sessions with no decisions, no state changes, no findings — "didn't go anywhere"
FAIL OPEN: when in doubt, verdict "document". An extra short memoir is cheap; a missing
one loses context.

SESSION:
- project: {project}
- title: {title}
- started: {started}
- cwd: {cwd}

TRANSCRIPT EXCERPT (head + tail):
{excerpt}

Return a fenced ```json packet:
{{"verdict": "document"|"skip", "reason": "<one line>"}}"""


SUMMARIZER_PROMPT = """You are writing a session memoir for Carter's homelab memory bank.

Using only the session evidence below, write a COMPACT memoir
(aim <= 15 lines, terse bullets — a memory bank, not a log). Keep only durable content:
decisions, state changes (concrete files/commands/system changes), gotchas, next steps.

SOURCE SESSION: {path}
SESSION EVIDENCE (a short session is the whole condensed transcript; a long one is
ordered notes from every transcript chunk plus the raw end of the transcript — the
notes cover the WHOLE session, weigh every part of it, not just the end):
{transcript}

Session metadata: project={project}, title={title}, started={started}

Write the body ONLY (no frontmatter, no leading H1 — the steward adds those), starting
with exactly these fields:
**Topics:** comma-separated list
**Decisions:**
- ...
**State changes:**
- ...
**Context for next time:** 1-2 sentences

Return a fenced ```json packet:
{{"label": "<short kebab-case topic slug, <= 5 words>", "markdown": "<the memoir body>"}}"""


MEMOIR_EXTEND_PROMPT = """You are bringing a session memoir in Carter's memory vault up
to date with the part of its source session that happened after it was written.

MEMOIR FILE: {memoir_path}
MEMOIR CONTENT (written with the full session context up to {covered}):
{memoir_content}

SOURCE SESSION: {path}
LATER PART OF THE SESSION (only the messages after {covered}; a short part is the
condensed transcript, a long one is ordered notes from every chunk of it plus its raw
end):
{transcript}

Keep the memoir's earlier content: you cannot see the part it was written from, so
never remove or shorten it unless the later part explicitly supersedes or corrects it.
Add the later part's decisions, state changes (concrete files/commands/system changes),
gotchas and open items, and update "Context for next time". Stay compact and terse.

If the later part adds nothing durable, verdict "ok". Otherwise return the full
extended body (no frontmatter, no H1) in "updated_markdown".

Return a fenced ```json packet:
{{"verdict": "ok"|"update", "reason": "<one line>", "updated_markdown": "<full body only if update>"}}"""


MEMOIR_CHUNK_NOTES_PROMPT = """You are condensing one chunk of a long interactive omp
session transcript for Carter's homelab memory bank. Another step writes the memoir from
the notes of every chunk, so record only what this chunk shows.

SOURCE SESSION: {path}
CHUNK {index} of {total} (condensed; tool output trimmed):
{chunk}

Write terse bullet notes (at most {max_chars} characters) under these headings, omitting
empty ones:
Decisions: what Carter decided or approved, and why
Changes: concrete state changes with file paths, services, hosts, commits
Verification: checks run and their results
Open items: unresolved problems, follow-ups, next steps
If the chunk contains nothing durable, notes "(nothing durable)".

Return a fenced ```json packet:
{{"notes": "<bullet notes>"}}"""


MEMOIR_NOTES_MERGE_PROMPT = """You are merging consecutive chunk notes from one long omp
session (Carter's homelab memory bank) into one shorter set of notes.

SOURCE SESSION: {path}
CHUNK NOTES (in session order):
{notes}

Keep every decision, concrete change (paths, services, hosts, commits), verification
result and open item; drop repetition and superseded intermediate states. Keep the chunk
range in a first line like "[chunks 3-7]". At most {max_chars} characters.

Return a fenced ```json packet:
{{"notes": "<merged bullet notes>"}}"""


def _document_session(path, s, deadline=None):
    """Filter judge -> summarizer -> write memoir. Fail-open on LLM errors."""
    excerpt = _session_excerpt(path)
    if len(excerpt.strip()) < 200:
        return {"action": "skipped_empty", "reason": "transcript too short (<200 chars)"}

    try:
        raw = _call_omp_p(
            FILTER_JUDGE_PROMPT.format(project=s["project"], title=s.get("title") or "(untitled)",
                                       started=s["started"], cwd=s.get("cwd") or "",
                                       excerpt=excerpt),
            model=STEWARD_MODEL, timeout=300, mode="json", tools=NO_TOOLS,
            deadline=deadline)
        packet = _extract_json(raw, "session-filter-judge")
    except DeadlinePassed:
        raise
    except Exception as e:
        packet = {"verdict": "document", "filter_error": str(e)[:200]}
    if packet.get("verdict") == "skip":
        return {"action": "skipped", "reason": (packet.get("reason") or "")[:200],
                "filter_error": packet.get("filter_error", "")}

    blocks, _, last_ts = _session_messages(path)
    try:
        transcript, n_chunks = _session_evidence(path, blocks, MEMOIR_MAX_CHUNKS,
                                                 deadline=deadline)
    except _TranscriptTooLong as e:
        return {"action": "summarizer_skipped", "reason": f"too long: {e}"}
    except DeadlinePassed:
        raise
    except Exception as e:
        return {"action": "summarizer_failed", "error": f"chunk notes: {str(e)[:200]}"}
    try:
        raw = _call_omp_p(
            SUMMARIZER_PROMPT.format(path=path, project=s["project"],
                                     title=s.get("title") or "(untitled)",
                                     started=s["started"],
                                     transcript=transcript),
            model=STEWARD_MODEL, timeout=MEMOIR_FINAL_TIMEOUT, mode="json", tools=NO_TOOLS,
            deadline=deadline)
        packet = _extract_json(raw, "session-summarizer")
        body = (packet.get("markdown") or "").strip()
        label = _sanitize_slug(packet.get("label") or s.get("title"))
        if not body:
            raise ValueError("summarizer returned empty markdown")
    except DeadlinePassed:
        raise
    except Exception as e:
        return {"action": "summarizer_failed", "error": str(e)[:200]}

    hhmm = _parse_iso(s["started"]).strftime("%H%M")
    mp = _memoir_path(s["date"], hhmm, label)
    _write_memoir(mp, s["date"], s["project"], {"title": s.get("title") or label,
                                                "timestamp": s["started"]},
                  body, path, s["session_id"], updated=last_ts)
    return {"action": "documented", "memoir": str(mp), "chunks": n_chunks}


def _judge_existing_memoir(path, s, memoir_path, deadline=None):
    """Bring an agent-written memoir up to date with the rest of its session (J008).

    Deterministic trigger: if no message came after the memoir was last brought up to
    date, no model call ("up_to_date"). Otherwise the no-tools model sees the whole
    memoir and only the later part of the session — directly or as chunk notes, never
    truncated (F258) — and extends the memoir, keeping its earlier content. Any chunk
    failure leaves the memoir unchanged (judge_error); a later part over
    MEMOIR_MAX_DELTA_CHUNKS or a memoir over MEMOIR_MAX_MEMOIR_CHARS is judge_skipped.
    """
    try:
        content = memoir_path.read_text(errors="replace")
    except OSError as e:
        return {"action": "judge_error", "error": str(e)[:200]}
    blocks, stamps, last_ts = _session_messages(path)
    covered = _memoir_covers_until(memoir_path, content)
    if covered is not None:
        if last_ts is not None and last_ts <= covered:
            return {"action": "up_to_date",
                    "reason": f"no messages after the memoir ({covered.isoformat()})"}
        blocks = _blocks_after(blocks, stamps, covered)
        if not blocks:
            return {"action": "up_to_date",
                    "reason": f"no text messages after the memoir ({covered.isoformat()})"}
    if len(content) > MEMOIR_MAX_MEMOIR_CHARS:
        return {"action": "judge_skipped",
                "reason": f"memoir too long ({len(content)} chars > {MEMOIR_MAX_MEMOIR_CHARS});"
                          " memoir left unchanged"}
    try:
        transcript, n_chunks = _session_evidence(path, blocks, MEMOIR_MAX_DELTA_CHUNKS,
                                                 "LATER-PART", deadline=deadline)
    except _TranscriptTooLong as e:
        return {"action": "judge_skipped",
                "reason": f"later part too long: {e}; memoir left unchanged"}
    except DeadlinePassed:
        raise
    except Exception as e:
        return {"action": "judge_error", "error": f"chunk notes: {str(e)[:200]}"}
    try:
        raw = _call_omp_p(
            MEMOIR_EXTEND_PROMPT.format(memoir_path=memoir_path,
                                        covered=covered.isoformat() if covered else "unknown",
                                        memoir_content=content, path=path,
                                        transcript=transcript),
            model=STEWARD_MODEL, timeout=MEMOIR_FINAL_TIMEOUT, mode="json", tools=NO_TOOLS,
            deadline=deadline)
        packet = _extract_json(raw, "session-memoir-judge")
    except DeadlinePassed:
        raise
    except Exception as e:
        return {"action": "judge_error", "error": str(e)[:200]}
    verdict = packet.get("verdict")
    reason = (packet.get("reason") or "")[:200]
    if verdict == "update":
        new_body = (packet.get("updated_markdown") or "").strip()
        if new_body:
            _write_memoir(memoir_path, s["date"], s["project"],
                          {"title": s.get("title"), "timestamp": s["started"]},
                          new_body, path, s["session_id"], updated=last_ts)
            return {"action": "updated", "reason": reason, "chunks": n_chunks}
        return {"action": "judge_error", "reason": "update verdict without updated_markdown"}
    return {"action": "judged_ok" if verdict == "ok" else "judge_unknown", "reason": reason,
            "chunks": n_chunks}


def _commit_memoirs(date_str):
    """Commit + push the notes vault session-memory changes. Best-effort."""
    try:
        r = run_capture_ok(["git", "-C", str(HOME / "notes"), "add", "logs/sessions"])
        if r[2] != 0:
            return {"ok": False, "error": (r[1] or r[0])[:300]}
        staged = run_capture(["git", "-C", str(HOME / "notes"), "diff", "--cached", "--name-only"])
        if not staged.strip():
            return {"ok": True, "nothing_to_commit": True}
        run(["git", "-C", str(HOME / "notes"), "commit", "-m", f"session memory: {date_str}"],
            capture_output=True, text=True)
        run(["git", "-C", str(HOME / "notes"), "push"], capture_output=True, text=True, timeout=60)
        return {"ok": True, "files": len(staged.splitlines())}
    except Exception as e:
        return {"ok": False, "error": str(e)[:300]}


def _prev_deadline_skips(run_dir):
    """Session paths the latest earlier run recorded as skipped_deadline in its
    00b-session-memory.json; only existing transcripts under SESSION_INTERACTIVE_DIR."""
    earlier = sorted(d for d in RUN_DIR_BASE.glob("[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]*")
                     if d.is_dir() and d.name < Path(run_dir).name)
    for prev in reversed(earlier):
        artifact = prev / "00b-session-memory.json"
        if not artifact.exists():
            continue
        try:
            data = read_json(artifact)
        except (ValueError, OSError):
            return []
        if data.get("dry_run"):
            continue
        paths = []
        for s in data.get("sessions") or []:
            if not isinstance(s, dict) or s.get("action") != "skipped_deadline":
                continue
            p = Path(s.get("path") or "")
            if p.parent.parent == SESSION_INTERACTIVE_DIR and p.suffix == ".jsonl" \
                    and p.is_file():
                paths.append(p)
        return paths
    return []


def _sessions_to_scan(cutoff, run_dir):
    """Sessions changed since cutoff, plus those the previous run skipped for its
    deadline (deduped): (project, path, mtime, header)."""
    seen = set()
    for project, path, mtime, header in _iter_interactive_sessions(cutoff):
        seen.add(path)
        yield project, path, mtime, header
    for path in _prev_deadline_skips(run_dir):
        if path in seen:
            continue
        seen.add(path)
        try:
            mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        except OSError:
            continue
        yield path.parent.name, path, mtime, _session_header(path)


def phase_0b_session_memory(run_dir, dry_run=False, setup=None):
    """Phase 0b: maintain the session memory bank (~/notes/logs/sessions/).

    Scans interactive omp sessions (~/.omp/agent/sessions/<project>/*.jsonl) newer than
    the last steward run (plus those the previous run skipped at its deadline),
    filter-skips test/dead-end sessions (LLM judge, fail-open),
    then writes compact memoirs with source pointers — or judges/updates memoirs the
    agent already wrote during the session. Commits the notes vault. Headless sessions
    (sessions-automated/) are excluded by directory.
    """
    print("[P0b] session memory")
    prev_date = (setup or {}).get("prev_date", "")

    # Cutoff: start of the last steward run; fall back to yesterday 00:00 UTC
    cutoff = None
    try:
        if RUNS_LOG.exists():
            lines = [l for l in RUNS_LOG.read_text().splitlines() if l.strip()]
            if lines:
                ts = json.loads(lines[-1]).get("ts")
                if ts:
                    cutoff = _parse_iso(ts)
    except Exception as e:
        print(f"  warn: runs log cutoff parse failed: {e}")
    if cutoff is None:
        try:
            cutoff = datetime.strptime(prev_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except Exception:
            cutoff = datetime.now(timezone.utc) - timedelta(days=1)
    print(f"  cutoff: {cutoff.isoformat()}")

    now = datetime.now(timezone.utc)
    sessions = []
    for project, path, mtime, header in _sessions_to_scan(cutoff, run_dir):
        stem = path.stem
        session_id = header.get("id") or (stem.split("_")[-1] if "_" in stem else stem)
        date_str = _session_date_str(header, mtime)
        entry = {
            "project": project, "path": str(path), "mtime": mtime.isoformat(),
            "started": header.get("timestamp") or mtime.isoformat(),
            "session_id": session_id, "title": header.get("title") or "",
            "cwd": header.get("cwd") or "", "date": date_str,
        }
        age_min = (now - mtime).total_seconds() / 60.0
        if age_min < SESSION_ACTIVE_MINUTES:
            entry["action"] = "skipped_active"
        else:
            memoir = _existing_memoir_for(session_id, path, date_str)
            entry["action"] = "judge" if memoir else "document"
            entry["memoir"] = str(memoir) if memoir else None
        sessions.append(entry)

    n_active = sum(1 for s in sessions if s["action"] == "skipped_active")
    print(f"  sessions since cutoff: {len(sessions)} ({n_active} active, skipped)")

    if dry_run:
        for s in sessions:
            if s["action"] in ("document", "judge"):
                print(f"  DRY RUN would {s['action']}: {s['path']}")
        write_json(run_dir / "00b-session-memory.json",
                   {"cutoff": cutoff.isoformat(), "dry_run": True, "sessions": sessions})
        return

    errors = []
    deadline = time.monotonic() + P0B_DEADLINE_SECONDS
    for s in sessions:
        if s["action"] == "skipped_active":
            continue
        path = Path(s["path"])
        try:
            if time.monotonic() >= deadline:
                raise DeadlinePassed("P0b deadline passed")
            if s["action"] == "judge":
                s.update(_judge_existing_memoir(path, s, Path(s["memoir"]), deadline))
            else:
                s.update(_document_session(path, s, deadline))
        except DeadlinePassed:
            s["action"] = "skipped_deadline"
            s["reason"] = f"P0b deadline ({P0B_DEADLINE_SECONDS}s) passed; memoir left unchanged"
        except Exception as e:
            s["action"] = "error"
            s["error"] = str(e)[:300]
            errors.append({"path": s["path"], "error": str(e)[:300]})
        print(f"  {s['action']}: {s['path']}")

    commit = {}
    if any(s["action"] in ("documented", "updated") for s in sessions):
        commit = _commit_memoirs(datetime.now(timezone.utc).strftime("%Y-%m-%d"))
        print(f"  notes commit: {commit}")

    result = {"cutoff": cutoff.isoformat(), "sessions": sessions, "commit": commit,
              "errors": errors}
    problems = _p0b_problems(sessions, commit)
    if problems:
        # Degraded, not failed: the run goes on; the workflow and the email show it.
        result["phase_status"] = "degraded"
        result["reason"] = "session memory: " + ", ".join(problems)
        print(f"  degraded: {result['reason']}")
    write_json(run_dir / "00b-session-memory.json", result)
    print(f"[P0b] done -> {run_dir / '00b-session-memory.json'}")


def _p0b_problems(sessions, commit):
    """Human-readable counts of sessions P0b could not handle (memoirs left unchanged)."""
    problems = []
    for action in P0B_PROBLEM_ACTIONS:
        n = sum(1 for s in sessions if s.get("action") == action)
        if n:
            problems.append(f"{n} {action}")
    if commit and not commit.get("ok"):
        problems.append("notes commit failed")
    return problems

