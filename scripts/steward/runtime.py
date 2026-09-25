"""Command execution, OMP protocol parsing, and durable artifact helpers.

P7b repair model/tool/test execution deliberately does not use this module's
Carter-home headless OMP path.  It is delegated to ``steward.worker`` and the
provisioned ``steward-worker`` service; the helpers below remain for
read-only audit/report phases and deterministic maintenance owned by the
orchestrator.
"""
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
try:
    from workflow_state import atomic_write_json, atomic_write_text
except ModuleNotFoundError as error:
    if error.name != "workflow_state":
        raise
    from ..workflow_state import atomic_write_json, atomic_write_text

import threading

def run(cmd, **kwargs):
    """Run a command, return CompletedProcess. Raises on non-zero exit."""
    kwargs.setdefault("check", True)
    kwargs.setdefault("text", True)
    kwargs.setdefault("timeout", 120)
    return subprocess.run(cmd, **kwargs)


def run_ok(cmd, **kwargs):
    """Run a command, return True if exit 0, False otherwise."""
    kwargs.setdefault("text", True)
    kwargs.setdefault("timeout", 120)
    try:
        subprocess.run(cmd, check=True, **kwargs)
        return True
    except subprocess.CalledProcessError:
        return False


def run_capture(cmd, **kwargs):
    """Run a command, capture stdout, return stripped string (or '' on failure)."""
    kwargs.setdefault("text", True)
    kwargs.setdefault("timeout", 120)
    try:
        cp = subprocess.run(cmd, capture_output=True, check=True, **kwargs)
        return cp.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError, NotADirectoryError):
        return ""


def run_capture_ok(cmd, **kwargs):
    """Run a command, return unmodified (stdout, stderr, exit_code). Never raises."""
    kwargs.setdefault("text", True)
    kwargs.setdefault("timeout", 120)
    try:
        cp = subprocess.run(cmd, capture_output=True, **kwargs)
        return cp.stdout, cp.stderr, cp.returncode
    except Exception as e:
        return "", str(e), -1


def user_env():
    env = {**os.environ,
           "XDG_RUNTIME_DIR": f"/run/user/{os.getuid()}",
           "PATH": f"{STEWARD_PATH}:{os.environ.get('PATH', '')}"}
    return env


def write_json(path, data):
    """Write a phase artifact atomically and durably."""
    return atomic_write_json(path, data)


def read_json(path):
    return json.loads(path.read_text())


def prev_workday(today):
    """Return yesterday's date."""
    return today - timedelta(days=1)


def parse_previous_summary(md_path):
    """Parse previous day's .md summary into lines by section."""
    if not md_path.exists():
        return {}
    text = md_path.read_text()
    sections = {}
    current = None
    for line in text.splitlines():
        m = re.match(r"^##\s+(.+)$", line)
        if m:
            current = m.group(1).strip()
            sections[current] = []
        elif current:
            sections[current].append(line)
    return sections


def apt_installed_version(pkg):
    """Parse 'apt-cache policy <pkg>' to get the Installed version."""
    out = run_capture(["apt-cache", "policy", pkg])
    m = re.search(r"Installed:\s+(.+)$", out, re.MULTILINE)
    if m:
        return m.group(1).strip()
    return None


def apt_upgradable():
    """Return dict of {package: current_version -> new_version} from apt list --upgradable."""
    out = run_capture(["apt", "list", "--upgradable"], env={**os.environ, "LANG": "C"})
    result = {}
    for line in out.splitlines():
        m = re.match(r"^(\S+)/\S+\s+(\S+)\s+\S+\s+\[upgradable from:\s+(.+)\]", line)
        if m:
            result[m.group(1)] = f"{m.group(3)} -> {m.group(2)}"
    return result


def _date_context():
    """Return a date-context string for LLM prompts."""
    now = datetime.now(timezone.utc)
    return (
        f"Today is {now.strftime('%Y-%m-%d')} "
        f"({now.strftime('%A')}). "
        f"The current time is {now.strftime('%H:%M')} UTC."
    )


def _ndjson_looks_like_event_stream(text):
    """True when text is omp --mode json NDJSON (not assistant prose/JSON)."""
    if not text or not isinstance(text, str):
        return False
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            return False
        if not isinstance(obj, dict):
            return False
        return obj.get("type") in {
            "session", "agent_start", "agent_end", "turn_start", "turn_end",
            "message_start", "message_end", "message_update", "message",
        }
    return False


def _assistant_text_from_message(msg):
    """Join text parts from an assistant message content list. Skip thinking/tools."""
    if not isinstance(msg, dict):
        return ""
    if msg.get("role") and msg.get("role") != "assistant":
        return ""
    parts = []
    for item in msg.get("content") or []:
        if not isinstance(item, dict):
            continue
        if item.get("type") == "text":
            t = item.get("text")
            if isinstance(t, str) and t:
                parts.append(t)
    return "".join(parts)


def _message_error_str(msg):
    """Format stopReason=error / errorMessage from an omp message object."""
    if not isinstance(msg, dict):
        return ""
    err_msg = (msg.get("errorMessage") or msg.get("error") or "").strip()
    status = msg.get("errorStatus") or msg.get("status")
    stop = msg.get("stopReason") or ""
    if stop != "error" and not err_msg and not status:
        return ""
    first = err_msg.splitlines()[0] if err_msg else stop or "error"
    first = first[:300]
    if status:
        return f"{status} {first}".strip()
    return first



def _balanced_json_slice(text, start):
    """Return exclusive end index of balanced JSON value starting at start, or -1."""
    if start < 0 or start >= len(text):
        return -1
    open_ch = text[start]
    if open_ch not in "{[":
        return -1
    pairs = {"{": "}", "[": "]"}
    stack = [open_ch]
    in_str = False
    esc = False
    for i in range(start + 1, len(text)):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
            continue
        if ch in "{[":
            stack.append(ch)
        elif ch in "}]":
            if not stack:
                return -1
            op = stack.pop()
            if pairs[op] != ch:
                return -1
            if not stack:
                return i + 1
    return -1


NO_TOOLS = ()
READ_ONLY_TOOLS = ("read", "grep", "glob")
_ALLOWED_MODEL_TOOLS = frozenset(READ_ONLY_TOOLS)


def _omp_tool_args(tools):
    """Translate an explicit tool allow-list into omp flags.

    NO_TOOLS → --no-tools; otherwise a subset of read/grep/glob. Anything
    else (bash, edit, write, ...) is rejected: steward model calls never mutate.
    """
    if tools is None or isinstance(tools, str):
        raise ValueError("_call_omp_p requires tools=NO_TOOLS or a tuple of read-only tools")
    names = tuple(tools)
    if not names:
        return ["--no-tools"]
    unknown = sorted(set(names) - _ALLOWED_MODEL_TOOLS)
    if unknown:
        raise ValueError(f"_call_omp_p: tools not allowed: {', '.join(unknown)}")
    return ["--tools", ",".join(names)]


def _call_omp_p(
    prompt,
    model=STEWARD_MODEL,
    timeout=600,
    append_system=None,
    mode="text",
    extra_args=None,
    *,
    tools,
):
    """Call omp -p (headless). Returns assistant text. Retries on transient API errors.

    tools is mandatory: NO_TOOLS (evidence must be inlined in the prompt) or
    READ_ONLY_TOOLS / a subset of it. The model never gets bash/edit/write.

    mode="text": plain -p stdout (final assistant message only). Fine for free-form
    summaries. Rejects NDJSON event streams (misconfigured --mode json bleed).
    mode="json": --mode json NDJSON, assistant text accumulated across ALL turns via
    extract_from_ndjson. Required when the caller will _extract_json — advisor loops
    often end on a prose ack while the real ```json packet was on an earlier turn.
    Never returns raw NDJSON for the caller to scavenge.
    """
    # P7b is intentionally absent from this path: fixes.py delegates model,
    # tool, and validation activity to steward.worker.
    cmd = [
        "/usr/bin/setpriv", "--no-new-privs",
        str(HOME / ".bun/bin/omp"), "-p", "--model", model,
        "--session-dir", str(SESSION_DIR),
        "--allow-home",
        "--config", str(HOME / ".omp/agent/headless-override.yml"),
        *_omp_tool_args(tools),
    ]
    if mode == "json":
        cmd.extend(["--mode", "json"])
    if append_system:
        cmd.extend(["--append-system-prompt", append_system])
    if extra_args:
        cmd.extend(str(arg) for arg in extra_args)
    cmd.append(prompt)
    # Retry transient errors: 401 (stale key / account rotation), 429 (rate limit),
    # 5xx (server error), subprocess timeout, and API errors surfaced in NDJSON.
    max_retries = 3
    last_error = None
    recoverable_markers = ("401", "429", "500", "502", "503", "504")

    def _is_recoverable(err_text: str) -> bool:
        return any(code in (err_text or "") for code in recoverable_markers)

    for attempt in range(max_retries):
        try:
            result = subprocess.run(
                cmd,
                # omp -p reads piped stdin as extra prompt input; an inherited open
                # pipe (eval kernels, other harnesses) blocks it until timeout.
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=timeout,
                env={**os.environ, "HOME": str(HOME), "PATH": f"{STEWARD_PATH}:{os.environ.get('PATH', '')}"},
            )
        except subprocess.TimeoutExpired as e:
            last_error = e
            if attempt < max_retries - 1:
                delay = 2 ** attempt
                print(f"  omp -p timeout (attempt {attempt + 1}/{max_retries}), retrying in {delay}s")
                time.sleep(delay)
                continue
            raise RuntimeError(f"omp -p timed out after {max_retries} attempts (timeout={timeout}s)")

        stdout = result.stdout or ""
        stderr = result.stderr or ""

        if mode == "json":
            if not stdout.strip() and result.returncode != 0:
                err_text = stderr[:500]
                if _is_recoverable(err_text) and attempt < max_retries - 1:
                    delay = 2 ** attempt
                    print(f"  omp -p rc={result.returncode} (attempt {attempt + 1}/{max_retries}), retrying in {delay}s")
                    time.sleep(delay)
                    last_error = f"rc={result.returncode}: {err_text}"
                    continue
                raise RuntimeError(
                    f"omp -p failed (rc={result.returncode}): {err_text}"
                )

            text, stats = extract_from_ndjson(stdout)
            errors = stats.get("errors") or []
            err_join = "; ".join(errors)

            if errors and not text.strip():
                if _is_recoverable(err_join) and attempt < max_retries - 1:
                    delay = 2 ** attempt
                    print(f"  omp -p api error (attempt {attempt + 1}/{max_retries}): {err_join[:120]}; retrying in {delay}s")
                    time.sleep(delay)
                    last_error = err_join
                    continue
                raise RuntimeError(f"omp -p api error: {err_join}")

            if not text.strip():
                # Empty assistant — may be hard failure or stream with only tools
                if result.returncode != 0:
                    err_text = stderr[:500] or err_join or "empty assistant text"
                    if _is_recoverable(err_text) and attempt < max_retries - 1:
                        delay = 2 ** attempt
                        print(f"  omp -p rc={result.returncode} (attempt {attempt + 1}/{max_retries}), retrying in {delay}s")
                        time.sleep(delay)
                        last_error = f"rc={result.returncode}: {err_text}"
                        continue
                    raise RuntimeError(
                        f"omp -p failed (rc={result.returncode}): {err_text}"
                    )
                raise RuntimeError(
                    "omp -p json returned empty assistant text"
                    + (f" ({err_join})" if err_join else "")
                )

            # Prefer assistant text; if API errors also present, still return text
            # (partial success) — callers extract JSON from text.
            return text

        # mode == "text"
        if result.returncode == 0 or stdout.strip():
            if _ndjson_looks_like_event_stream(stdout):
                raise RuntimeError(
                    "omp -p text mode received NDJSON event stream; "
                    "refusing to treat session logs as assistant prose"
                )
            if stdout.strip():
                return stdout
            # rc==0 but empty
            if result.returncode == 0:
                return stdout

        err_text = stderr[:500]
        if _is_recoverable(err_text) and attempt < max_retries - 1:
            delay = 2 ** attempt
            print(f"  omp -p rc={result.returncode} (attempt {attempt + 1}/{max_retries}), retrying in {delay}s")
            time.sleep(delay)
            last_error = f"rc={result.returncode}: {err_text}"
            continue

        raise RuntimeError(
            f"omp -p failed (rc={result.returncode}): {err_text}"
        )

    raise RuntimeError(
        f"omp -p failed after {max_retries} attempts: {last_error}"
    )


def _extract_json(text, label="output"):
    """Extract JSON from assistant text. Never scavenges omp NDJSON event streams."""
    if text is None:
        raise ValueError(f"Could not extract JSON from {label}: text is None")
    if not isinstance(text, str):
        text = str(text)

    if _ndjson_looks_like_event_stream(text):
        raise ValueError(
            f"Could not extract JSON from {label}: got omp NDJSON event stream "
            f"(parser should have returned assistant text only). "
            f"Raw text (first 500 chars):\n{text[:500]}"
        )

    # Fenced blocks — last successful parse wins (final agent packet).
    fences = re.findall(r"```(?:json)?\s*\n?(.*?)```", text, re.DOTALL)
    for block in reversed(fences):
        try:
            return json.loads(block.strip())
        except json.JSONDecodeError:
            continue

    stripped = text.strip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            return json.loads(stripped)
        except json.JSONDecodeError:
            pass

    # Brace-balanced scan — keep (start, end, value) and prefer largest dict packet.
    candidates = []  # (end-start, start, value)
    for i, ch in enumerate(text):
        if ch not in "{[":
            continue
        end = _balanced_json_slice(text, i)
        if end < 0:
            continue
        snippet = text[i:end]
        try:
            val = json.loads(snippet)
        except json.JSONDecodeError:
            continue
        candidates.append((end - i, i, val))
    if candidates:
        dicts = [c for c in candidates if isinstance(c[2], dict)]
        pool = dicts or candidates
        # Largest span wins; tie-break later start (final packet in multi-object prose).
        pool.sort(key=lambda c: (c[0], c[1]))
        return pool[-1][2]

    raise ValueError(
        f"Could not extract JSON from {label}. Raw text (first 500 chars):\n{text[:500]}"
    )


def extract_from_ndjson(stdout):
    """Parse omp --mode json NDJSON stdout → (assistant_text, stats).

    Supports:
      - Legacy (pi-style): message_update / assistantMessageEvent text_delta
      - Current omp (2026-07+): message_start/message_end with full message objects;
        also turn_end and agent_end.assistant messages

    stats keys: input_tokens, output_tokens, cost_usd, errors[list[str]], format
    Never returns raw NDJSON as text.
    """
    stats = {
        "input_tokens": 0,
        "output_tokens": 0,
        "cost_usd": 0.0,
        "errors": [],
        "format": "empty",
    }
    if not stdout or not str(stdout).strip():
        return "", stats

    delta_parts = []
    end_texts = []  # assistant texts from message_end / turn_end (ordered)
    saw_delta = False
    saw_end = False
    agent_end_text = ""

    def _absorb_usage(msg):
        if not isinstance(msg, dict):
            return
        usage = msg.get("usage") or {}
        if not isinstance(usage, dict):
            return
        stats["input_tokens"] += int(usage.get("input") or 0)
        stats["output_tokens"] += int(usage.get("output") or 0)
        cost = usage.get("cost") or {}
        if isinstance(cost, dict):
            try:
                stats["cost_usd"] += float(cost.get("total") or 0.0)
            except (TypeError, ValueError):
                pass

    def _absorb_error(msg):
        err = _message_error_str(msg)
        if err and err not in stats["errors"]:
            stats["errors"].append(err)

    for line in str(stdout).splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        typ = obj.get("type") or ""

        if typ == "message_update":
            ev = obj.get("assistantMessageEvent") or {}
            if isinstance(ev, dict) and ev.get("type") == "text_delta":
                delta = ev.get("delta") or ""
                if delta:
                    delta_parts.append(delta)
                    saw_delta = True

        elif typ in ("message_end", "turn_end"):
            msg = obj.get("message") or {}
            if not isinstance(msg, dict):
                continue
            _absorb_usage(msg)
            _absorb_error(msg)
            if msg.get("role") == "assistant":
                saw_end = True
                t = _assistant_text_from_message(msg)
                if t:
                    end_texts.append(t)

        elif typ == "message_start":
            # Errors sometimes only appear fully on message_end; still check.
            msg = obj.get("message") or {}
            if isinstance(msg, dict) and msg.get("role") == "assistant":
                _absorb_error(msg)

        elif typ == "agent_end":
            messages = obj.get("messages") or []
            if isinstance(messages, list):
                for msg in messages:
                    if not isinstance(msg, dict):
                        continue
                    if msg.get("role") == "assistant":
                        _absorb_usage(msg)
                        _absorb_error(msg)
                        t = _assistant_text_from_message(msg)
                        if t:
                            agent_end_text = t  # last assistant wins

    if saw_delta and saw_end:
        stats["format"] = "mixed"
    elif saw_delta:
        stats["format"] = "legacy-delta"
    elif saw_end or agent_end_text:
        stats["format"] = "message-end"
    else:
        stats["format"] = "empty"

    # Prefer deltas when present (streaming path); else message_end texts;
    # else agent_end fallback. Do not double-append end text when deltas exist.
    if saw_delta:
        text = "".join(delta_parts)
    elif end_texts:
        # Multiple assistant message_ends across turns — join in order (advisor loops).
        text = "\n".join(end_texts)
    else:
        text = agent_end_text or ""

    return text, stats


def _evidence_hash(evidence):
    """Return a deterministic SHA256 hash of an evidence dict for delta comparison."""
    raw = json.dumps(evidence, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()


def _load_prev_artifact(run_dir, prev_date_str, name):
    """Load a named artifact from the previous run dir, if it exists."""
    prev_dir = RUN_DIR_BASE / prev_date_str
    path = prev_dir / name
    if path.exists():
        try:
            return read_json(path)
        except (json.JSONDecodeError, OSError):
            return None
    return None



def _reboot_if_needed(run_dir, phase_label, dry_run=False):
    """Check /var/run/reboot-required. If present and not dry-run, write pending.md and reboot.

    Returns True if a reboot was triggered (caller should exit after this).
    """
    REBOOT_FLAG = Path("/var/run/reboot-required")
    if not REBOOT_FLAG.exists():
        return False

    if dry_run:
        print(f"  [reboot] DRY RUN — /var/run/reboot-required exists (would reboot)")
        return False

    print(f"  [reboot] /var/run/reboot-required detected — writing pending.md and rebooting")

    # Write pending.md with full context for boot-time resume
    PENDING_PATH.parent.mkdir(parents=True, exist_ok=True)
    now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    pending_content = f"""# Pending Task — {now_ts}
**Reason:** Kernel update requires reboot after steward {phase_label}
**Action:** Run `python3 ~/scripts/steward_runner.py --resume --run-dir {run_dir}` to continue
**Run dir:** {run_dir}
**State DB:** {run_dir / "workflow-state.sqlite3"}
**Completed phases:** through {phase_label}
**Context:** The homelab steward was mid-run when a kernel update (or other
/var/run/reboot-required trigger) was detected. On resume, only phases with a
succeeded WorkflowState row whose code, policy, upstream hashes, flags, schema,
and artifact hash still match are skipped. Failed rows always run again.
"""
    atomic_write_text(PENDING_PATH, pending_content)
    print(f"  [reboot] wrote {PENDING_PATH}")

    try:
        run(["sudo", "systemctl", "reboot"], capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        print(f"  [reboot] reboot command failed: {e}")
        return False

    # If we get here, reboot was accepted — but Python may continue briefly.
    # The caller should still exit.
    return True



# ── service memory sampling ──────────────────────────────────────────

_CGROUP_ROOT = Path("/sys/fs/cgroup")


def _own_cgroup_dir():
    """Return this process's cgroup v2 directory, or None outside cgroup v2."""
    try:
        for line in Path("/proc/self/cgroup").read_text().splitlines():
            if line.startswith("0::"):
                path = _CGROUP_ROOT / line[3:].lstrip("/")
                return path if (path / "memory.stat").is_file() else None
    except OSError:
        return None
    return None


def _cgroup_memory_stat(cgroup_dir):
    """Return current, anon, and file bytes for a cgroup, or None if unreadable."""
    stats = {}
    try:
        for line in (cgroup_dir / "memory.stat").read_text().splitlines():
            key, _, value = line.partition(" ")
            if key in ("anon", "file"):
                stats[key] = int(value)
        stats["current"] = int((cgroup_dir / "memory.current").read_text().strip())
    except (OSError, ValueError):
        return None
    return stats


class MemorySampler:
    """Record the service cgroup's program (anon) and page-cache (file) maxima.

    memory.peak alone cannot distinguish real memory pressure from the kernel
    filling page cache up to MemoryHigh. Maxima persist in ``path`` so a reboot
    resume or the post-P7b re-exec keeps accumulating into the same run record.
    """

    def __init__(self, path, interval=10.0, cgroup_dir=None, flush_every=6):
        self.path = Path(path)
        self.interval = interval
        self.flush_every = max(1, int(flush_every))
        self.cgroup_dir = cgroup_dir if cgroup_dir is not None else _own_cgroup_dir()
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._thread = None
        self.data = self._load()

    def _load(self):
        try:
            data = json.loads(self.path.read_text())
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def sample(self):
        if self.cgroup_dir is None:
            return
        stats = _cgroup_memory_stat(self.cgroup_dir)
        if stats is None:
            return
        try:
            peak = int((self.cgroup_dir / "memory.peak").read_text().strip())
        except (OSError, ValueError):
            peak = None
        with self._lock:
            data = self.data
            data["samples"] = int(data.get("samples") or 0) + 1
            for key, name in (
                ("current", "max_current_bytes"),
                ("anon", "max_anon_bytes"),
                ("file", "max_file_bytes"),
            ):
                if key in stats:
                    data[name] = max(int(data.get(name) or 0), stats[key])
            if peak is not None:
                data["peak_bytes"] = max(int(data.get("peak_bytes") or 0), peak)

    def flush(self):
        """Take a final sample and persist the maxima when the run dir exists."""
        self.sample()
        with self._lock:
            if self.data and self.path.parent.is_dir():
                atomic_write_json(self.path, self.data)

    def _loop(self):
        ticks = 0
        while not self._stop.wait(self.interval):
            ticks += 1
            if ticks % self.flush_every:
                self.sample()
            else:
                self.flush()

    def start(self):
        if self.cgroup_dir is None or self._thread is not None:
            return self
        self._thread = threading.Thread(
            target=self._loop, name="steward-memory-sampler", daemon=True
        )
        self._thread.start()
        return self

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
        self.flush()
