"""Local and gaming-rig update operations."""
from __future__ import annotations

import shutil

from .config import (
    AUTO_PKGS,
    DEFAULT_TEMPLATE,
    AUTO_MERGE_CANDIDATES,
    DEPENDABOT_AGENT_OWNED_REPOS,
    DEPENDABOT_WEBHOOK_BUNDLER_REPOS,
    DEPLOY_REGISTRY,
    GITHUB_OWNER,
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
)

# Local apt is deliberately bounded independently of the runtime command
# default.  A package transaction may legitimately outlive the 120s helper
# default, but it must still leave a finite, reportable attempt.
P1_APT_TIMEOUT = 900
_P1_FAILURE_STATUSES = frozenset({"failed", "error", "timeout", "started"})


def _p1_output_text(value):
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _p1_exception_packet(step, error, *, timeout_s=None):
    """Turn an unexpected substep exception into durable result data."""
    timed_out = isinstance(error, subprocess.TimeoutExpired)
    status = "timeout" if timed_out else "failed"
    if timed_out:
        limit = timeout_s if timeout_s is not None else getattr(error, "timeout", None)
        detail = (
            f"{step} timed out after {limit}s"
            if limit is not None
            else f"{step} timed out"
        )
    else:
        detail = f"{step} failed: {error}"
    output = "\n".join(
        part for part in (
            _p1_output_text(getattr(error, "stdout", None)),
            _p1_output_text(getattr(error, "stderr", None)),
        ) if part
    )
    packet = {"step": step, "status": status, "error": str(detail)[:2048]}
    if timeout_s is not None:
        packet["timeout_s"] = timeout_s
    if output:
        packet["output"] = output[-4000:]
    return packet


def _p1_run_step(steps, name, operation, persist, **fields):
    """Persist ``started`` before running one operation, then its outcome.

    ``fields`` (e.g. ``service``) identify the row even if the operation
    raises or the process dies mid-step.
    """
    steps.append({"step": name, "status": "started", **fields})
    persist()
    try:
        result = operation()
    except subprocess.TimeoutExpired as error:
        result = _p1_exception_packet(name, error)
    except Exception as error:
        result = _p1_exception_packet(name, error)
    if not isinstance(result, dict):
        result = {
            "step": name,
            "status": "failed",
            "error": f"substep returned {type(result).__name__}, not an object",
        }
    else:
        result.setdefault("step", name)
    for key, value in fields.items():
        result.setdefault(key, value)
    steps[-1] = result
    persist()
    return result


def _p1_progress_payload(steps, *, dry_run=False):
    payload = {"steps": list(steps)}
    if dry_run:
        payload["dry_run"] = True
    return payload


def _p1_apt_upgrade():
    """Run the bounded local apt update + upgrade operation."""
    print("  [1a] apt update + upgrade")
    stage = "apt update"
    try:
        run(
            ["sudo", "apt", "update"],
            capture_output=True,
            text=True,
            timeout=P1_APT_TIMEOUT,
        )
        stage = "apt upgrade"
        upgrade = run(
            ["sudo", "apt", "upgrade", "-y", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"],
            capture_output=True,
            text=True,
            timeout=P1_APT_TIMEOUT,
        )
        stdout = upgrade.stdout or ""
        m = re.search(r"(\d+)\s+upgraded", stdout)
        upgraded = int(m.group(1)) if m else 0
        # needrestart / apt may restart docker even when our auto_* steps later
        # report "skipped" (versions already match post-upgrade).
        docker_touched = bool(re.search(
            r"(?im)^(setting up|unpacking)\s+docker-|"
            r"^setting up\s+containerd\.io|"
            r"restarting.*\bdocker\.service\b|"
            r"\bdocker\.service\b.*restart",
            stdout,
        ))
        return {
            "step": "apt_upgrade",
            "status": "ok",
            "upgraded_count": upgraded,
            "docker_touched": docker_touched,
            "output_tail": "\n".join(stdout.strip().splitlines()[-20:]),
        }
    except subprocess.TimeoutExpired as error:
        packet = _p1_exception_packet(
            "apt_upgrade",
            error,
            timeout_s=P1_APT_TIMEOUT,
        )
        packet["error"] = f"{stage} timed out after {P1_APT_TIMEOUT}s"
        packet["stage"] = stage
        return packet
    except subprocess.CalledProcessError as error:
        return {
            "step": "apt_upgrade",
            "status": "failed",
            "error": str(error),
            "output": _p1_output_text(error.stdout),
            "stage": stage,
        }


def _wait_docker_stack_ready(timeout_s=120):
    """After docker daemon restart, wait until docker + key HTTP endpoints answer.

    open-webui in particular can take >30s to leave 'health: starting' and bind
    48100; a single immediate curl yields empty http_code and a false FAIL.
    """
    print(f"  [docker-settle] waiting up to {timeout_s}s for docker + endpoints")
    deadline = time.time() + timeout_s
    last = {"docker": "", "endpoints": {}}
    while time.time() < deadline:
        root = run_capture(
            ["docker", "info", "--format", "{{.DockerRootDir}}"], timeout=15)
        last["docker"] = root
        if root != "/var/lib/docker":
            time.sleep(3)
            continue

        endpoint_ok = {}
        all_ok = True
        for name, url in ENDPOINTS.items():
            if name == "searxng":
                # JSON content check is heavier; connectivity is enough here.
                code = run_capture(
                    ["curl", "-so", "/dev/null", "-w", "%{http_code}",
                     "--connect-timeout", "3", "--max-time", "8",
                     url.split("?")[0] if "?" in url else url],
                    timeout=15,
                )
            else:
                code = run_capture(
                    ["curl", "-so", "/dev/null", "-w", "%{http_code}",
                     "--connect-timeout", "3", "--max-time", "8", url],
                    timeout=15,
                )
            ok = bool(code) and (code.startswith("2") or code.startswith("3"))
            endpoint_ok[name] = code or "empty"
            if not ok:
                all_ok = False
        last["endpoints"] = endpoint_ok
        if all_ok:
            print(f"  [docker-settle] ready: {endpoint_ok}")
            return {"status": "ok", "endpoints": endpoint_ok}
        time.sleep(3)

    print(f"  [docker-settle] timed out: {last}")
    return {"status": "timeout", **last}


def _p1_auto_pkgs(progress=None):
    """Auto-apply docker-* and cloudflared upgrades with durable progress."""
    results = []
    for pkg in AUTO_PKGS:
        step_name = f"auto_{pkg}"
        print(f"  [1b] auto-apply {pkg}")
        results.append({"step": step_name, "status": "started"})
        if progress is not None:
            progress(list(results))
        pre_ver = None
        try:
            pre_ver = apt_installed_version(pkg)
            run(
                ["sudo", "apt", "install", "--only-upgrade", pkg, "-y", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"],
                capture_output=True,
                text=True,
                timeout=P1_APT_TIMEOUT,
            )
            post_ver = apt_installed_version(pkg)
            result = {
                "step": step_name,
                "status": "ok" if post_ver != pre_ver else "skipped",
                "pre_version": pre_ver,
                "post_version": post_ver,
            }
        except subprocess.TimeoutExpired as error:
            result = _p1_exception_packet(
                step_name,
                error,
                timeout_s=P1_APT_TIMEOUT,
            )
            result["pre_version"] = pre_ver
        except subprocess.CalledProcessError as error:
            result = {
                "step": step_name,
                "status": "failed",
                "pre_version": pre_ver,
                "error": str(error),
                "output": _p1_output_text(error.stdout).strip(),
            }
        except Exception as error:
            result = _p1_exception_packet(step_name, error)
            result["pre_version"] = pre_ver
        results[-1] = result
        if progress is not None:
            progress(list(results))
    return results


def _p1_docker_assert():
    """Assert docker daemon root == /var/lib/docker."""
    print("  [1c] assert docker daemon root")
    try:
        root = run(["docker", "info", "--format", "{{.DockerRootDir}}"],
                   capture_output=True, text=True, timeout=30).stdout.strip()
    except subprocess.CalledProcessError as e:
        return {"step": "docker_daemon_assert", "status": "failed",
                "error": f"docker info failed: {e}"}
    if root != "/var/lib/docker":
        return {"step": "docker_daemon_assert", "status": "failed",
                "error": f"unexpected DockerRootDir: {root!r}"}
    return {"step": "docker_daemon_assert", "status": "ok", "root": root}


FRESHRSS_DIR = HOME / "freshrss"
FRESHRSS_COMPOSE = FRESHRSS_DIR / "docker-compose.yml"
FRESHRSS_UP = FRESHRSS_DIR / "up.sh"
FRESHRSS_TAGS_API = (
    "https://hub.docker.com/v2/repositories/freshrss/freshrss/tags?"
    "page_size=50&ordering=last_updated"
)
_FRESHRSS_PIN_RE = re.compile(
    r"freshrss/freshrss:(\d+\.\d+\.\d+)@(sha256:[0-9a-f]{64})")


def _select_freshrss_tag(tags, current_tag):
    """Newest stable N.N.N tag newer than current_tag that carries a digest."""
    def version(name):
        return tuple(int(x) for x in name.split("."))
    candidates = [
        t for t in tags
        if re.fullmatch(r"\d+\.\d+\.\d+", t.get("name", ""))
        and re.fullmatch(r"sha256:[0-9a-f]{64}", t.get("digest") or "")
        and version(t["name"]) > version(current_tag)
    ]
    return max(candidates, key=lambda t: version(t["name"])) if candidates else None


def _wait_freshrss_healthy(timeout_s=60):
    """Require FreshRSS's login page to answer on its loopback port."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(ENDPOINTS["freshrss"], timeout=8) as response:
                if response.status < 400:
                    return True
        except Exception:
            pass
        time.sleep(2)
    return False


def _p1_freshrss_update(tags=None):
    """Bump the compose image pin (tag@digest) to the newest release; roll back on failure."""
    print("  [1e] freshrss tag check")
    if not FRESHRSS_COMPOSE.exists():
        return {"step": "freshrss", "status": "skipped",
                "reason": f"compose file not found: {FRESHRSS_COMPOSE}"}

    compose_text = FRESHRSS_COMPOSE.read_text()
    m = _FRESHRSS_PIN_RE.search(compose_text)
    if not m:
        return {"step": "freshrss", "status": "failed",
                "reason": "could not parse freshrss/freshrss:<tag>@sha256 pin from compose file"}
    old_ref = m.group(0)
    current_tag = m.group(1)

    if tags is None:
        try:
            req = urllib.request.Request(
                FRESHRSS_TAGS_API, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                tags = json.loads(resp.read().decode()).get("results", [])
        except Exception as e:
            return {"step": "freshrss", "status": "error",
                    "reason": f"Docker Hub unreachable: {e}", "current_tag": current_tag}

    target = _select_freshrss_tag(tags, current_tag)
    if not target:
        return {"step": "freshrss", "status": "current", "current_tag": current_tag}

    latest_tag = target["name"]
    new_ref = f"freshrss/freshrss:{latest_tag}@{target['digest']}"
    print(f"  freshrss: {current_tag} -> {latest_tag}")
    try:
        run(["docker", "pull", new_ref], capture_output=True, text=True, timeout=300)
    except Exception as exc:
        # Nothing in production changed yet: report without touching compose.
        msg = str(exc)
        if isinstance(exc, subprocess.CalledProcessError) and exc.stderr:
            msg += f" | stderr: {exc.stderr[-500:]}"
        return {"step": "freshrss", "status": "failed", "reason": "pull failed",
                "current_tag": current_tag, "latest_tag": latest_tag, "error": msg}
    try:
        FRESHRSS_COMPOSE.write_text(compose_text.replace(old_ref, new_ref, 1))
        run([str(FRESHRSS_UP)], cwd=FRESHRSS_DIR, capture_output=True, text=True, timeout=300)
        if not _wait_freshrss_healthy():
            raise RuntimeError("login page health check timed out")
        return {"step": "freshrss", "status": "bumped",
                "current_tag": current_tag, "latest_tag": latest_tag,
                "pre_image": old_ref, "post_image": new_ref}
    except Exception as exc:
        msg = str(exc)
        if isinstance(exc, subprocess.CalledProcessError) and exc.stderr:
            msg += f" | stderr: {exc.stderr[-500:]}"
        FRESHRSS_COMPOSE.write_text(compose_text)
        rollback_error = ""
        try:
            run([str(FRESHRSS_UP)], cwd=FRESHRSS_DIR, capture_output=True, text=True,
                timeout=300)
            if not _wait_freshrss_healthy():
                raise RuntimeError("restored pin failed login page health check")
        except Exception as rollback_exc:
            rollback_error = str(rollback_exc)
        return {"step": "freshrss",
                "status": "failed" if rollback_error else "reverted",
                "current_tag": current_tag, "latest_tag": latest_tag,
                "reverted_to": old_ref, "error": msg,
                "rollback_error": rollback_error}


OPENWEBUI_IMAGE = "ghcr.io/open-webui/open-webui"
OPENWEBUI_SERVICE = "open-webui"   # compose service and container name
OPENWEBUI_DATA = Path("/var/lib/docker/volumes/open-webui_open-webui/_data")
OPENWEBUI_URL = "http://127.0.0.1:48100"
OPENWEBUI_RECOVERY_ROOT = HOME / "backups" / "open-webui-upgrades"
# Core tables whose row counts must never drop across an update.  A missing
# required table means the baseline cannot be trusted, so the update skips.
OPENWEBUI_REQUIRED_TABLES = (
    "user", "chat", "model", "function", "tool", "knowledge", "file",
)
OPENWEBUI_EXTRA_TABLES = ("auth", "chat_message", "folder")
OPENWEBUI_HEALTH_TIMEOUT = 180
OPENWEBUI_TAR_TIMEOUT = 1800
_OWUI_LOG_ERROR = re.compile(
    r"(?im)^.*(?:traceback \(most recent call last\)"
    r"|alembic\S*.*\b(?:error|exception|failed)\b"
    r"|migration\S*.*\b(?:error|exception|failed)\b"
    r"|sqlite3?\.OperationalError|no such (?:table|column)"
    r"|application startup failed).*$"
)
# Moves every top-level volume entry the archive covers (all but cache/ and
# the old top-level *.bak files) aside, then restores the verified
# pre-update archive.  Nothing is deleted.
_OWUI_RESTORE_SCRIPT = r'''set -euo pipefail
data=$1 aside=$2 archive=$3
install -d -m 0700 -- "$aside"
find "$data" -mindepth 1 -maxdepth 1 ! -name cache ! -name '*.bak' -exec mv -t "$aside" -- {} +
tar -xzpf "$archive" --acls --xattrs --xattrs-include='*' --numeric-owner -C "$data"
'''


def _semver(tag):
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", str(tag or "").strip())
    return tuple(int(part) for part in match.groups()) if match else None


def _owui_compose(*args, timeout=300):
    return run_capture_ok(
        ["docker", "compose", "-f", str(OPENWEBUI_COMPOSE), *args],
        cwd=str(OPENWEBUI_COMPOSE.parent), timeout=timeout)


def _owui_sqlite(db, sql, timeout=300):
    """Run one sqlite3 statement as root (the Docker volume is root-owned)."""
    return run_capture_ok(["sudo", "-n", "sqlite3", str(db), sql], timeout=timeout)


def _owui_sudo(*args, timeout=OPENWEBUI_TAR_TIMEOUT):
    return run_capture_ok(["sudo", "-n", *args], timeout=timeout)


def _owui_db_state(db):
    """Integrity result and core row counts of one SQLite file, or an error."""
    out, err, code = _owui_sqlite(db, "PRAGMA integrity_check;")
    if code != 0:
        return {"error": f"integrity_check could not run: {(err or out).strip()[-300:]}"}
    integrity = out.strip()
    out, err, code = _owui_sqlite(
        db, "SELECT name FROM sqlite_master WHERE type='table';")
    if code != 0:
        return {"error": f"table list failed: {(err or out).strip()[-300:]}"}
    tables = set(out.split())
    missing = [name for name in OPENWEBUI_REQUIRED_TABLES if name not in tables]
    tracked = [name for name in OPENWEBUI_REQUIRED_TABLES + OPENWEBUI_EXTRA_TABLES
               if name in tables]
    counts = {}
    if tracked:
        sql = " UNION ALL ".join(
            f"SELECT '{name}', count(*) FROM \"{name}\"" for name in tracked) + ";"
        out, err, code = _owui_sqlite(db, sql)
        if code != 0:
            return {"error": f"row counts failed: {(err or out).strip()[-300:]}"}
        for line in out.splitlines():
            name, _, count = line.partition("|")
            if name in tracked and count.strip().isdigit():
                counts[name] = int(count)
    if set(counts) != set(tracked):
        return {"error": "row counts incomplete", "integrity": integrity}
    return {"integrity": integrity, "counts": counts, "missing_tables": missing}


def _owui_baseline_problem(state):
    """Why a DB state cannot serve as a trusted baseline, or ''."""
    if state.get("error"):
        return state["error"]
    if state.get("integrity") != "ok":
        return f"integrity_check returned {str(state.get('integrity'))[:200]!r}"
    if state.get("missing_tables"):
        return "required tables missing: " + ", ".join(state["missing_tables"])
    return ""


def _owui_count_regressions(baseline, counts):
    return [
        f"{name}: {before} -> {counts.get(name, 'missing')}"
        for name, before in sorted(baseline.items())
        if name not in counts or counts[name] < before
    ]


def _owui_container_state():
    out, _, code = run_capture_ok([
        "docker", "inspect", "--format",
        "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}"
        "|{{.RestartCount}}|{{.State.StartedAt}}",
        OPENWEBUI_SERVICE,
    ], timeout=30)
    parts = out.strip().split("|")
    if code != 0 or len(parts) != 4:
        return {}
    return {"status": parts[0], "health": parts[1], "restarts": parts[2],
            "started_at": parts[3]}


def _owui_http(path):
    """(HTTP status, body) from the loopback Open WebUI; status 0 when unreachable."""
    try:
        with urllib.request.urlopen(OPENWEBUI_URL + path, timeout=10) as response:
            return response.status, response.read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, ""
    except Exception:
        return 0, ""


def _owui_api_version():
    code, body = _owui_http("/api/version")
    if code != 200:
        return ""
    try:
        return str(json.loads(body).get("version") or "")
    except (ValueError, AttributeError):
        return ""


def _owui_wait_healthy(timeout_s=OPENWEBUI_HEALTH_TIMEOUT):
    """Wait for running+healthy; fail fast on exited/dead/unhealthy."""
    deadline = time.time() + timeout_s
    while True:
        state = _owui_container_state()
        if state.get("status") in ("exited", "dead") or state.get("health") == "unhealthy":
            return False, state
        if state.get("status") == "running" and state.get("health") == "healthy":
            return True, state
        if time.time() >= deadline:
            return False, state
        time.sleep(3)


def _owui_image_identity(ref):
    """(version label, repo digest, image id) of a local image, or ('', '', '')."""
    out, _, code = run_capture_ok([
        "docker", "image", "inspect", "--format",
        '{{index .Config.Labels "org.opencontainers.image.version"}}'
        "|{{json .RepoDigests}}|{{.Id}}",
        ref,
    ], timeout=60)
    parts = out.strip().split("|", 2)
    if code != 0 or len(parts) != 3:
        return "", "", ""
    try:
        digests = json.loads(parts[1]) or []
    except ValueError:
        digests = []
    digest = next((item for item in digests
                   if str(item).startswith(f"{OPENWEBUI_IMAGE}@sha256:")), "")
    return parts[0], digest, parts[2]


def _owui_verify(expected_version, baseline_counts, recovery, label):
    """Post-start gates.  Returns (failed gate or '', evidence)."""
    evidence = {}
    healthy, state = _owui_wait_healthy()
    evidence["container"] = state
    if not healthy:
        return f"container not healthy: {state or 'not found'}", evidence
    code, _ = _owui_http("/")
    evidence["http_status"] = code
    if code != 200:
        return f"HTTP {code} from {OPENWEBUI_URL}/", evidence
    version = _owui_api_version()
    evidence["api_version"] = version
    if version != expected_version:
        return f"/api/version reports {version!r}, expected {expected_version}", evidence
    # Scan only the startup window (container start -> healthy).  Later
    # runtime tracebacks (e.g. an unreachable image backend) are not
    # migration evidence and must not trigger a data rollback.
    healthy_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    logs_out, logs_err, logs_code = run_capture_ok(
        ["docker", "logs", "--since", state.get("started_at") or "10m",
         "--until", healthy_at, OPENWEBUI_SERVICE], timeout=60)
    if logs_code != 0:
        return "could not read container logs", evidence
    log_errors = [m.group(0).strip()[:200]
                  for m in _OWUI_LOG_ERROR.finditer(f"{logs_out}\n{logs_err}")]
    evidence["log_errors"] = log_errors[:5]
    if log_errors:
        return f"migration/startup errors in logs: {log_errors[0]}", evidence
    copy = recovery / f"webui-{label}.db"
    out, err, code = _owui_sqlite(
        OPENWEBUI_DATA / "webui.db", f".backup '{copy}'")
    if code != 0:
        return f"{label} SQLite backup failed: {(err or out).strip()[-200:]}", evidence
    db_state = _owui_db_state(copy)
    evidence["db"] = db_state
    if db_state.get("error") or db_state.get("integrity") != "ok":
        return (f"integrity_check failed: "
                f"{db_state.get('error') or db_state.get('integrity')}"), evidence
    regressions = _owui_count_regressions(baseline_counts, db_state.get("counts", {}))
    if regressions:
        return "core row counts reduced: " + "; ".join(regressions[:6]), evidence
    return "", evidence


def _owui_restart_unchanged(current_tag, baseline_counts, recovery):
    """Snapshot-gate failure: start the untouched old container and verify it."""
    _owui_compose("up", "-d")
    gate, evidence = _owui_verify(current_tag, baseline_counts or {}, recovery, "restart")
    return gate, evidence


def _owui_rollback(compose_text, current_tag, baseline_counts, recovery):
    """Restore the previous pin and the verified pre-update data, then re-verify."""
    steps = {}
    out, err, code = _owui_compose("stop", OPENWEBUI_SERVICE)
    steps["stop"] = code
    if code != 0:
        # Never move data out from under a running container.
        return (f"could not stop the target container: {(err or out).strip()[-300:]}",
                {"steps": steps})
    OPENWEBUI_COMPOSE.write_text(compose_text)
    # Same filesystem as the volume but outside _data, so the failed state
    # keeps its root ownership and never lands in the served directory.
    aside = OPENWEBUI_DATA.parent / (
        f"steward-failed-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}")
    out, err, code = _owui_sudo(
        "bash", "-c", _OWUI_RESTORE_SCRIPT, "owui-restore",
        str(OPENWEBUI_DATA), str(aside), str(recovery / "data-critical.tar.gz"))
    steps["data_restore"] = code
    if code != 0:
        return (f"data restore failed: {(err or out).strip()[-300:]}",
                {"steps": steps, "failed_state": str(aside)})
    steps["up"] = _owui_compose("up", "-d")[2]
    gate, evidence = _owui_verify(current_tag, baseline_counts, recovery, "rollback")
    evidence.update({"steps": steps, "failed_state": str(aside)})
    return gate, evidence


def _owui_prepare_recovery(current_tag, target_tag):
    OPENWEBUI_RECOVERY_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    recovery = OPENWEBUI_RECOVERY_ROOT / f"{stamp}-{current_tag}-to-{target_tag}"
    recovery.mkdir(mode=0o700)
    for source, name in ((OPENWEBUI_COMPOSE, "docker-compose.yml.pre"),
                         (OPENWEBUI_COMPOSE.parent / ".env", ".env.pre")):
        if source.exists():
            fd = os.open(recovery / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(source.read_bytes())
    return recovery


def _owui_free_space_problem(recovery_root):
    out, err, code = _owui_sudo(
        "du", "-sb", "--exclude=cache", str(OPENWEBUI_DATA), timeout=300)
    size = out.split()[0] if out.split() else ""
    if code != 0 or not size.isdigit():
        return f"could not size the data volume: {(err or out).strip()[-200:]}"
    stats = os.statvfs(recovery_root if recovery_root.exists() else HOME)
    free = stats.f_bavail * stats.f_frsize
    needed = 3 * int(size) + 4 * 1024 ** 3   # live/offline/archive copies + image
    if free < needed:
        return f"insufficient free space: {free} bytes free, {needed} needed"
    return ""


def _owui_transaction(current_tag, target_tag, compose_text, common):
    """Snapshot, pin, start, gate; roll back image and data on any failed gate."""
    image_old = f"{OPENWEBUI_IMAGE}:{current_tag}"
    image_new = f"{OPENWEBUI_IMAGE}:{target_tag}"
    compose_path = str(OPENWEBUI_COMPOSE).replace(str(HOME), "~", 1)

    def skip(reason, **extra):
        return {**common, **extra, "status": "skipped", "reason": reason}

    # Preflight: never touch a deployment that is not already healthy.
    state = _owui_container_state()
    if state.get("status") != "running" or state.get("health") != "healthy":
        return skip(f"preflight: open-webui is not running+healthy ({state or 'not found'})")
    running = _owui_api_version()
    if running != current_tag:
        return skip(f"preflight: /api/version {running!r} does not match pin {current_tag}")
    space = _owui_free_space_problem(OPENWEBUI_RECOVERY_ROOT)
    if space:
        return skip(f"preflight: {space}")

    # Preload and verify the exact image while the old container serves.
    out, err, code = run_capture_ok(["docker", "pull", image_new], timeout=900)
    if code != 0:
        return {**common, "status": "failed",
                "error": f"image pull failed: {(err or out).strip()[-300:]}"}
    label, digest, image_id = _owui_image_identity(image_new)
    if label != target_tag or not digest:
        return {**common, "status": "failed",
                "error": f"image identity mismatch: label={label!r} digest={digest!r}"}
    _, pre_digest, _ = _owui_image_identity(image_old)
    common.update({"target_digest": digest, "target_image_id": image_id,
                   "pre_digest": pre_digest})

    recovery = _owui_prepare_recovery(current_tag, target_tag)
    common["recovery_dir"] = str(recovery)
    live_db = OPENWEBUI_DATA / "webui.db"

    # Online snapshot = trusted baseline before any downtime.
    out, err, code = _owui_sqlite(live_db, f".backup '{recovery / 'webui-live.db'}'")
    online = (_owui_db_state(recovery / "webui-live.db") if code == 0
              else {"error": f"online backup failed: {(err or out).strip()[-200:]}"})
    problem = _owui_baseline_problem(online)
    if problem:
        return skip(f"baseline: {problem}")

    # Quiesce, then offline snapshot and non-cache archive.
    out, err, code = _owui_compose("stop", OPENWEBUI_SERVICE)
    if code != 0:
        gate, _ = _owui_restart_unchanged(current_tag, online["counts"], recovery)
        return {**common, "status": "failed",
                "error": f"stop failed: {(err or out).strip()[-200:]}"
                         + (f"; restart check: {gate}" if gate else "")}

    def snapshot_gate():
        out, err, code = _owui_sqlite(live_db, "PRAGMA wal_checkpoint(TRUNCATE);")
        if code != 0:
            return f"wal_checkpoint failed: {(err or out).strip()[-200:]}", None
        out, err, code = _owui_sqlite(live_db, f".backup '{recovery / 'webui-offline.db'}'")
        if code != 0:
            return f"offline backup failed: {(err or out).strip()[-200:]}", None
        offline = _owui_db_state(recovery / "webui-offline.db")
        problem = _owui_baseline_problem(offline)
        if problem:
            return f"offline snapshot: {problem}", None
        regressions = _owui_count_regressions(online["counts"], offline["counts"])
        if regressions:
            return "offline snapshot lost rows: " + "; ".join(regressions), None
        archive = recovery / "data-critical.tar.gz"
        out, err, code = _owui_sudo(
            "tar", "--acls", "--xattrs", "--xattrs-include=*", "--numeric-owner",
            "-czpf", str(archive), "--exclude=./cache", "--exclude=./*.bak",
            "-C", str(OPENWEBUI_DATA), ".")
        if code != 0:
            return f"data archive failed: {(err or out).strip()[-200:]}", None
        out, err, code = _owui_sudo("tar", "-tzf", str(archive))
        if code != 0 or "./webui.db" not in out.split():
            return "data archive listing does not contain ./webui.db", None
        verify_dir = recovery / "archive-verify"
        verify_dir.mkdir(mode=0o700)
        out, err, code = _owui_sudo(
            "tar", "-xzpf", str(archive), "-C", str(verify_dir), "./webui.db")
        if code != 0:
            return f"data archive extract failed: {(err or out).strip()[-200:]}", None
        extracted = _owui_db_state(verify_dir / "webui.db")
        problem = _owui_baseline_problem(extracted)
        if problem:
            return f"archived database: {problem}", None
        if extracted["counts"] != offline["counts"]:
            return "archived database counts differ from the offline snapshot", None
        _owui_sudo("chown", "-R", f"{os.getuid()}:{os.getgid()}", str(recovery), timeout=300)
        _owui_sudo("chmod", "-R", "go-rwx", str(recovery), timeout=300)
        return "", offline

    try:
        gate, offline = snapshot_gate()
    except Exception as exc:   # the container is stopped: never leave it down
        gate, offline = f"unexpected error: {exc}"[:300], None
    if gate:
        # Nothing changed yet: the pin and data are untouched.  A baseline that
        # cannot be collected is a skip, provided the old container is back.
        restart_gate, _ = _owui_restart_unchanged(current_tag, online["counts"], recovery)
        if not restart_gate:
            return skip(f"baseline: {gate}; old container restarted and verified",
                        recovery_dir=str(recovery))
        return {**common, "status": "failed",
                "error": f"snapshot gate failed before any change: {gate}; "
                         f"old container restart FAILED: {restart_gate}"}
    baseline = offline["counts"]
    common["counts_before"] = baseline

    # Change the managed pin (P9b commits it later) and start the target.
    # Any exception from here on is a failed gate, never a half-applied update.
    evidence = {}
    try:
        OPENWEBUI_COMPOSE.write_text(compose_text.replace(image_old, image_new, 1))
        out, err, code = _owui_compose("up", "-d")
        gate = (f"docker compose up -d failed: {(err or out).strip()[-200:]}"
                if code != 0 else "")
        if not gate:
            gate, evidence = _owui_verify(target_tag, baseline, recovery, "post")
    except Exception as exc:
        gate = f"unexpected error after pin change: {exc}"[:300]
    if not gate:
        result = {
            **common, "status": "ok", "post_version": target_tag,
            "local_mutation": True,
            "counts_after": evidence.get("db", {}).get("counts", {}),
            "revert": (
                f"sed -i 's|{image_new}|{image_old}|' {compose_path} && "
                f"docker compose -f {compose_path} up -d  # if the {target_tag} "
                f"schema must be undone too, restore {recovery}/data-critical.tar.gz "
                "per /update-openweb-ui step 7"),
        }
        return _owui_finalize(recovery, result)

    print(f"    open-webui gate failed ({gate}); rolling back to {current_tag}")
    rollback_gate, rollback = _owui_rollback(compose_text, current_tag, baseline, recovery)
    result = {
        **common,
        "status": "failed" if rollback_gate else "rolled_back",
        "post_version": current_tag if not rollback_gate else rollback.get("api_version", ""),
        "local_mutation": True,
        "failed_gate": gate,
        "error": (f"{target_tag} failed gate: {gate}; "
                  + (f"ROLLBACK FAILED: {rollback_gate}" if rollback_gate
                     else f"image pin and data restored to {current_tag} and verified")),
        "rollback": {k: v for k, v in rollback.items() if k != "db"},
        "revert": None if not rollback_gate else (
            f"restore {recovery}/docker-compose.yml.pre and "
            f"{recovery}/data-critical.tar.gz per /update-openweb-ui step 7"),
    }
    return _owui_finalize(recovery, result)


def _owui_finalize(recovery, result):
    """Keep root-written gate copies private to Carter and record the outcome."""
    _owui_sudo("chown", "-R", f"{os.getuid()}:{os.getgid()}", str(recovery), timeout=300)
    _owui_sudo("chmod", "-R", "go-rwx", str(recovery), timeout=300)
    write_json(recovery / "steward-update.json", result)
    return result


def _p1_openwebui(dry_run=False, *, release=None):
    """Guarded Open WebUI update to the latest stable release: snapshot, gate, roll back."""
    print("  [1f] open-webui guarded update")
    step = "openwebui_update"
    if not OPENWEBUI_COMPOSE.exists():
        return {"step": step, "status": "skipped", "revert": None,
                "reason": f"compose file not found: {OPENWEBUI_COMPOSE}"}

    compose_text = OPENWEBUI_COMPOSE.read_text()
    current_m = re.search(
        re.escape(OPENWEBUI_IMAGE) + r":([^\s\"'@]+)", compose_text)
    current_tag = current_m.group(1) if current_m else ""
    base = {"step": step, "pre_version": current_tag, "post_version": current_tag,
            "local_mutation": False, "revert": None}
    if not _semver(current_tag):
        return {**base, "status": "skipped",
                "reason": f"could not parse an exact semver pin: {current_tag!r}"}

    if release is None:
        try:
            req = urllib.request.Request(
                GH_API, headers={"Accept": "application/vnd.github+json"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                release = json.loads(resp.read().decode())
        except Exception as exc:
            return {**base, "status": "failed",
                    "error": f"GitHub release lookup failed: {exc}"}

    latest_tag = str(release.get("tag_name") or "").lstrip("v")
    common = {**base, "latest_tag": latest_tag,
              "release_url": release.get("html_url", ""),
              "published_at": release.get("published_at", "")}
    if release.get("draft") or release.get("prerelease"):
        return {**common, "status": "skipped",
                "reason": f"latest release is not stable: {latest_tag}"}
    if not _semver(latest_tag):
        return {**common, "status": "skipped",
                "reason": f"latest release tag is not numeric semver: {latest_tag!r}"}
    if _semver(latest_tag) <= _semver(current_tag):
        return {**common, "status": "skipped", "reason": "current"}

    reason = "latest stable release"
    if dry_run:
        return {**common, "status": "skipped",
                "reason": f"dry run: would update {current_tag} -> {latest_tag} ({reason})"}
    print(f"    updating open-webui {current_tag} -> {latest_tag} ({reason})")
    common["reason"] = reason
    return _owui_transaction(current_tag, latest_tag, compose_text, common)


def _p1_herdr_update():
    """Self-update herdr via `herdr update` (installs to ~/.local/bin/herdr).

    `herdr update` refuses to run inside a herdr session (env-var detection) —
    that only happens on a manual steward run launched from a herdr pane, so it
    is reported as skipped rather than failing P1. The nightly timer runs
    outside herdr (systemd user manager has no HERDR_* vars) and updates
    normally.
    """
    print("  [1g] herdr update")
    env = user_env()
    pre_ver = run_capture(["herdr", "--version"], env=env, timeout=30)
    stdout, stderr, code = run_capture_ok(["herdr", "update"], env=env, timeout=300)
    out = f"{stdout}\n{stderr}".strip()
    post_ver = run_capture(["herdr", "--version"], env=env, timeout=30)

    if "outside herdr" in out:
        return {"step": "herdr_update", "status": "skipped",
                "reason": "refused: run inside a herdr session (nightly timer runs outside)",
                "pre_version": pre_ver, "output_tail": out[-500:]}
    if post_ver and post_ver != pre_ver:
        return {"step": "herdr_update", "status": "ok",
                "pre_version": pre_ver, "post_version": post_ver,
                "output_tail": out[-500:]}
    if code == 0:
        return {"step": "herdr_update", "status": "skipped",
                "pre_version": pre_ver, "post_version": post_ver,
                "reason": "already current", "output_tail": out[-500:]}
    return {"step": "herdr_update", "status": "failed",
            "pre_version": pre_ver, "post_version": post_ver,
            "error": out[-500:] or f"exit {code}"}


_CI_OK_CONCLUSIONS = frozenset({"success", "neutral", "skipped"})
# Seconds between TERM and a KILL from `timeout`.  deploy.sh rolls back in its
# EXIT trap, so it must get TERM first and ample time before any hard kill.
APP_DEPLOY_KILL_AFTER = 120


def _ci_green(github, sha):
    """(green, detail): check runs plus commit statuses for one exact commit.

    Green means at least one check exists and every one is completed with a
    success/neutral/skipped conclusion (statuses: state success).
    """
    env = user_env()
    out, err, code = run_capture_ok(
        ["gh", "api", f"repos/{github}/commits/{sha}/check-runs?per_page=100"],
        env=env, timeout=60)
    if code != 0:
        return False, f"check-runs lookup failed: {(err or out).strip()[-200:]}"
    s_out, s_err, s_code = run_capture_ok(
        ["gh", "api", f"repos/{github}/commits/{sha}/status?per_page=100"],
        env=env, timeout=60)
    if s_code != 0:
        return False, f"commit status lookup failed: {(s_err or s_out).strip()[-200:]}"
    try:
        runs_payload, status_payload = json.loads(out), json.loads(s_out)
        runs = list(runs_payload.get("check_runs") or [])
        statuses = list(status_payload.get("statuses") or [])
        total_runs = int(runs_payload.get("total_count", len(runs)))
    except (ValueError, AttributeError, TypeError) as exc:
        return False, f"unparseable CI payload: {exc}"
    if total_runs > len(runs):
        return False, f"{total_runs} check runs exceed one page; cannot verify all"
    if not runs and not statuses:
        return False, "no CI checks reported"
    problems = [
        f"{run.get('name')}: {run.get('status')}/{run.get('conclusion')}"
        for run in runs
        if run.get("status") != "completed" or run.get("conclusion") not in _CI_OK_CONCLUSIONS
    ] + [
        f"{status.get('context')}: {status.get('state')}"
        for status in statuses if status.get("state") != "success"
    ]
    if problems:
        return False, "; ".join(problems[:6])
    return True, f"{len(runs)} check run(s), {len(statuses)} status(es) green"


def _p1_app_deploy(service, spec, dry_run=False):
    """Deploy one DEPLOY_REGISTRY service to CI-green origin/main.

    The service's deploy script owns the transaction (fast-forward production,
    build, health-check, roll back on failure); this step gates it and
    verifies the deployed commit afterwards: production HEAD, or the commit
    ``version_cmd`` reports for services deployed as a built artifact.
    """
    print(f"  [1k] app deploy: {service}")
    env = user_env()
    repo = Path(spec["repo"])
    version_cmd = spec.get("version_cmd")
    production = " ".join(version_cmd) if version_cmd else Path(spec["production"])
    limit = int(spec["timeout"])
    row = {"step": "app_deploy", "service": service, "pre_version": "",
           "post_version": "", "local_mutation": False, "revert": None}

    def git(path, *args, timeout=60):
        out, err, code = run_capture_ok(
            ["git", "-C", str(path), *args], env=env, timeout=timeout)
        return out.strip(), (err or out).strip()[-200:], code

    def skip(reason):
        return {**row, "status": "skipped", "reason": reason}

    def deployed():
        if not version_cmd:
            return git(production, "rev-parse", "HEAD")
        out, err, code = run_capture_ok(list(version_cmd), env=env, timeout=30)
        out = out.strip()
        if code == 0 and not re.fullmatch(r"[0-9a-f]{40}", out):
            return out, f"not a commit SHA: {out[:80]!r}", 1
        return out, (err or out).strip()[-200:], code

    pre, err, code = deployed()
    if code != 0 or not pre:
        return skip(f"cannot read production HEAD in {production}: {err}")
    row.update({"pre_version": pre, "post_version": pre})
    _, err, code = git(repo, "fetch", "--prune", "origin", "main", timeout=120)
    if code != 0:
        return skip(f"git fetch origin main failed in {repo}: {err}")
    target, err, code = git(repo, "rev-parse", "--verify", "origin/main^{commit}")
    if code != 0 or not target:
        return skip(f"cannot resolve origin/main in {repo}: {err}")
    row["target_version"] = target
    if pre == target:
        return skip("current")
    branch, _, code = git(repo, "symbolic-ref", "--short", "HEAD")
    if code != 0 or branch != "main":
        return skip(f"canonical checkout {repo} is on {branch or 'a detached HEAD'}, not main")
    dirty, err, code = git(repo, "status", "--porcelain")
    if code != 0 or dirty:
        return skip(f"canonical checkout {repo} has uncommitted changes"
                    if code == 0 else f"git status failed in {repo}: {err}")
    local, _, _ = git(repo, "rev-parse", "HEAD")
    if git(repo, "merge-base", "--is-ancestor", local, target)[2] != 0:
        return skip(f"canonical main {local[:7]} cannot fast-forward to origin/main {target[:7]}")
    if git(repo, "merge-base", "--is-ancestor", pre, target)[2] != 0:
        return skip(f"production HEAD {pre[:7]} is not an ancestor of origin/main {target[:7]}")
    green, detail = _ci_green(spec["github"], target)
    row["ci"] = detail
    if not green:
        return skip(f"origin/main {target[:7]} is not CI-green: {detail}")
    if dry_run:
        return skip(f"dry run: would deploy {pre[:7]} -> {target[:7]}")
    if local != target:
        _, err, code = git(repo, "merge", "--ff-only", "origin/main", timeout=120)
        if code != 0:
            return skip(f"fast-forward of canonical main failed: {err}")

    # TERM first so deploy.sh's EXIT trap can roll back; KILL only if it
    # ignores TERM for APP_DEPLOY_KILL_AFTER seconds.  The Python timeout sits
    # beyond both so it never pre-empts `timeout` with its own SIGKILL.
    command = ["timeout", "--signal=TERM", f"--kill-after={APP_DEPLOY_KILL_AFTER}",
               str(limit), *spec["deploy"]]
    out, err, code = run_capture_ok(
        command, cwd=str(repo), env=env, timeout=limit + APP_DEPLOY_KILL_AFTER + 60)
    row["output_tail"] = f"{out}\n{err}".strip()[-800:]
    post, _, _ = deployed()
    row.update({"post_version": post, "local_mutation": True})
    if code == 0:
        if post != target:
            return {**row, "status": "failed",
                    "error": f"deploy exited 0 but production HEAD is {post[:7] or '?'}, "
                             f"expected origin/main {target[:7]}"}
        repo_arg = str(repo).replace(str(HOME), "~", 1)
        deploy_cmd = shlex.join(spec["deploy"]).replace(str(HOME), "~")
        return {**row, "status": "ok", "reason": f"CI-green origin/main ({detail})",
                "revert": (
                    f"git -C {repo_arg} read-tree -u --reset {pre} && "
                    f"git -C {repo_arg} commit -m 'Revert {service} to {pre[:12]}' && "
                    f"git -C {repo_arg} push origin main && {deploy_cmd}"
                    "  # deploy.sh only fast-forwards to origin/main, so the previous "
                    "tree is re-deployed as a new commit")}
    if code == 124:
        cause = f"deploy timed out after {limit}s (sent TERM)"
    elif code in (137, -9):
        cause = f"deploy ignored TERM and was killed after {limit + APP_DEPLOY_KILL_AFTER}s"
    elif code == -1:
        cause = f"deploy could not run or exceeded the outer timeout: {err.strip()[-200:]}"
    else:
        cause = f"deploy exited {code}"
    if post == pre:
        return {**row, "status": "rolled_back",
                "error": f"{cause}; production verified back at {pre[:7]}"}
    return {**row, "status": "failed",
            "error": f"{cause}; production HEAD is {post[:7] or 'unreadable'}, "
                     f"not the previous {pre[:7]}: rollback NOT verified"}


_DEPENDABOT_BUMP = re.compile(
    r"\b[Bb]ump (?P<dep>\S+) from (?P<old>\S+) to (?P<new>\S+?)\.?(?:\s|$)")
# A version, not a commit SHA or digest: optional v, digits, then . - + or end.
_DEPENDABOT_VERSION = re.compile(r"[vV]?(\d+)(?:[.+-]\S*)?")
_DEPENDABOT_PR_FIELDS = (
    "number,title,url,headRefName,baseRefName,isDraft,mergeable,statusCheckRollup")


def _dependabot_bump(title):
    """(dependency, old, new, major) from a "Bump X from A to B" title, or None.

    Major means the leading (semver-major) version component changed.
    """
    match = _DEPENDABOT_BUMP.search(str(title or ""))
    if not match:
        return None
    parts = []
    for value in (match["old"], match["new"]):
        version = _DEPENDABOT_VERSION.fullmatch(value.strip("`"))
        if not version:
            return None
        parts.append(int(version[1]))
    return match["dep"], match["old"], match["new"], parts[0] != parts[1]


def _dependabot_checks_green(rollup):
    """(green, detail) for a PR statusCheckRollup; no checks is not green."""
    if not rollup:
        return False, "no checks reported"
    bad = []
    for check in rollup:
        if not isinstance(check, dict):
            bad.append("unreadable check")
        elif check.get("__typename") == "StatusContext" or "state" in check:
            if check.get("state") != "SUCCESS":
                bad.append(f"{check.get('context')}: {check.get('state')}")
        elif (check.get("status") != "COMPLETED"
              or str(check.get("conclusion") or "").lower() not in _CI_OK_CONCLUSIONS):
            bad.append(f"{check.get('name')}: {check.get('status')}/{check.get('conclusion')}")
    if bad:
        return False, "; ".join(bad[:4])
    return True, f"{len(rollup)} check(s) green"


def _p1_dependabot_merge(dry_run=False, *, ctx=None):
    """Queue green, non-major Dependabot PRs in auto-merge candidate repos.

    dependabot/bundler/* PRs in the webhook's repos and every hyperliquid PR
    are owned elsewhere and never touched.  Everything else needs green
    checks, a mergeable branch, a non-major version bump and the repository's
    live auto_merge_eligibility(); GitHub then merges it (rebase, else squash,
    else merge commit, per the repository settings) once its required checks
    pass.  Never --admin.
    """
    from .routing import RouteContext, auto_merge_eligibility, repo_merge_method

    print("  [1j] dependabot auto-merge")
    ctx = ctx or RouteContext(dry_run=dry_run)
    merged, skipped, needs_carter, errors = [], [], [], []
    for repo in sorted(AUTO_MERGE_CANDIDATES):
        nwo = f"{GITHUB_OWNER}/{repo}"
        if repo in DEPENDABOT_AGENT_OWNED_REPOS:
            skipped.append({"repo": repo, "reason": "Dependabot PRs are owned by its own agent"})
            continue
        cp = ctx.gh(["pr", "list", "--repo", nwo, "--author", "app/dependabot",
                     "--state", "open", "--limit", "100", "--json", _DEPENDABOT_PR_FIELDS], None)
        try:
            prs = json.loads(cp.stdout or "null") if cp.returncode == 0 else None
        except ValueError:
            prs = None
        if not isinstance(prs, list):
            errors.append(f"{repo}: could not list Dependabot PRs: "
                          f"{(cp.stderr or cp.stdout or '').strip()[-200:]}")
            continue
        eligibility, method = {}, None
        for pr in prs:
            if not isinstance(pr, dict):
                continue
            item = {"repo": repo, "number": pr.get("number"),
                    "title": str(pr.get("title") or "")[:200], "url": pr.get("url", "")}
            branch = str(pr.get("headRefName") or "")

            def skip(reason):
                skipped.append({**item, "reason": reason})

            if repo in DEPENDABOT_WEBHOOK_BUNDLER_REPOS and branch.startswith("dependabot/bundler/"):
                skip("bundler update owned by the dependabot-webhook")
                continue
            if pr.get("isDraft"):
                skip("draft")
                continue
            bump = _dependabot_bump(pr.get("title"))
            if bump is None:
                skip("title is not a single 'Bump X from A to B' update")
                continue
            if bump[3]:
                needs_carter.append({**item, "reason": f"major bump {bump[1]} -> {bump[2]}"})
                continue
            green, detail = _dependabot_checks_green(pr.get("statusCheckRollup"))
            if not green:
                skip(f"checks not green: {detail}")
                continue
            if pr.get("mergeable") != "MERGEABLE":
                skip(f"not mergeable ({pr.get('mergeable') or 'unknown'})")
                continue
            base = str(pr.get("baseRefName") or "")
            if base not in eligibility:
                eligibility[base] = auto_merge_eligibility(ctx, repo, nwo, base)
            eligible, reason = eligibility[base]
            if not eligible:
                skip(f"not eligible for auto-merge: {reason}")
                continue
            if method is None:
                method = repo_merge_method(ctx, nwo)
            flag, why = method
            if flag is None:
                skip(why)
                continue
            if dry_run:
                skip(f"dry run: would request auto-merge ({flag})")
                continue
            result = ctx.gh(["pr", "merge", str(pr.get("number")), "--repo", nwo,
                             "--auto", flag], None)
            if result.returncode != 0:
                errors.append(f"{repo}#{pr.get('number')}: merge request failed: "
                              f"{(result.stderr or result.stdout or '').strip()[-200:]}")
                continue
            merged.append({**item, "reason": f"{bump[1]} -> {bump[2]}; {detail}"})
    row = {"step": "dependabot_merge", "merged": merged, "skipped": skipped,
           "needs_carter": needs_carter, "local_mutation": False, "revert": None}
    if merged:
        row["revert"] = ("before GitHub merges: gh pr merge --disable-auto <url>; after: "
                         "revert the merged commit on the default branch")
    if errors:
        return {**row, "status": "warning", "error": "; ".join(errors[:6])}
    return {**row, "status": "ok" if merged else "skipped",
            "reason": f"{len(merged)} merged, {len(needs_carter)} major for Carter, "
                      f"{len(skipped)} skipped"}


def _p1_deploy_step_ok(step):
    """True when a P1 step actually mutated state."""
    if step.get("local_mutation") is False:
        return False
    name = step.get("step", "")
    status = step.get("status", "")
    if name.startswith("auto_") and status == "ok":
        return True
    if name == "freshrss" and status == "bumped":
        return True
    if name in (
        "herdr_update", "omp_update", "searxng", "openwebui_update",
        "app_deploy", "worker_omp_refresh",
    ) and status == "ok":
        return True
    return False


_P1_RETRYABLE_STATUSES = _P1_FAILURE_STATUSES
_P1_DEGRADED_STATUSES = frozenset({"reverted", "rolled_back", "warning", "degraded"})


def _p1_status_packets(value, path=""):
    """Yield bounded status packets, including nested remote substeps."""
    if isinstance(value, dict):
        status = str(value.get("status") or "").strip().lower()
        if status in _P1_RETRYABLE_STATUSES | _P1_DEGRADED_STATUSES:
            yield path, value
        for key in ("steps", "substeps", "checks"):
            children = value.get(key)
            if isinstance(children, list):
                for index, child in enumerate(children):
                    child_path = f"{path}.{key}[{index}]" if path else f"{key}[{index}]"
                    yield from _p1_status_packets(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            child_path = f"{path}[{index}]" if path else f"[{index}]"
            yield from _p1_status_packets(child, child_path)


def _p1_packet_detail(path, packet):
    detail = packet.get("error") or packet.get("reason") or packet.get("step")
    if not detail:
        detail = packet.get("status") or "unknown failure"
    label = f"{path}: " if path else ""
    return f"{label}{str(detail)[:400]}"


def _finish_p1(run_dir, data, progress=None):
    """Persist P1's durable outcome while retaining every step packet."""
    packets = list(_p1_status_packets(data.get("steps", [])))
    retryable = [
        _p1_packet_detail(path, packet)
        for path, packet in packets
        if str(packet.get("status") or "").lower() in _P1_RETRYABLE_STATUSES
    ]
    degraded = [
        _p1_packet_detail(path, packet)
        for path, packet in packets
        if str(packet.get("status") or "").lower() in _P1_DEGRADED_STATUSES
    ]
    if retryable:
        data.update({
            "phase_status": "failed",
            "phase_failed": True,
            "reason": "retryable P1 step failure: " + "; ".join(retryable[:8]),
        })
    elif degraded:
        data.update({
            "phase_status": "degraded",
            "reason": "P1 completed with degraded step(s): " + "; ".join(degraded[:8]),
        })
    else:
        data.setdefault("phase_status", "succeeded")
    if progress is None:
        write_json(run_dir / "01-applied.json", data)
    else:
        progress(data)
    return data


def _release_time(value):
    """Parse an upstream UTC timestamp into an aware datetime."""
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _release_is_mature(value, now=None):
    """True once an upstream release has existed for the safety window."""
    now = now or datetime.now(timezone.utc)
    return now - _release_time(value) >= timedelta(days=UPDATE_MIN_AGE_DAYS)


def _searxng_tag_date(tag):
    match = re.fullmatch(r"(\d{4})\.(\d{1,2})\.(\d{1,2})-[0-9a-f]+", tag or "")
    return tuple(int(part) for part in match.groups()) if match else None


def _select_mature_searxng_tag(tags, current_tag, now=None):
    """Newest immutable SearXNG tag old enough to deploy, never a downgrade."""
    current_item = next((item for item in tags if item.get("name") == current_tag), None)
    current_time = _release_time(current_item["last_updated"]) if current_item else None
    current_date = _searxng_tag_date(current_tag)
    candidates = []
    for item in tags:
        name = item.get("name", "")
        published = item.get("last_updated", "")
        digest = item.get("digest", "")
        tag_date = _searxng_tag_date(name)
        if not tag_date or not digest or not published:
            continue
        try:
            published_time = _release_time(published)
        except ValueError:
            continue
        if not _release_is_mature(published, now=now):
            continue
        if current_time and published_time <= current_time:
            continue
        if not current_time and current_date and tag_date <= current_date:
            continue
        candidates.append((published_time, item))
    return max(candidates, key=lambda pair: pair[0])[1] if candidates else None


def _select_mature_llama_release(releases, current_tag, now=None):
    """Newest non-draft llama.cpp release old enough to deploy."""
    match = re.fullmatch(r"b(\d+)", current_tag or "")
    if not match:
        return None
    current_build = int(match.group(1))
    candidates = []
    for release in releases:
        tag = release.get("tag_name", "")
        published = release.get("published_at", "")
        tag_match = re.fullmatch(r"b(\d+)", tag)
        if (release.get("draft") or release.get("prerelease") or not tag_match
                or not published):
            continue
        try:
            mature = _release_is_mature(published, now=now)
        except ValueError:
            continue
        build = int(tag_match.group(1))
        if mature and build > current_build:
            candidates.append((build, release))
    return max(candidates, key=lambda pair: pair[0])[1] if candidates else None


def _wait_searxng_healthy(timeout_s=45):
    """Require SearXNG's JSON search API, not merely an open TCP port."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            req = urllib.request.Request(ENDPOINTS["searxng"])
            with urllib.request.urlopen(req, timeout=8) as response:
                payload = json.loads(response.read().decode())
            if isinstance(payload, dict) and isinstance(payload.get("results"), list):
                return True
        except Exception:
            pass
        time.sleep(2)
    return False


def _p1_searxng_update(tags=None, now=None):
    """Advance the immutable image pin after seven days; roll back on failure."""
    print("  [1h] searxng mature-image update")
    compose = HOME / "searxng" / "docker-compose.yml"
    if not compose.exists():
        return {"step": "searxng", "status": "skipped",
                "reason": f"compose file not found: {compose}"}

    compose_text = compose.read_text()
    image_match = re.search(
        r"docker\.io/searxng/searxng@sha256:[0-9a-f]{64}", compose_text)
    if not image_match:
        return {"step": "searxng", "status": "failed",
                "reason": "could not parse immutable image pin"}
    old_ref = image_match.group(0)
    current_tag = run_capture([
        "docker", "inspect", "searxng", "--format",
        '{{index .Config.Labels "org.opencontainers.image.version"}}',
    ], timeout=30)
    if not _searxng_tag_date(current_tag):
        return {"step": "searxng", "status": "failed", "image_ref": old_ref,
                "reason": f"could not parse running version label: {current_tag!r}"}

    if tags is None:
        try:
            req = urllib.request.Request(
                SEARXNG_TAGS_API, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=20) as response:
                tags = json.loads(response.read().decode()).get("results", [])
        except Exception as exc:
            return {"step": "searxng", "status": "error",
                    "current_tag": current_tag,
                    "reason": f"Docker Hub unreachable: {exc}"}

    target = _select_mature_searxng_tag(tags, current_tag, now=now)
    if not target:
        return {"step": "searxng", "status": "skipped",
                "current_tag": current_tag,
                "reason": f"no newer release is {UPDATE_MIN_AGE_DAYS} days old"}

    target_tag = target["name"]
    target_ref = f"docker.io/searxng/searxng@{target['digest']}"
    if target_ref == old_ref:
        return {"step": "searxng", "status": "skipped",
                "current_tag": current_tag, "target_tag": target_tag,
                "reason": "eligible release already pinned"}

    new_text = compose_text.replace(old_ref, target_ref, 1)
    print(f"    bumping searxng: {current_tag} -> {target_tag}")
    try:
        run(["docker", "pull", target_ref], capture_output=True, text=True, timeout=300)
        compose.write_text(new_text)
        run(["docker", "compose", "-f", str(compose), "up", "-d"],
            cwd=compose.parent, capture_output=True, text=True, timeout=180)
        if not _wait_searxng_healthy():
            raise RuntimeError("JSON search health check timed out")
        return {"step": "searxng", "status": "ok",
                "pre_version": current_tag, "post_version": target_tag,
                "pre_image": old_ref, "post_image": target_ref,
                "release_age_days": (
                    (now or datetime.now(timezone.utc))
                    - _release_time(target["last_updated"])
                ).days}
    except Exception as exc:
        compose.write_text(compose_text)
        rollback_error = ""
        try:
            run(["docker", "compose", "-f", str(compose), "up", "-d"],
                cwd=compose.parent, capture_output=True, text=True, timeout=180)
            if not _wait_searxng_healthy():
                raise RuntimeError("restored pin failed JSON search health check")
        except Exception as rollback_exc:
            rollback_error = str(rollback_exc)
        return {"step": "searxng",
                "status": "failed" if rollback_error else "reverted",
                "pre_version": current_tag, "target_version": target_tag,
                "reverted_to": old_ref, "error": str(exc),
                "rollback_error": rollback_error}

def _p1_llama_cpp_update(releases=None, now=None):
    """Build a seven-day-old llama.cpp release on Linux and atomically deploy it."""
    print("  [1i] llama.cpp mature-release update")
    try:
        current_path = run_capture(
            _rig_ssh_command(["readlink", "-f", "/usr/local/bin/llama-server"]),
            timeout=20,
        )
    except Exception as exc:
        return {
            "step": "llama_cpp",
            "status": "skipped",
            "reason": "gaming rig Linux unavailable or SSH probe failed",
            "error": str(exc)[:300],
        }
    current_match = re.search(r"/opt/llama\.cpp/(b\d+)/bin/llama-server$", current_path)
    if not current_match:
        return {"step": "llama_cpp", "status": "skipped",
                "reason": "gaming rig Linux unavailable or current build path unreadable",
                "current_path": current_path}
    current_tag = current_match.group(1)

    if releases is None:
        try:
            req = urllib.request.Request(
                LLAMA_CPP_RELEASES_API,
                headers={"Accept": "application/vnd.github+json"})
            with urllib.request.urlopen(req, timeout=20) as response:
                releases = json.loads(response.read().decode())
        except Exception as exc:
            return {"step": "llama_cpp", "status": "error",
                    "current_tag": current_tag,
                    "reason": f"GitHub API unreachable: {exc}"}

    target = _select_mature_llama_release(releases, current_tag, now=now)
    if not target:
        return {"step": "llama_cpp", "status": "skipped",
                "current_tag": current_tag,
                "reason": f"no newer release is {UPDATE_MIN_AGE_DAYS} days old"}
    target_tag = target["tag_name"]
    if not LLAMA_CPP_UPDATE_SCRIPT.exists():
        return {"step": "llama_cpp", "status": "failed",
                "current_tag": current_tag, "target_tag": target_tag,
                "reason": f"update helper missing: {LLAMA_CPP_UPDATE_SCRIPT}"}

    stdout, stderr, code = run_capture_ok(
        _rig_ssh_command(["bash", "-s", "--", target_tag]),
        input=LLAMA_CPP_UPDATE_SCRIPT.read_text(),
        timeout=1800,
    )
    detail = f"{stdout}\n{stderr}".strip()
    common = {
        "step": "llama_cpp",
        "pre_version": current_tag,
        "target_version": target_tag,
        "release_age_days": (
            (now or datetime.now(timezone.utc))
            - _release_time(target["published_at"])
        ).days,
        "output_tail": detail[-1000:],
    }
    if code == 0 and f"UPDATE_OK {target_tag}" in stdout:
        return {**common, "status": "ok", "post_version": target_tag}
    if "ROLLBACK_OK" in detail:
        return {**common, "status": "reverted", "reverted_to": current_tag,
                "error": f"deployment failed with exit {code}"}
    return {**common, "status": "failed",
            "error": f"deployment or rollback failed with exit {code}"}


# Bun global package: only the rig's single omp install uses it
# (_rig_omp_update). The ThinkPad runs a standalone binary.
_OMP_PKG = "@oh-my-pi/pi-coding-agent"
WORKER_OMP = Path("/usr/local/libexec/steward-worker/omp")
OMP_ROLLBACK_KEEP = 2


def _omp_canonical():
    """The one supported ThinkPad OMP install: the standalone ~/.bun/bin/omp.

    It is a single self-contained binary (P7b worker provisioning copies it as
    one file); ~/.local/bin/omp is only a symlink to it.  Never resolve
    ``omp`` through PATH for mutations: on 2026-09-23 that updated a stray copy
    while the rollback targeted a different install.
    """
    return HOME / ".bun" / "bin" / "omp"


def _omp_rollback_dir():
    return HOME / ".local" / "state" / "omp-rollback"


def _omp_snapshot(omp, pre_tag, rollback_dir):
    """Copy the pre-update binary to rollback_dir/omp-<version>; keep the last 2."""
    rollback_dir.mkdir(parents=True, exist_ok=True)
    safe_tag = re.sub(r"[^A-Za-z0-9._-]", "_", pre_tag)
    dest = rollback_dir / f"omp-{safe_tag}"
    tmp = rollback_dir / f".omp-{safe_tag}.tmp"
    shutil.copy2(os.path.realpath(omp), tmp)
    os.replace(tmp, dest)
    os.utime(dest)  # newest snapshot sorts last for pruning
    snapshots = sorted(
        (p for p in rollback_dir.glob("omp-*") if p.is_file()),
        key=lambda p: p.stat().st_mtime,
    )
    for old in snapshots[:-OMP_ROLLBACK_KEEP]:
        if old != dest:
            old.unlink()
    return dest


def _omp_restore(snapshot, omp):
    """Atomically put the snapshot back in place of the canonical binary."""
    tmp = Path(omp).with_name(".omp.rollback.tmp")
    shutil.copy2(snapshot, tmp)
    os.chmod(tmp, 0o755)
    os.replace(tmp, omp)


def _omp_smoke_ok(omp, env):
    """Cheap deterministic binary check: `omp -p` with empty input.

    An empty headless prompt has nothing to run, so it exits 0 in ~1s without
    any LLM call — it only fails on a broken/partial install, not on API
    outages (which must not trigger a revert).
    """
    _, _, code = run_capture_ok([str(omp), "-p"], env=env, timeout=60, input="")
    return code == 0


def _omp_entry_points(env):
    """Every way this host starts omp, with its realpath and version.

    Returns (entries, problem); ``problem`` is '' only when all entry points
    resolve to the same file reporting the same version.
    """
    candidates = [("canonical", str(_omp_canonical()))]
    local = HOME / ".local" / "bin" / "omp"
    if local.exists() or local.is_symlink():
        candidates.append(("local_bin", str(local)))
    on_path = shutil.which("omp", path=env.get("PATH", ""))
    candidates.append(("path", on_path or ""))
    versions = {}
    entries = []
    for label, path in candidates:
        real = os.path.realpath(path) if path else ""
        if real and real not in versions:
            versions[real] = run_capture([real, "--version"], env=env, timeout=30)
        entries.append({"entry": label, "path": path, "realpath": real,
                        "version": versions.get(real, "")})
    problems = [f"{item['entry']} {item['path'] or '(omp not on PATH)'} "
                "did not report a version"
                for item in entries if not item["version"]]
    if len({item["realpath"] for item in entries}) > 1:
        problems.append("omp entry points resolve to different files: " + ", ".join(
            f"{item['entry']}={item['realpath'] or '-'}" for item in entries))
    if len({item["version"] for item in entries}) > 1:
        problems.append("omp entry points report different versions: " + ", ".join(
            f"{item['entry']}={item['version'] or '-'}" for item in entries))
    return entries, "; ".join(problems)


def _omp_stale_processes(canonical, proc_root=Path("/proc")):
    """Running omp processes not executing the current canonical binary.

    Report only; sessions are Carter's and are never killed.  The sandboxed
    worker binary is a separate install by design and is excluded.
    """
    canonical_real = os.path.realpath(canonical)
    pids = []
    try:
        entries = list(proc_root.iterdir())
    except OSError:
        return {"count": 0, "pids": [], "error": f"cannot list {proc_root}"}
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            target = os.readlink(entry / "exe")
        except OSError:
            continue   # exited, kernel thread, or another user's process
        deleted = target.endswith(" (deleted)")
        path = target[:-len(" (deleted)")] if deleted else target
        if os.path.basename(path) != "omp" or path == str(WORKER_OMP):
            continue
        if deleted or path != canonical_real:
            pids.append(int(entry.name))
    pids.sort()
    return {"count": len(pids), "pids": pids[:50]}


def _omp_update_transaction(omp, env):
    """Snapshot binary -> `omp update` -> smoke -> atomic restore on breakage."""
    base = {"step": "omp_update", "binary": str(omp)}
    pre_ver = run_capture([str(omp), "--version"], env=env, timeout=30)
    pre_tag = pre_ver.replace("omp/", "").strip() if pre_ver else ""
    if not pre_tag:
        return {**base, "status": "failed",
                "pre_version": pre_ver, "post_version": pre_ver,
                "error": f"could not snapshot the pre-update version of {omp}"}
    try:
        snapshot = _omp_snapshot(omp, pre_tag, _omp_rollback_dir())
    except OSError as error:
        return {**base, "status": "failed",
                "pre_version": pre_ver, "post_version": pre_ver,
                "error": f"could not snapshot {omp} before updating: {error}"}
    revert = f"install -m 755 {shlex.quote(str(snapshot))} {shlex.quote(str(omp))}"

    stdout, stderr, code = run_capture_ok([str(omp), "update"], env=env, timeout=600)
    out = f"{stdout}\n{stderr}".strip()
    post_ver = run_capture([str(omp), "--version"], env=env, timeout=30)
    works = _omp_smoke_ok(omp, env)

    if works and post_ver and post_ver != pre_ver:
        return {**base, "status": "ok",
                "pre_version": pre_ver, "post_version": post_ver,
                "snapshot": str(snapshot), "revert": revert,
                "output_tail": out[-500:]}
    if works and code == 0:
        return {**base, "status": "skipped",
                "pre_version": pre_ver, "post_version": post_ver,
                "reason": "already current", "output_tail": out[-500:]}

    # install failed or the new binary is broken — restore the snapshot
    msg = f"post-update check failed; reverting to {pre_tag}" if not works \
        else (out[-500:] or f"exit {code}")
    try:
        _omp_restore(snapshot, omp)
        restore_detail = f"restored {snapshot}"
    except OSError as error:
        restore_detail = f"restore from {snapshot} failed: {error}"
    rev_ver = run_capture([str(omp), "--version"], env=env, timeout=30)
    reverted = bool(rev_ver) and rev_ver == pre_ver and _omp_smoke_ok(omp, env)
    return {**base,
            "status": "reverted" if reverted else "failed",
            "pre_version": pre_ver, "post_version": post_ver,
            "reverted_to": rev_ver, "error": msg, "snapshot": str(snapshot),
            "revert_detail": restore_detail}


def _p1_omp_update(proc_root=Path("/proc")):
    """Self-update the canonical omp; verify every entry point; revert on breakage.

    omp is the steward's own engine (P5/P7/P7b/P9b spawn `omp -p`), so a bad
    `omp update` is caught here deterministically rather than surfacing later
    as failed agent phases with no working fallback.  Version, update, smoke,
    and rollback all use the absolute canonical binary.
    """
    print("  [1i] omp update")
    env = user_env()
    omp = _omp_canonical()
    if not os.access(omp, os.X_OK):
        result = {"step": "omp_update", "status": "failed", "binary": str(omp),
                  "error": f"canonical omp {omp} is missing or not executable"}
    else:
        result = _omp_update_transaction(omp, env)
        if result["status"] in ("ok", "skipped", "reverted"):
            entries, problem = _omp_entry_points(env)
            result["entry_points"] = entries
            if problem:
                previous = result.get("error")
                result["status"] = "failed"
                result["error"] = problem + (f"; {previous}" if previous else "")
    result["stale_processes"] = _omp_stale_processes(omp, proc_root)
    return result


def _p1_worker_omp_refresh(omp_result):
    """Reinstall the sandboxed P7b worker's OMP after a local version change."""
    step = "worker_omp_refresh"
    local_pre = str(omp_result.get("pre_version") or "")
    local_post = str(omp_result.get("post_version") or "")
    if omp_result.get("status") != "ok" or not local_post or local_post == local_pre:
        return {"step": step, "status": "skipped",
                "reason": "omp_update did not change the local version this run"}
    print("  [1j] steward worker omp refresh")

    def worker_version():
        version = run_capture([str(WORKER_OMP), "--version"], timeout=30)
        return version or run_capture(
            ["sudo", "-n", str(WORKER_OMP), "--version"], timeout=30)

    pre = worker_version()
    provision = HOME / "system-config" / "steward-worker-provision.sh"
    stdout, stderr, code = run_capture_ok(
        ["sudo", "-n", "bash", str(provision), "--omp-only"], timeout=600)
    out = f"{stdout}\n{stderr}".strip()
    post = worker_version()
    row = {"step": step, "pre_version": pre, "post_version": post,
           "expected_version": local_post, "output_tail": out[-500:]}
    if code != 0:
        return {**row, "status": "failed",
                "error": f"--omp-only provisioning exited {code}: {out[-300:]}"}
    if post != local_post:
        return {**row, "status": "failed",
                "error": f"worker omp reports {post or 'nothing'}, local is {local_post}"}
    return {**row, "status": "ok"}


def _rig_ssh_command(remote_args):
    """Build an injection-safe SSH argv for the pinned Linux rig alias.

    The host key is intentionally checked by the user's SSH configuration.
    ``BatchMode`` makes unknown/mismatched keys fail closed instead of asking
    the unattended timer to accept one.  Every command also has both an SSH
    connection bound and a subprocess timeout.
    """
    if isinstance(remote_args, (str, bytes)):
        raise TypeError("remote_args must be a sequence, not a command string")
    return [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={max(1, int(RIG_SSH_CONNECT_TIMEOUT))}",
        "-o", "ConnectionAttempts=1",
        "-o", "ServerAliveInterval=5",
        "-o", "ServerAliveCountMax=2",
        "-o", "StrictHostKeyChecking=yes",
        RIG_SSH_ALIAS,
        "env", f"PATH={RIG_REMOTE_PATH}",
        *[shlex.quote(str(arg)) for arg in remote_args],
    ]


def _rig_ssh(remote_args, timeout=RIG_SSH_COMMAND_TIMEOUT, input_data=None):
    """Run one bounded command through the pinned rig SSH alias."""
    kwargs = {"timeout": max(1, int(timeout))}
    if input_data is not None:
        kwargs["input"] = input_data
    return run_capture_ok(_rig_ssh_command(remote_args), **kwargs)


def _rig_tail(stdout="", stderr="", limit=700):
    """Keep remote command evidence bounded in JSON/email artifacts."""
    detail = "\n".join(part for part in (stdout or "", stderr or "") if part)
    return detail[-limit:]


def _rig_command_result(step, remote_args, timeout=RIG_SSH_COMMAND_TIMEOUT,
                        input_data=None, capture_full=False):
    """Return the normal P1 result shape for one remote command.

    ``capture_full`` is an internal escape hatch for parsers that must inspect
    the complete command response (for example JSON or apt's final count).
    The full fields are transient; callers must consume and remove them before
    storing the result in an artifact.
    """
    stdout, stderr, code = _rig_ssh(
        remote_args, timeout=timeout, input_data=input_data)
    result = {
        "step": step,
        "status": "ok" if code == 0 else "failed",
        "exit_code": code,
    }
    if stdout:
        result["stdout_tail"] = stdout[-700:]
    if stderr:
        result["stderr_tail"] = stderr[-700:]
    if capture_full:
        result["_full_stdout"] = stdout or ""
        result["_full_stderr"] = stderr or ""
    if code != 0:
        result["error"] = _rig_tail(stdout, stderr) or f"exit {code}"
    return result


_RIG_HOST_KEY_PATTERNS = (
    "host key verification failed",
    "remote host identification has changed",
    "offending ed25519 key",
    "offending ecdsa key",
    "no ed25519 host key is known",
    "no ecdsa host key is known",
    "host key is not known",
    "man-in-the-middle",
)
_RIG_WINDOWS_PATTERNS = (
    "windows",
    "windows_nt",
    "microsoft",
    "mingw",
    "msys",
    "cygwin",
    "not recognized as an internal or external command",
    "operable program or batch file",
    "the term 'uname' is not recognized",
    "uname : the term",
)
_RIG_TIMEOUT_PATTERNS = (
    "connection timed out",
    "operation timed out",
    "connect_timeout",
    "timed out",
    "no route to host",
    "connection refused",
    "network is unreachable",
)


def _rig_probe_reason(stdout, stderr, code):
    """Classify a failed Linux probe without attempting wake/OS switching."""
    detail = _rig_tail(stdout, stderr, limit=280).replace("\n", " ").strip()
    lower = detail.lower()
    stdout_lower = (stdout or "").lower()
    stderr_lower = (stderr or "").lower()
    if any(pattern in lower for pattern in _RIG_HOST_KEY_PATTERNS):
        return "host key mismatch: SSH refused the pinned gamingrig-linux key"
    if any(pattern in stdout_lower for pattern in _RIG_WINDOWS_PATTERNS):
        return "Windows host: Linux SSH probe command is unavailable"
    if any(
        pattern in stderr_lower
        for pattern in _RIG_WINDOWS_PATTERNS
        if pattern != "windows"
    ):
        return "Windows host: Linux SSH probe command is unavailable"
    if any(pattern in lower for pattern in _RIG_TIMEOUT_PATTERNS):
        if "refused" in lower:
            return "offline or sleeping: SSH connection refused"
        if "no route" in lower or "unreachable" in lower:
            return "offline or sleeping: no route to gamingrig-linux"
        return "offline or sleeping: SSH connection timed out"
    if detail:
        return f"remote platform unavailable: {detail[:220]}"
    return f"remote platform probe failed (exit {code})"


def _rig_windows_health_corroboration():
    """Confirm a Windows probe through the trusted local llm-proxy health API."""
    endpoint = ENDPOINTS["llm-proxy"]
    try:
        request = urllib.request.Request(endpoint)
        with urllib.request.urlopen(request, timeout=8) as response:
            payload = json.loads(response.read().decode())
    except Exception as exc:
        return {
            "status": "failed",
            "endpoint": endpoint,
            "error": f"trusted llm-proxy health unavailable: {exc}",
        }
    if not isinstance(payload, dict):
        return {
            "status": "failed",
            "endpoint": endpoint,
            "error": "trusted llm-proxy health returned a non-object JSON value",
        }
    rig_os = str(payload.get("rig_os") or "").strip().lower()
    if rig_os != "windows":
        return {
            "status": "failed",
            "endpoint": endpoint,
            "rig_os": rig_os or "missing",
            "error": "trusted llm-proxy health did not report rig_os=windows",
        }
    return {
        "status": "ok",
        "endpoint": endpoint,
        "rig_os": "windows",
    }


def _rig_platform_probe():
    """Probe only; no wake-on-LAN, firmware, or Windows switching is allowed."""
    stdout, stderr, code = _rig_ssh(
        ["uname", "-s"], timeout=RIG_SSH_CONNECT_TIMEOUT)
    platform = (stdout or "").strip()
    if code == 0 and platform.lower() == "linux":
        return {
            "step": "platform_probe",
            "status": "ok",
            "os": "Linux",
            "host": RIG_SSH_ALIAS,
        }, True

    reason = _rig_probe_reason(stdout, stderr, code)
    base = {
        "step": "platform_probe",
        "host": RIG_SSH_ALIAS,
        "reason": reason,
        "exit_code": code,
        "output_tail": _rig_tail(stdout, stderr, limit=500),
    }
    if reason.startswith("offline or sleeping:"):
        base["status"] = "skipped"
        return base, False
    if (
        reason.startswith("Windows host:")
        or reason.startswith("host key mismatch:")
    ):
        corroboration = _rig_windows_health_corroboration()
        base["windows_corroboration"] = corroboration
        if corroboration["status"] == "ok":
            base["status"] = "skipped"
            base["os"] = "Windows"
            base["reason"] = (
                "Windows host: trusted llm-proxy health corroborated "
                "rig_os=windows"
            )
        else:
            base["status"] = "failed"
            if reason.startswith("Windows host:"):
                base["error"] = (
                    "Windows probe was not corroborated by trusted llm-proxy "
                    f"health: {corroboration.get('error', 'unknown error')}"
                )
            else:
                base["error"] = (
                    f"{reason}; trusted llm-proxy did not corroborate Windows: "
                    f"{corroboration.get('error', 'unknown error')}"
                )
        return base, False
    base["status"] = "failed"
    base["error"] = reason
    return base, False


def _rig_apt_upgrade():
    """Run unattended apt update/upgrade and report planned and applied counts."""
    update = _rig_command_result(
        "apt_update",
        [
            "sudo", "-n", "env", "DEBIAN_FRONTEND=noninteractive",
            "apt-get", "update",
        ],
        timeout=RIG_APT_TIMEOUT,
    )
    if update["status"] != "ok":
        return {
            "step": "apt_upgrade",
            "status": "failed",
            "planned_count": 0,
            "upgraded_count": 0,
            "substeps": [update],
            "output_tail": _rig_tail(
                update.get("stdout_tail", ""), update.get("stderr_tail"),
                limit=1400,
            ),
            "error": update.get("error", "apt update failed"),
        }

    plan = _rig_command_result(
        "apt_upgrade_plan", ["apt-get", "--simulate", "upgrade"],
        timeout=RIG_APT_TIMEOUT,
        capture_full=True,
    )
    # The summary precedes the package list and may be outside the stored tail.
    plan_stdout = plan.pop("_full_stdout", "")
    plan_stderr = plan.pop("_full_stderr", "")
    if not plan_stdout and not plan_stderr:
        plan_stdout = plan.get("stdout_tail", "")
        plan_stderr = plan.get("stderr_tail", "")
    plan_output = _rig_tail(plan_stdout, plan_stderr, limit=1400)
    match = re.search(r"(?im)(\d+)\s+upgraded\b", plan_stdout + "\n" + plan_stderr)
    planned = int(match.group(1)) if match else 0
    if plan["status"] != "ok" or match is None:
        plan["status"] = "failed"
        plan["error"] = plan.get("error") or (
            "apt simulation did not report an upgrade count")
        return {
            "step": "apt_upgrade",
            "status": "failed",
            "planned_count": planned,
            "upgraded_count": 0,
            "substeps": [update, plan],
            "output_tail": plan_output,
            "error": plan["error"],
        }

    upgrade = _rig_command_result(
        "apt_upgrade_apply",
        [
            "sudo", "-n", "env", "DEBIAN_FRONTEND=noninteractive",
            "apt-get", "-y", "-o", "Dpkg::Use-Pty=0",
            "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold",
            "upgrade",
        ],
        timeout=RIG_APT_TIMEOUT,
        capture_full=True,
    )
    # Parse the complete apply response before discarding the private capture.
    # Only bounded tails remain in the artifact/substep.
    apply_stdout = upgrade.pop("_full_stdout", "")
    apply_stderr = upgrade.pop("_full_stderr", "")
    if not apply_stdout and not apply_stderr:
        apply_stdout = upgrade.get("stdout_tail", "")
        apply_stderr = upgrade.get("stderr_tail", "")
    apply_output = _rig_tail(apply_stdout, apply_stderr, limit=1400)
    applied_match = re.search(r"(?im)(\d+)\s+upgraded\b", apply_stdout + "\n" + apply_stderr)
    applied = int(applied_match.group(1)) if applied_match else 0

    output = _rig_tail(
        update.get("stdout_tail", ""), update.get("stderr_tail", ""),
        limit=1400,
    ) + "\n" + apply_output
    status = "ok" if upgrade["status"] == "ok" else "failed"
    result = {
        "step": "apt_upgrade",
        "status": status,
        "planned_count": planned,
        "upgraded_count": applied if status == "ok" else 0,
        "substeps": [update, plan, upgrade],
        "output_tail": output[-1800:],
    }
    if status == "ok" and applied_match is None:
        result["status"] = "failed"
        result["upgraded_count"] = 0
        result["error"] = "apt upgrade did not report an applied upgrade count"
    elif status == "failed":
        result["error"] = upgrade.get("error", "apt upgrade failed")
    return result


def _rig_herdr_update():
    """Update Herdr as the rig user; refuse to block on an interactive session."""
    pre_out, pre_err, pre_code = _rig_ssh(
        ["herdr", "--version"], timeout=30)
    pre_ver = pre_out.strip()
    if pre_code != 0 or not pre_ver:
        return {
            "step": "herdr_update",
            "status": "failed",
            "pre_version": pre_ver,
            "error": _rig_tail(pre_out, pre_err) or f"version probe exit {pre_code}",
        }

    stdout, stderr, code = _rig_ssh(
        ["herdr", "update"], timeout=RIG_UPDATE_TIMEOUT)
    detail = _rig_tail(stdout, stderr)
    if (
        "outside herdr" in detail.lower()
        or "inside a herdr session" in detail.lower()
        or "already in a herdr session" in detail.lower()
    ):
        return {
            "step": "herdr_update",
            "status": "skipped",
            "pre_version": pre_ver,
            "reason": "refused inside a Herdr session",
            "output_tail": detail,
        }

    post_out, post_err, post_code = _rig_ssh(
        ["herdr", "--version"], timeout=30)
    post_ver = post_out.strip()
    if code == 0 and post_code == 0 and post_ver and post_ver != pre_ver:
        return {
            "step": "herdr_update",
            "status": "ok",
            "pre_version": pre_ver,
            "post_version": post_ver,
            "output_tail": detail,
        }
    if code == 0 and post_code == 0 and post_ver == pre_ver:
        return {
            "step": "herdr_update",
            "status": "skipped",
            "pre_version": pre_ver,
            "post_version": post_ver,
            "reason": "already current",
            "output_tail": detail,
        }
    return {
        "step": "herdr_update",
        "status": "failed",
        "pre_version": pre_ver,
        "post_version": post_ver,
        "error": detail or _rig_tail(post_out, post_err) or f"update exit {code}",
    }


def _rig_omp_tag(version):
    """Extract a safe package version from ``omp --version`` output."""
    value = (version or "").strip()
    match = re.search(
        r"\bomp[/\s]+([vV]?[0-9][A-Za-z0-9._+-]*)",
        value,
        re.I,
    )
    if match:
        return match.group(1).lstrip("vV")
    match = re.fullmatch(r"[vV]?([0-9][A-Za-z0-9._+-]*)", value)
    return match.group(1) if match else ""


def _rig_omp_update():
    """Update the rig's OMP CLI, smoke it, and Bun-rollback a broken install."""
    pre_out, pre_err, pre_code = _rig_ssh(
        ["omp", "--version"], timeout=30)
    pre_ver = pre_out.strip()
    pre_tag = _rig_omp_tag(pre_ver)
    if pre_code != 0 or not pre_ver or not pre_tag:
        return {
            "step": "omp_update",
            "status": "failed",
            "pre_version": pre_ver,
            "error": _rig_tail(pre_out, pre_err)
                     or f"could not snapshot pre-update version (exit {pre_code})",
        }

    stdout, stderr, code = _rig_ssh(
        ["omp", "update"], timeout=RIG_UPDATE_TIMEOUT)
    detail = _rig_tail(stdout, stderr)
    post_out, post_err, post_code = _rig_ssh(
        ["omp", "--version"], timeout=30)
    post_ver = post_out.strip()
    smoke_out, smoke_err, smoke_code = _rig_ssh(
        ["omp", "-p"], timeout=60, input_data="")
    smoke_ok = smoke_code == 0

    common = {
        "step": "omp_update",
        "pre_version": pre_ver,
        "post_version": post_ver,
        "smoke_ok": smoke_ok,
        "smoke_output_tail": _rig_tail(smoke_out, smoke_err, limit=500),
        "output_tail": detail,
    }
    if code == 0 and post_code == 0 and smoke_ok and post_ver and post_ver != pre_ver:
        return {**common, "status": "ok"}
    if code == 0 and post_code == 0 and smoke_ok and post_ver == pre_ver:
        return {**common, "status": "skipped", "reason": "already current"}

    # The only dynamic argument is a strictly validated package version.
    rollback_args = [
        "bun", "add", "-g", f"{_OMP_PKG}@{pre_tag}",
    ]
    r_stdout, r_stderr, r_code = _rig_ssh(
        rollback_args, timeout=RIG_UPDATE_TIMEOUT)
    rev_out, rev_err, rev_code = _rig_ssh(
        ["omp", "--version"], timeout=30)
    rev_ver = rev_out.strip()
    rev_smoke_out, rev_smoke_err, rev_smoke_code = _rig_ssh(
        ["omp", "-p"], timeout=60, input_data="")
    reverted = (
        r_code == 0 and rev_code == 0 and rev_ver == pre_ver
        and rev_smoke_code == 0
    )
    return {
        **common,
        "status": "reverted" if reverted else "failed",
        "reverted_to": rev_ver,
        "rollback_ok": reverted,
        "rollback_exit_code": r_code,
        "rollback_output_tail": _rig_tail(
            r_stdout, r_stderr, limit=700),
        "rollback_smoke_output_tail": _rig_tail(
            rev_smoke_out, rev_smoke_err, limit=500),
        "error": (
            f"post-update check failed; reverted to {pre_tag}"
            if not smoke_ok else detail or f"update exit {code}"
        ),
    }


def _rig_disk_health():
    result = _rig_command_result("disk", ["df", "-P", "/"], timeout=30)
    if result["status"] != "ok":
        return result
    lines = [line.split() for line in
             (result.get("stdout_tail") or "").splitlines()
             if line.strip()]
    row = lines[-1] if lines else []
    percent = next((part for part in row if part.endswith("%")), "")
    if not percent:
        return {
            **result,
            "status": "failed",
            "error": "df output did not contain a root filesystem percentage",
        }
    try:
        used = int(percent.rstrip("%"))
    except ValueError:
        return {**result, "status": "failed",
                "error": f"invalid root filesystem percentage: {percent}"}
    result["used_percent"] = used
    if used > RIG_DISK_MAX_PERCENT:
        result["status"] = "failed"
        result["error"] = (
            f"root filesystem {used}% used (limit {RIG_DISK_MAX_PERCENT}%)")
    elif used >= 90:
        result["status"] = "warning"
        result["reason"] = f"root filesystem {used}% used"
    return result


def _rig_failed_units_health():
    result = _rig_command_result(
        "failed_units",
        ["systemctl", "--failed", "--no-legend", "--no-pager", "--plain"],
        timeout=30,
    )
    output = result.get("stdout_tail", "")
    units = []
    for line in output.splitlines():
        clean = line.strip()
        if not clean or re.match(r"^\d+\s+loaded units? listed", clean, re.I):
            continue
        if clean.lower().startswith("unit "):
            continue
        units.append(clean)
    if units:
        result["status"] = "failed"
        result["error"] = "failed systemd units: " + "; ".join(units[:8])
    elif (
        result["exit_code"] not in (0, 1)
        or (result["exit_code"] == 1 and result.get("stderr_tail"))
    ):
        result["status"] = "failed"
        result["error"] = result.get("error", "systemctl failed-unit query failed")
    else:
        result["status"] = "ok"
    if result["status"] == "ok" and result["exit_code"] == 1:
        result.pop("error", None)
    return result


def _rig_model_ids_from_response(raw):
    """Validate a complete OpenAI-compatible ``/v1/models`` response."""
    try:
        payload = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError(f"malformed model endpoint JSON: {exc}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
        raise ValueError("model endpoint response is missing a data list")

    model_ids = []
    for index, model in enumerate(payload["data"]):
        if not isinstance(model, dict):
            raise ValueError(f"model endpoint entry {index} is not an object")
        model_id = model.get("id")
        if not isinstance(model_id, str) or not model_id.strip():
            raise ValueError(f"model endpoint entry {index} is missing a non-empty id")
        model_ids.append(model_id)

    expected = set(RIG_REQUIRED_MODEL_IDS)
    actual = set(model_ids)
    if (
        len(model_ids) != len(RIG_REQUIRED_MODEL_IDS)
        or len(actual) != len(model_ids)
        or actual != expected
    ):
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        raise ValueError(
            "model endpoint IDs do not match retained registry"
            f" (missing={missing}, unexpected={unexpected}, count={len(model_ids)})"
        )
    return model_ids


def _rig_health_checks():
    """Collect non-mutating rig health checks in a stable order."""
    checks = [
        _rig_disk_health(),
        _rig_failed_units_health(),
        _rig_command_result(
            "nvidia_smi",
            [
                "nvidia-smi", "--query-gpu=name,memory.used,memory.total,"
                "utilization.gpu,temperature.gpu", "--format=csv,noheader",
            ],
            timeout=30,
        ),
        _rig_command_result(
            "llama_swap",
            ["systemctl", "is-active", "--quiet", "llama-swap.service"],
            timeout=30,
        ),
    ]
    model_check = _rig_command_result(
        "model_endpoint",
        [
            "curl", "-fsS", "--connect-timeout", "3", "--max-time", "8",
            RIG_MODEL_ENDPOINT,
        ],
        timeout=20,
        capture_full=True,
    )
    model_output = model_check.pop("_full_stdout", "")
    model_check.pop("_full_stderr", None)
    if model_check["status"] == "ok":
        try:
            model_check["model_ids"] = _rig_model_ids_from_response(
                model_output or model_check.get("stdout_tail", "")
            )
        except ValueError as exc:
            model_check["status"] = "failed"
            model_check["error"] = str(exc)
    checks.append(model_check)

    # ``nvidia-smi`` and curl are successful only when they return evidence.
    for check in checks:
        if check["step"] == "nvidia_smi":
            if check["status"] == "ok" and not check.get("stdout_tail"):
                check["status"] = "failed"
                check["error"] = "command returned no health evidence"
    statuses = [check["status"] for check in checks]
    if any(status == "failed" for status in statuses):
        status = "failed"
    elif any(status == "warning" for status in statuses):
        status = "warning"
    else:
        status = "ok"
    result = {
        "step": "health",
        "status": status,
        "checks": checks,
    }
    if status in ("failed", "warning"):
        result["error"] = "; ".join(
            f"{check['step']}: {check.get('error') or check.get('reason') or check['status']}"
            for check in checks if check.get("status") in ("failed", "error", "warning")
        )
    return result


def _rig_reboot_required():
    """Detect reboot-required without treating the normal false result as fail."""
    result = _rig_command_result(
        "reboot_required",
        ["test", "-f", "/var/run/reboot-required"],
        timeout=20,
    )
    code = result.get("exit_code")
    if code == 1:
        result["status"] = "skipped"
        result["required"] = False
        result["reason"] = "reboot not required"
        result.pop("error", None)
    elif code == 0:
        result["status"] = "ok"
        result["required"] = True
    else:
        result["status"] = "failed"
        result["required"] = False
        result["error"] = result.get("error", "could not inspect reboot-required flag")
    return result

def _rig_boot_id(step="boot_id"):
    """Read and validate the current Linux boot identifier."""
    result = _rig_command_result(
        step, ["cat", "/proc/sys/kernel/random/boot_id"], timeout=20)
    boot_id = (result.get("stdout_tail") or "").strip()
    if (
        result["status"] != "ok"
        or not re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            boot_id,
            re.I,
        )
    ):
        result["status"] = "failed"
        result["error"] = result.get("error") or "invalid Linux boot ID"
        return result
    result["boot_id"] = boot_id
    return result


def _rig_arm_bootnext():
    """Re-arm Ubuntu's established firmware entry before a rig reboot."""
    arm = _rig_command_result(
        "bootnext_arm",
        ["sudo", "-n", "efibootmgr", "--bootnext", RIG_BOOT_ENTRY],
        timeout=30,
    )
    verify = _rig_command_result(
        "bootnext_verify", ["sudo", "-n", "efibootmgr"], timeout=30)
    verified = (
        verify["status"] == "ok"
        and bool(re.search(
            rf"(?im)^\s*BootNext:\s*{re.escape(RIG_BOOT_ENTRY)}\b",
            verify.get("stdout_tail", ""),
        ))
    )
    result = {
        "step": "bootnext",
        "status": "ok" if arm["status"] == "ok" and verified else "failed",
        "entry": RIG_BOOT_ENTRY,
        "substeps": [arm, verify],
    }
    if not verified:
        result["error"] = (
            verify.get("error")
            or f"efibootmgr did not report BootNext: {RIG_BOOT_ENTRY}"
        )
    return result


def _rig_reboot():
    """Request reboot; a connection close/reset is expected on success."""
    stdout, stderr, code = _rig_ssh(
        ["sudo", "-n", "systemctl", "reboot"], timeout=20)
    detail = _rig_tail(stdout, stderr)
    lower = detail.lower()
    disconnected = (
        "connection reset" in lower
        or "broken pipe" in lower
        or bool(re.search(r"connection(?: to .+)? closed", lower))
    )
    if code == 0 or disconnected:
        return {
            "step": "reboot",
            "status": "ok",
            "requested": True,
            "connection_lost": bool(code != 0),
            "output_tail": detail,
        }
    return {
        "step": "reboot",
        "status": "failed",
        "requested": False,
        "error": detail or f"reboot command exit {code}",
    }


def _rig_wait_for_linux(previous_boot_id, timeout_s=RIG_REBOOT_WAIT_TIMEOUT):
    """Wait for pinned Linux SSH to return on a demonstrably new boot."""
    deadline = time.monotonic() + max(0, int(timeout_s))
    attempts = 0
    last = {}
    while True:
        attempts += 1
        stdout, stderr, code = _rig_ssh(
            ["cat", "/proc/sys/kernel/random/boot_id"],
            timeout=RIG_SSH_CONNECT_TIMEOUT,
        )
        boot_id = (stdout or "").strip()
        last = {
            "stdout": stdout[-180:] if stdout else "",
            "stderr": stderr[-280:] if stderr else "",
            "exit_code": code,
            "boot_id": boot_id,
        }
        if code == 0 and boot_id and boot_id != previous_boot_id:
            return {
                "step": "ssh_return",
                "status": "ok",
                "attempts": attempts,
                "os": "Linux",
                "boot_id": boot_id,
            }
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(2, remaining))
    reason = (
        "Linux SSH returned but the boot ID did not change"
        if last.get("exit_code") == 0 and last.get("boot_id") == previous_boot_id
        else _rig_probe_reason(
            last.get("stdout", ""),
            last.get("stderr", ""),
            last.get("exit_code", -1),
        )
    )
    return {
        "step": "ssh_return",
        "status": "failed",
        "attempts": attempts,
        "error": (
            f"new Linux boot did not appear within {int(timeout_s)}s: {reason}"
        ),
        "last_probe": last,
    }


def _rig_wait_for_health(timeout_s=RIG_REBOOT_WAIT_TIMEOUT):
    """Poll all rig health/readiness checks until the new boot is healthy."""
    deadline = time.monotonic() + max(0, int(timeout_s))
    attempts = 0
    last = {
        "step": "health",
        "status": "failed",
        "checks": [],
        "error": "no post-reboot health result",
    }
    while True:
        attempts += 1
        last = _rig_health_checks()
        if last.get("status") == "ok":
            gate = dict(last)
            gate["step"] = "post_reboot_health"
            gate["attempts"] = attempts
            return gate
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(2, remaining))

    gate = dict(last)
    gate["step"] = "post_reboot_health"
    gate["status"] = "failed"
    gate["attempts"] = attempts
    detail = str(last.get("error") or last.get("status") or "unhealthy")
    gate["error"] = (
        f"post-reboot health did not pass within {int(timeout_s)}s: {detail[:300]}"
    )
    return gate


def _rig_has_failure(value):
    """Recursively detect a failed command/health result."""
    if isinstance(value, dict):
        if value.get("status") in ("failed", "error"):
            return True
        return any(_rig_has_failure(item) for item in value.get("substeps", []))
    if isinstance(value, list):
        return any(_rig_has_failure(item) for item in value)
    return False


def _p1_gamingrig_maintenance(dry_run=False):
    """Maintain gamingrig-linux without waking it or switching its operating system."""
    result = {
        "step": "gamingrig_maintenance",
        "host": RIG_SSH_ALIAS,
        "local_mutation": False,
        "substeps": [],
        "reboot_requested": False,
        "new_boot_observed": False,
        "rebooted": False,
        "post_reboot_health_passed": False,
    }
    if dry_run:
        result.update({
            "status": "skipped",
            "reason": "dry-run: remote maintenance not attempted",
        })
        return result

    try:
        probe, linux = _rig_platform_probe()
        result["substeps"].append(probe)
        if not linux:
            result.update({
                "status": "skipped" if probe.get("status") == "skipped" else "failed",
                "reason": probe.get("reason", "Linux platform unavailable"),
            })
            if probe.get("status") != "skipped":
                result["error"] = probe.get("error") or probe.get("reason")
            return result
        result["os"] = "Linux"

        # Keep independent maintenance steps running so one remote failure is
        # evidence in the artifact, not an exception that skips later checks.
        result["substeps"].append(_rig_apt_upgrade())
        result["substeps"].append(_rig_herdr_update())
        result["substeps"].append(_rig_omp_update())

        health = _rig_health_checks()
        result["substeps"].append(health)
        result["health"] = health

        reboot = _rig_reboot_required()
        result["substeps"].append(reboot)
        if reboot.get("required"):
            boot_id = _rig_boot_id("pre_reboot_boot_id")
            result["substeps"].append(boot_id)
            if boot_id["status"] == "ok":
                bootnext = _rig_arm_bootnext()
                result["substeps"].append(bootnext)
                if bootnext["status"] == "ok":
                    reboot_result = _rig_reboot()
                    result["substeps"].append(reboot_result)
                    if (
                        reboot_result["status"] == "ok"
                        and reboot_result.get("requested", True)
                    ):
                        result["reboot_requested"] = True
                        returned = _rig_wait_for_linux(boot_id["boot_id"])
                        result["substeps"].append(returned)
                        if returned["status"] == "ok":
                            result["new_boot_observed"] = True
                            result["rebooted"] = True
                            post_health = _rig_wait_for_health()
                            result["substeps"].append(post_health)
                            result["post_reboot_health"] = post_health
                            result["post_reboot_health_passed"] = (
                                post_health.get("status") == "ok"
                            )

        result["rebooted"] = (
            result["reboot_requested"] and result["new_boot_observed"]
        )
        result["status"] = (
            "failed" if _rig_has_failure(result["substeps"]) else "ok"
        )
        if result["status"] == "failed":
            failures = [
                sub.get("error", sub.get("reason", sub.get("step", "failure")))
                for sub in result["substeps"]
                if _rig_has_failure(sub)
            ]
            result["error"] = "; ".join(str(item) for item in failures)
        return result
    except Exception as exc:
        # A malformed local invocation must still leave the rest of P1 alive.
        result.update({
            "status": "failed",
            "error": f"remote maintenance exception: {exc}",
        })
        return result


def phase_1_apply(run_dir, dry_run=False, *, progress=None):
    """Phase 1: apply safe updates, checkpointing each substep atomically."""
    if progress is None:
        progress = lambda payload: write_json(run_dir / "01-applied.json", payload)

    steps = []

    def persist():
        progress(_p1_progress_payload(steps, dry_run=dry_run))

    # Replace any prior attempt's artifact before the first operation.  The
    # workflow-owned callback also stamps and validates the current attempt.
    persist()
    print("[P1] applying safe updates" if not dry_run
          else "[P1] DRY RUN — skipping all mutations")

    # Remote maintenance is first so local P1 failures cannot skip it.
    _p1_run_step(
        steps,
        "gamingrig_maintenance",
        lambda: _p1_gamingrig_maintenance(dry_run=dry_run),
        persist,
    )
    if dry_run:
        return _finish_p1(
            run_dir,
            {"dry_run": True, "steps": steps},
            progress,
        )

    # 1a: apt upgrade.  Keep the existing stop boundary, but leave its timeout
    # packet in the artifact rather than allowing an exception to erase prior
    # remote evidence.
    apt_result = _p1_run_step(steps, "apt_upgrade", _p1_apt_upgrade, persist)
    if apt_result.get("status") in _P1_FAILURE_STATUSES:
        print(f"  FAILED: apt upgrade — {apt_result.get('error')}")
        return _finish_p1(run_dir, {"steps": steps}, progress)

    # 1b: auto-apply docker + cloudflared.  The callback checkpoints each
    # package, including a package currently marked started if the process is
    # interrupted between invocation and completion.
    auto_results = _p1_auto_pkgs(
        progress=lambda partial: progress({"steps": steps + partial})
    )
    steps.extend(auto_results)
    persist()
    for auto_result in auto_results:
        if auto_result.get("status") in _P1_FAILURE_STATUSES:
            print(f"  FAILED: {auto_result.get('step')} — {auto_result.get('error')}")
            return _finish_p1(run_dir, {"steps": steps}, progress)

    # 1c: settle docker after apt/auto path restarts the daemon.
    # apt needrestart may bounce docker even when auto_* later reports "skipped"
    # (versions already match). open-webui takes >30s after daemon restart.
    docker_upgraded = any(
        s.get("step", "").startswith("auto_docker") and s.get("status") == "ok"
        for s in auto_results
    )
    docker_touched = bool(apt_result.get("docker_touched")) or docker_upgraded
    if docker_touched:
        reason = (
            "apt_docker_touched"
            if apt_result.get("docker_touched")
            else "auto_docker_upgrade"
        )

        def settle_docker():
            settle = _wait_docker_stack_ready(timeout_s=120)
            return {
                "step": "docker_settle",
                "status": settle.get("status", "ok"),
                "endpoints": settle.get("endpoints", {}),
                "reason": reason,
            }

        _p1_run_step(
            steps,
            "docker_settle",
            settle_docker,
            persist,
        )
        _p1_run_step(steps, "docker_daemon_assert", _p1_docker_assert, persist)

    # 1d: cloudflared restart if upgraded.
    cloudflared_upgraded = any(
        s.get("step") == "auto_cloudflared" and s.get("status") == "ok"
        for s in auto_results
    )
    if cloudflared_upgraded:
        print("  [1d] restart cloudflared")

        def restart_cloudflared():
            run(
                ["sudo", "systemctl", "restart", "cloudflared"],
                capture_output=True,
                text=True,
                timeout=60,
            )
            time.sleep(5)
            return {"step": "cloudflared_restart", "status": "ok"}

        _p1_run_step(
            steps,
            "cloudflared_restart",
            restart_cloudflared,
            persist,
        )

    # Remaining independent update checks continue and are each checkpointed.
    _p1_run_step(steps, "freshrss", _p1_freshrss_update, persist)
    _p1_run_step(steps, "openwebui_update", _p1_openwebui, persist)
    _p1_run_step(steps, "herdr_update", _p1_herdr_update, persist)
    _p1_run_step(steps, "searxng", _p1_searxng_update, persist)
    _p1_run_step(steps, "llama_cpp", _p1_llama_cpp_update, persist)
    omp_result = _p1_run_step(steps, "omp_update", _p1_omp_update, persist)
    # The sandboxed P7b worker runs its own root-owned copy of omp; refresh it
    # only when this run actually changed the local version.
    _p1_run_step(steps, "worker_omp_refresh",
                 lambda: _p1_worker_omp_refresh(omp_result), persist)
    _p1_run_step(steps, "dependabot_merge", _p1_dependabot_merge, persist)
    # App deploys come after every package/container step so P2 validation
    # (which runs after P1) observes the deployed revisions.
    for service, spec in DEPLOY_REGISTRY.items():
        _p1_run_step(steps, "app_deploy",
                     lambda service=service, spec=spec: _p1_app_deploy(service, spec),
                     persist, service=service)

    data = _finish_p1(run_dir, {"steps": steps}, progress)
    n_ok = sum(1 for s in steps if s.get("status") == "ok")
    n_bumped = sum(1 for s in steps if s.get("status") == "bumped")
    n_available = sum(1 for s in steps if s.get("status") == "available")
    n_skipped = sum(1 for s in steps if s.get("status") == "skipped")
    n_failed = sum(
        1 for s in steps if s.get("status") in _P1_FAILURE_STATUSES
    )
    print(f"[P1] done -> {run_dir / '01-applied.json'}")
    print(f"  {n_ok} ok, {n_bumped} bumped, {n_available} available, "
          f"{n_skipped} skipped, {n_failed} failed")
    return data

