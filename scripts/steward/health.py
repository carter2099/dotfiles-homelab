"""Validation, remediation, and heartbeat health checks."""
from __future__ import annotations

import jev

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
from .updates import (
    FRESHRSS_COMPOSE,
    _OMP_PKG,
    _RIG_HOST_KEY_PATTERNS,
    _RIG_TIMEOUT_PATTERNS,
    _RIG_WINDOWS_PATTERNS,
    _omp_smoke_ok,
    _p1_apt_upgrade,
    _p1_auto_pkgs,
    _p1_deploy_step_ok,
    _p1_docker_assert,
    _p1_freshrss_update,
    _p1_gamingrig_maintenance,
    _p1_herdr_update,
    _p1_llama_cpp_update,
    _p1_omp_update,
    _p1_openwebui,
    _p1_searxng_update,
    _release_is_mature,
    _release_time,
    _rig_apt_upgrade,
    _rig_arm_bootnext,
    _rig_boot_id,
    _rig_command_result,
    _rig_disk_health,
    _rig_failed_units_health,
    _rig_has_failure,
    _rig_health_checks,
    _rig_herdr_update,
    _rig_model_ids_from_response,
    _rig_omp_tag,
    _rig_omp_update,
    _rig_platform_probe,
    _rig_probe_reason,
    _rig_reboot,
    _rig_reboot_required,
    _rig_ssh,
    _rig_ssh_command,
    _rig_tail,
    _rig_wait_for_health,
    _rig_wait_for_linux,
    _rig_windows_health_corroboration,
    _searxng_tag_date,
    _select_mature_llama_release,
    _select_mature_searxng_tag,
    _wait_docker_stack_ready,
    _wait_searxng_healthy,
    phase_1_apply,
)

def phase_2_validate(run_dir):
    """Phase 2: run all validation checks."""
    print("[P2] validating services")
    checks = []

    # Docker containers
    out = run_capture(["docker", "ps", "-a", "--format", "{{.Names}} {{.Status}}"])
    checks.append({"name": "docker_containers", "output": out, "status": "ok"})

    # Endpoint curls — retry briefly; containers may still be binding after an
    # apt-triggered docker restart (open-webui especially).
    def _probe_endpoint(name, url, attempts=8, delay_s=5):
        last = None
        for i in range(attempts):
            if name == "searxng":
                resp = run_capture(
                    ["curl", "-s", "--connect-timeout", "10", "--max-time", "20", url],
                    timeout=25,
                )
                if resp:
                    try:
                        data = json.loads(resp)
                        healthy = isinstance(data.get("results"), list)
                        last = {
                            "name": f"endpoint_{name}", "url": url,
                            "http_code": "200", "status": "ok" if healthy else "fail",
                            "content_valid": healthy,
                        }
                        if healthy:
                            return last
                    except json.JSONDecodeError:
                        last = {
                            "name": f"endpoint_{name}", "url": url,
                            "http_code": "??", "status": "fail",
                            "error": "invalid JSON response",
                        }
                else:
                    last = {
                        "name": f"endpoint_{name}", "url": url,
                        "http_code": "", "status": "fail",
                        "error": "empty response",
                    }
            else:
                code = run_capture(
                    ["curl", "-so", "/dev/null", "-w", "%{http_code}",
                     "--connect-timeout", "5", "--max-time", "15", url],
                    timeout=20,
                )
                healthy = bool(code) and (code.startswith("2") or code.startswith("3"))
                last = {
                    "name": f"endpoint_{name}", "url": url,
                    "http_code": code, "status": "ok" if healthy else "fail",
                }
                if not code:
                    last["error"] = "empty response / connect failed"
                if healthy:
                    return last
            if i + 1 < attempts:
                time.sleep(delay_s)
        return last

    for name, url in ENDPOINTS.items():
        checks.append(_probe_endpoint(name, url))

    # LLM proxy X-Fallback header
    fallback = run_capture(["curl", "-sI", "http://127.0.0.1:8081/health"])
    fallback_active = "X-Fallback: true" in fallback
    checks.append({
        "name": "llm_fallback", "status": "warning" if fallback_active else "ok",
        "fallback_active": fallback_active,
    })

    # open-webui running image vs compose tag
    owu_image_check = {"name": "openwebui_image_match", "status": "skipped"}
    try:
        running_image = run_capture(
            ["docker", "inspect", "open-webui", "--format", "{{.Config.Image}}"])
        if running_image:
            if OPENWEBUI_COMPOSE.exists():
                compose_text = OPENWEBUI_COMPOSE.read_text()
                compose_m = re.search(r"ghcr\.io/open-webui/open-webui:([^\s\"']+)", compose_text)
                compose_tag = compose_m.group(1) if compose_m else None
                if compose_tag:
                    owu_image_check["running_image"] = running_image
                    owu_image_check["compose_tag"] = compose_tag
                    if compose_tag in running_image:
                        owu_image_check["status"] = "ok"
                    else:
                        owu_image_check["status"] = "warning"
                else:
                    owu_image_check["reason"] = "could not parse compose tag"
            else:
                owu_image_check["reason"] = "compose file missing"
        else:
            owu_image_check["reason"] = "container not found or not running"
    except Exception as e:
        owu_image_check["status"] = "error"
        owu_image_check["error"] = str(e)
    checks.append(owu_image_check)

    # CF tunnel connector health
    cf_check = {"name": "endpoint_tunnel-health", "status": "skipped"}
    try:
        cf_token = (HOME / ".config" / "cloudflare" / "api-token").read_text().strip()
        cf_account_id = (HOME / ".config" / "cloudflare" / "account-id").read_text().strip()
        cf_tunnel_id = (HOME / ".config" / "cloudflare" / "homelab-tunnel-id").read_text().strip()
        if cf_token and cf_account_id and cf_tunnel_id:
            cf_url = (
                f"https://api.cloudflare.com/client/v4/accounts/{cf_account_id}"
                f"/cfd_tunnel/{cf_tunnel_id}/connections"
            )
            cf_req = urllib.request.Request(
                cf_url, headers={"Authorization": f"Bearer {cf_token}"})
            with urllib.request.urlopen(cf_req, timeout=15) as cf_resp:
                cf_data = json.loads(cf_resp.read().decode())
            connectors = cf_data.get("result", [])
            healthy = False
            active_conns = 0
            for connector in connectors:
                for conn in connector.get("conns", []):
                    if not conn.get("is_pending_reconnect", True):
                        active_conns += 1
            healthy = active_conns > 0
            cf_check["status"] = "ok" if healthy else "fail"
            cf_check["connector_count"] = len(connectors)
            cf_check["active_connections"] = active_conns
            cf_check["healthy"] = healthy
        else:
            cf_check["reason"] = "missing CF config files"
    except Exception as e:
        cf_check["status"] = "error"
        cf_check["error"] = str(e)
    checks.append(cf_check)

    data = {"checks": checks}
    write_json(run_dir / "02-validation.json", data)
    print(f"[P2] done -> {run_dir / '02-validation.json'}")
    return data


# ── P3: troubleshoot ─────────────────────────────────────────────────

# Endpoint -> the service behind it, fixed from the phase_2_validate checks
# (config.ENDPOINTS plus the tunnel connector check).  The fix menu is built
# only from this map, never from model output.  herdr-server, the rig,
# llama-swap and k3s are deliberately absent.
P3_ENDPOINT_SERVICES = {
    "open-webui": {"container": "open-webui"},
    "blog": {"container": "blog-web-1"},
    "llm-proxy": {"user_unit": "llm-proxy.service"},
    "searxng": {"container": "searxng"},
    "news": {"container": "carter-news"},
    "freshrss": {"container": "freshrss"},
    "tunnel-health": {},
}
# Endpoints reached from the internet through the Cloudflare tunnel.
P3_TUNNEL_ENDPOINTS = frozenset({"open-webui", "blog", "news", "tunnel-health"})
# P1 steps that deploy an endpoint; host package steps (apt/auto_*) apply to all.
P3_ENDPOINT_P1_STEPS = {"open-webui": {"openwebui_update"}, "searxng": {"searxng"},
                        "freshrss": {"freshrss"}}
P3_FIX_MIN_CONFIDENCE = 0.8
P3_FIX_MAX_ACTIONS = 3
P3_FIX_TIMEOUT = 180
P3_JEV_DEADLINE_S = 120
P3_JEV_PURPOSE = "steward-p3-fix"


def _p3_fix_menu(endpoint):
    """Allowed fix actions for one regressed endpoint: label -> action.

    No P1 rollback is offered: each P1 rollback (open-webui, searxng,
    app_deploy) runs inside its own step and none is reusable afterwards.
    """
    service = P3_ENDPOINT_SERVICES.get(endpoint)
    menu = {}
    if service is not None:
        unit = service.get("user_unit")
        if unit:
            menu["restart_unit"] = {
                "description": f"Restart the user systemd unit {unit} that serves this endpoint.",
                "argv": ["systemctl", "--user", "restart", unit], "user_env": True}
        unit = service.get("system_unit")
        if unit:
            menu["restart_unit"] = {
                "description": f"Restart the system unit {unit} that serves this endpoint.",
                "argv": ["sudo", "-n", "systemctl", "restart", unit]}
        container = service.get("container")
        if container:
            menu["restart_container"] = {
                "description": f"Restart the Docker container {container} that serves this endpoint.",
                "argv": ["docker", "restart", "--time", "30", container]}
            menu["restart_docker"] = {
                "description": "Restart the Docker daemon (restarts every container on the host).",
                "argv": ["sudo", "-n", "systemctl", "restart", "docker.service"]}
        if endpoint in P3_TUNNEL_ENDPOINTS:
            menu["restart_cloudflared"] = {
                "description": "Restart the cloudflared tunnel connector (all public hostnames).",
                "argv": ["sudo", "-n", "systemctl", "restart", "cloudflared.service"]}
    menu["none"] = {"description": "Take no action; leave it for Carter.", "argv": None}
    return menu


def _p3_jev_state(endpoint, applied_steps, packet):
    """Bounded Jev state: the endpoint, its P1 steps tonight, and the diagnosis."""
    names = P3_ENDPOINT_P1_STEPS.get(endpoint, set())
    steps = []
    for step in applied_steps:
        name = str(step.get("step", ""))
        if (name in names or step.get("service") == endpoint
                or name == "apt_upgrade" or name.startswith("auto_")):
            steps.append({k: str(step[k])[:300] for k in
                          ("step", "service", "status", "pre_version", "post_version", "error")
                          if step.get(k) not in (None, "")})
    evidence = packet.get("evidence")
    return {
        "endpoint": endpoint,
        "p1_steps_tonight": steps[:10],
        "diagnosis": str(packet.get("diagnosis", ""))[:1000],
        "evidence": [str(e)[:300] for e in evidence[:8]] if isinstance(evidence, list) else [],
    }


def _p3_state_has_secret(state):
    """Deterministic secret scan of the Jev state; a hit means it is never sent."""
    from .dotfiles import scan_diff_for_secrets
    lines = json.dumps(state, indent=1).splitlines()
    diff = ("diff --git a/p3-state b/p3-state\n+++ b/p3-state\n@@ -0,0 +1 @@\n"
            + "\n".join("+" + line for line in lines))
    return bool(scan_diff_for_secrets(diff))


def _p3_fix_question(menu):
    return {
        "type": "choice",
        "instructions": (
            "The service behind `endpoint` stopped answering its health check after "
            "tonight's updates (`p1_steps_tonight`). Given `diagnosis` and `evidence`, "
            "which single action is most likely to restore it? Choose none unless the "
            "diagnosis and evidence point to that action."),
        "criteria": {label: action["description"] for label, action in menu.items()},
    }


def _p3_jev_client():
    return jev.load_client(deadline=time.monotonic() + P3_JEV_DEADLINE_S)


def _p3_prior_fix_actions(run_dir):
    """Executed fix rows from an earlier pass of tonight's P3 (reboot resume)."""
    try:
        prior = read_json(run_dir / "03-troubleshoot.json").get("fix_actions") or []
    except (OSError, ValueError, AttributeError):
        return []
    return [r for r in prior if isinstance(r, dict) and r.get("executed") is True
            and isinstance(r.get("argv"), list)]


def _p3_apply_fix_menu(regressed_names, applied_steps, packet, client, prior=()):
    """Ask Jev per regressed endpoint; run at most one menu action each, 3 per night.

    Jev unavailable, an off-menu choice, "none" or confidence below
    P3_FIX_MIN_CONFIDENCE all mean no action.  Commands are fixed argv lists.
    ``prior`` holds actions already executed tonight; they count against both
    limits and are carried into the result.
    """
    rows = list(prior)
    ran = {tuple(r["argv"]) for r in prior}
    handled = {r.get("endpoint") for r in prior}
    for endpoint in regressed_names:
        if endpoint in handled:
            continue
        menu = _p3_fix_menu(endpoint)
        row = {"endpoint": endpoint, "menu": sorted(menu), "choice": None,
               "confidence": None, "executed": False}
        rows.append(row)
        if len(menu) == 1:
            row["reason"] = "no fix on the menu for this endpoint"
            continue
        if client is None:
            row["reason"] = "jev unavailable: no_key"
            continue
        state = _p3_jev_state(endpoint, applied_steps, packet)
        if _p3_state_has_secret(state):
            row["reason"] = "secret-like content in diagnosis; not sent to Jev"
            continue
        try:
            answers = client.ask(P3_JEV_PURPOSE, state, {"action": _p3_fix_question(menu)})
        except jev.JevUnavailable as exc:
            row["reason"] = f"jev unavailable: {exc.reason}"
            continue
        answer = answers.get("action") if isinstance(answers, dict) else None
        answer = answer if isinstance(answer, dict) else {}
        choice, confidence = answer.get("choice"), answer.get("confidence")
        row["choice"] = str(choice)[:80] if choice is not None else None
        row["confidence"] = confidence if isinstance(confidence, (int, float)) else None
        action = menu.get(choice) if isinstance(choice, str) else None
        if action is None:
            row["reason"] = "choice is not on this endpoint's menu"
        elif action["argv"] is None:
            row["reason"] = "Jev chose no action"
        elif row["confidence"] is None or row["confidence"] < P3_FIX_MIN_CONFIDENCE:
            row["reason"] = f"confidence below {P3_FIX_MIN_CONFIDENCE}"
        elif len(ran) >= P3_FIX_MAX_ACTIONS:
            row["reason"] = f"nightly limit of {P3_FIX_MAX_ACTIONS} actions reached"
        elif tuple(action["argv"]) in ran:
            row["reason"] = "same action already ran tonight for another endpoint"
        else:
            argv = list(action["argv"])
            kwargs = {"env": user_env()} if action.get("user_env") else {}
            out, err, code = run_capture_ok(argv, timeout=P3_FIX_TIMEOUT, **kwargs)
            ran.add(tuple(argv))
            row.update(executed=True, argv=argv, exit_code=code,
                       output_tail=f"{out}\n{err}".strip()[-500:])
            print(f"[P3] fix menu: {endpoint} -> {choice} "
                  f"(confidence {row['confidence']:.2f}, exit {code})")
    return rows



def phase_3_troubleshoot(run_dir, dry_run=False):
    """Phase 3: diagnose endpoints that regressed after P1, then run the code-owned fix menu.

    Loads yesterday's validation to detect regressions (was-ok, now-not-ok).
    Generalizes prompt with all regressed endpoints.
    Triggers only when an endpoint that was ok yesterday is now failing.
    """
    if dry_run:
        print("[P3] DRY RUN — skipping troubleshooting agent")
        write_json(run_dir / "03-troubleshoot.json", {"triggered": False, "dry_run": True})
        return

    validation_path = run_dir / "02-validation.json"
    applied_path = run_dir / "01-applied.json"
    if not validation_path.exists() or not applied_path.exists():
        print("[P3] skipped — no validation or applied data")
        return

    validation = read_json(validation_path)
    applied = read_json(applied_path)
    # A reboot resume re-runs P3: tonight's executed fixes still count.
    prior_fixes = _p3_prior_fix_actions(run_dir)

    # Check for P1 mutations — any update step that actually changed state.
    # Covers apt auto-pkgs, freshrss/open-webui tag bumps, and the herdr/omp/searxng
    # self-updates so the troubleshooting fallback fires if one of them regresses.
    mutations = sum(1 for s in applied.get("steps", []) if _p1_deploy_step_ok(s))
    if not mutations:
        print("[P3] skipped — no packages were actually upgraded")
        write_json(run_dir / "03-troubleshoot.json",
                   {"triggered": False, "reason": "no_mutations"})
        return

    # Build today's endpoint status map
    today_status = {}
    for c in validation.get("checks", []):
        if c.get("name", "").startswith("endpoint_"):
            today_status[c["name"]] = c.get("status", "?")

    # Load yesterday's validation for regression detection
    prev_date = prev_workday(datetime.now())
    prev_date_str = prev_date.strftime("%Y-%m-%d")
    prev_validation_path = RUN_DIR_BASE / prev_date_str / "02-validation.json"
    yesterday_status = {}
    if prev_validation_path.exists():
        try:
            prev_validation = read_json(prev_validation_path)
            for c in prev_validation.get("checks", []):
                if c.get("name", "").startswith("endpoint_"):
                    yesterday_status[c["name"]] = c.get("status", "?")
        except Exception as e:
            print(f"[P3] warning — could not read yesterday's validation: {e}")

    # Find regressions: yesterday ok, today not ok
    regressed = []
    for name, today_s in sorted(today_status.items()):
        yesterday_s = yesterday_status.get(name)
        if yesterday_s == "ok" and today_s != "ok":
            regressed.append(name)

    if not regressed:
        print("[P3] skipped — no endpoint regressions")
        data = {"triggered": False, "reason": "no_regressions",
                "today_status": today_status, "yesterday_status": yesterday_status,
                "mutations": mutations}
        if prior_fixes:
            data["fix_actions"] = prior_fixes
        write_json(run_dir / "03-troubleshoot.json", data)
        return

    regressed_names = [r.replace("endpoint_", "") for r in regressed]
    print(f"[P3] TROUBLESHOOT — {len(regressed)} endpoint(s) regressed: {regressed_names}")

    # Gather diagnostic context for regressed services
    diag = {
        "applied_steps": applied.get("steps", []),
        "validation": today_status,
        "yesterday_validation": yesterday_status,
        "regressed": regressed,
        "containers": run_capture(
            ["docker", "ps", "-a", "--format", "{{.Names}} {{.Status}} {{.Image}}"]),
        "listeners": run_capture(["sudo", "-n", "ss", "-Htlnp"]),
        "docker_journal": run_capture(
            ["sudo", "journalctl", "-u", "docker", "--since", "30 min ago",
             "--no-pager", "-n", "80"]),
    }

    # Add journal output for each regressed service
    for name in regressed_names:
        safe = name.replace("-", "_")
        journal_out = run_capture(
            ["journalctl", "--user", "-u", name, "--since", "30 min ago",
             "--no-pager", "-n", "50"], env=user_env())
        if not journal_out:
            journal_out = run_capture(
                ["sudo", "journalctl", "-u", name, "--since", "30 min ago",
                 "--no-pager", "-n", "50"])
        diag[f"{safe}_journal"] = journal_out


    # Build diagnostic journal sections for the prompt
    journal_sections = ""
    for key, val in sorted(diag.items()):
        if key.endswith("_journal") and key not in ("docker_journal",):
            journal_sections += f"- {key}:\n{val}\n\n"

    regressed_list = "\n".join(f"  - {r}" for r in regressed)
    troubleshoot_prompt = f"""
You are a homelab troubleshooter in DIAGNOSE-ONLY mode. The nightly steward auto-applied
updates and now the following endpoints have REGRESSED (were healthy yesterday,
unhealthy today):

{regressed_list}

Your job: work out the most likely cause of each regression and the next step Carter
should take. You cannot change anything: your only tools are read, grep, and glob
(no shell, no network). Base the diagnosis on the diagnostics below and on config or
log files you can read. Never claim to have fixed, restarted, or killed anything.

After you answer, the steward's own code (not you) may run at most one action per
endpoint from a fixed menu: restart the endpoint's systemd unit or Docker container,
restart Docker, or restart cloudflared. It picks from your diagnosis and evidence and
re-validates afterwards. So name the failing component precisely and cite the exact
evidence, but never say or predict that anything was or will be fixed.

WHAT CHANGED (P1 applied steps):
{json.dumps(diag["applied_steps"], indent=2)}

VALIDATION TODAY:
{json.dumps(diag["validation"], indent=2)}

YESTERDAY (was healthy):
{json.dumps(diag.get("yesterday_validation", {}), indent=2)}

DIAGNOSTICS:
- Containers:
{diag["containers"]}
- Listening sockets (ss -tlnp):
{diag["listeners"]}
- Docker journal:
{diag["docker_journal"]}
{journal_sections}
Common causes: orphaned docker-proxy holding a port, docker daemon failed to restart
after an engine upgrade, cloudflared tunnel down, config mismatch, process crash.

Return a fenced ```json packet:
{{"status": "diagnosed"|"uncertain",
 "diagnosis": "most likely cause in one sentence",
 "next_steps": ["concrete step Carter should take", ...],
 "evidence": ["file/log line or diagnostic that supports the diagnosis", ...]}}
"""

    agent_output = ""
    agent_packet = {}
    try:
        agent_output = _call_omp_p(troubleshoot_prompt, timeout=600, mode="json",
                                   tools=READ_ONLY_TOOLS)
        agent_packet = _extract_json(agent_output, "troubleshoot packet")
    except Exception as e:
        agent_packet = {"status": "agent-failed", "diagnosis": str(e),
                        "next_steps": [], "evidence": []}

    # Code-owned fix menu: Jev picks at most one menu action per endpoint from
    # the diagnosis; no diagnosis means no action.
    if agent_packet.get("status") in ("diagnosed", "uncertain"):
        fix_actions = _p3_apply_fix_menu(
            regressed_names, applied.get("steps", []), agent_packet, _p3_jev_client(),
            prior=prior_fixes)
    else:
        handled = {r.get("endpoint") for r in prior_fixes}
        fix_actions = prior_fixes + [
            {"endpoint": name, "choice": None, "confidence": None,
             "executed": False, "reason": "no diagnosis"}
            for name in regressed_names if name not in handled]

    # Re-validation alone decides whether the regressions cleared.
    re_validation = phase_2_validate(run_dir)
    write_json(run_dir / "02b-validation.json", re_validation)
    re_status = {c.get("name"): c.get("status") for c in re_validation.get("checks", [])}
    for row in fix_actions:
        if row["executed"]:
            healthy = re_status.get(f"endpoint_{row['endpoint']}") == "ok"
            row["outcome"] = "healthy after re-validation" if healthy else "still failing"

    all_healthy = True
    for c in re_validation.get("checks", []):
        if c.get("name") in regressed and c.get("status") != "ok":
            all_healthy = False

    def _str_list(value):
        return [str(v)[:500] for v in value] if isinstance(value, list) else []

    data = {
        "triggered": True,
        "mode": "diagnose-then-fix-menu",
        "regressed": regressed,
        "agent_status": agent_packet.get("status", "unknown"),
        "diagnosis": str(agent_packet.get("diagnosis", ""))[:1000],
        "next_steps": _str_list(agent_packet.get("next_steps")),
        "evidence": _str_list(agent_packet.get("evidence")),
        "agent_raw": agent_output[:4000],
        "re_validation_healthy": all_healthy,
        "fix_actions": fix_actions,
    }
    if not all_healthy:
        data["final_diagnostics"] = {
            "containers": run_capture(
                ["docker", "ps", "-a", "--format", "{{.Names}} {{.Status}} {{.Image}}"]),
        }
    write_json(run_dir / "03-troubleshoot.json", data)
    print(f"[P3] done -> {run_dir / '03-troubleshoot.json'} "
          f"(agent: {agent_packet.get('status')}, regressed: {regressed_names})")
    return data


# ── P3a: deterministic report-only host drift checks ─────────────────

UFW_EXPECTED_RULES = HOME / "system-config" / "ufw-expected-rules.txt"
UFW_ADDED_HEADER = "Added user rules"


def _parse_ufw_added(output):
    """Rule lines printed by `ufw show added`, without the header."""
    rules = []
    for line in (output or "").splitlines():
        line = line.strip()
        if not line or line.startswith(UFW_ADDED_HEADER):
            continue
        rules.append(line)
    return rules


def _read_expected_ufw_rules(path=UFW_EXPECTED_RULES):
    """Expected rules, one `ufw ...` line each; None when the file is missing."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    return [
        line.strip() for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def ufw_rule_drift(expected_path=None):
    """Compare live `ufw show added` against the expected list. Never mutates."""
    expected_path = Path(expected_path or UFW_EXPECTED_RULES)
    expected = _read_expected_ufw_rules(expected_path)
    if expected is None:
        return {"status": "attention_needed",
                "reason": "expected rule list missing",
                "expected_path": str(expected_path)}
    out, err, rc = run_capture_ok(["sudo", "-n", "ufw", "show", "added"], timeout=30)
    if rc != 0 or UFW_ADDED_HEADER not in out:
        return {"status": "error",
                "reason": f"ufw show added failed (rc={rc}): {(err or out)[:300]}",
                "expected_path": str(expected_path)}
    live = _parse_ufw_added(out)
    missing = [rule for rule in expected if rule not in live]
    extra = [rule for rule in live if rule not in expected]
    return {
        "status": "drift" if missing or extra else "ok",
        "expected_path": str(expected_path),
        "live_count": len(live),
        "expected_count": len(expected),
        "missing": missing,
        "extra": extra,
    }


def phase_3a_remediation(run_dir, dry_run=False):
    """Phase 3a: deterministic, report-only drift checks — no LLM, no mutation.

    Checks:
    1. Documented ports held by an orphaned docker-proxy (reported, never killed)
    2. UFW rule drift: `ufw show added` vs ~/system-config/ufw-expected-rules.txt
    3. Open WebUI → host 8082 reachability probe (health signal)
    """
    print("[P3a] report-only drift checks")

    DOCUMENTED_PORTS = {
        33099: "blog",
        48100: "open-webui",
        8080: "searxng",
        8081: "llm-proxy",
        8082: "opencode-go-proxy",
    }

    docker_proxy_results = []

    # ── 1. Orphaned docker-proxy check (report only) ──
    ss_out = run_capture(["sudo", "-n", "ss", "-Htlnp"])
    for port, container_name in DOCUMENTED_PORTS.items():
        result = {"port": port, "container": container_name, "action": "ok"}
        try:
            matching_lines = [l for l in ss_out.splitlines()
                              if re.search(rf":{port}\s", l)]
            if not matching_lines:
                result["state"] = "no_listener"
                docker_proxy_results.append(result)
                continue
            line = matching_lines[0].strip()
            result["state"] = line
            if "docker-proxy" not in line:
                # Native services (e.g. the 8081/8082 proxies) own their ports.
                result["reason"] = "held by a non-docker process"
            else:
                publishers = run_capture(
                    ["docker", "ps", "--filter", f"publish={port}",
                     "--format", "{{.Names}} {{.Status}}"])
                result["publisher"] = publishers or "none"
                if not publishers:
                    result["action"] = "attention_needed"
                    result["reason"] = ("docker-proxy holds the port but no running "
                                        "container publishes it; inspect manually")
        except Exception as e:
            result["action"] = "error"
            result["error"] = str(e)
        docker_proxy_results.append(result)

    # ── 2. UFW rule drift (report only) ──
    try:
        ufw_drift = ufw_rule_drift()
    except Exception as e:
        ufw_drift = {"status": "error", "reason": str(e)[:300]}

    # ── 3. Open WebUI → host 8082 reachability (read-only probe) ──
    _, _, probe_rc = run_capture_ok(["docker", "exec", "open-webui", "curl", "-sf",
                                     "-o", "/dev/null", "--connect-timeout", "5",
                                     "http://host.docker.internal:8082/health"])
    probe_ok = probe_rc == 0
    bridge_probe = {"from": "open-webui", "target": "host.docker.internal:8082",
                    "status": "ok" if probe_ok else "unreachable"}

    data = {
        "report_only": True,
        "docker_proxy": docker_proxy_results,
        "ufw_drift": ufw_drift,
        "bridge_probe": bridge_probe,
    }
    write_json(run_dir / "03a-remediation.json", data)
    print(f"[P3a] done -> {run_dir / '03a-remediation.json'} "
          f"(ufw: {ufw_drift.get('status')}, 8082 probe: {bridge_probe['status']})")
    return data


# ── P4: heartbeat ────────────────────────────────────────────────────


def _parse_bundle_audit(output):
    """Advisories from `bundle-audit check` output: [{name, version, id, criticality}]."""
    advisories, current = [], {}
    for line in (output or "").splitlines():
        key, _, value = line.partition(":")
        key, value = key.strip(), value.strip()
        if key == "Name":
            current = {"name": value}
            advisories.append(current)
        elif current and key == "Version":
            current["version"] = value
        elif current and key in ("CVE", "GHSA") and "id" not in current:
            current["id"] = value
        elif current and key == "Criticality":
            current["criticality"] = value
    return advisories


def _bundle_audit(app_dir):
    """One-line bundle-audit verdict for a Ruby app directory."""
    out, err, rc = run_capture_ok(
        ["bundle-audit", "check", str(app_dir)], timeout=120,
        env={**os.environ, "PATH": f"{STEWARD_PATH}:{os.environ.get('PATH', '')}"},
    )
    if rc == 0:
        return "no vulnerabilities found"
    advisories = _parse_bundle_audit(out)
    if rc == 1 and advisories:
        listed = ", ".join(
            f"{a['name']} {a.get('version', '?')} ({a.get('id', '?')}, {a.get('criticality', '?')})"
            for a in advisories[:12]
        )
        more = f", +{len(advisories) - 12} more" if len(advisories) > 12 else ""
        return f"{len(advisories)} vulnerabilities: {listed}{more}"
    return f"bundle-audit error (rc={rc}): {(err or out).strip()[:300]}"


def _systemctl_unit_name(token):
    """Normalize a systemctl list/failed token to a unit name.

    Non-plain list-units prefixes failed/not-found rows with a glyph (often '●'),
    so naive split()[0] returns the glyph and drops the real unit from the set —
    which then falsely flags oneshot units like hyperliquid-sdk.service as missing.
    Prefer --plain when collecting; this helper still defends mixed inputs.
    """
    if not token:
        return ""
    tok = token.strip()
    if tok in {"●", "○", "×", "*"}:
        return ""
    # Strip leading non-unit junk (UTF-8 bullet etc.)
    tok = re.sub(r"^[^\w@.\\-]+", "", tok)
    return tok


def _parse_systemctl_unit_names(output, suffixes=(".service", ".timer")):
    """Extract unit names from systemctl list-units / --failed output."""
    names = set()
    for line in (output or "").splitlines():
        parts = line.split()
        if not parts:
            continue
        unit = ""
        for tok in parts[:3]:
            cand = _systemctl_unit_name(tok)
            if cand.endswith(suffixes):
                unit = cand
                break
        if unit:
            names.add(unit)
    return names


def _parse_failed_unit_lines(output):
    """Return structured failed-unit rows from systemctl --failed --no-legend."""
    rows = []
    for line in (output or "").splitlines():
        raw = line.strip()
        if not raw:
            continue
        parts = raw.split()
        unit = ""
        for tok in parts[:3]:
            cand = _systemctl_unit_name(tok)
            if cand.endswith((".service", ".timer", ".socket", ".target", ".path", ".mount")):
                unit = cand
                break
        if not unit:
            continue
        rows.append({"unit": unit, "raw": raw})
    return rows


def _clear_stale_oneshot_failures(failed_rows, env):
    """Reset oneshot units stuck failed after a later successful run.

    systemd leaves Type=oneshot units in failed until reset-failed. If the
    hyperliquid state file records a Last run newer than the unit's last exit,
    clear the stale failure so heartbeat/email stop alarming.
    """
    cleared = []
    kept = []
    for row in failed_rows:
        unit = row.get("unit") or ""
        if unit != "hyperliquid-sdk.service":
            kept.append(row)
            continue
        state_path = HOME / "agent-state" / "hyperliquid-sdk.md"
        if not state_path.exists():
            kept.append(row)
            continue
        try:
            text = state_path.read_text(errors="replace")
        except OSError:
            kept.append(row)
            continue
        m = re.search(r"\*\*Last run:\*\*\s*(\d{4}-\d{2}-\d{2})", text)
        if not m:
            kept.append(row)
            continue
        try:
            last_run = datetime.strptime(m.group(1), "%Y-%m-%d").date()
        except ValueError:
            kept.append(row)
            continue
        exit_ts = run_capture(
            ["systemctl", "--user", "show", unit,
             "-p", "ExecMainExitTimestamp", "--value"],
            env=env,
        ).strip()
        exit_date = None
        if exit_ts and exit_ts not in ("", "n/a", "0"):
            dm = re.search(r"(\d{4}-\d{2}-\d{2})", exit_ts)
            if dm:
                try:
                    exit_date = datetime.strptime(dm.group(1), "%Y-%m-%d").date()
                except ValueError:
                    exit_date = None
        if exit_date is None or not (last_run > exit_date):
            kept.append(row)
            continue
        run_capture(["systemctl", "--user", "reset-failed", unit], env=env)
        still = run_capture(
            ["systemctl", "--user", "is-failed", unit], env=env).strip()
        if still == "failed":
            kept.append(row)
            continue
        cleared.append({
            "unit": unit,
            "reason": f"state Last run {last_run} > unit exit {exit_date}",
        })
        print(f"  cleared stale failed unit {unit} (Last run {last_run} > exit {exit_date})")
    return kept, cleared


def phase_4_heartbeat(run_dir):
    """Phase 4: extended heartbeat block."""
    print("[P4] heartbeat checks")
    env = user_env()

    # Failed systemd units (plain output avoids ● glyph prefix)
    failed_user = run_capture(
        ["systemctl", "--user", "--failed", "--no-legend", "--plain"], env=env)
    failed_system = run_capture(
        ["systemctl", "--failed", "--no-legend", "--plain"])
    failed_user_rows = _parse_failed_unit_lines(failed_user)
    failed_system_rows = _parse_failed_unit_lines(failed_system)
    failed_user_rows, cleared_failed = _clear_stale_oneshot_failures(
        failed_user_rows, env)

    # LLM stack health
    llm_health = run_capture(["curl", "-s", "http://127.0.0.1:8081/health"])
    fallback_headers = run_capture(["curl", "-sI", "http://127.0.0.1:8081/health"])
    falling_back = "X-Fallback: true" in fallback_headers

    # Backup recency
    backup_ts = run_capture(
        ["systemctl", "--user", "show", "homelab-backup", "-p", "ExecMainStartTimestamp"],
        env=env,
    ).replace("ExecMainStartTimestamp=", "").strip()


    # Disk usage
    disk_df = run_capture(["df", "-h", "/"])
    docker_df = run_capture(["docker", "system", "df"])

    # Journal disk usage
    journal_usage = run_capture(["journalctl", "--disk-usage"])

    # NVMe SMART health
    smart_data = {}
    smartctl_path = "/usr/sbin/smartctl"
    if Path(smartctl_path).exists() and Path("/dev/nvme0n1").exists():
        out, stderr, rc = run_capture_ok(["sudo", smartctl_path, "-a", "/dev/nvme0n1"], timeout=30)
        wear_pct = ""
        spare = ""
        spare_thresh = ""
        media_errors = ""
        error_log = ""
        for line in out.splitlines():
            if "Percentage Used:" in line:
                wear_pct = line.split(":")[-1].strip()
            elif "Available Spare:" in line:
                spare = line.split(":")[-1].strip()
            elif "Available Spare Threshold:" in line:
                spare_thresh = line.split(":")[-1].strip()
            elif "Media and Data Integrity Errors:" in line:
                media_errors = line.split(":")[-1].strip()
            elif "Error Information Log Entries:" in line:
                error_log = line.split(":")[-1].strip()
        smart_data = {
            "wear_pct": wear_pct, "available_spare": spare,
            "spare_threshold": spare_thresh, "media_errors": media_errors,
            "error_log_entries": error_log,
            "raw_output": out[:2000],
        }
    else:
        smart_data = {"status": "skipped", "reason": "smartctl or /dev/nvme0n1 not found"}

    # Reboot required
    reboot_needed = (Path("/var/run/reboot-required")).exists()
    kernel_ver = run_capture(["uname", "-r"])

    # Snap refresh
    snap_list = run_capture(["snap", "refresh", "--list"])

    # Memory pressure / OOM risk
    mem_free = run_capture(["free", "-h"])
    mem_pressure = run_capture(["cat", "/proc/pressure/memory"]) if Path("/proc/pressure/memory").exists() else ""
    mem_avail = ""
    for line in mem_free.splitlines():
        if "Mem:" in line:
            parts = line.split()
            if len(parts) >= 7:
                mem_avail = parts[6]

    # TLS cert expiry for 3 hostnames
    tls_certs = {}
    for host in ["blog.carter2099.com", "chat.carter2099.com"]:
        try:
            tls_out = run_capture(
                ["bash", "-c",
                 f"echo | openssl s_client -connect {host}:443 -servername {host} "
                 f"2>/dev/null | openssl x509 -noout -enddate"],
                timeout=15,
            )
            tls_certs[host] = tls_out.strip() if tls_out else "error"
        except Exception as e:
            tls_certs[host] = f"error: {e}"

    # DNS resolution of homelab hostnames
    dns_hostnames = [
        "blog.carter2099.com", "chat.carter2099.com",
        "freshrss.carter2099.com", "hooks.carter2099.com",
    ]
    dns_results = {}
    for host in dns_hostnames:
        out = run_capture(["dig", "+short", host], timeout=10)
        dns_results[host] = {"resolves": bool(out), "records": out.splitlines() if out else []}

    # /etc/hosts gamingrig entry
    hosts_gamingrig = run_capture(["getent", "hosts", "gamingrig"])
    hosts_gamingrig_ok = bool(hosts_gamingrig and not hosts_gamingrig.startswith("error"))

    # docker-user-rules iptables verification
    iptables_docker_user = run_capture(["sudo", "iptables", "-L", "DOCKER-USER", "-n"])
    iptables_ok = "DROP" in iptables_docker_user and "0.0.0.0/0" in iptables_docker_user

    # User-unit inventory vs documented set
    documented_units = {
        "homelab-backup.service", "homelab-backup.timer",
        "notify-failure@.service",
        "digests-daily.service", "digests-daily.timer",
        "hyperliquid-sdk.service", "hyperliquid-sdk.timer",
        "homelab-steward.service", "homelab-steward.timer",
        "homelab-steward-resume.service", "homelab-steward-resume.timer",
        "opencode-go-proxy.service",
        "llm-proxy.service",
        "dependabot-webhook.service",
        "homelab-backup-restore-drill.service", "homelab-backup-restore-drill.timer",
    }
    all_user_units = run_capture(
        ["systemctl", "--user", "list-units", "--all", "--no-legend", "--plain"],
        env=env,
    )
    # Prefer unit-files for "installed"; list-units can miss inactive oneshots.
    # Union both so documented oneshots aren't false-missing.
    user_unit_files_out = run_capture(
        ["systemctl", "--user", "list-unit-files", "--no-legend", "--plain"],
        env=env,
    )
    active_units = _parse_systemctl_unit_names(all_user_units)
    active_units |= _parse_systemctl_unit_names(user_unit_files_out)
    extra_units = active_units - documented_units
    missing_units = documented_units - active_units

    # System unit inventory
    documented_system_units = {
        "cloudflared.service", "docker-user-rules.service", "ssh.service",
        "ufw.service", "cron.service", "containerd.service", "docker.service",
        "apparmor.service", "fstrim.timer",
    }
    all_system_units = run_capture(
        ["systemctl", "list-units", "--all", "--no-legend", "--plain"])
    system_unit_files_out = run_capture(
        ["systemctl", "list-unit-files", "--no-legend", "--plain"])
    active_system_units = _parse_systemctl_unit_names(all_system_units)
    active_system_units |= _parse_systemctl_unit_names(system_unit_files_out)
    extra_system_units = active_system_units - documented_system_units
    missing_system_units = documented_system_units - active_system_units

    # Agent-state staleness (>14d flag)
    agent_state_stale = []
    agent_state_dir = HOME / "agent-state"
    if agent_state_dir.exists():
        cutoff = datetime.now() - timedelta(days=14)
        for f in agent_state_dir.iterdir():
            if f.is_file():
                mtime = datetime.fromtimestamp(f.stat().st_mtime)
                if mtime < cutoff:
                    agent_state_stale.append({"file": f.name, "mtime": mtime.isoformat()})

    # bundle-audit: run in the app directory (bundler-audit joins --gemfile-lock
    # onto the directory, so an absolute lock path never resolves). Exit 1
    # means vulnerabilities were found; anything else non-zero is an error.
    bundle_audit = {}
    for app_name, app_dir in [
        ("blog", HOME / "blog" / "blog"),
        ("delta_neutral", HOME / "dev" / "delta_neutral"),
    ]:
        if (app_dir / "Gemfile.lock").exists():
            bundle_audit[app_name] = _bundle_audit(app_dir)
        else:
            bundle_audit[app_name] = "Gemfile.lock not found"

    # Steward self-health: last runs.log entry
    steward_self = {"status": "ok", "last_entry": None, "warning": None}
    if RUNS_LOG.exists():
        try:
            lines = RUNS_LOG.read_text().strip().splitlines()
            if lines:
                last = json.loads(lines[-1])
                steward_self["last_entry"] = last
                last_ts = datetime.fromisoformat(last.get("ts", "2000-01-01T00:00:00"))
                if (datetime.now(timezone.utc) - last_ts) > timedelta(hours=36):
                    steward_self["warning"] = "Last steward run >36h ago"
                    steward_self["status"] = "warning"
        except Exception:
            steward_self["warning"] = "Could not parse runs.log"
            steward_self["status"] = "warning"
    else:
        steward_self["warning"] = "No previous steward runs"
        steward_self["status"] = "first_run"

    # Self-drift detection
    # Endpoints: compare docker exposed ports to ENDPOINTS
    docker_ps = run_capture(["docker", "ps", "--format", "{{.Names}}\t{{.Ports}}"])
    exposed_ports = set()
    for line in docker_ps.splitlines():
        if "\t" in line:
            _, ports = line.split("\t", 1)
            for part in ports.split(", "):
                if "->" in part:
                    host_part = part.split("->")[0]
                    if ":" in host_part:
                        port_str = host_part.rsplit(":", 1)[-1]
                        try:
                            exposed_ports.add(int(port_str))
                        except ValueError:
                            pass
    endpoint_ports = set()
    for url in ENDPOINTS.values():
        m = re.search(r":(\d+)", url)
        if m:
            endpoint_ports.add(int(m.group(1)))
    extra_ports_drift = sorted(exposed_ports - endpoint_ports)
    missing_endpoints_drift = sorted(endpoint_ports - exposed_ports)

    # Unit drift: installed user units vs documented
    installed_user_units = _parse_systemctl_unit_names(user_unit_files_out)
    extra_installed_units = sorted(installed_user_units - documented_units)
    stale_documented_units = sorted(documented_units - installed_user_units)

    # AUTO_PKGS drift
    auto_pkg_installed = set()
    try:
        apt_check = run_capture(
            ["bash", "-c",
             "apt list --installed 2>/dev/null | grep -E 'docker-ce|docker-ce-cli|containerd|cloudflared'"]
        )
        for line in apt_check.splitlines():
            pkg = line.split("/")[0].strip()
            if pkg:
                auto_pkg_installed.add(pkg)
    except Exception:
        pass
    auto_pkg_extra = sorted(auto_pkg_installed - set(AUTO_PKGS))
    auto_pkg_missing = sorted(set(AUTO_PKGS) - auto_pkg_installed)

    # TLS hostname drift: compare tunnel routes to TLS-checked hostnames
    tunnel_hostnames = []
    try:
        tunnel_list = run_capture(["cloudflared", "tunnel", "list"], timeout=15)
        for line in tunnel_list.splitlines():
            parts = line.split()
            if parts and len(parts) >= 2:
                tid = parts[0]
                if tid and tid != "ID":
                    routes = run_capture(
                        ["cloudflared", "tunnel", "route", "dns", tid],
                        timeout=15,
                    )
                    for rline in routes.splitlines():
                        rparts = rline.split()
                        if rparts and "." in rparts[0]:
                            tunnel_hostnames.append(rparts[0])
                    break
    except Exception:
        pass
    tls_checked_hostnames = ["blog.carter2099.com", "chat.carter2099.com"]
    unchecked_tls = sorted(set(tunnel_hostnames) - set(tls_checked_hostnames))

    self_drift = {
        "endpoints": {
            "extra_ports": extra_ports_drift,
            "missing_endpoints": missing_endpoints_drift,
        },
        "units": {
            "extra_installed": extra_installed_units,
            "stale_documented": stale_documented_units,
        },
        "auto_pkgs": {
            "extra_installed": auto_pkg_extra,
            "missing_from_list": auto_pkg_missing,
        },
        "tls_hostnames": {
            "tunnel_hostnames": tunnel_hostnames,
            "checked_hostnames": tls_checked_hostnames,
            "unchecked": unchecked_tls,
        },
    }

    data = {
        "failed_units": {
            "user": [r["unit"] for r in failed_user_rows],
            "system": [r["unit"] for r in failed_system_rows],
            "user_raw": [r["raw"] for r in failed_user_rows],
            "system_raw": [r["raw"] for r in failed_system_rows],
            "cleared": cleared_failed,
        },
        "llm_stack": {"health": llm_health, "falling_back": falling_back},
        "backup": {"last_run": backup_ts},
        "disk": {"df_root": disk_df, "docker_system_df": docker_df},
        "journal_disk_usage": journal_usage,
        "smart": smart_data,
        "reboot": {"needed": reboot_needed, "kernel": kernel_ver},
        "snap": {"refresh_list": snap_list if snap_list and "All snaps up to date" not in snap_list else ""},
        "memory": {"free_output": mem_free, "available": mem_avail, "pressure": mem_pressure},
        "tls_certs": tls_certs,
        "dns": dns_results,
        "hosts": {"gamingrig": {"resolves": hosts_gamingrig_ok, "output": hosts_gamingrig}},
        "docker_user_rules": {
            "chain_present": bool(iptables_docker_user),
            "has_drop_default": iptables_ok,
            "output": iptables_docker_user[:500],
        },
        "units": {
            "active": sorted(active_units),
            "documented": sorted(documented_units),
            "extra": sorted(extra_units),
            "missing": sorted(missing_units),
            "system": {
                "active": sorted(active_system_units),
                "documented": sorted(documented_system_units),
                "extra": sorted(extra_system_units),
                "missing": sorted(missing_system_units),
            },
        },
        "agent_state_stale": agent_state_stale,
        "bundle_audit": bundle_audit,
        "steward_self": steward_self,
        "self_drift": self_drift,
    }
    write_json(run_dir / "04-heartbeat.json", data)
    print(f"[P4] done -> {run_dir / '04-heartbeat.json'}")
    return data

