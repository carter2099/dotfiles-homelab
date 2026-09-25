"""Daily News runtime, OMP adapters, and shared article cache."""
from __future__ import annotations

import hashlib
import inspect
import json
import os
import re
import subprocess
import time
import uuid
from datetime import date, datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from typing import Any

import requests

try:
    import yaml
except ImportError:  # pragma: no cover - preflight reports missing dependency
    yaml = None

from workflow_state import (
    WorkflowState,
    atomic_write_json,
    atomic_write_text,
    canonical_fingerprint,
    file_sha256,
)
from .contracts import normalize_url as _normalize_url

DIGESTS_DIR = Path.home() / "digests"

TEMPLATE_PATH = DIGESTS_DIR / "template.html"

DIGEST_OMP_SANDBOX = Path.home() / "scripts" / "digest-omp-sandbox.ts"

DIGEST_OMP_CONFIG = Path.home() / ".omp/agent/daily-news-headless.yml"

ARTICLE_CACHE_DIR = DIGESTS_DIR / ".article-cache"

ATTENTION_SNAPSHOT_DIR = DIGESTS_DIR / ".attention-snapshot"

ATTENTION_ARCHIVE_DIR = DIGESTS_DIR / "news" / "attention"


LLM_PROXY_URL = "http://localhost:8081/v1/chat/completions"

MODEL = "deepseek-v4.1-flash"                   # API primary

MODEL_FALLBACK = "mimo-v2.5"                    # API fallback via opencode-go

MODEL_REVIEWER = "deepseek-v4.1-flash"          # separate critic pass

DEFAULT_TIMEOUT = 900

EDITORIAL_TIMEOUT = 300

INTRO_TIMEOUT = 90

RESEARCH_TIMEOUT = 1800

FETCH_TIMEOUT = 900

TEST_MODE: bool = False
TEST_ROOT: Path | None = None
TEST_LABEL: str | None = None

MODEL_OVERRIDE: str | None = None

_MODEL_PROVIDER_CACHE: dict[str, dict] = {}

_OMP_MODELS_YML = Path.home() / ".omp" / "agent" / "models.yml"

_OMP_CONFIG_YML = Path.home() / ".omp" / "agent" / "config.yml"

def _load_providers() -> dict[str, dict]:
    """Load provider definitions from omp's models.yml + config.yml.

    Returns {provider_name: {baseUrl, models: set[str]}}.
    """
    providers: dict[str, dict] = {}

    # models.yml has explicit model lists per provider
    if _OMP_MODELS_YML.exists() and yaml:
        raw = yaml.safe_load(_OMP_MODELS_YML.read_text())
        for pname, pconf in (raw or {}).get("providers", {}).items():
            models = set()
            for m in (pconf.get("models") or []):
                mid = (m.get("id") or "").strip()
                if mid:
                    models.add(mid)
            providers[pname] = {
                "baseUrl": (pconf.get("baseUrl") or "").rstrip("/"),
                "models": models,
            }

    # config.yml may declare additional providers (e.g. local-llm)
    if _OMP_CONFIG_YML.exists() and yaml:
        raw = yaml.safe_load(_OMP_CONFIG_YML.read_text())
        for pname, pconf in (raw or {}).get("providers", {}).items():
            if pname not in providers:
                providers[pname] = {
                    "baseUrl": (pconf.get("baseUrl") or "").rstrip("/"),
                    "models": set(),
                }

    # Infer opencode-go provider from modelRoles if not present
    if _OMP_CONFIG_YML.exists() and yaml:
        raw = yaml.safe_load(_OMP_CONFIG_YML.read_text())
        for role, model_spec in (raw or {}).get("modelRoles", {}).items():
            if "/" in (model_spec or ""):
                prov = model_spec.split("/")[0]
                if prov not in providers:
                    providers[prov] = {
                        "baseUrl": f"http://localhost:8082/v1",
                        "models": set(),
                    }

    return providers

def _detect_model_provider(model_id: str) -> dict:
    """Return {provider, chat_url} for a model by reading omp's models.yml.

    Result is cached so the file is only parsed once.
    Falls back to local-llm on any error or unknown model.
    """
    if model_id in _MODEL_PROVIDER_CACHE:
        return _MODEL_PROVIDER_CACHE[model_id]

    providers = _load_providers()

    # Try exact model match in a provider's explicit list
    for pname, pinfo in providers.items():
        if model_id in pinfo["models"]:
            info = {
                "provider": pname,
                "chat_url": f"{pinfo['baseUrl']}/chat/completions",
            }
            _MODEL_PROVIDER_CACHE[model_id] = info
            return info

    # Handle qualified name (provider/model)
    if "/" in model_id:
        prov, mname = model_id.split("/", 1)
        if prov in providers:
            info = {
                "provider": prov,
                "chat_url": f"{providers[prov]['baseUrl']}/chat/completions",
            }
            _MODEL_PROVIDER_CACHE[model_id] = info
            return info

    # Fallback: assume opencode-go (primary API provider for digest models)
    # Previously fell back to local-llm, which caused silent routing of API models
    # (e.g. deepseek-v4.1-flash, mimo-v2.5) to the gaming rig's llama.cpp — resulting in
    # command failures when the local provider didn't have those models.
    if providers and "opencode-go" in providers:
        fb = {
            "provider": "opencode-go",
            "chat_url": f"{providers['opencode-go']['baseUrl']}/chat/completions",
        }
    else:
        fb = {
            "provider": "opencode-go",
            "chat_url": "http://localhost:8082/v1/chat/completions",
        }
    _MODEL_PROVIDER_CACHE[model_id] = fb
    return fb

def _effective_model(requested: str) -> str:
    """Return the effective model, respecting --model override."""
    return MODEL_OVERRIDE if MODEL_OVERRIDE else requested

MAX_PARALLEL_RESEARCH = 2

MAX_PARALLEL_FETCH = 2

ARTICLE_CACHE_TTL_HOURS = 24

ARTICLE_CACHE_VERSION = 1

FETCH_PROMPT_VERSION = 3

SEARXNG_URL = "http://localhost:8080"

HEALTH_LOG_PATH = DIGESTS_DIR / ".search-health.log"

ATTENTION_HEALTH_LOG_PATH = DIGESTS_DIR / ".attention-health.log"

MAX_ENGINE_ERRORS_BEFORE_WARN = 100  # per-engine errors observed in 1h

MIN_WORKING_ENGINES = 2               # minimum engines returning results

# Attention monitor thresholds (see check_attention_health)
ATTENTION_MIN_SOURCE_AVAILABILITY = 0.6  # snapshot sources returning data across the window
ATTENTION_HEALTH_WINDOW_RUNS = 5         # records considered for sustained-degradation judgment

def configure_test_mode(test_root: Path | None = None) -> None:
    """Route every mutable shared cache and monitor artifact under the test root."""
    global TEST_MODE, TEST_ROOT, ARTICLE_CACHE_DIR, ATTENTION_SNAPSHOT_DIR
    global ATTENTION_ARCHIVE_DIR, HEALTH_LOG_PATH, ATTENTION_HEALTH_LOG_PATH

    TEST_MODE = True
    root = test_root or DIGESTS_DIR / "test"
    TEST_ROOT = root
    ARTICLE_CACHE_DIR = root / ".article-cache"
    ATTENTION_SNAPSHOT_DIR = root / ".attention-snapshot"
    ATTENTION_ARCHIVE_DIR = root / "news" / "attention"
    HEALTH_LOG_PATH = root / ".search-health.log"
    ATTENTION_HEALTH_LOG_PATH = root / ".attention-health.log"

def check_search_health(label: str = "") -> dict[str, Any]:
    """Check the fresh-news SearXNG fallback without gating the primary provider.

    Returns:
        {
            "ok": True/False,
            "results": count,
            "engines_working": [names],
            "engines_suspended": [(name, reason), ...],
            "recent_errors": count (1h),
            "recommendation": "ok" | "warn",
        }
    """
    status: dict[str, Any] = {
        "ok": False, "results": 0, "engines_working": [],
        "engines_suspended": [], "recent_errors": 0,
        "recommendation": "ok", "label": label,
        "query": "artificial intelligence", "time_range": "day",
        "categories": "news",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    try:
        # Test the same time-filtered news path digest discovery depends on.
        # A generic unfiltered query can look healthy while every fresh-news
        # query returns zero results.
        resp = requests.get(
            f"{SEARXNG_URL}/search",
            params={
                "q": status["query"],
                "format": "json",
                "language": "en",
                "time_range": status["time_range"],
                "categories": status["categories"],
            },
            timeout=20,
        )
        resp.raise_for_status()
        data = resp.json()
        results = data.get("results", [])
        status["results"] = len(results)

        engines_seen: set[str] = set()
        for result in results:
            engines_seen.update(result.get("engines", []))
            if result.get("engine"):
                engines_seen.add(result["engine"])
        status["engines_working"] = sorted(engines_seen)

        unresponsive = data.get("unresponsive_engines", [])
        status["engines_suspended"] = [
            {"engine": e[0], "reason": e[1]} for e in unresponsive
        ]

        # Check recent SearXNG errors. Docker writes container logs to stderr.
        try:
            result = subprocess.run(
                ["docker", "logs", "searxng", "--since", "1h"],
                capture_output=True, text=True, timeout=10,
            )
            log_output = result.stdout + result.stderr
            status["recent_errors"] = log_output.count("ERROR:searx.engines")
        except Exception:
            status["recent_errors"] = -1  # couldn't check

        # SearXNG is a fallback. Degradation is observable but must not block
        # successful research from the primary provider.
        working_count = len(status["engines_working"])
        suspended_count = len(status["engines_suspended"])

        if status["results"] == 0 or working_count == 0:
            status["recommendation"] = "warn"
            status["ok"] = False
        elif working_count < MIN_WORKING_ENGINES and suspended_count > 3:
            status["recommendation"] = "warn"
            status["ok"] = False
        elif suspended_count >= 3 or status.get("recent_errors", 0) > MAX_ENGINE_ERRORS_BEFORE_WARN:
            status["recommendation"] = "warn"
            status["ok"] = True
        else:
            status["recommendation"] = "ok"
            status["ok"] = True

    except Exception as e:
        status["error"] = str(e)[:200]
        status["recommendation"] = "warn"
        status["ok"] = False

    # 5. Log to health file
    try:
        with open(HEALTH_LOG_PATH, "a") as f:
            f.write(json.dumps(status) + "\n")
    except Exception:
        pass

    # 6. Print summary
    emoji = {"ok": "✓", "warn": "⚠"}.get(status["recommendation"], "?")
    print(f"  [health:{label}] {emoji} {status['results']} results from "
          f"{status['engines_working']} | "
          f"{len(status['engines_suspended'])} suspended | "
          f"{status.get('recent_errors', '?')} errors/1h | "
          f"rec: {status['recommendation']}")

    return status


def check_attention_health(
    attention_artifact: dict[str, Any],
    label: str = "attention",
) -> dict[str, Any]:
    """Record snapshot source availability, match rate, and Jev status for one run.

    A missing source is left out of scoring and missing attention falls back to
    importance-only priority, so degradation never blocks publication. This
    monitor warns on low rolling availability, a source that stays incomplete
    for the whole window (it needs repair), or degraded Jev. Appends one JSON
    line per section run to ATTENTION_HEALTH_LOG_PATH and judges the rolling
    window (current record plus the ATTENTION_HEALTH_WINDOW_RUNS - 1 most
    recent prior records).
    """
    snapshot = attention_artifact.get("snapshot") or {}
    sources = {
        name: (meta or {}).get("status", "unavailable")
        for name, meta in sorted((snapshot.get("sources") or {}).items())
    }
    attempted = [name for name, status in sources.items() if status != "skipped"]
    source_availability = (
        sum(sources[name] == "ok" for name in attempted) / len(attempted) if attempted else None
    )
    observations = attention_artifact.get("observations") or []
    statuses = [((row.get("attention") or {}).get("status")) for row in observations]
    matched = sum(status == "ok" for status in statuses)
    jev = attention_artifact.get("jev") or {}
    status: dict[str, Any] = {
        "ok": True,
        "recommendation": "ok",
        "kind": "attention",
        "provider": attention_artifact.get("provider", ""),
        "label": label,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "snapshot_id": snapshot.get("id"),
        "sources": sources,
        "source_availability": (
            round(source_availability, 3) if source_availability is not None else None
        ),
        "candidates": len(statuses),
        "matched": matched,
        "no_matches": sum(status == "no_matches" for status in statuses),
        "unavailable": sum(status == "unavailable" for status in statuses),
        "match_rate": round(matched / len(statuses), 3) if statuses else None,
        "jev": {key: jev.get(key) for key in ("status", "attempts", "requests", "input_tokens", "failures")},
        "excluded_sources": attention_artifact.get("excluded_sources") or {},
        "window_availability": None,
    }

    window: list[float] = []
    prior_sources: list[dict[str, Any]] = []
    if source_availability is not None:
        window.append(source_availability)
    try:
        if ATTENTION_HEALTH_LOG_PATH.exists():
            lines = ATTENTION_HEALTH_LOG_PATH.read_text().splitlines()
            for line in lines[-(ATTENTION_HEALTH_WINDOW_RUNS - 1):]:
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                if record.get("kind") != "attention":
                    continue
                if isinstance(record.get("source_availability"), (int, float)):
                    window.append(float(record["source_availability"]))
                if isinstance(record.get("sources"), dict):
                    prior_sources.append(record["sources"])
    except OSError:
        pass
    if window:
        status["window_availability"] = round(sum(window) / len(window), 3)

    degraded_sources = (
        status["window_availability"] is not None
        and status["window_availability"] < ATTENTION_MIN_SOURCE_AVAILABILITY
    )
    # One source broken every run barely moves availability but is permanently left out.
    persistent = sorted(
        name for name in attempted
        if sources[name] != "ok"
        and len(prior_sources) == ATTENTION_HEALTH_WINDOW_RUNS - 1
        and all(record.get(name) in ("partial", "unavailable") for record in prior_sources)
    )
    status["persistent_source_failures"] = persistent
    degraded_jev = jev.get("status") == "degraded"
    if degraded_sources or persistent or degraded_jev:
        status["recommendation"] = "warn"
        status["ok"] = False
        status["degradation"] = {
            "sources": degraded_sources, "persistent_sources": persistent, "jev": degraded_jev,
        }

    try:
        ATTENTION_HEALTH_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(ATTENTION_HEALTH_LOG_PATH, "a") as f:
            f.write(json.dumps(status) + "\n")
    except OSError:
        pass

    print(
        f"  [attention:{label}] {'✓' if status['ok'] else '⚠'} "
        f"sources {sum(value == 'ok' for value in sources.values())}/{len(attempted)} ok, "
        f"{matched}/{len(statuses)} matched, jev {jev.get('status', 'n/a')}, "
        f"rec: {status['recommendation']}"
    )
    return status


def _date_context() -> str:
    """Return a date context string injected into every LLM call."""
    now = datetime.now()
    return (
        f"Today's date is {now.strftime('%Y-%m-%d')} "
        f"({now.strftime('%A')}). "
        f"The current time is {now.strftime('%H:%M')} UTC. "
        f"All date checks should use this as the reference point. "
        f"'Last 24 hours' means stories published on or after "
        f"{(now - timedelta(days=1)).strftime('%Y-%m-%d')}."
    )

PROXY_5XX_RETRIES = 2

PROXY_5XX_BACKOFF_SECONDS = 5

def _call_llm_proxy(
    system: str,
    user: str,
    model: str = MODEL,
    temperature: float = 0.3,
    timeout: int = DEFAULT_TIMEOUT,
) -> str:
    """Call Luna through OMP, or an API fallback through chat completions."""
    eff_model = _effective_model(model)
    if eff_model.startswith("openai-codex/"):
        return _call_omp_no_tools(system, user, eff_model, timeout)
    provider_info = _detect_model_provider(eff_model)
    request_headers: dict[str, str] = {}
    if provider_info["provider"] == "opencode-go":
        # Each direct API call is one standalone conversation. Keep its ID
        # stable across the bounded 5xx retry loop for upstream affinity.
        request_headers["x-opencode-session"] = str(uuid.uuid4())
    date_prefix = _date_context()
    payload: dict[str, Any] = {
        "model": eff_model,
        "messages": [
            {"role": "system", "content": f"{date_prefix}\n\n{system}"},
            {"role": "user", "content": user},
        ],
        "temperature": temperature,
    }
    resp = None
    for _attempt in range(PROXY_5XX_RETRIES + 1):
        resp = requests.post(
            provider_info["chat_url"],
            json=payload,
            headers=request_headers,
            timeout=timeout,
        )
        try:
            resp.raise_for_status()
            break
        except requests.HTTPError:
            # A transient proxy 502/503/504 must not skip an entire editorial
            # stage — on 08-23 both Mimo calls 503'd and the ai-tech proposal
            # fell to raw fallback with no critic (digest-quality audit
            # 2026-08-24). Back off briefly and retry before the stage-level
            # fallback engages.
            if _attempt >= PROXY_5XX_RETRIES or resp.status_code not in (502, 503, 504):
                raise
            time.sleep(PROXY_5XX_BACKOFF_SECONDS * (_attempt + 1))
    body = resp.json()
    return body["choices"][0]["message"]["content"]

def _omp_agent_environment() -> dict[str, str]:
    """Return the minimal environment needed by a network-only digest agent."""
    allowed = {
        "DBUS_SESSION_BUS_ADDRESS",
        "HOME",
        "LANG",
        "LC_ALL",
        "LOGNAME",
        "NO_PROXY",
        "PATH",
        "SHELL",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
        "TERM",
        "TMPDIR",
        "TZ",
        "USER",
        "XDG_RUNTIME_DIR",
    }
    env = {key: value for key, value in os.environ.items() if key in allowed}
    env["HOME"] = str(Path.home())
    return env

def _call_omp_no_tools(
    system: str,
    user: str,
    model: str,
    timeout: int,
) -> str:
    """Run a transformation-only OMP call without host or web tools."""
    import tempfile

    full_system = f"{_date_context()}\n\n{system}"
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", prefix="omp_digest_transform_", delete=False
    ) as tf:
        tf.write(user)
        prompt_file = tf.name

    try:
        cmd = [
            "omp", "-p",
            "--model", model,
            "--system-prompt", full_system,
            "--config", str(Path.home() / ".omp/agent/headless-override.yml"),
            "--no-session",
            "--no-tools",
            "--no-extensions",
            "--no-skills",
            "--no-rules",
            "--no-lsp",
            "--no-pty",
            f"@{prompt_file}",
        ]
        result = subprocess.run(
            cmd,
            # The prompt is an @file; an inherited open stdin pipe would make
            # omp -p wait for EOF until the timeout.
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd="/tmp",
            env=_omp_agent_environment(),
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"omp -p failed (rc={result.returncode}): {result.stderr[:500]}"
            )
        return result.stdout
    finally:
        try:
            Path(prompt_file).unlink()
        except OSError:
            pass

def _call_omp_p(
    prompt: str,
    model: str = MODEL,
    timeout: int = RESEARCH_TIMEOUT,
    append_system: str | None = None,
) -> str:
    """Call omp -p (headless) for steps that need web_search/read tools.

    Returns the raw stdout. Uses provider/model format so omp routes to the
    correct provider. Prompt is written to a temp file and passed via @file
    (omp doesn't reliably extract URLs from stdin; @file works correctly).
    """
    import tempfile
    eff_model = _effective_model(model)
    if "/" in eff_model:
        omp_model = eff_model
    else:
        provider_info = _detect_model_provider(eff_model)
        omp_model = f"{provider_info['provider']}/{eff_model}"
    date_prefix = _date_context()
    full_system = f"{date_prefix}\n\n{append_system}" if append_system else date_prefix

    # Pass the prompt by file so long research/fetch instructions avoid shell
    # quoting and stdin ambiguity.
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", prefix="omp_digest_", delete=False
    ) as tf:
        tf.write(prompt)
        prompt_file = tf.name

    try:
        cmd = [
            "omp", "-p",
            "--model", omp_model,
            "--session-dir", str(Path.home() / ".omp/agent/sessions-automated"),
            "--config", str(DIGEST_OMP_CONFIG),
            "--append-system-prompt", full_system,
            "--tools", "read,web_search",
            "--no-extensions",
            "--extension", str(DIGEST_OMP_SANDBOX),
            "--no-skills",
            "--no-rules",
            "--no-lsp",
            "--no-pty",
            f"@{prompt_file}",
        ]
        result = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd="/tmp",
            env=_omp_agent_environment(),
        )
        if result.returncode != 0 and not result.stdout.strip():
            raise RuntimeError(f"omp -p failed (rc={result.returncode}): {result.stderr[:500]}")
        return result.stdout
    finally:
        try:
            Path(prompt_file).unlink()
        except OSError:
            pass

def _extract_json(text: str, label: str = "output") -> Any:
    """Extract JSON from LLM output. Tries markdown fences first, then raw JSON."""
    m = re.search(r"```(?:json)?\s*\n?(.*?)```", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1).strip())
        except json.JSONDecodeError:
            pass

    for pattern in [r"\{[\s\S]*\}", r"\[[\s\S]*\]"]:
        m = re.search(pattern, text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(0))
            except json.JSONDecodeError:
                continue

    text_stripped = text.strip()
    if text_stripped.startswith("{") or text_stripped.startswith("["):
        try:
            return json.loads(text_stripped)
        except json.JSONDecodeError:
            pass

    # Fallback: scan for JSON after common introductory keywords
    # Catches cases where the model writes prose before the JSON payload
    for keyword in ["Results:", "Output:", "Findings:", "JSON:", "Here is", "Here's", "following"]:
        idx = text.find(keyword)
        if idx >= 0:
            # Try to find JSON after the keyword line
            remainder = text[idx + len(keyword):]
            for pattern in [r"\{.*\}", r"\[.*\]"]:
                m = re.search(pattern, remainder, re.DOTALL)
                if m:
                    try:
                        return json.loads(m.group(0))
                    except json.JSONDecodeError:
                        continue

    raise ValueError(f"Could not extract JSON from {label}. Raw text (first 500 chars):\n{text[:500]}")

def _article_cache_path(url: str, cache_dir: Path | None = None) -> Path:
    key = hashlib.sha256(_normalize_url(url).encode()).hexdigest()
    return (cache_dir or ARTICLE_CACHE_DIR) / f"{key}.json"

def _load_article_cache(
    url: str,
    *,
    model: str,
    cache_dir: Path | None = None,
    now: datetime | None = None,
) -> dict | None:
    """Load a same-day article summary produced by the same model/prompt contract."""
    if not _normalize_url(url):
        return None
    path = _article_cache_path(url, cache_dir)
    try:
        entry = json.loads(path.read_text())
        fetched_at = datetime.fromisoformat(entry["fetched_at"])
        current = now or datetime.now(timezone.utc)
        if fetched_at.tzinfo is None:
            fetched_at = fetched_at.replace(tzinfo=timezone.utc)
        age = current - fetched_at
        if not timedelta(0) <= age <= timedelta(hours=ARTICLE_CACHE_TTL_HOURS):
            return None
        if entry.get("version") != ARTICLE_CACHE_VERSION:
            return None
        if entry.get("prompt_version") != FETCH_PROMPT_VERSION:
            return None
        if entry.get("model") != _effective_model(model):
            return None
        if entry.get("normalized_url") != _normalize_url(url):
            return None
        result = entry.get("result")
        return result if isinstance(result, dict) else None
    except (AttributeError, OSError, KeyError, TypeError, ValueError):
        return None

def _save_article_cache(
    url: str,
    result: dict,
    *,
    model: str,
    cache_dir: Path | None = None,
    now: datetime | None = None,
) -> None:
    """Atomically cache successful topic-neutral article fetch/summary output."""
    if not result.get("fetch_success", True) or not _normalize_url(url):
        return
    path = _article_cache_path(url, cache_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "version": ARTICLE_CACHE_VERSION,
        "prompt_version": FETCH_PROMPT_VERSION,
        "model": _effective_model(model),
        "normalized_url": _normalize_url(url),
        "fetched_at": (now or datetime.now(timezone.utc)).isoformat(),
        "result": {k: v for k, v in result.items() if k != "cache_hit"},
    }
    atomic_write_json(path, entry)

def _prune_article_cache(
    *,
    cache_dir: Path | None = None,
    now: datetime | None = None,
) -> int:
    """Delete expired or malformed cache entries; return the number removed."""
    root = cache_dir or ARTICLE_CACHE_DIR
    current = now or datetime.now(timezone.utc)
    removed = 0
    try:
        paths = list(root.glob("*.json"))
    except OSError:
        return 0
    for path in paths:
        try:
            entry = json.loads(path.read_text())
            fetched_at = datetime.fromisoformat(entry["fetched_at"])
            if fetched_at.tzinfo is None:
                fetched_at = fetched_at.replace(tzinfo=timezone.utc)
            age = current - fetched_at
            valid = (
                timedelta(0) <= age <= timedelta(hours=ARTICLE_CACHE_TTL_HOURS)
                and entry.get("version") == ARTICLE_CACHE_VERSION
                and entry.get("prompt_version") == FETCH_PROMPT_VERSION
            )
        except (AttributeError, OSError, KeyError, TypeError, ValueError):
            valid = False
        if not valid:
            try:
                path.unlink()
                removed += 1
            except OSError:
                pass
    return removed


def issue_date_for_run(run_dir: Path) -> date:
    """Derive the immutable edition date encoded by a production or test run."""

    try:
        return date.fromisoformat(run_dir.name)
    except ValueError:
        match = re.search(r"(\d{8})-\d{6}$", run_dir.name)
        if match is None:
            raise ValueError(
                "run directory must encode YYYY-MM-DD or end in YYYYMMDD-HHMMSS"
            )
        return datetime.strptime(match.group(1), "%Y%m%d").date()


# State rows are scoped to one run directory.  A phase may resume only when
# its durable state row, code/policy fingerprint, upstream fingerprints, and
# artifact hash all match.  Existing files without a row are deliberately
# treated as legacy and recomputed.
WORKFLOW_NAME = "daily-news"
PIPELINE_CODE_VERSION = "daily-news-modular-2026-09-01"

def pipeline_code_fingerprint() -> tuple[dict[str, str], str]:
    """Hash every local module that can affect a resumable Daily News phase."""
    package_dir = Path(__file__).resolve().parent
    script_dir = package_dir.parent
    paths = sorted(package_dir.glob("*.py"))
    paths.extend(
        (
            script_dir / "digest_runner.py",
            script_dir / "news_attention.py",
            script_dir / "news_publish.py",
            script_dir / "workflow_state.py",
            script_dir / "jev.py",
            DIGEST_OMP_SANDBOX,
            DIGEST_OMP_CONFIG,
            TEMPLATE_PATH,
        )
    )
    hashes: dict[str, str] = {}
    for path in paths:
        try:
            hashes[str(path)] = file_sha256(path)
        except OSError:
            hashes[str(path)] = "missing"
    return hashes, canonical_fingerprint(hashes)

_STARTUP_CODE_HASHES, _STARTUP_CODE_HASH = pipeline_code_fingerprint()

def track_phase_failure(phase: str):
    """Mark a started phase failed before propagating its exception."""
    if not isinstance(phase, str) or not phase:
        raise ValueError("phase must be a non-empty string")

    def decorate(function):
        signature = inspect.signature(function)

        @wraps(function)
        def wrapped(*args, **kwargs):
            bound = signature.bind_partial(*args, **kwargs)
            run_dir = bound.arguments.get("run_dir")
            try:
                return function(*args, **kwargs)
            except BaseException as error:
                if run_dir is not None:
                    try:
                        state = WorkflowState(
                            Path(run_dir), WORKFLOW_NAME, run_id=Path(run_dir).name
                        )
                        state.fail_phase(phase, error)
                    except BaseException:
                        pass
                raise

        return wrapped

    return decorate


def phase_inputs(
    phase: str,
    *,
    topic: dict[str, Any] | None = None,
    upstream: Any = None,
    policy: Any = None,
) -> dict[str, Any]:
    """Build canonical inputs with actual code, policy, and upstream hashes."""
    current_hashes, current_hash = pipeline_code_fingerprint()
    if current_hash != _STARTUP_CODE_HASH:
        changed = sorted(
            path
            for path in set(_STARTUP_CODE_HASHES) | set(current_hashes)
            if _STARTUP_CODE_HASHES.get(path) != current_hashes.get(path)
        )
        raise RuntimeError(
            "Daily News code or policy changed during the run: "
            + ", ".join(changed)
        )
    code_hashes, code_hash = _STARTUP_CODE_HASHES, _STARTUP_CODE_HASH
    return {
        "phase": phase,
        "code_version": PIPELINE_CODE_VERSION,
        "code_hashes": code_hashes,
        "code_hash": code_hash,
        "policy_version": policy if policy is not None else PIPELINE_CODE_VERSION,
        "topic": (topic or {}).get("category", ""),
        "upstream": upstream,
    }


def begin_or_load_phase(
    run_dir: Path,
    phase: str,
    *,
    inputs: Any,
    artifact_path: Path,
    schema_version: int,
    validator: Any = None,
) -> tuple[WorkflowState, Any | None]:
    """Return state and validated cached payload, or begin a fresh attempt."""
    state = WorkflowState(run_dir, WORKFLOW_NAME, run_id=run_dir.name)
    cached = state.load_json(
        phase,
        inputs=inputs,
        artifact_path=artifact_path,
        schema_version=schema_version,
        validator=validator,
    )
    if cached is not None:
        print(f"  [skip] {phase} output validated: {artifact_path}")
        return state, cached
    state.begin_phase(
        phase,
        inputs=inputs,
        artifact_path=artifact_path,
        schema_version=schema_version,
    )
    return state, None


def complete_phase_json(
    state: WorkflowState,
    phase: str,
    path: Path,
    data: Any,
    *,
    outcome: str = "succeeded",
    reason: str | None = None,
) -> None:
    """Atomically write and durably record a JSON phase artifact."""
    state.complete_json(
        phase,
        data,
        artifact_path=path,
        outcome=outcome,
        reason=reason,
    )


def complete_phase_text(
    state: WorkflowState,
    phase: str,
    path: Path,
    text: str,
    *,
    outcome: str = "succeeded",
    reason: str | None = None,
) -> None:
    """Atomically write and durably record a text phase artifact."""
    state.complete_text(
        phase,
        text,
        artifact_path=path,
        outcome=outcome,
        reason=reason,
    )


def begin_or_load_text_phase(
    run_dir: Path,
    phase: str,
    *,
    inputs: Any,
    artifact_path: Path,
    schema_version: int,
) -> tuple[WorkflowState, str | None]:
    """Resume a validated text artifact or begin a new text phase attempt."""
    state = WorkflowState(run_dir, WORKFLOW_NAME, run_id=run_dir.name)
    cached = state.load_text(
        phase,
        inputs=inputs,
        artifact_path=artifact_path,
        schema_version=schema_version,
    )
    if cached is not None:
        return state, cached
    state.begin_phase(
        phase, inputs=inputs, artifact_path=artifact_path,
        schema_version=schema_version,
    )
    return state, None


def write_phase_status(path: Path, *, status: str, reason: str, **details: Any) -> Path:
    """Write a deterministic status sidecar for an empty/no-input phase."""
    payload = {"status": status, "reason": reason, **details}
    status_path = path.with_name(f"{path.stem}.status.json")
    atomic_write_json(status_path, payload)
    return status_path
