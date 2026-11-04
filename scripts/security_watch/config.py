"""Paths, constants and policy/registry loaders for security-watch."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

PACKAGE_DIR = Path(__file__).resolve().parent
SCRIPTS_DIR = PACKAGE_DIR.parent


def home() -> Path:
    return Path(os.environ.get("HOME") or Path.home())


def state_dir() -> Path:
    """Private runtime state (gitignored, never published)."""
    override = os.environ.get("SECURITY_WATCH_STATE_DIR")
    return Path(override) if override else home() / ".local/state/security-watch"


def db_path() -> Path:
    return state_dir() / "state.sqlite3"


def report_path() -> Path:
    """Read by the steward's nightly email (report.py)."""
    return state_dir() / "report.json"


POLICY_PATH = PACKAGE_DIR / "policy.toml"
COMPONENTS_PATH = PACKAGE_DIR / "components.toml"
STOPGAPS_PATH = PACKAGE_DIR / "stopgaps.toml"
SEND_DIGEST = SCRIPTS_DIR / "send_digest.py"

OSV_API = "https://api.osv.dev"
USER_AGENT = "homelab-security-watch/1"

# Every network fetch must target one of these hosts (net.fetch enforces it).
ALLOWED_HOSTS = frozenset({
    "api.osv.dev",
    "radar.cloudflare.com",
    "vuln.go.dev",
    "go.dev",
    "www.cisa.gov",
    "news.php.net",
    "www.php.net",
    "news-web.php.net",
    "nodejs.org",
    "firefox.settings.services.mozilla.com",
    "api.ransomware.live",
    "ubuntu.com",
    "www.debian.org",
    "api.github.com",
    "registry-1.docker.io",
    "auth.docker.io",
    "hub.docker.com",
    "ghcr.io",
    "proxy.golang.org",
    "127.0.0.1",
})

STEWARD_UNITS = ("homelab-steward.service", "homelab-steward-resume.service")


@dataclass(frozen=True)
class Policy:
    mode: str                               # "shadow" | "active"
    recipient: str
    max_actions_per_day: int
    component_cooldown_hours: int
    release_min_age_hours: int
    urgent_window_hours: int
    urgent_max_per_day: int
    tick_budget_seconds: int
    inventory_refresh_hours: int
    osv_rescan_minutes: int
    reach_max_agent_calls_per_tick: int
    reach_reachable_p: float
    reach_not_reachable_p: float
    jev_deadline_seconds: int
    shadow_min_days: int
    shadow_min_source_ok_rate: float
    lock_timeout_seconds: int
    vendors: tuple[dict[str, Any], ...]
    upstream_repos: tuple[str, ...]
    source_intervals: dict[str, int] = field(default_factory=dict)  # source name -> seconds
    reach_max_agent_calls_per_day: int = 24

    @property
    def active(self) -> bool:
        return self.mode == "active"


@dataclass(frozen=True)
class ComponentSpec:
    """One deployed surface from components.toml.  Unknown keys stay in ``extra``."""
    id: str
    kind: str                # "host" | "container" | "host-binary" | "venv" | "runtime" | "rig"
    collector: str           # inventory collector id
    exposure: str            # "public" | "access" | "lan" | "loopback" | "none"
    owner: str               # playbook id ("alert" = no automated fix)
    lock: str                # deploy_lock service key
    description: str = ""
    untrusted_input: str = ""
    health: tuple[str, ...] = ()
    repo: str = ""           # ~/dev/<repo> for repo-backed components
    extra: dict[str, Any] = field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        return self.extra.get(key, default)


_SPEC_FIELDS = {"id", "kind", "collector", "exposure", "owner", "lock", "description",
                "untrusted_input", "health", "repo"}


def load_policy(path: Path = POLICY_PATH) -> Policy:
    data = tomllib.loads(path.read_text())
    mode = data["mode"]
    if mode not in {"shadow", "active"}:
        raise ValueError(f"policy mode must be shadow or active, got {mode!r}")
    return Policy(
        mode=mode,
        recipient=data["recipient"],
        max_actions_per_day=int(data["max_actions_per_day"]),
        component_cooldown_hours=int(data["component_cooldown_hours"]),
        release_min_age_hours=int(data["release_min_age_hours"]),
        urgent_window_hours=int(data["urgent_window_hours"]),
        urgent_max_per_day=int(data["urgent_max_per_day"]),
        tick_budget_seconds=int(data["tick_budget_seconds"]),
        inventory_refresh_hours=int(data["inventory_refresh_hours"]),
        osv_rescan_minutes=int(data["osv_rescan_minutes"]),
        reach_max_agent_calls_per_tick=int(data["reach_max_agent_calls_per_tick"]),
        reach_reachable_p=float(data["reach_reachable_p"]),
        reach_not_reachable_p=float(data["reach_not_reachable_p"]),
        jev_deadline_seconds=int(data["jev_deadline_seconds"]),
        shadow_min_days=int(data["shadow_min_days"]),
        shadow_min_source_ok_rate=float(data["shadow_min_source_ok_rate"]),
        lock_timeout_seconds=int(data["lock_timeout_seconds"]),
        vendors=tuple(data.get("vendor", [])),
        upstream_repos=tuple(data.get("upstream_repos", [])),
        source_intervals={k: int(v) for k, v in data.get("source_intervals", {}).items()},
        reach_max_agent_calls_per_day=int(data.get("reach_max_agent_calls_per_day", 24)),
    )


def load_components(path: Path = COMPONENTS_PATH) -> list[ComponentSpec]:
    data = tomllib.loads(path.read_text())
    specs: list[ComponentSpec] = []
    seen: set[str] = set()
    for raw in data.get("component", []):
        if raw["id"] in seen:
            raise ValueError(f"duplicate component id {raw['id']!r}")
        seen.add(raw["id"])
        health = raw.get("health", ())
        specs.append(ComponentSpec(
            id=raw["id"],
            kind=raw["kind"],
            collector=raw["collector"],
            exposure=raw["exposure"],
            owner=raw["owner"],
            lock=raw["lock"],
            description=raw.get("description", ""),
            untrusted_input=raw.get("untrusted_input", ""),
            health=tuple([health] if isinstance(health, str) else health),
            repo=raw.get("repo", ""),
            extra={k: v for k, v in raw.items() if k not in _SPEC_FIELDS},
        ))
    return specs


@dataclass(frozen=True)
class Stopgap:
    id: str
    component: str
    cves: tuple[str, ...]
    description: str
    since: str
    remove: str
    doc: str = ""


def load_stopgaps(path: Path = STOPGAPS_PATH) -> list[Stopgap]:
    if not path.exists():
        return []
    data = tomllib.loads(path.read_text())
    return [Stopgap(id=raw["id"], component=raw["component"], cves=tuple(raw.get("cves", ())),
                    description=raw.get("description", ""), since=raw.get("since", ""),
                    remove=raw.get("remove", ""), doc=raw.get("doc", ""))
            for raw in data.get("stopgap", [])]



def expand(path: str) -> Path:
    """Expand a leading ``~`` against the current HOME (tests point HOME at a temp dir)."""
    return home() / path[2:] if path.startswith("~/") else Path(path)
