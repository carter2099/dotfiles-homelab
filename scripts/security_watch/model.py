"""Shared data model for security-watch.

Every module exchanges these types; none of them performs I/O.
Times are timezone-aware UTC ``datetime`` values, serialized as ISO-8601 strings.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime | None) -> str | None:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds") if value else None


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


# --- inventory ---------------------------------------------------------------

# OSV ecosystems are used verbatim ("Debian:13", "Ubuntu:24.04:LTS", "Alpine:v3.24",
# "PyPI", "Go", "npm", "RubyGems").  Versions are passed to OSV exactly as listed:
# dpkg source versions, apk versions, Go versions without a leading "go"/"v".
# Non-OSV runtimes use ecosystem "runtime" and name = the runtime id ("php", "node",
# "bun", ...); they are matched by runtime release checks and GitHub repo advisories.
RUNTIME_ECOSYSTEM = "runtime"


@dataclass(frozen=True)
class Package:
    ecosystem: str
    name: str
    version: str
    binary: str = ""     # binary package / artifact detail, display only
    location: str = ""   # where it was found (binary path, container path)

    @property
    def is_runtime(self) -> bool:
        return self.ecosystem == RUNTIME_ECOSYSTEM

    def ident(self) -> str:
        return f"{self.ecosystem}/{self.name}@{self.version}"


@dataclass
class Inventory:
    component_id: str
    collected_at: datetime
    status: str                     # "ok" | "partial" | "unknown"
    fingerprint: str                # cheap artifact identity (image id, binary sha256, ...)
    packages: list[Package] = field(default_factory=list)
    reason: str = ""                # why partial/unknown (never empty for those)
    meta: dict[str, Any] = field(default_factory=dict)  # os, image, digest, vcs_revision, binaries...


# --- signals (feed items) ----------------------------------------------------

TIER_ISSUER = "issuer"     # structured record from the publisher of the fix; may drive actions
TIER_CURATED = "curated"   # curated intelligence (Zero Wire, KEV): raises urgency, triggers rescans
TIER_LEAD = "lead"         # unstructured lead: alert/rescan only, never drives an action


@dataclass(frozen=True)
class AdvisoryPackage:
    """Structured affected package named by an issuer record (never LLM-derived)."""
    ecosystem: str
    name: str
    vulnerable_range: str = ""      # e.g. ">= 1.0.21, < 1.4.4" (GitHub) or "" when ranges are in OSV
    fixed: tuple[str, ...] = ()


@dataclass(frozen=True)
class Signal:
    source: str                     # feed name, e.g. "zero_wire"
    key: str                        # stable dedupe key within the source (slug, CVE, GHSA id)
    version: str                    # changes when the item is updated (guid, modified, updated_at)
    title: str
    url: str
    tier: str
    published: str | None = None    # ISO-8601 when the publisher dated it
    cves: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()
    kev: bool = False
    urgency_hint: str = ""          # "needs-attention" | "pre-announcement" | "vendor-breach" | ""
    packages: tuple[AdvisoryPackage, ...] = ()
    summary: str = ""               # plain text, already clipped to <= 1000 chars
    links: tuple[str, ...] = ()     # issuer links named by the item (display/evidence only)


# --- findings ----------------------------------------------------------------

@dataclass
class Reach:
    verdict: str                    # "reachable" | "not_reachable" | "unknown"
    method: str                     # "govulncheck" | "agent+jev" | "static" | "none"
    p: float | None = None          # Jev probability that untrusted input reaches the vulnerable code
    summary: str = ""
    evidence: list[dict[str, Any]] = field(default_factory=list)  # [{file, line, note}]
    assessed_at: str | None = None
    cache_key: str = ""


URGENCY_URGENT = "urgent"
URGENCY_NORMAL = "normal"
URGENCY_LOW = "low"


@dataclass
class Finding:
    key: str                        # f"{component_id}|{group}"; group = lowest CVE alias, else advisory id
    component_id: str
    group: str
    package: Package
    advisory_ids: list[str]
    cves: list[str]
    fixed_versions: list[str]       # fixed versions for this package/ecosystem named by issuer records
    fix_available: bool
    status: str = "affected"        # "affected" | "unknown" | "fixed"
    severity: str = ""              # "critical" | "high" | "medium" | "low" | ""
    kev: bool = False
    zero_wire: list[str] = field(default_factory=list)   # Zero Wire slugs naming one of the CVEs
    summary: str = ""
    first_seen: str | None = None
    reach: Reach | None = None
    urgency: str = URGENCY_NORMAL
    reasons: list[str] = field(default_factory=list)     # why this urgency (human readable)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        return data


# --- remediation -------------------------------------------------------------

@dataclass
class Plan:
    playbook: str                   # playbook id from components.toml "owner"
    component_id: str
    finding_keys: list[str]
    target: str                     # human target, e.g. "freshrss 1.30.5", "go1.27.4 rebuild"
    lock_keys: list[str]            # deploy_lock keys, acquisition order
    steps: list[str]                # human-readable steps (shown in shadow proposals)
    undo: str                       # one shell command (or instruction) that undoes the change
    release_published: str | None = None   # ISO publish time of the fix release, for the age rule
    fixed_version: str = ""         # exact fixed package version the plan installs (two-source rule)
    state: dict[str, Any] = field(default_factory=dict)  # playbook-private data carried to apply/advance


@dataclass
class Refusal:
    playbook: str
    component_id: str
    reason: str                     # precondition that failed, human readable
    alert: bool = True              # surface to Carter (False for transient, e.g. lock busy)
    finding_keys: list[str] = field(default_factory=list)  # findings it concerns; empty = the whole group


@dataclass
class Outcome:
    status: str                     # "done" | "pending" | "failed" | "rolled_back" | "refused"
    detail: str
    undo: str = ""
    verify: bool = True             # rescan the component and require the finding to clear
    state: dict[str, Any] = field(default_factory=dict)  # persisted for advance() on later ticks
