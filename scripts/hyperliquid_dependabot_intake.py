#!/usr/bin/env python3
"""Build a classified, sanitized Dependabot manifest for hyperliquid-run."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

REPOSITORY = "carter2099/hyperliquid"
DEFAULT_CLASSIFIER_URL = "http://127.0.0.1:8090"
MAX_GITHUB_OUTPUT_BYTES = 16 << 20
MAX_CLASSIFIER_TEXT_BYTES = 1 << 20
MAX_CLASSIFIER_RESPONSE_BYTES = 64 << 10
DEPENDABOT_AUTHORS = {"app/dependabot", "dependabot[bot]"}
HEAD_REF_RE = re.compile(
    r"\Adependabot/(?P<ecosystem>bundler|github_actions)/"
    r"(?P<dependency>[A-Za-z0-9][A-Za-z0-9_.\-/]*?)-"
    r"(?P<target>v?\d[A-Za-z0-9_.+\-]*)\Z"
)
SHA_RE = re.compile(r"\A[0-9a-f]{40}\Z")


class IntakeError(RuntimeError):
    """The PR batch cannot be safely handed to the scheduled agent."""


Classifier = Callable[[str], dict[str, Any]]


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def list_open_dependabot_prs() -> list[dict[str, Any]]:
    command = [
        "gh",
        "pr",
        "list",
        "--repo",
        REPOSITORY,
        "--author",
        "app/dependabot",
        "--state",
        "open",
        "--limit",
        "100",
        "--json",
        "number,author,baseRefName,headRefName,headRefOid,isDraft,title,body",
    ]
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise IntakeError(f"cannot list Dependabot PRs: {exc}") from exc

    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()[:500]
        raise IntakeError(
            f"gh pr list exited {completed.returncode}: {detail or '(no stderr)'}"
        )
    if len(completed.stdout) > MAX_GITHUB_OUTPUT_BYTES:
        raise IntakeError("gh pr list output exceeds 16 MiB")

    try:
        listed = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IntakeError(f"cannot decode gh pr list output: {exc}") from exc
    if not isinstance(listed, list):
        raise IntakeError("gh pr list did not return a JSON array")
    if len(listed) >= 100:
        raise IntakeError("gh pr list reached its 100-PR limit; refusing a partial intake")
    return listed


def prompt_guard_classifier(classifier_url: str) -> Classifier:
    endpoint = classifier_url.rstrip("/") + "/classify"

    def classify(text: str) -> dict[str, Any]:
        encoded_text = text.encode("utf-8")
        if len(encoded_text) > MAX_CLASSIFIER_TEXT_BYTES:
            raise IntakeError("Dependabot title and body exceed the 1 MiB classifier limit")
        payload = canonical_json({"text": text}).encode("utf-8")
        request = Request(
            endpoint,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=5) as response:
                status = response.status
                body = response.read(MAX_CLASSIFIER_RESPONSE_BYTES + 1)
        except HTTPError as exc:
            detail = exc.read(500).decode("utf-8", errors="replace").strip()
            raise IntakeError(
                f"Prompt Guard returned HTTP {exc.code}: {detail or '(empty response)'}"
            ) from exc
        except (OSError, TimeoutError, URLError) as exc:
            raise IntakeError(f"Prompt Guard request failed: {exc}") from exc

        if status != 200:
            raise IntakeError(f"Prompt Guard returned HTTP {status}")
        if len(body) > MAX_CLASSIFIER_RESPONSE_BYTES:
            raise IntakeError("Prompt Guard response exceeds 64 KiB")
        try:
            result = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise IntakeError(f"cannot decode Prompt Guard response: {exc}") from exc
        return validate_classification(result)

    return classify


def validate_classification(result: object) -> dict[str, Any]:
    if not isinstance(result, dict):
        raise IntakeError("Prompt Guard response is not a JSON object")
    label = result.get("label")
    score = result.get("score")
    flagged = result.get("flagged")
    if not isinstance(label, str):
        raise IntakeError("Prompt Guard response has no string label")
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        raise IntakeError("Prompt Guard response has no numeric score")
    score = float(score)
    if not math.isfinite(score) or not 0.0 <= score <= 1.0:
        raise IntakeError("Prompt Guard score is outside [0, 1]")
    if not isinstance(flagged, bool):
        raise IntakeError("Prompt Guard response has no boolean flagged value")
    if flagged or label != "SAFE":
        raise IntakeError(
            f"Prompt Guard rejected Dependabot content (label={label}, score={score:.6f})"
        )
    return {"label": label, "score": score, "flagged": flagged}


def parse_pull_request(raw: object) -> tuple[dict[str, Any], str]:
    if not isinstance(raw, dict):
        raise IntakeError("GitHub returned a non-object PR entry")

    number = raw.get("number")
    if isinstance(number, bool) or not isinstance(number, int) or number <= 0:
        raise IntakeError("GitHub returned an invalid PR number")

    author = raw.get("author")
    if not isinstance(author, dict):
        raise IntakeError(f"PR #{number} has no structured author")
    if author.get("login") not in DEPENDABOT_AUTHORS or author.get("is_bot") is not True:
        raise IntakeError(f"PR #{number} is not authored by Dependabot")

    if raw.get("isDraft") is not False:
        raise IntakeError(f"PR #{number} is a draft")

    base_ref = raw.get("baseRefName")
    if base_ref not in {"main", "dev"}:
        raise IntakeError(f"PR #{number} has unexpected base branch {base_ref!r}")

    head_ref = raw.get("headRefName")
    if not isinstance(head_ref, str):
        raise IntakeError(f"PR #{number} has no head branch")
    match = HEAD_REF_RE.fullmatch(head_ref)
    if match is None:
        raise IntakeError(f"PR #{number} has unsupported Dependabot branch {head_ref!r}")

    dependency = match.group("dependency")
    if (
        dependency.endswith(("/", "-"))
        or "//" in dependency
        or any(part in {"", ".", ".."} for part in dependency.split("/"))
    ):
        raise IntakeError(f"PR #{number} has invalid dependency name {dependency!r}")

    head_sha = raw.get("headRefOid")
    if not isinstance(head_sha, str) or SHA_RE.fullmatch(head_sha) is None:
        raise IntakeError(f"PR #{number} has invalid head SHA")

    title = raw.get("title")
    body = raw.get("body")
    if not isinstance(title, str) or not title:
        raise IntakeError(f"PR #{number} has no title")
    if body is None:
        body = ""
    if not isinstance(body, str):
        raise IntakeError(f"PR #{number} has a non-string body")

    target_version = match.group("target").removeprefix("v")
    actionable = {
        "number": number,
        "ecosystem": match.group("ecosystem"),
        "dependency": dependency,
        "target_version": target_version,
        "base_ref": base_ref,
        "head_ref": head_ref,
        "head_sha": head_sha,
    }
    text_to_classify = title + ("\n" + body if body else "")
    return actionable, text_to_classify


def build_manifest(
    listed: list[dict[str, Any]],
    classify: Classifier,
    *,
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    parsed: list[tuple[dict[str, Any], str]] = []
    seen_numbers: set[int] = set()
    seen_heads: set[str] = set()
    for raw in listed:
        actionable, text_to_classify = parse_pull_request(raw)
        number = actionable["number"]
        head_ref = actionable["head_ref"]
        if number in seen_numbers:
            raise IntakeError(f"GitHub returned duplicate PR #{number}")
        if head_ref in seen_heads:
            raise IntakeError(f"GitHub returned duplicate head branch {head_ref!r}")
        seen_numbers.add(number)
        seen_heads.add(head_ref)
        parsed.append((actionable, text_to_classify))
    parsed.sort(key=lambda pair: pair[0]["number"])

    max_score = 0.0
    pull_requests: list[dict[str, Any]] = []
    for actionable, text_to_classify in parsed:
        try:
            result = validate_classification(classify(text_to_classify))
        except IntakeError as exc:
            raise IntakeError(f"PR #{actionable['number']}: {exc}") from exc
        max_score = max(max_score, result["score"])
        pull_requests.append(actionable)

    actionable_payload = {
        "repository": REPOSITORY,
        "pull_requests": pull_requests,
    }
    intake_sha256 = hashlib.sha256(
        canonical_json(actionable_payload).encode("ascii")
    ).hexdigest()

    handoff_score: float | None = None
    if pull_requests:
        try:
            handoff = validate_classification(classify(canonical_json(actionable_payload)))
        except IntakeError as exc:
            raise IntakeError(f"sanitized handoff: {exc}") from exc
        handoff_score = handoff["score"]

    timestamp = generated_at or datetime.now(timezone.utc)
    if timestamp.tzinfo is None:
        raise IntakeError("manifest timestamp must be timezone-aware")
    timestamp = timestamp.astimezone(timezone.utc).replace(microsecond=0)

    return {
        "schema_version": 1,
        "repository": REPOSITORY,
        "generated_at": timestamp.isoformat().replace("+00:00", "Z"),
        "intake_sha256": intake_sha256,
        "classification": {
            "policy": "title_and_body_per_pr_then_sanitized_handoff",
            "result": "SAFE" if pull_requests else "NOT_NEEDED",
            "classified_pull_requests": len(pull_requests),
            "max_pull_request_score": round(max_score, 8) if pull_requests else None,
            "sanitized_handoff_score": round(handoff_score, 8)
            if handoff_score is not None
            else None,
        },
        "pull_requests": pull_requests,
    }


def write_manifest(path: Path, manifest: dict[str, Any]) -> None:
    path = path.expanduser().resolve()
    if not path.parent.is_dir():
        raise IntakeError(f"manifest parent directory does not exist: {path.parent}")

    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=path.name + ".",
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            os.chmod(temporary_path, 0o600)
            json.dump(manifest, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build the preclassified Dependabot intake for hyperliquid-run."
    )
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--classifier-url",
        default=os.environ.get("CLASSIFIER_URL", DEFAULT_CLASSIFIER_URL),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        listed = list_open_dependabot_prs()
        manifest = build_manifest(
            listed,
            prompt_guard_classifier(args.classifier_url),
        )
        write_manifest(args.output, manifest)
    except IntakeError as exc:
        print(f"FATAL: Dependabot intake failed: {exc}", file=sys.stderr)
        return 1

    print(
        "ok: preclassified "
        f"{len(manifest['pull_requests'])} open Hyperliquid Dependabot PR(s); "
        f"intake_sha256={manifest['intake_sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
