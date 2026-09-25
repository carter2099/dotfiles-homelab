#!/usr/bin/env python3
"""Behavioral contracts for the Hyperliquid Dependabot intake."""

from __future__ import annotations

import json
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from hyperliquid_dependabot_intake import (
    IntakeError,
    REPOSITORY,
    build_manifest,
    write_manifest,
)


def check(condition: bool, message: object) -> None:
    if not condition:
        raise AssertionError(message)


def pull_request(
    number: int,
    *,
    head_ref: str = "dependabot/bundler/faraday-retry-2.4.0",
    title: str = "Bump a dependency",
    body: str = "Untrusted release notes",
) -> dict[str, object]:
    return {
        "number": number,
        "author": {"login": "app/dependabot", "is_bot": True},
        "baseRefName": "main",
        "headRefName": head_ref,
        "headRefOid": f"{number:040x}",
        "isDraft": False,
        "title": title,
        "body": body,
    }


def safe_classifier(calls: list[str]):
    def classify(text: str) -> dict[str, object]:
        calls.append(text)
        return {"label": "SAFE", "score": 0.0125, "flagged": False}

    return classify


def test_safe_prs_are_sorted_classified_and_sanitized() -> None:
    calls: list[str] = []
    manifest = build_manifest(
        [
            pull_request(
                9,
                head_ref="dependabot/github_actions/actions/checkout-7",
                title="Second untrusted title",
                body="Second untrusted body",
            ),
            pull_request(
                3,
                title="First untrusted title",
                body="First untrusted body",
            ),
        ],
        safe_classifier(calls),
        generated_at=datetime(2026, 8, 31, 12, 0, tzinfo=timezone.utc),
    )

    check(manifest["repository"] == REPOSITORY, manifest)
    check(manifest["generated_at"] == "2026-08-31T12:00:00Z", manifest)
    check([pr["number"] for pr in manifest["pull_requests"]] == [3, 9], manifest)
    check(
        manifest["pull_requests"][0]["dependency"] == "faraday-retry",
        manifest,
    )
    check(
        manifest["pull_requests"][1]["dependency"] == "actions/checkout",
        manifest,
    )
    check(manifest["pull_requests"][1]["target_version"] == "7", manifest)
    check(manifest["classification"]["classified_pull_requests"] == 2, manifest)
    check(len(calls) == 3, calls)
    check(calls[0] == "First untrusted title\nFirst untrusted body", calls)
    check(calls[1] == "Second untrusted title\nSecond untrusted body", calls)
    check("title" not in calls[2].casefold(), calls[2])
    serialized = json.dumps(manifest)
    check("untrusted title" not in serialized.casefold(), serialized)
    check("untrusted body" not in serialized.casefold(), serialized)
    check(len(manifest["intake_sha256"]) == 64, manifest)


def test_flagged_pr_rejects_the_entire_batch() -> None:
    def flagged_classifier(_text: str) -> dict[str, object]:
        return {"label": "JAILBREAK", "score": 0.99, "flagged": True}

    try:
        build_manifest([pull_request(7)], flagged_classifier)
    except IntakeError as exc:
        check("PR #7" in str(exc), exc)
        check("rejected" in str(exc), exc)
    else:
        raise AssertionError("flagged PR was accepted")


def test_classifier_failure_rejects_the_entire_batch() -> None:
    def unavailable_classifier(_text: str) -> dict[str, object]:
        raise IntakeError("classifier unavailable")

    try:
        build_manifest([pull_request(8)], unavailable_classifier)
    except IntakeError as exc:
        check("PR #8" in str(exc), exc)
        check("classifier unavailable" in str(exc), exc)
    else:
        raise AssertionError("classifier failure was accepted")


def test_non_dependabot_and_unsupported_refs_are_rejected() -> None:
    wrong_author = pull_request(10)
    wrong_author["author"] = {"login": "someone", "is_bot": False}
    malformed_ref = pull_request(
        11,
        head_ref="dependabot/docker/image-2.0.0",
    )

    for candidate, expected in (
        (wrong_author, "not authored by Dependabot"),
        (malformed_ref, "unsupported Dependabot branch"),
    ):
        try:
            build_manifest([candidate], safe_classifier([]))
        except IntakeError as exc:
            check(expected in str(exc), exc)
        else:
            raise AssertionError(f"unsafe PR metadata was accepted: {candidate}")


def test_empty_intake_does_not_require_classifier() -> None:
    def must_not_classify(_text: str) -> dict[str, object]:
        raise AssertionError("classifier should not run without PRs")

    manifest = build_manifest(
        [],
        must_not_classify,
        generated_at=datetime(2026, 8, 31, tzinfo=timezone.utc),
    )
    check(manifest["pull_requests"] == [], manifest)
    check(manifest["classification"]["result"] == "NOT_NEEDED", manifest)


def test_manifest_write_is_private_and_complete() -> None:
    calls: list[str] = []
    manifest = build_manifest(
        [pull_request(12)],
        safe_classifier(calls),
        generated_at=datetime(2026, 8, 31, tzinfo=timezone.utc),
    )
    with tempfile.TemporaryDirectory() as temporary:
        output = Path(temporary) / "intake.json"
        write_manifest(output, manifest)
        mode = stat.S_IMODE(output.stat().st_mode)
        check(mode == 0o600, oct(mode))
        check(json.loads(output.read_text(encoding="utf-8")) == manifest, output)


def main() -> None:
    tests = [
        test_safe_prs_are_sorted_classified_and_sanitized,
        test_flagged_pr_rejects_the_entire_batch,
        test_classifier_failure_rejects_the_entire_batch,
        test_non_dependabot_and_unsupported_refs_are_rejected,
        test_empty_intake_does_not_require_classifier,
        test_manifest_write_is_private_and_complete,
    ]
    for test in tests:
        test()
        print(f"OK  {test.__name__}")
    print("ALL PASSED")


if __name__ == "__main__":
    main()
