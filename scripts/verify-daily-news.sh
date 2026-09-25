#!/usr/bin/env bash
# Deterministic, offline verification for the Daily News package and release.
# Usage: verify-daily-news.sh [fast|full]
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# Repo root of the dotfiles checkout ($HOME locally, $GITHUB_WORKSPACE in CI).
ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
PYTHON="${PYTHON:-python3}"
SHELLCHECK="${SHELLCHECK:-shellcheck}"
BUN="${BUN:-$(command -v bun || printf '%s' "$HOME/.bun/bin/bun")}"
MODE="${1:-fast}"

usage() {
    printf 'Usage: %s [fast|full]\n' "${BASH_SOURCE[0]}"
}

if (( $# > 1 )); then
    usage >&2
    exit 2
fi

case "$MODE" in
    fast|--fast)
        MODE=fast
        ;;
    full|--full)
        MODE=full
        ;;
    help|--help)
        usage
        exit 0
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac

export PYTHONNOUSERSITE=1
export PIP_DISABLE_PIP_VERSION_CHECK=1
export DAILY_NEWS_OFFLINE=1

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/daily-news-verify.XXXXXX")"
cleanup() { # shellcheck disable=SC2329
    local status
    status=$?
    rm -rf -- "$WORKDIR"
    return "$status"
}
trap cleanup EXIT

run_shellcheck() {
    command -v "$SHELLCHECK" >/dev/null || {
        printf 'required tool is unavailable: %s\n' "$SHELLCHECK" >&2
        return 1
    }
    "$SHELLCHECK" --shell=bash \
        "$SCRIPT_DIR/run_all_digests.sh" \
        "$SCRIPT_DIR/verify-daily-news.sh"
}

run_import_checks() {
    PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
        "$PYTHON" - "$SCRIPT_DIR" <<'PY'
import ast
import pathlib
import sys

script_dir = pathlib.Path(sys.argv[1])
package = script_dir / "daily_news"
expected = {
    "catalog.py", "contracts.py", "runtime.py", "research.py",
    "editorial.py", "copy.py", "archive.py", "attention.py", "workflow.py",
    "attention_sources.py", "attention_match.py",
}
actual = {path.name for path in package.glob("*.py")}
missing = expected - actual
if missing:
    raise SystemExit(f"missing Daily News modules: {sorted(missing)}")
for path in sorted(package.glob("*.py")):
    ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

import daily_news  # noqa: E402
from daily_news.catalog import TOPICS  # noqa: E402
from daily_news.workflow import run_digest  # noqa: E402

required_topics = {"ai-tech", "agentic-platform", "ai-hardware", "gaming", "world"}
if set(TOPICS) != required_topics:
    raise SystemExit(f"unexpected topic contract: {sorted(TOPICS)}")
if not callable(run_digest):
    raise SystemExit("workflow.run_digest is not callable")
print("Daily News package import and AST checks passed")
PY
}

run_release_smoke() {
    "$PYTHON" - "$WORKDIR" "$SCRIPT_DIR" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
script_dir = pathlib.Path(sys.argv[2])
sys.path.insert(0, str(script_dir))
import news_publish

issue_date = "2026-08-31"
digests = root / "digests"
news_dir = root / "news"
assets = root / "assets"
assets.mkdir(parents=True)
(assets / "news.css").write_text("body { color: #171716; }\n", encoding="utf-8")
(assets / "news.js").write_text("void 0;\n", encoding="utf-8")

for key in news_publish.TOPIC_ORDER:
    topic = news_publish.TOPICS[key]
    run_dir = digests / topic["category"] / issue_date
    run_dir.mkdir(parents=True)
    publication = {
        "schema_version": 2,
        "ranking_schema_version": 3,
        "date": issue_date,
        "slug": topic["web_slug"],
        "title": topic["web_title"],
        "source_category": topic["category"],
        "status": "published",
        "notice": "",
        "standfirst": f"{topic['web_title']} reports the verified developments shaping this section.",
        "fresh": [{
            "title": f"{topic['web_title']} lead",
            "url": f"https://example.com/{topic['web_slug']}/lead",
            "source_domain": "example.com",
            "date_published": issue_date,
            "summary": "A source-backed summary with the material facts.",
            "editorial_significance": "high",
            "priority_score": 80.0,
        }],
        "ongoing": [],
        "generated_at": f"{issue_date}T12:00:00+00:00",
    }
    (run_dir / "publication.json").write_text(
        json.dumps(publication), encoding="utf-8"
    )

result = news_publish.publish(
    issue_date,
    digests_dir=digests,
    news_dir=news_dir,
    asset_dir=assets,
    send_email=False,
)
if result["date"] != issue_date or result["dates"] != 1 or result["categories"] != 5:
    raise SystemExit(f"unexpected publish result: {result}")
current = news_dir / "current"
if not current.is_symlink():
    raise SystemExit("release did not activate current symlink")
required_pages = [
    current / "index.html",
    current / issue_date / "index.html",
    current / "archive" / "index.html",
    current / "404.html",
    current / "assets" / "news.css",
    current / "assets" / "news.js",
]
for key in news_publish.TOPIC_ORDER:
    required_pages.append(current / issue_date / news_publish.TOPICS[key]["web_slug"] / "index.html")
for path in required_pages:
    if not path.is_file():
        raise SystemExit(f"release page missing: {path}")
build = json.loads((current / "build.json").read_text(encoding="utf-8"))
if build != {
    **build,
    "latest_date": issue_date,
    "dates": 1,
    "pages": 14,
}:
    raise SystemExit(f"unexpected build manifest: {build}")
manifest = json.loads(
    (news_dir / "publications" / "manifest.json").read_text(encoding="utf-8")
)
if manifest["dates"][0]["date"] != issue_date:
    raise SystemExit(f"publication manifest missed {issue_date}")
print("Daily News static release smoke passed")
PY
}

run_fast() {
    run_shellcheck
    run_import_checks
    # Preflight validates tracked runtime files resolved under Path.home();
    # point it at this checkout so CI (HOME != checkout) checks the same files.
    HOME="$ROOT" PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
        "$PYTHON" "$SCRIPT_DIR/digest_runner.py" --preflight
    PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
        "$PYTHON" "$SCRIPT_DIR/test_workflow_state.py"
    run_release_smoke
}

run_full() {
    run_fast
    PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
        "$PYTHON" "$SCRIPT_DIR/test_news_attention.py"
    PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
        "$PYTHON" "$SCRIPT_DIR/test_news_attention_budget.py"
    # Includes preflight assertions against the checkout's tracked runtime files.
    HOME="$ROOT" PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
        "$PYTHON" "$SCRIPT_DIR/test_digest_pipeline.py"
    PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
        "$PYTHON" "$SCRIPT_DIR/test_news_publish.py"
    # F234: digest read sandbox must block parser-differential local-path reads.
    "$BUN" "$SCRIPT_DIR/test_digest_omp_sandbox.ts"
}

case "$MODE" in
    fast)
        run_fast
        ;;
    full)
        run_full
        ;;
esac
printf 'Daily News verification (%s) complete\n' "$MODE"
