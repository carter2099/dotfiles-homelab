#!/usr/bin/env bash
# Deterministic verification for the Python Dependabot intake boundary.
# Usage: verify-dependabot-intake.sh [fast|full]
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PYTHON="${PYTHON:-python3}"
SHELLCHECK="${SHELLCHECK:-shellcheck}"
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

require_tool() {
  local name
  name=$1
  if ! command -v "$name" >/dev/null 2>&1; then
    printf 'FATAL: required tool is unavailable: %s\n' "$name" >&2
    exit 127
  fi
}
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/dependabot-intake-verify.XXXXXX")"
classifier_pid=""

cleanup() { # shellcheck disable=SC2329
  local status
  status=$?
  if [[ -n "$classifier_pid" ]]; then
    kill "$classifier_pid" >/dev/null 2>&1 || true
    wait "$classifier_pid" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$WORKDIR"
  return "$status"
}
trap cleanup EXIT

run_shellcheck() {
  "$SHELLCHECK" --shell=bash "$SCRIPT_DIR/verify-dependabot-intake.sh"
}

run_python_checks() {
  local pycache_prefix
  pycache_prefix="$WORKDIR/pycache"
  PYTHONPYCACHEPREFIX="$pycache_prefix" "$PYTHON" -m py_compile \
    "$SCRIPT_DIR/hyperliquid_dependabot_intake.py" \
    "$SCRIPT_DIR/test_hyperliquid_dependabot_intake.py"
  PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
    PYTHONPYCACHEPREFIX="$pycache_prefix" \
    "$PYTHON" "$SCRIPT_DIR/test_hyperliquid_dependabot_intake.py"
}

wait_for_file() {
  local path attempts
  path=$1
  attempts=0
  while [[ ! -s "$path" ]]; do
    if (( attempts >= 100 )); then
      printf 'FATAL: fixture did not publish %s\n' "$path" >&2
      return 1
    fi
    attempts=$((attempts + 1))
    sleep 0.05
  done
}

run_cli_fixture() {
  local fixture_dir fixture_bin gh_fixture classifier_info classifier_port manifest
  fixture_dir="$WORKDIR/fixtures"
  fixture_bin="$fixture_dir/bin"
  gh_fixture="$fixture_dir/open-prs.json"
  classifier_info="$fixture_dir/classifier.port"
  manifest="$WORKDIR/intake.json"
  mkdir -p -- "$fixture_bin"

  cat > "$gh_fixture" <<'JSON'
[
  {
    "number": 9,
    "author": {"login": "app/dependabot", "is_bot": true},
    "baseRefName": "main",
    "headRefName": "dependabot/github_actions/actions/checkout-7",
    "headRefOid": "2222222222222222222222222222222222222222",
    "isDraft": false,
    "title": "Untrusted title must not enter the manifest",
    "body": "Untrusted release notes are classified outside the handoff"
  },
  {
    "number": 3,
    "author": {"login": "app/dependabot", "is_bot": true},
    "baseRefName": "main",
    "headRefName": "dependabot/bundler/faraday-retry-2.4.0",
    "headRefOid": "1111111111111111111111111111111111111111",
    "isDraft": false,
    "title": "Another untrusted title",
    "body": "Another untrusted body"
  }
]
JSON

  cat > "$fixture_bin/gh" <<'BASH'
#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "${1:-}" != pr || "${2:-}" != list ]]; then
  printf 'unexpected gh fixture invocation\n' >&2
  exit 1
fi
cat -- "${INTAKE_GH_FIXTURE:?}"
BASH
  chmod 0755 "$fixture_bin/gh"

  "$PYTHON" - "$classifier_info" >"$WORKDIR/classifier.log" 2>&1 <<'PY' &
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

info_path = Path(sys.argv[1])

class Classifier(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/classify":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        try:
            request = json.loads(self.rfile.read(length))
        except (ValueError, TypeError):
            self.send_error(400)
            return
        if not isinstance(request, dict) or not isinstance(request.get("text"), str):
            self.send_error(400)
            return
        payload = json.dumps({"label": "SAFE", "score": 0.01, "flagged": False}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, _format, *_args):
        return

server = HTTPServer(("127.0.0.1", 0), Classifier)
temporary_info_path = info_path.with_name(info_path.name + ".tmp")
temporary_info_path.write_text(str(server.server_port), encoding="ascii")
temporary_info_path.replace(info_path)
server.serve_forever()
PY
  classifier_pid=$!
  wait_for_file "$classifier_info"
  classifier_port="$(<"$classifier_info")"
  if [[ ! "$classifier_port" =~ ^[0-9]+$ ]]; then
    printf 'FATAL: classifier fixture published an invalid port\n' >&2
    return 1
  fi

  INTAKE_GH_FIXTURE="$gh_fixture" \
    PATH="$fixture_bin:$PATH" \
    PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
    PYTHONPYCACHEPREFIX="$WORKDIR/pycache" \
    "$PYTHON" "$SCRIPT_DIR/hyperliquid_dependabot_intake.py" \
      --output "$manifest" \
      --classifier-url "http://127.0.0.1:$classifier_port"

  [[ -s "$manifest" ]]
  MANIFEST="$manifest" "$PYTHON" - <<'PY'
import json
import os
from pathlib import Path

manifest = json.loads(Path(os.environ["MANIFEST"]).read_text(encoding="utf-8"))
if [item["number"] for item in manifest["pull_requests"]] != [3, 9]:
    raise SystemExit("fixture PRs were not sorted")
if manifest["classification"]["result"] != "SAFE":
    raise SystemExit("fixture intake was not classified SAFE")
if manifest["classification"]["classified_pull_requests"] != 2:
    raise SystemExit("fixture classification count is wrong")
serialized = json.dumps(manifest).casefold()
if "untrusted title" in serialized or "untrusted body" in serialized:
    raise SystemExit("untrusted title/body entered the manifest")
for pull_request in manifest["pull_requests"]:
    if set(pull_request) != {
        "number", "ecosystem", "dependency", "target_version",
        "base_ref", "head_ref", "head_sha",
    }:
        raise SystemExit("manifest contains an unexpected PR field")
print("exact CLI fixture manifest accepted")
PY
}

require_tool "$PYTHON"
require_tool "$SHELLCHECK"
run_shellcheck
run_python_checks
if [[ "$MODE" == full ]]; then
  run_cli_fixture
fi
printf 'DEPENDABOT_INTAKE_%s_OK\n' "${MODE^^}"
