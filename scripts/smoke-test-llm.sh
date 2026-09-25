#!/bin/bash
# Behavioral and throughput smoke test for Linux llama-swap through llm-proxy.
# Usage: smoke-test-llm.sh [primary_model] [secondary_model] [context_file]
set -euo pipefail

PRIMARY_MODEL="${1:-qwen-3.8-27b-iq2}"
SECONDARY_MODEL="${2:-ornith-1.0-9b-q6}"
CONTEXT_FILE="${3:-$HOME/benchmarks/context-window/context_20_000.md}"
ENDPOINT="http://127.0.0.1:8081/v1/chat/completions"
HEALTH_ENDPOINT="http://127.0.0.1:8081/health"
TIMEOUT=900
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

passes=0
failures=0
pass() { printf '[PASS] %s\n' "$1"; passes=$((passes + 1)); }
fail() { printf '[FAIL] %s\n' "$1"; failures=$((failures + 1)); }
info() { printf '[INFO] %s\n' "$1"; }

printf 'Local LLM smoke test\n'
printf 'Primary:   %s\n' "$PRIMARY_MODEL"
printf 'Secondary: %s\n' "$SECONDARY_MODEL"
printf 'Started:   %s\n\n' "$(date --iso-8601=seconds)"

health_json="$(curl --fail --silent --show-error --max-time 10 "$HEALTH_ENDPOINT")"
if HEALTH_JSON="$health_json" python3 - <<'PY'
import json, os, sys
health = json.loads(os.environ["HEALTH_JSON"])
print(f"state={health.get('status')} os={health.get('rig_os')} backend={health.get('backend')}")
sys.exit(0 if health.get("status") == "healthy" and health.get("rig_os") == "linux" else 1)
PY
then
  pass "Proxy reports a healthy Linux backend"
else
  fail "Proxy is not serving from Linux"
  exit 1
fi

models_json="$(curl --fail --silent --show-error --max-time 10 http://127.0.0.1:8081/v1/models)"
if MODELS_JSON="$models_json" PRIMARY_MODEL="$PRIMARY_MODEL" SECONDARY_MODEL="$SECONDARY_MODEL" python3 - <<'PY'
import json, os, sys
ids = {item["id"] for item in json.loads(os.environ["MODELS_JSON"]).get("data", [])}
required = {os.environ["PRIMARY_MODEL"], os.environ["SECONDARY_MODEL"]}
missing = sorted(required - ids)
if missing:
    print("missing=" + ",".join(missing))
    sys.exit(1)
print("registered=" + ",".join(sorted(required)))
PY
then
  pass "Requested models are registered"
else
  fail "Requested model is absent from /v1/models"
  exit 1
fi

info "Linux memory before probes"
ssh -o BatchMode=yes gamingrig-linux 'free -h | sed -n "1,2p"; nvidia-smi --query-gpu=name,memory.used,memory.total,utilization.gpu,temperature.gpu --format=csv,noheader' || true

run_probe() {
  local label="$1" model="$2" prompt="$3" marker="$4"
  local stem="$WORKDIR/${label// /-}"
  MODEL="$model" PROMPT="$prompt" python3 - "$stem.payload" <<'PY'
import json, os, sys
with open(sys.argv[1], "w") as handle:
    json.dump({
        "model": os.environ["MODEL"],
        "messages": [{"role": "user", "content": os.environ["PROMPT"]}],
        "max_tokens": 2048,
        "stream": False,
    }, handle)
PY

  info "$label: requesting $model"
  if ! elapsed="$(curl --fail-with-body --silent --show-error --max-time "$TIMEOUT" \
      -D "$stem.headers" -o "$stem.response" -w '%{time_total}' \
      -H 'Content-Type: application/json' --data-binary "@$stem.payload" "$ENDPOINT")"; then
    fail "$label HTTP request"
    cat "$stem.response" 2>/dev/null || true
    return
  fi

  if python3 - "$stem.response" "$stem.headers" "$marker" "$elapsed" <<'PY'
import json, pathlib, sys
response_path, headers_path, marker, elapsed = sys.argv[1:]
headers = pathlib.Path(headers_path).read_text(errors="replace").lower()
if "x-fallback: true" in headers:
    print("unexpected cloud fallback")
    sys.exit(1)
body = json.loads(pathlib.Path(response_path).read_text())
choice = body.get("choices", [{}])[0]
message = choice.get("message", {})
content = message.get("content") or ""
reasoning = message.get("reasoning_content") or message.get("reasoning") or ""
usage = body.get("usage", {})
timings = body.get("timings", {})
print(f"content={content.strip()}")
print(f"elapsed_seconds={float(elapsed):.3f}")
print(f"prompt_tokens={usage.get('prompt_tokens', '?')}")
print(f"completion_tokens={usage.get('completion_tokens', '?')}")
print(f"generation_tokens_per_second={timings.get('predicted_per_second', '?')}")
print(f"reasoning_characters={len(reasoning)} finish_reason={choice.get('finish_reason', '?')}")
sys.exit(0 if marker in content and choice.get("finish_reason") == "stop" else 1)
PY
  then
    pass "$label behavioral response"
  else
    fail "$label behavioral response"
  fi
}

run_probe "primary" "$PRIMARY_MODEL" \
  "What is 17 multiplied by 19? End your final answer with exactly PRIMARY_MODEL_OK_323 on its own line." \
  "PRIMARY_MODEL_OK_323"
run_probe "secondary" "$SECONDARY_MODEL" \
  "A service retries after 2, 4, and 8 seconds. What is the total delay? End with exactly SECONDARY_MODEL_OK_14 on its own line." \
  "SECONDARY_MODEL_OK_14"

if [[ -f "$CONTEXT_FILE" ]]; then
  info "context recall: $(basename "$CONTEXT_FILE") ($(wc -c < "$CONTEXT_FILE") bytes)"
  MODEL="$SECONDARY_MODEL" CONTEXT_FILE="$CONTEXT_FILE" python3 - "$WORKDIR/context.payload" <<'PY'
import json, os, pathlib, sys
content = pathlib.Path(os.environ["CONTEXT_FILE"]).read_text()
with open(sys.argv[1], "w") as handle:
    json.dump({
        "model": os.environ["MODEL"],
        "messages": [{"role": "user", "content": content}],
        "max_tokens": 2048,
        "stream": False,
    }, handle)
PY
  if context_elapsed="$(curl --fail-with-body --silent --show-error --max-time "$TIMEOUT" \
      -D "$WORKDIR/context.headers" -o "$WORKDIR/context.response" -w '%{time_total}' \
      -H 'Content-Type: application/json' --data-binary "@$WORKDIR/context.payload" "$ENDPOINT")" && \
      python3 - "$WORKDIR/context.response" "$WORKDIR/context.headers" "$context_elapsed" <<'PY'
import json, pathlib, sys
response_path, headers_path, elapsed = sys.argv[1:]
if "x-fallback: true" in pathlib.Path(headers_path).read_text(errors="replace").lower():
    print("unexpected cloud fallback")
    sys.exit(1)
body = json.loads(pathlib.Path(response_path).read_text())
choice = body.get("choices", [{}])[0]
content = choice.get("message", {}).get("content") or ""
checks = ["Portland", "age 7", "Dune", "2019", "Daily Grind", "Maple", "March 14", "2 years", "Thai green curry", "Queenstown"]
score = sum(item.lower() in content.lower() for item in checks)
usage = body.get("usage", {})
print(f"elapsed_seconds={float(elapsed):.3f} prompt_tokens={usage.get('prompt_tokens', '?')} recall={score}/10 finish_reason={choice.get('finish_reason', '?')}")
sys.exit(0 if score >= 8 and choice.get("finish_reason") == "stop" else 1)
PY
  then
    pass "Context recall at least 8/10"
  else
    fail "Context recall benchmark"
  fi
else
  info "Context file absent; skipped: $CONTEXT_FILE"
fi

info "Linux memory after probes"
ssh -o BatchMode=yes gamingrig-linux 'free -h | sed -n "1,2p"; nvidia-smi --query-gpu=name,memory.used,memory.total,utilization.gpu,temperature.gpu --format=csv,noheader' || true

printf '\nResults: %d passed, %d failed\n' "$passes" "$failures"
[[ "$failures" -eq 0 ]]
