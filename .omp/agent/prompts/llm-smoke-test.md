---
description: Run behavioral, throughput, context-recall, and memory checks against the Linux-primary local LLM stack. Use after llama.cpp, llama-swap, model, driver, or proxy changes.
---

# Local LLM Smoke Test

Test the Linux-primary llama-swap service on `gamingrig-linux` through the homelab proxy. Do not bypass the proxy except when diagnosing a failed load.

## Architecture

```text
OMP / curl -> llm-proxy 127.0.0.1:8081 -> gamingrig-linux 192.168.4.103:8080 -> llama-swap -> llama-server
                                      \-> OpenCode Go fallback only when Linux is unavailable
```

Current served IDs:

| Model | Role | Context |
|---|---|---:|
| `qwen-3.8-27b-iq2` | General reasoning, default smoke target | 150K |
| `ornith-1.0-35b-q8` | Agentic coding | 256K |
| `ornith-1.0-9b-q6` | Fast dense reasoning/coding | 256K |
| `gemma-4-12b-q6` | Fast general use with MTP drafting | 128K |
| `gemma-4-26b-q8` | Quality-first general use with MTP drafting | 256K |

## Standard run

```bash
bash ~/scripts/smoke-test-llm.sh
```

Defaults: Qwen 3.8 primary, Ornith 9B secondary, and the 20K context-recall fixture. Override all three positionally:

```bash
bash ~/scripts/smoke-test-llm.sh \
  gemma-4-26b-q8 \
  gemma-4-12b-q6 \
  ~/benchmarks/context-window/context_50_000.md
```

The script must verify:

1. `/health` reports `status=healthy` and `rig_os=linux`.
2. Both requested IDs appear in the proxy's `/v1/models` response.
3. Each model produces its required behavioral marker with a natural stop.
4. No response carries `X-Fallback: true`.
5. Server-reported generation throughput and token counts are printed.
6. Context recall scores at least 8/10 when the fixture exists.
7. Linux RAM and NVIDIA VRAM snapshots are captured before and after.

A cloud-fallback response is not a local model pass, even if its answer is correct.

## Focused diagnostics

```bash
curl -s http://127.0.0.1:8081/health | python3 -m json.tool
curl -s http://127.0.0.1:8081/v1/models | python3 -m json.tool
ssh gamingrig-linux 'sudo systemctl status llama-swap --no-pager; nvidia-smi'
ssh gamingrig-linux 'curl -Ns --max-time 2 http://127.0.0.1:8080/logs/stream/upstream'
```

For a single OMP probe:

```bash
echo 'Reply with exactly LOCAL_OK.' | \
  omp -p --provider local-llm --model qwen-3.8-27b-iq2 --api-key none
```

Report exact HTTP status, model ID, finish reason, token counts, generation tokens/second, elapsed time, context score, and memory state. Read llama-swap's model-specific log stream before changing model parameters when a load fails.
