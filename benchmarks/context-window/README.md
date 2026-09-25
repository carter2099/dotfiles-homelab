# Context Window Benchmark

Tests a model's recall across varying context sizes using planted facts in
interview transcripts.

## How to run

Pipe a file into any LLM as the prompt. The file contains an interview
transcript followed by 10 questions. The model reads the interview and
answers the questions.

```bash
# With pi
pi -p --provider <provider> --model <model> < context_20_000.md

# Or with curl against an OpenAI-compatible API
curl -s http://localhost:8081/v1/chat/completions \
  -d "$(jq -n --arg content "$(cat context_20_000.md)" '{
    model: "qwen3.6-35b-a3b-q6_k",
    messages: [{role: "user", content: $content}]
  }')" | jq -r '.choices[0].message.content'
```

## Available files

| File | Tokens | Size |
|---|---|---|
| `context_20_000.md` | ~20k | 94 KB |
| `context_50_000.md` | ~50k | 234 KB |
| `context_100_000.md` | ~100k | 469 KB |
| `context_200_000.md` | ~200k | 938 KB |

## How it works

Each file is a podcast-style interview with **Jordan Chen**, a fictional
software engineer. Ten facts about Jordan's life (hometown, favorite book,
dog's name, etc.) are planted at different depths in the transcript.

At the end of the file are 10 questions — one per planted fact.

The model must read the entire interview and answer all 10 questions. There
are no tricks or contradictions; every answer is stated directly in the
transcript.

## Scoring

Count correct answers out of 10. A model with perfect long-context recall
should get 10/10 on all four files.

**Expected behavior as context grows:**
- Good recall: 10/10 on all files
- Degradation: wrong answers on later questions (facts planted deeper in
  the document), or answers citing the metadata table instead of the
  interview body
- Severe degradation: wrong answers throughout, or failure to follow the
  questions at the end

## File format

Each file has three sections:

1. **Metadata header** — lists the 10 planted facts and their expected
   answers (this is for your reference — don't let the model cheat from it)
2. **Interview body** — the actual transcript with facts woven in at
   different depth percentages
3. **Questions** — 10 questions labeled 1–10

Facts are placed at these approximate depths (of total tokens):

| # | Fact | Depth | Expected answer |
|---|---|---|---|
| 1 | grew up in Portland, Oregon | 10% | Portland, Oregon |
| 2 | learned piano at age 7 | 20% | 7 |
| 3 | favorite book is Dune | 30% | Dune by Frank Herbert |
| 4 | started current job in 2019 | 40% | 2019 |
| 5 | met spouse at The Daily Grind | 50% | The Daily Grind coffee shop |
| 6 | dog named Maple | 60% | Maple |
| 7 | mother's birthday March 14th | 70% | March 14th |
| 8 | lived in Tokyo 2 years | 80% | 2 years |
| 9 | favorite food Thai green curry | 85% | Thai green curry |
| 10 | skydived in Queenstown, NZ | 90% | Queenstown, New Zealand |

## Methodology notes

- Token counts use `cl100k_base` encoding (tiktoken) — matches OpenAI /
  most modern models
- Files are within ±0.5% of their target token count
- The generator is `generate.py` — see it for reproducibility details
- Repetition: the larger files reuse ~48 unique filler exchanges
  cyclically. This is intentional — it simulates the kind of repetitive
  content real conversations contain and tests whether the model can
  locate the single occurrence of each fact among similar distractor
  content

## Results

After running a test, record results here or in `/home/carter/notes/`.

### Reference: deepseek-v4-flash (OpenCode Go)

| File | Score | Time |
|---|---|---|
| context_20_000.md | 10/10 | ~5s |
| context_50_000.md | 10/10 | ~13s |
| context_100_000.md | 10/10 | ~16s |
| context_200_000.md | 10/10 | ~22s |
