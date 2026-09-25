---
description: Review code changes from the current session. Spawns a reviewer subagent, then the parent agent verifies every finding before presenting results to the user.
---

# Review

Review changes made in the current session by spawning a dedicated reviewer subagent. The parent agent does NOT act on findings blindly — it verifies each one before presenting results.

## Step 1: Determine review scope

If the user specified a target (file, directory, commit range, PR, etc.), use that directly.

If the user just said `/review-session` with no target, scan the session for what was changed:

- Check the conversation history for files edited, created, or deleted
- Check `git diff` / `git status` in the active repo
- Check if there's an obvious scope (a feature branch, a PR, a set of changed files)

If you genuinely cannot determine what should be reviewed, ask the user: "What should I review? (file, directory, PR number, or commit range)"

Never guess a scope — if it's unclear after a reasonable scan, ask.

## Step 2: Gather review context

Before spawning the reviewer, collect and write the relevant context to a temporary file so the reviewer has everything it needs:

- Changed file paths
- Diffs (if git is available: `git diff` or `git diff <base>`)
- Any relevant project conventions (AGENTS.md, CLAUDE.md, etc. in the repo)
- User's stated goals or constraints from the session

Write this to a local artifact: `local://review-context.md`

## Step 3: Spawn the reviewer subagent

Use the `task` tool to spawn a subagent with `agent: "reviewer"` (case-insensitive; the harness resolves it). The prompt MUST include:

- The path to `local://review-context.md`
- Instructions to read that file for full context
- Instructions to produce findings in a structured format:
  - **Severity:** `critical` | `high` | `medium` | `low` | `style`
  - **File + line range**
  - **Finding:** what the issue is
  - **Recommendation:** concrete fix
- Instructions to write output to `local://review-findings.md`

Example task:

```
# Target: review changed files documented in local://review-context.md
# Change: read local://review-context.md for full context. Perform a thorough code review. For each finding, note severity (critical/high/medium/low/style), file + line range, the issue, and a concrete fix recommendation. Write findings to local://review-findings.md.
# Acceptance: local://review-findings.md contains all findings in the structured format. No project-wide commands (no test runs, no linters).
```

If `local://review-context.md` is large, reference it by URI rather than inlining — the subagent reads it via the `read` tool.

## Step 4: Verify every finding (MANDATORY)

Once the reviewer returns, read `local://review-findings.md`. **Do NOT present findings to the user until you have verified each one.**

For each finding:
1. Read the cited file at the cited line range
2. Confirm the issue actually exists in the current state of the code
3. Validate the severity assessment
4. For any finding marked `critical` or `high`, confirm it with additional evidence (e.g., check callers, grep for related patterns, check if it would actually break at runtime)

**Discard** findings that don't hold up on verification (state the reason). **Downgrade** severity if the reviewer overestimated impact. **Keep** verified findings as-is.

## Step 5: Present to user

Present verified findings in a clean format:

```
## Code Review — <scope>

### Critical
- **<file>:<line>** — <finding>
  → <recommendation>

### High
- ...

### Medium
- ...

### Low
- ...

### Style
- ...
```

Then suggest which findings should be addressed and in what order. Ask: "Apply these fixes?"

Do NOT apply any fixes unless the user explicitly confirms. If they confirm, apply them in the order presented (critical first).

## Important

- The reviewer subagent is a special-purpose agent — it reviews code, it does NOT edit.
- The parent agent (you) is the gatekeeper. You verify, you present, you apply.
- Never skip verification. A false finding presented to the user erodes trust.
- If the reviewer finds nothing, report that too — "No issues found" is a valid and useful result.
