/**
 * Prevent hyperliquid-run from discovering or reading Dependabot PRs itself.
 *
 * The wrapper supplies a Prompt-Guard-classified manifest. The agent may use
 * only that sanitized metadata and may close those exact PR numbers after the
 * verified dev-branch update. Ordinary SDK upstream research remains allowed.
 */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";

const repository = "carter2099/hyperliquid";
const closeComment =
  "Applied to dev by the scheduled Hyperliquid SDK maintenance run.";
const manifestPath = process.env.HYPERLIQUID_DEPENDABOT_MANIFEST ?? "";

interface PullRequest {
  number: number;
  ecosystem: "bundler" | "github_actions";
  dependency: string;
  target_version: string;
  base_ref: "main" | "dev";
  head_ref: string;
  head_sha: string;
}

interface IntakeManifest {
  schema_version: number;
  repository: string;
  generated_at: string;
  intake_sha256: string;
  classification: {
    policy: "title_and_body_per_pr_then_sanitized_handoff";
    result: "SAFE" | "NOT_NEEDED";
    classified_pull_requests: number;
    max_pull_request_score: number | null;
    sanitized_handoff_score: number | null;
  };
  pull_requests: PullRequest[];
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  const object = value as Record<string, unknown>;
  return `{${Object.keys(object)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(object[key])}`)
    .join(",")}}`;
}

function loadManifest(source: string): IntakeManifest {
  if (!manifestPath) {
    throw new Error("HYPERLIQUID_DEPENDABOT_MANIFEST is not set");
  }
  const parsed = JSON.parse(source) as IntakeManifest;
  const expectedManifestKeys = [
    "classification",
    "generated_at",
    "intake_sha256",
    "pull_requests",
    "repository",
    "schema_version",
  ];
  if (
    JSON.stringify(Object.keys(parsed).sort()) !== JSON.stringify(expectedManifestKeys) ||
    parsed.schema_version !== 1 ||
    parsed.repository !== repository ||
    !/^[0-9a-f]{64}$/.test(parsed.intake_sha256)
  ) {
    throw new Error("manifest schema or repository is invalid");
  }
  const generatedAt = Date.parse(parsed.generated_at);
  const manifestAge = Date.now() - generatedAt;
  if (!Number.isFinite(generatedAt) || manifestAge < -300_000 || manifestAge > 900_000) {
    throw new Error("manifest is stale or has an invalid timestamp");
  }
  if (!Array.isArray(parsed.pull_requests)) {
    throw new Error("manifest pull_requests is not an array");
  }
  const expectedClassificationKeys = [
    "classified_pull_requests",
    "max_pull_request_score",
    "policy",
    "result",
    "sanitized_handoff_score",
  ];
  const classification = parsed.classification;
  if (
    !classification ||
    JSON.stringify(Object.keys(classification).sort()) !==
      JSON.stringify(expectedClassificationKeys) ||
    classification.policy !== "title_and_body_per_pr_then_sanitized_handoff" ||
    classification.classified_pull_requests !== parsed.pull_requests.length ||
    (parsed.pull_requests.length > 0
      ? classification.result !== "SAFE" ||
        typeof classification.max_pull_request_score !== "number" ||
        typeof classification.sanitized_handoff_score !== "number" ||
        !Number.isFinite(classification.max_pull_request_score) ||
        !Number.isFinite(classification.sanitized_handoff_score) ||
        classification.max_pull_request_score < 0 ||
        classification.max_pull_request_score > 1 ||
        classification.sanitized_handoff_score < 0 ||
        classification.sanitized_handoff_score > 1
      : classification.result !== "NOT_NEEDED" ||
        classification.max_pull_request_score !== null ||
        classification.sanitized_handoff_score !== null)
  ) {
    throw new Error("manifest classification does not cover the full PR batch");
  }

  const expectedKeys = [
    "base_ref",
    "dependency",
    "ecosystem",
    "head_ref",
    "head_sha",
    "number",
    "target_version",
  ];
  let previousNumber = 0;
  const seenNumbers = new Set<number>();
  const seenHeads = new Set<string>();
  for (const pullRequest of parsed.pull_requests) {
    const keys = Object.keys(pullRequest).sort();
    if (JSON.stringify(keys) !== JSON.stringify(expectedKeys)) {
      throw new Error("manifest PR entry contains unexpected fields");
    }
    if (
      !Number.isInteger(pullRequest.number) ||
      pullRequest.number <= previousNumber ||
      seenNumbers.has(pullRequest.number)
    ) {
      throw new Error("manifest PR numbers are invalid, duplicated, or unsorted");
    }
    if (!/^(bundler|github_actions)$/.test(pullRequest.ecosystem)) {
      throw new Error(`manifest PR #${pullRequest.number} has an invalid ecosystem`);
    }
    if (!/^[A-Za-z0-9][A-Za-z0-9_.\-/]*$/.test(pullRequest.dependency)) {
      throw new Error(`manifest PR #${pullRequest.number} has an invalid dependency`);
    }
    if (!/^\d[A-Za-z0-9_.+\-]*$/.test(pullRequest.target_version)) {
      throw new Error(`manifest PR #${pullRequest.number} has an invalid target version`);
    }
    if (!/^(main|dev)$/.test(pullRequest.base_ref)) {
      throw new Error(`manifest PR #${pullRequest.number} has an invalid base branch`);
    }
    const headPrefix =
      `dependabot/${pullRequest.ecosystem}/${pullRequest.dependency}-`;
    if (
      pullRequest.head_ref !== headPrefix + pullRequest.target_version &&
      pullRequest.head_ref !== headPrefix + "v" + pullRequest.target_version
    ) {
      throw new Error(`manifest PR #${pullRequest.number} has inconsistent metadata`);
    }
    if (!/^[0-9a-f]{40}$/.test(pullRequest.head_sha) || seenHeads.has(pullRequest.head_ref)) {
      throw new Error(`manifest PR #${pullRequest.number} has an invalid or duplicate head`);
    }
    previousNumber = pullRequest.number;
    seenNumbers.add(pullRequest.number);
    seenHeads.add(pullRequest.head_ref);
  }

  const actionable = {
    repository: parsed.repository,
    pull_requests: parsed.pull_requests,
  };
  const actualDigest = createHash("sha256")
    .update(canonicalJson(actionable), "ascii")
    .digest("hex");
  if (actualDigest !== parsed.intake_sha256) {
    throw new Error("manifest actionable metadata failed its SHA-256 check");
  }
  return parsed;
}

let manifest: IntakeManifest | null = null;
let validatedManifestFileSha256 = "";
let initializationError = "";
try {
  const source = readFileSync(manifestPath, "utf8");
  manifest = loadManifest(source);
  validatedManifestFileSha256 = createHash("sha256").update(source, "utf8").digest("hex");
} catch (error) {
  initializationError = error instanceof Error ? error.message : String(error);
}

const allowedCloseCommands = new Set(
  (manifest?.pull_requests ?? []).map(
    ({ number }) =>
      `gh pr close ${number} --repo ${repository} --comment "${closeComment}"`,
  ),
);

const ghCommand = /(?:^|[\/\s])gh(?:\s|$)/;
const pullRef = /(?:refs\/pull\/|dependabot\/(?:bundler|github_actions)\/)/;
const ownGithubUrl = /(?:(?:api\.)?github\.com\/(?:repos\/)?|raw\.githubusercontent\.com\/)carter2099\/hyperliquid(?:[\s/#?]|$)/i;
const githubApi = /api\.github\.com/i;
const githubGraphql = /api\.github\.com\/graphql/i;
const ownRepoReference = /carter2099(?:\/|%2f)hyperliquid/i;
const internalPullUrl = /(?:^|[;\s])pr:\/\//i;
const directGitDiscovery = /(?:^|&&|\|\||[;|])\s*git(?:\s+-C\s+(?:"[^"\r\n]*"|'[^'\r\n]*'|\S+))?\s+(?:fetch|ls-remote)(?:\s|$)/;

function blockedBashReason(command: string): string | null {
  const trimmed = command.trim();
  if (allowedCloseCommands.has(trimmed)) return null;
  if (ghCommand.test(trimmed)) {
    return "GitHub CLI PR discovery is blocked; use only the classified intake manifest.";
  }
  if (
    directGitDiscovery.test(trimmed) ||
    pullRef.test(trimmed) ||
    ownGithubUrl.test(trimmed) ||
    githubGraphql.test(trimmed) ||
    (githubApi.test(trimmed) && ownRepoReference.test(trimmed))
  ) {
    return "Direct Dependabot branch or PR access is blocked; use only the classified intake manifest.";
  }
  return null;
}

// OMP fetches URL-shaped read targets via WHATWG URL parsing, which drops
// tab/newline characters, strips leading/trailing C0/space, and treats `\` as
// `/` (F234 class). Match the blocklist against that normalized form and its
// percent-decoded form too, so "github.com/carter2099/hyper\tliquid" or
// "github.com\\carter2099\\hyperliquid" cannot slip past the raw-string regexes.
function blockedReadReason(rawPath: string): string | null {
  const normalized = rawPath.replace(/[\s\x00-\x1f\x7f]/g, "").replace(/\\/g, "/");
  let decoded = normalized;
  try {
    decoded = decodeURIComponent(normalized);
  } catch {
    // Malformed percent-encoding: the raw and normalized forms are still checked.
  }
  for (const candidate of [rawPath, normalized, decoded]) {
    if (
      internalPullUrl.test(candidate) ||
      pullRef.test(candidate) ||
      ownGithubUrl.test(candidate) ||
      githubGraphql.test(candidate) ||
      (githubApi.test(candidate) && ownRepoReference.test(candidate))
    ) {
      return "PR reads are blocked; use only the classified intake manifest.";
    }
  }
  return null;
}

export default function (pi: ExtensionAPI) {
  pi.on("tool_call", async (event) => {
    const input = event.input as { command?: string; path?: string };
    if (initializationError) {
      return {
        block: true,
        reason: `Blocked by Hyperliquid Dependabot guard: ${initializationError}.`,
      };
    }
    try {
      const currentSource = readFileSync(manifestPath, "utf8");
      const currentSha256 = createHash("sha256")
        .update(currentSource, "utf8")
        .digest("hex");
      if (currentSha256 !== validatedManifestFileSha256) {
        return {
          block: true,
          reason:
            "Blocked by Hyperliquid Dependabot guard: manifest changed after validation.",
        };
      }
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      return {
        block: true,
        reason: `Blocked by Hyperliquid Dependabot guard: cannot re-read manifest: ${detail}.`,
      };
    }
    if (event.toolName === "bash") {
      const reason = blockedBashReason(input.command ?? "");
      if (reason) return { block: true, reason };
    }
    if (event.toolName === "read" || event.toolName === "grep") {
      const reason = blockedReadReason(input.path ?? "");
      if (reason) return { block: true, reason };
    }
  });
}
