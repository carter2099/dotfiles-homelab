#!/usr/bin/env bun
/** Behavioral contracts for the Hyperliquid Dependabot agent guard. */

import { createHash, randomUUID } from "node:crypto";
import { chmodSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const object = value as Record<string, unknown>;
  return `{${Object.keys(object)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(object[key])}`)
    .join(",")}}`;
}

const temporaryDirectory = mkdtempSync(join(tmpdir(), "hyperliquid-guard-test-"));
const manifestPath = join(temporaryDirectory, "intake.json");
const pullRequests = [
  {
    base_ref: "main",
    dependency: "faraday-retry",
    ecosystem: "bundler",
    head_ref: "dependabot/bundler/faraday-retry-2.4.0",
    head_sha: "0123456789abcdef0123456789abcdef01234567",
    number: 6,
    target_version: "2.4.0",
  },
];
const actionable = {
  repository: "carter2099/hyperliquid",
  pull_requests: pullRequests,
};
const intakeSha256 = createHash("sha256")
  .update(canonicalJson(actionable), "ascii")
  .digest("hex");
const manifest = {
  schema_version: 1,
  repository: "carter2099/hyperliquid",
  generated_at: new Date().toISOString(),
  intake_sha256: intakeSha256,
  classification: {
    policy: "title_and_body_per_pr_then_sanitized_handoff",
    result: "SAFE",
    classified_pull_requests: 1,
    max_pull_request_score: 0.01,
    sanitized_handoff_score: 0.01,
  },
  pull_requests: pullRequests,
};

try {
  await Bun.write(manifestPath, `${JSON.stringify(manifest)}\n`);
  chmodSync(manifestPath, 0o600);
  process.env.HYPERLIQUID_DEPENDABOT_MANIFEST = manifestPath;

  // Dynamic import is required: the guard reads this test manifest at module initialization.

  const guardPath = process.env.HYPERLIQUID_GUARD_PATH;
  if (!guardPath) throw new Error("HYPERLIQUID_GUARD_PATH is required");
  const guardUrl = `${pathToFileURL(guardPath).href}?test=${randomUUID()}`;
  const guard = await import(guardUrl);
  let handler: ((event: unknown) => Promise<unknown>) | undefined;
  guard.default({
    on: (_event: string, callback: (event: unknown) => Promise<unknown>) => {
      handler = callback;
    },
  });
  if (!handler) throw new Error("guard did not register a tool-call handler");

  const blockedCases = [
    {
      toolName: "bash",
      input: { command: "gh pr list --repo carter2099/hyperliquid" },
    },
    {
      toolName: "bash",
      input: { command: "gh api graphql -f query='{ repository(owner: \"carter2099\", name: \"hyperliquid\") { pullRequests { nodes { number } } } }'" },
    },
    {
      toolName: "bash",
      input: { command: "curl https://api.github.com/repos/carter2099/hyperliquid/pulls" },
    },
    {
      toolName: "bash",
      input: { command: "git -C ~/dev/hyperliquid fetch origin 0123456789abcdef0123456789abcdef01234567" },
    },
    {
      toolName: "bash",
      input: { command: "gh pr close 999 --repo carter2099/hyperliquid --comment \"Applied to dev by the scheduled Hyperliquid SDK maintenance run.\"" },
    },
    {
      toolName: "read",
      input: { path: "pr://carter2099/hyperliquid/6" },
    },
    {
      toolName: "grep",
      input: { path: "https://github.com/carter2099/hyperliquid/pull/6" },
    },
    // F234 class: WHATWG URL parsing drops tabs/newlines and maps `\` to `/`.
    {
      toolName: "read",
      input: { path: "https://github.com/carter2099/hyper\tliquid/pull/6" },
    },
    {
      toolName: "read",
      input: { path: "https://github.com/carter2099/hyper\nliquid/pull/6" },
    },
    {
      toolName: "read",
      input: { path: "https://github.com\\carter2099\\hyperliquid\\pull\\6" },
    },
    {
      toolName: "read",
      input: { path: "https://api.github.com/repos/carter2099/hyper%6Ciquid/pulls" },
    },
  ];
  for (const blockedCase of blockedCases) {
    const result = await handler(blockedCase) as { block?: boolean } | undefined;
    if (!result?.block) {
      throw new Error(`guard allowed blocked case: ${JSON.stringify(blockedCase)}`);
    }
  }

  const allowedCases = [
    {
      toolName: "bash",
      input: { command: "gh pr close 6 --repo carter2099/hyperliquid --comment \"Applied to dev by the scheduled Hyperliquid SDK maintenance run.\"" },
    },
    {
      toolName: "bash",
      input: { command: "git pull origin dev" },
    },
    {
      toolName: "read",
      input: { path: "https://api.github.com/repos/nktkas/hyperliquid/commits/main" },
    },
  ];
  for (const allowedCase of allowedCases) {
    const result = await handler(allowedCase);
    if (result !== undefined) {
      throw new Error(`guard blocked allowed case: ${JSON.stringify(allowedCase)}`);
    }
  }

  const tamperedManifest = structuredClone(manifest);
  tamperedManifest.pull_requests[0].head_sha =
    "ffffffffffffffffffffffffffffffffffffffff";
  await Bun.write(manifestPath, `${JSON.stringify(tamperedManifest)}\n`);
  const tamperedResult = await handler({
    toolName: "read",
    input: { path: "/home/carter/dev/hyperliquid/Gemfile" },
  }) as { block?: boolean; reason?: string } | undefined;
  if (
    !tamperedResult?.block ||
    !tamperedResult.reason?.includes("manifest changed after validation")
  ) {
    throw new Error(`tampered manifest was not rejected: ${JSON.stringify(tamperedResult)}`);
  }

  console.log("ALL PASSED");
} finally {
  rmSync(temporaryDirectory, { recursive: true, force: true });
}
