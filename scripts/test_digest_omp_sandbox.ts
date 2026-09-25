#!/usr/bin/env bun
/**
 * Behavioral contracts for the Daily News digest read sandbox.
 *
 * F234: OMP classifies read targets as URL vs local file on the raw string,
 * while `new URL()` strips whitespace/control characters and treats `\` as
 * `/`. Every input the two could classify differently must be blocked.
 * Usage: bun test_digest_omp_sandbox.ts [sandbox.ts]  (default: sibling file)
 */

import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const sandboxPath = process.argv[2] ?? join(import.meta.dir, "digest-omp-sandbox.ts");
// Dynamic import: the sandbox path is runtime-selected so the same contract can run against old copies.
const sandbox = await import(`${pathToFileURL(sandboxPath).href}?test=${randomUUID()}`);
let handler: ((event: unknown) => Promise<unknown>) | undefined;
sandbox.default({
  on: (_event: string, callback: (event: unknown) => Promise<unknown>) => {
    handler = callback;
  },
});
if (!handler) throw new Error("sandbox did not register a tool-call handler");

const traversal = "example.com/../../../home/carter/.ssh/id_ed25519";
const blockedPaths = [
  ` https://${traversal}`,
  `\thttps://${traversal}`,
  `\nhttps://${traversal}`,
  `ht\ttps://${traversal}`,
  `https://${traversal}\n`,
  `\x00https://${traversal}`,
  `\x7fhttps://${traversal}`,
  `https:\\\\example.com\\..\\..\\home\\carter\\.ssh\\id_ed25519`,
  `https:/\\example.com/`,
  `https:/example.com/`,
  "https:example.com/",
  "www.example.com/",
  "http://example.com/",
  "/home/carter/.ssh/id_ed25519",
  "https://localhost/",
  "https://127.0.0.1/",
  "https://192.168.1.10/",
  "https://[::1]/",
  "https://user:pass@example.com/",
  "",
];
const allowedPaths = [
  "https://example.com/",
  "https://www.reuters.com/world/some-article-2026-09-24/",
  "HTTPS://Example.com/path?q=a%20b#frag",
  "https://example.com/article:50-100",
];

const failures: string[] = [];
for (const path of blockedPaths) {
  const result = await handler({ toolName: "read", input: { path } }) as { block?: boolean } | undefined;
  if (!result?.block) failures.push(`allowed blocked read: ${JSON.stringify(path)}`);
}
for (const path of allowedPaths) {
  const result = await handler({ toolName: "read", input: { path } });
  if (result !== undefined) failures.push(`blocked allowed read: ${JSON.stringify(path)}`);
}
const missing = await handler({ toolName: "read", input: {} }) as { block?: boolean } | undefined;
if (!missing?.block) failures.push("allowed read without a path");

if (failures.length > 0) {
  console.error(failures.join("\n"));
  process.exit(1);
}
console.log("ALL PASSED");
