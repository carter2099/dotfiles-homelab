/**
 * Network-only sandbox for digest research agents.
 *
 * Digest agents need public web search and HTTPS article reads. They never need
 * local filesystem access, shell execution, browser control, or write tools.
 */

import net from "node:net";
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";

function isPrivateHostname(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (
    host === "localhost" ||
    host === "0.0.0.0" ||
    host.endsWith(".localhost") ||
    host.endsWith(".local") ||
    host.endsWith(".internal")
  ) {
    return true;
  }

  if (net.isIPv4(host)) {
    const [a, b] = host.split(".").map(Number);
    return (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127) ||
      a >= 224
    );
  }

  if (net.isIPv6(host)) {
    return host === "::" || host === "::1" || host.startsWith("fc") || host.startsWith("fd") || host.startsWith("fe8") || host.startsWith("fe9") || host.startsWith("fea") || host.startsWith("feb");
  }

  return false;
}

// OMP decides URL-vs-local-file on the RAW string (pi-tui isReadableUrlPath:
// /^https?:\/\/?/i), while WHATWG `new URL()` strips leading/trailing C0/space
// and every tab/newline and treats `\` as `/`. Any input the two parsers could
// classify differently (F234: " https://x/../../etc/passwd" is a local path to
// OMP but a public URL to `new URL`) is rejected before the URL checks run.
const unsafeUrlChars = /[\s\x00-\x1f\x7f\\]/;
const rawHttpsPrefix = /^https:\/\//i;

function isAllowedPublicUrl(raw: unknown): boolean {
  if (typeof raw !== "string" || unsafeUrlChars.test(raw) || !rawHttpsPrefix.test(raw)) return false;
  try {
    const url = new URL(raw);
    return (
      url.protocol === "https:" &&
      url.username === "" &&
      url.password === "" &&
      !isPrivateHostname(url.hostname)
    );
  } catch {
    return false;
  }
}

export default function (pi: ExtensionAPI) {
  pi.on("tool_call", async (event) => {
    if (event.toolName !== "read") return;

    const input = event.input as { path?: string };
    if (!isAllowedPublicUrl(input.path)) {
      return {
        block: true,
        reason: "Blocked by digest sandbox: reads are limited to public HTTPS URLs; local and private-network paths are denied.",
      };
    }
  });
}
