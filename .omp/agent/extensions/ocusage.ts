import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

export default function ocusageExtension(pi: ExtensionAPI) {
  pi.registerTool({
    name: "ocusage",
    label: "OpenCode Usage",
    description:
      "Show real-time aggregate OpenCode Go billing usage across all proxy-managed accounts. Fetches from the opencode-go-proxy which scrapes opencode.ai billing dashboards. More accurate than /usage for total spend because it includes non-omp traffic (Open WebUI, etc.).",
    promptSnippet: "ocusage: show real OpenCode Go billing across all accounts",
    promptGuidelines: [
      "Use ocusage when the user asks about their OpenCode spend, billing, or usage limits.",
      "Prefer ocusage over the built-in /usage for billing questions — /usage only tracks omp's own API costs.",
    ],
    parameters: Type.Object({}),

    async execute(_toolCallId, _params, _signal, _onUpdate, _ctx) {
      try {
        const resp = await fetch("http://localhost:8082/usage", {
          signal: AbortSignal.timeout(5000),
        });
        if (!resp.ok) {
          return {
            content: [{ type: "text", text: `Proxy returned HTTP ${resp.status}` }],
            details: { status: "error", httpStatus: resp.status },
          };
        }
        const text = await resp.text();
        return {
          content: [{ type: "text", text }],
          details: { status: "ok" },
        };
      } catch (err) {
        return {
          content: [{
            type: "text",
            text: `Failed to reach opencode-go-proxy: ${err}\n\nIs the proxy running? Check: systemctl --user status opencode-go-proxy`,
          }],
          details: { status: "error", error: String(err) },
        };
      }
    },
  });
}
