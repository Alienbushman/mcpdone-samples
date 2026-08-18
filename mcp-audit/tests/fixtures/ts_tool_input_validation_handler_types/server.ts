/**
 * Handler-typing shapes that must NOT be flagged. Every one of these was a
 * false positive found during the 2026-08 corpus smoke run, and every one of
 * them is correct code.
 *
 * Expected findings: 0.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { agentRunInputShape } from "./shapes.js";
import { TOOL_TABLE } from "./table.js";

const server = new McpServer({ name: "handler-types", version: "0.0.1" });

// firecrawl-mcp-server writes this on 26 tools. `unknown` is TypeScript's safe
// top type: the compiler forces the narrowing below, so the schema has not
// been thrown away.
server.registerTool(
  "scrape",
  {
    title: "Scrape",
    inputSchema: { url: z.string().url(), maxAge: z.number().int() },
  },
  async (args: unknown, extra) => {
    const { url } = args as { url: string };
    return { content: [{ type: "text", text: url + String(extra) }] };
  },
);

// mcp-server-neon:777 — a zero-argument tool whose ignored parameter says so.
server.registerTool(
  "listDocs",
  { title: "List docs", inputSchema: { locale: z.enum(["en", "de"]) } },
  async (_args: any, extra) => ({ content: [{ type: "text", text: String(extra) }] }),
);

// mcp-server-neon:382 — a generic dispatch loop. The schema is a runtime
// value, so `any` is the only annotation the author can write.
for (const tool of TOOL_TABLE) {
  server.registerTool(
    tool.name,
    { description: tool.description, inputSchema: tool.inputSchema },
    async (args: any, extra: any) => ({
      content: [{ type: "text", text: String(args) + String(extra) }],
    }),
  );
}

// exa-mcp-server's agent_run: the deprecated ladder with the raw shape passed
// by name, followed by an annotations object. A schema IS declared here.
server.tool(
  "agent_run",
  "Start or resume an agent run",
  agentRunInputShape,
  { readOnlyHint: true, destructiveHint: false },
  async ({ query, runId, systemPrompt }, extra) => ({
    content: [{ type: "text", text: String(query) + String(runId) + String(systemPrompt) + String(extra) }],
  }),
);
