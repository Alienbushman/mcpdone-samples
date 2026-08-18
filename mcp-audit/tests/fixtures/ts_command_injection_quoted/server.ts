/**
 * Quoted interpolation. sentry-mcp's device-code-flow.ts:160-167 opens a
 * browser with ``exec(`open ${JSON.stringify(url)}`)`` — the value cannot
 * escape its own shell argument, so this is correct code and must be silent.
 *
 * Expected findings: 0.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { exec } from "node:child_process";
import { z } from "zod";

const server = new McpServer({ name: "quoted", version: "0.0.1" });

server.registerTool(
  "openUrl",
  { title: "Open a URL", inputSchema: { url: z.string() } },
  async ({ url }) => {
    exec(`open ${JSON.stringify(url)}`);
    return { content: [{ type: "text", text: "ok" }] };
  },
);
