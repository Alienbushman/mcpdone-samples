/**
 * RECON A rule R2. A `tool(name, description, callback)` registration
 * declares NO input schema, so the SDK dispatches `callback(extra)` — the
 * first parameter is the RequestHandlerExtra server context, never tool
 * arguments. browser-tools-mcp/mcp-server.ts:178 is exactly this shape.
 * Treating parameter 0 as attacker-controlled here would fire on a tool
 * that accepts no input at all.
 *
 * Expected findings: 0.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { execSync } from "node:child_process";

const server = new McpServer({ name: "noschema", version: "0.0.1" });

server.tool("getLogs", "Check our server logs", async (extra) => {
  const out = execSync(`ls ${extra}`).toString();
  return { content: [{ type: "text", text: out }] };
});
