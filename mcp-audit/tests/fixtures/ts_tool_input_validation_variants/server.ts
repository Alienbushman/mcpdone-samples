/**
 * Registration shapes other than registerTool(name, config, handler).
 *
 * Expected findings: 1 (deprecated tool() overload, raw shape field 'cmd').
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "variants", version: "0.0.1" });

// Deprecated overload: tool(name, description, rawShape, cb). The third
// argument IS the input schema.
server.tool("run", "Run a command", { cmd: z.string() }, async ({ cmd }) => ({
  content: [{ type: "text", text: cmd }],
}));

// Same ladder, constrained -> clean.
server.tool("tag", "Tag a thing", { label: z.enum(["a", "b"]) }, async ({ label }) => ({
  content: [{ type: "text", text: label }],
}));
