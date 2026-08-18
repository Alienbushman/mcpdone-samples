/**
 * Zero-argument tools. An absent inputSchema is the CORRECT encoding: the SDK
 * then invokes the callback as handler(extra), so parameter 0 is the server
 * context. Compare browser-tools-mcp/mcp-server.ts:178, which is exactly this
 * shape and is correct code.
 *
 * Expected findings: 0.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "noschema", version: "0.0.1" });

// No parameters at all.
server.tool("ping", "Health probe", async () => ({
  content: [{ type: "text", text: "pong" }],
}));

// Destructures only RequestHandlerExtra / ServerContext properties from the
// first parameter — that is the server context of a no-input tool, not a
// broken schema.
server.tool("status", "Report status", async ({ sessionId, signal }) => ({
  content: [{ type: "text", text: String(sessionId) + String(signal) }],
}));

// Same, with the v2 context shape.
server.registerTool("uptime", { title: "Uptime" }, async ({ requestId, authInfo, _meta }) => ({
  content: [{ type: "text", text: String(requestId) + String(authInfo) + String(_meta) }],
}));
