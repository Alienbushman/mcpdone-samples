/**
 * The registration declares no inputSchema, but the handler destructures real
 * tool-argument names from parameter 0. The SDK calls a schemaless handler as
 * handler(extra), so `path` and `content` are undefined at runtime.
 *
 * Expected findings: 1 (tool 'write').
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "undeclared", version: "0.0.1" });

server.registerTool("write", { title: "Write" }, async ({ path, content }) => {
  return { content: [{ type: "text", text: String(path) + String(content) }] };
});
