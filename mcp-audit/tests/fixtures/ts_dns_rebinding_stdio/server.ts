// Realistic correct code: an ordinary stdio MCP server. The advisory does
// not affect stdio, and there is no HTTP transport construction at all.
//
// Expected findings: 0.
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new McpServer({ name: "notes", version: "1.0.0" });

server.registerTool(
  "echo",
  { title: "Echo", inputSchema: { text: z.string().min(1).max(200) } },
  async ({ text }) => ({ content: [{ type: "text", text }] }),
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main();
