// The legacy SSE transport takes (endpoint, res, options?) — with no third
// argument nothing is configured, so protection is off.
//
// Expected findings: 1.
import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";

const app = express();
const server = new McpServer({ name: "demo", version: "1.0.0" });

app.get("/sse", async (_req, res) => {
  const transport = new SSEServerTransport("/messages", res);
  await server.connect(transport);
});

app.listen(3001);
