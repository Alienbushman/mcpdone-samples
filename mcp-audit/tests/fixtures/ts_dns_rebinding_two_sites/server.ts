// Two transports in one file: granularity is one finding per construction
// site, so both are reported.
//
// Expected findings: 2.
import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";

const app = express();
const server = new McpServer({ name: "demo", version: "1.0.0" });

app.post("/mcp", async (req, res) => {
  const modern = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  await server.connect(modern);
  await modern.handleRequest(req, res, req.body);
});

app.get("/sse", async (_req, res) => {
  const legacy = new SSEServerTransport("/messages", res);
  await server.connect(legacy);
});

app.listen(3000);
