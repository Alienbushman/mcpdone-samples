// `enableDnsRebindingProtection: true` with neither allowedHosts nor
// allowedOrigins. In the SDK's validateRequestHeaders() both branches are
// guarded by `length > 0`, so the function falls through and every request
// passes: the protection reads as enabled and is a complete no-op.
//
// Expected findings: 1 (noop_protection).
import express from "express";
import { randomUUID } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

const app = express();
app.use(express.json());

const server = new McpServer({ name: "demo", version: "1.0.0" });

app.post("/mcp", async (req, res) => {
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => randomUUID(),
    enableDnsRebindingProtection: true,
  });
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

app.listen(3000);
