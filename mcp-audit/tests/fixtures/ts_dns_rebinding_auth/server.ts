// Realistic correct code: the transport options are exactly as loose as the
// bad fixture's, but the endpoint sits behind bearer auth. An authenticated
// endpoint is not reachable by a drive-by page, so nothing is flagged.
//
// Expected findings: 0.
import express from "express";
import { randomUUID } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";

const app = express();
app.use(express.json());

const server = new McpServer({ name: "demo", version: "1.0.0" });

app.post("/mcp", requireBearerAuth({ verifier, requiredScopes: ["mcp"] }), async (req, res) => {
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => randomUUID(),
  });
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

app.listen(3000);
