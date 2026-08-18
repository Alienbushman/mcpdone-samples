// Realistic correct code. The transport options are exactly as loose as the
// bad fixture's, but every request must present a shared secret in the
// `X-API-Key` header, which a drive-by page cannot know. This is how
// `context7` and `firecrawl-mcp-server` authenticate in the real corpus.
//
// The original `_AUTH_HEADER_RE` matched only `authorization`, so this shape
// was reported HIGH as an unauthenticated endpoint. False positive.
//
// Expected findings: 0.
import express from "express";
import { randomUUID } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

const app = express();
app.use(express.json());

app.use((req, res, next) => {
  if (req.headers["x-api-key"] !== process.env.MCP_SHARED_SECRET) {
    res.status(401).send("unauthorized");
    return;
  }
  next();
});

const server = new McpServer({ name: "demo", version: "1.0.0" });

app.post("/mcp", async (req, res) => {
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => randomUUID(),
  });
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

app.listen(3000);
