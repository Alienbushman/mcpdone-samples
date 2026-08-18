// The transport options are as loose as the bad fixture's, but the repo
// validates the Host header by hand in middleware.ts. Author awareness of
// the problem — even partial, in another file — suppresses the check.
//
// Expected findings: 0.
import express from "express";
import { randomUUID } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { hostGuard } from "./middleware";

const app = express();
app.use(express.json());
app.use(hostGuard);

const server = new McpServer({ name: "demo", version: "1.0.0" });

app.post("/mcp", async (req, res) => {
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => randomUUID(),
  });
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

app.listen(3000);
