// Intentional bad case: an express-hosted Streamable HTTP MCP server with no
// DNS-rebinding protection and no auth of any kind.
//
// Expected findings: 1 (the `new StreamableHTTPServerTransport` site).
import express from "express";
import cors from "cors";
import { randomUUID } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

const app = express();
app.use(cors({ origin: "*" }));          // CORS is NOT a mitigation here
app.use(express.json());

const server = new McpServer({ name: "demo", version: "1.0.0" });

app.post("/mcp", async (req, res) => {
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => randomUUID(),
  });                                    // <- flagged: protection defaults false
  res.on("close", () => transport.close());
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

app.listen(3000, "127.0.0.1");           // localhost bind is NOT a mitigation
