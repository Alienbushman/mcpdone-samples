// A CORS allow-list is NOT a DNS-rebinding mitigation: after rebinding the
// request is genuinely same-origin, so CORS never runs.
//
// Expected findings: 1.
import express from "express";
import cors from "cors";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

const app = express();
app.use(cors({ origin: ["https://app.example.com"] }));
app.use(express.json());

const server = new McpServer({ name: "demo", version: "1.0.0" });

app.post("/mcp", async (req, res) => {
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

app.listen(3000);
