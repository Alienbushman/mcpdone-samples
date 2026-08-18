// Belt and braces: the transport arms `enableDnsRebindingProtection` without
// either allow-list (inert on its own), AND the app mounts the SDK's real
// `hostHeaderValidation()` middleware ahead of it. The request IS validated.
//
// The `noop_protection` variant deliberately ignores the repo-level
// host/origin gate, because `enableDnsRebindingProtection` is itself one of
// that gate's tokens. The original code dropped the gate ENTIRELY, so this
// protected server was reported HIGH with a message asserting that "every
// request passes" — which is false. False positive, and a factually wrong
// one, which is the worst kind.
//
// The fix keeps the variant alive against the three self-referential option
// keys but honours every independent guard. `ts_dns_rebinding_noop` still
// fires, so this is not a blanket disarm.
//
// Expected findings: 0.
import express from "express";
import { randomUUID } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { hostHeaderValidation } from "@modelcontextprotocol/sdk/server/middleware.js";

const app = express();
app.use(express.json());
app.use(hostHeaderValidation(["127.0.0.1:3000", "localhost:3000"]));

const server = new McpServer({ name: "demo", version: "1.0.0" });

app.post("/mcp", async (req, res) => {
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => randomUUID(),
    enableDnsRebindingProtection: true,
  });
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

app.listen(3000, "127.0.0.1");
