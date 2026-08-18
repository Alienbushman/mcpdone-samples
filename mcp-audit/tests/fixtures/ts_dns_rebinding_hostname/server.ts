// Realistic correct code, and the most damaging of the false positives: this
// server performs EXACTLY the mitigation the check's own remediation text
// asks for — it rejects any request whose Host header is not a loopback name
// — but spells the read `req.hostname`, which is how Express and Fastify both
// expose the Host header. `filesystem-mcp-server` in the real corpus uses
// this spelling.
//
// The original `_HOST_HEADER_RE` matched only `headers.host`, `headers['host']`
// and `.get('host')`, so this repo was reported HIGH for a problem it had
// already fixed. False positive.
//
// The receiver anchor matters: a BARE `hostname` local must not suppress.
// `mcp-server-browserbase` takes `hostname` as a plain function parameter and
// is a verified true positive that has to keep firing.
//
// Expected findings: 0.
import express from "express";
import { randomUUID } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

const app = express();
app.use(express.json());

const ALLOWED = new Set(["localhost", "127.0.0.1"]);

app.use((req, res, next) => {
  if (!ALLOWED.has(req.hostname)) {
    res.status(403).send("bad host");
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

app.listen(3000, "127.0.0.1");
