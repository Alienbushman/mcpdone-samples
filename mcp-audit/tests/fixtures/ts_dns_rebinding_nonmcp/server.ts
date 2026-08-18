// A project's own class that happens to share a name with an SDK transport.
// Nothing in this file imports from @modelcontextprotocol/, so it is not an
// MCP transport and must not be flagged.
//
// Expected findings: 0.
import express from "express";
import { StreamableHTTPServerTransport } from "./internal/http-transport";

const app = express();

app.post("/events", (req, res) => {
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  transport.attach(req, res);
});

app.listen(4000);
