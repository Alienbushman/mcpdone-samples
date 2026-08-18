// Regression: an OUTBOUND Authorization header, set by a tool that calls a
// third-party API, says nothing about whether this server's own endpoint is
// authenticated. It is not. Shaped after mcp-playwright's
// src/tools/api/requests.ts (writes) + src/http-server.ts (unauthenticated).
//
// Expected findings: 1.
import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";

export async function callApi(url: string, token?: string, customHeaders: Record<string, string> = {}) {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;   // outbound, not inbound
  }
  if (token && customHeaders["Authorization"]) {
    console.warn("both token and Authorization header provided");
  }
  return fetch(url, { headers: { ...headers, ...customHeaders } });
}

const app = express();
const server = new McpServer({ name: "api", version: "1.0.0" });

app.get("/sse", async (_req, res) => {
  const transport = new SSEServerTransport("/messages", res);
  await server.connect(transport);
});

app.listen(3000);
