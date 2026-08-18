// Realistic correct code, Hono flavour. Hono is the dominant framework for
// hosted / Workers MCP servers and spells both of its accessors differently
// from Express: the middleware is `bearerAuth`, not `requireBearerAuth`, and
// the header accessor is `c.req.header("Authorization")`, not `req.get(...)`
// nor `req.headers.authorization`. `sentry-mcp` and `git-mcp-server` in the
// real corpus both use the `.header("Authorization")` spelling.
//
// The original token set and header regex saw neither, so this authenticated
// server was reported HIGH. False positive.
//
// Expected findings: 0.
import { Hono } from "hono";
import { bearerAuth } from "hono/bearer-auth";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

const app = new Hono();

app.use("/mcp", bearerAuth({ token: process.env.MCP_TOKEN ?? "" }));

app.use("/mcp", async (c, next) => {
  const presented = c.req.header("Authorization");
  if (!presented) {
    return c.text("unauthorized", 401);
  }
  await next();
});

const server = new McpServer({ name: "demo", version: "1.0.0" });

app.all("/mcp", async (c) => {
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
  });
  await server.connect(transport);
  return c.body(null, 204);
});

export default app;
