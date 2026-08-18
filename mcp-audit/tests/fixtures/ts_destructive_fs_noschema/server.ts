/**
 * Registrations whose parameter 0 is NOT the tool arguments, plus two
 * registrations the check cannot statically resolve.
 *
 * With no `inputSchema` the SDK calls `handler(extra)` — parameter 0 is the
 * server context (RequestHandlerExtra), not attacker input. Treating it as
 * tainted would fire on `browser-tools-mcp/mcp-server.ts:178`
 * (`server.tool("getConsoleLogs", "Check our browser logs", async () => …)`),
 * a tool that accepts no input at all.
 *
 * Expected findings: 0.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import fs from "node:fs";
import { TOOL_CONFIG, makeHandler } from "./config.js";

const server = new McpServer({ name: "noschema", version: "1.0.0" });

// Three-arg tool() with a description and no schema: param 0 is `extra`.
server.tool("getLogs", "Check our browser logs", async (extra) => {
  await fs.promises.rm(extra.workdir, { recursive: true });
  return { content: [{ type: "text", text: "ok" }] };
});

// registerTool with a config carrying no inputSchema: same story.
server.registerTool("ping", { title: "Ping" }, async (extra) => {
  await fs.rmSync(extra.scratch);
  return { content: [{ type: "text", text: "pong" }] };
});

// Zero-parameter handler: nothing can be tainted.
server.registerTool("status", { title: "Status" }, async () => {
  fs.rmSync("/tmp/mcp-status");
  return { content: [{ type: "text", text: "up" }] };
});

// Config is an imported identifier: schema presence is unknowable, suppress.
server.registerTool("opaque", TOOL_CONFIG, async (args) => {
  await fs.promises.rm(args.dir, { recursive: true });
  return { content: [{ type: "text", text: "ok" }] };
});

// Handler is a factory call in another module: not statically resolvable.
server.registerTool("forwarded", { title: "Forwarded", inputSchema: {} }, makeHandler("forwarded"));
