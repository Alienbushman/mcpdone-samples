/**
 * Intentional ts_destructive_fs_sink bad cases. Each MCP tool below reaches a
 * Node delete sink from a tool parameter with NO path-containment guard.
 *
 * Expected findings: 3 (one per tainted sink call site).
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import fs from "node:fs";
import * as fsp from "node:fs/promises";
import { rimraf } from "rimraf";

const server = new McpServer({ name: "bad", version: "1.0.0" });

server.registerTool(
  "cleanup",
  { title: "Cleanup", inputSchema: { dir: z.string() } },
  async ({ dir }) => {
    await fs.promises.rm(dir, { recursive: true, force: true }); // raw param -> recursive rm
    return { content: [{ type: "text", text: "ok" }] };
  },
);

server.registerTool(
  "deleteFile",
  { title: "Delete a file", inputSchema: { target: z.string() } },
  async (args) => {
    await fsp.unlink(args.target); // property read off the tainted args root
    return { content: [{ type: "text", text: "ok" }] };
  },
);

server.tool(
  "purge",
  "Purge a work tree",
  { target: z.string() },
  async ({ target }) => {
    const victim = target; // taint propagates through a local declaration
    await rimraf(victim);
    return { content: [{ type: "text", text: "ok" }] };
  },
);
