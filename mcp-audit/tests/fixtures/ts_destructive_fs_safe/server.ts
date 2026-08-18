/**
 * Realistic correct code: the dangerous pattern is simply NOT present. Tools
 * read files, and the only delete target is a module-level constant the
 * server owns. Nothing here is attacker-influenced.
 *
 * Expected findings: 0.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import fs from "node:fs";
import * as fsp from "node:fs/promises";

const TMP_DIR = "/var/tmp/mcp-scratch";
const server = new McpServer({ name: "safe", version: "1.0.0" });

server.registerTool(
  "readNote",
  { title: "Read a note", inputSchema: { id: z.string().min(1).max(64) } },
  async ({ id }) => {
    const body = await fsp.readFile(`${TMP_DIR}/${id}.txt`, "utf8");
    return { content: [{ type: "text", text: body }] };
  },
);

server.registerTool(
  "resetScratch",
  { title: "Reset the scratch directory", inputSchema: { confirm: z.boolean() } },
  async ({ confirm }) => {
    if (!confirm) {
      throw new Error("confirm required");
    }
    // Fixed, server-managed directory — no tool parameter reaches this call.
    await fs.promises.rm(TMP_DIR, { recursive: true, force: true });
    return { content: [{ type: "text", text: "reset" }] };
  },
);

server.registerTool(
  "archive",
  { title: "Archive", inputSchema: { name: z.string().max(32) } },
  async ({ name }) => {
    await fsp.rm(TMP_DIR, { recursive: true }); // constant target, tainted name unused here
    return { content: [{ type: "text", text: `archived ${name}` }] };
  },
);
