/**
 * The remaining sink families: synchronous core-fs, `fs-extra`, and the
 * `del` package, plus a named `from 'node:fs/promises'` import used bare.
 *
 * Expected findings: 4 (one per tainted sink call site).
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import * as fs from "node:fs";
import { rmdir } from "node:fs/promises";
import fse from "fs-extra";
import { deleteSync } from "del";

const server = new McpServer({ name: "extra", version: "1.0.0" });

server.registerTool(
  "wipeSync",
  { title: "Wipe", inputSchema: { dir: z.string() } },
  async ({ dir }) => {
    fs.rmSync(dir, { recursive: true, force: true }); // core fs, sync
    return { content: [{ type: "text", text: "ok" }] };
  },
);

server.registerTool(
  "dropDir",
  { title: "Drop", inputSchema: { dir: z.string() } },
  async ({ dir }) => {
    await rmdir(dir); // bare named import from node:fs/promises
    return { content: [{ type: "text", text: "ok" }] };
  },
);

server.registerTool(
  "emptyOut",
  { title: "Empty", inputSchema: { dir: z.string() } },
  async ({ dir }) => {
    await fse.emptyDir(dir); // fs-extra
    return { content: [{ type: "text", text: "ok" }] };
  },
);

server.registerTool(
  "nuke",
  { title: "Nuke", inputSchema: { globs: z.string() } },
  async ({ globs }) => {
    deleteSync(globs); // del package
    return { content: [{ type: "text", text: "ok" }] };
  },
);
