/**
 * Guarded destructive-fs cases. Each tool deletes a tool-parameter-derived
 * path BUT canonicalizes and confines it first. The check must NOT flag any
 * of these (false-negative bias: a containment guard suppresses).
 *
 * Expected findings: 0.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import nodePath from "node:path";
import fs from "node:fs";
import * as fsp from "node:fs/promises";
import { rimraf } from "rimraf";

const BASE = "/srv/work";
const server = new McpServer({ name: "guarded", version: "1.0.0" });

server.registerTool(
  "cleanup",
  { title: "Cleanup", inputSchema: { dir: z.string() } },
  async ({ dir }) => {
    const real = nodePath.resolve(BASE, dir); // canonicalize…
    const rel = nodePath.relative(BASE, real); // …then confine
    if (rel.startsWith("..") || nodePath.isAbsolute(rel)) {
      throw new Error("outside root");
    }
    await fs.promises.rm(real, { recursive: true, force: true });
    return { content: [{ type: "text", text: "ok" }] };
  },
);

server.registerTool(
  "deleteFile",
  { title: "Delete a file", inputSchema: { target: z.string() } },
  async (args) => {
    const real = await fsp.realpath(nodePath.join(BASE, args.target));
    if (!real.startsWith(BASE)) {
      throw new Error("outside root");
    }
    await fsp.unlink(real);
    return { content: [{ type: "text", text: "ok" }] };
  },
);

server.tool(
  "purge",
  "Purge a work tree",
  { target: z.string() },
  async ({ target }) => {
    // Allow-set membership: the server owns every directory in this list.
    const SCRATCH = ["/srv/work/a", "/srv/work/b"];
    if (!SCRATCH.includes(target)) {
      throw new Error("not a scratch dir");
    }
    await rimraf(target);
    return { content: [{ type: "text", text: "ok" }] };
  },
);
