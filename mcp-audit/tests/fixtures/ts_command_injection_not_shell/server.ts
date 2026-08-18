/**
 * `exec` is not a shell function in JavaScript unless it came from
 * child_process. RegExp.prototype.exec is idiomatic (desktop-commander's
 * search-manager.ts:578, utils/files/docx.ts:246) and better-sqlite3's
 * db.exec() appears in the TypeScript SDK's own examples
 * (examples/shared/src/auth.ts). Neither may fire — and the file below also
 * imports the real child_process, so the import gate has to do actual work
 * rather than being short-circuited by "no cp import in this file".
 *
 * Expected findings: 0.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { execFileSync } from "node:child_process";
import Database from "better-sqlite3";
import { z } from "zod";

const server = new McpServer({ name: "notshell", version: "0.0.1" });
const db = new Database("app.db");

server.registerTool(
  "parseTag",
  { title: "Parse a tag", inputSchema: { tag: z.string() } },
  async ({ tag }) => {
    const m = /^v(\d+)$/.exec(tag);
    const version = m ? m[1] : "0";
    const out = execFileSync("git", ["rev-parse", "HEAD"]).toString();
    return { content: [{ type: "text", text: `${version} ${out}` }] };
  },
);

server.registerTool(
  "readRow",
  { title: "Read a row", inputSchema: { id: z.string() } },
  async ({ id }) => {
    db.exec(`SELECT * FROM t WHERE id = ${id}`);
    return { content: [{ type: "text", text: "ok" }] };
  },
);
