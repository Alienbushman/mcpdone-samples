/**
 * Lexing traps: dangerous-looking delete calls that live inside comments,
 * string literals, template-literal text, and a regex body. None of them is
 * code, so none may produce a finding.
 *
 * Expected findings: 0.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import fs from "node:fs";
import * as fsp from "node:fs/promises";

const server = new McpServer({ name: "strings", version: "1.0.0" });

// await fs.promises.rm(dir, { recursive: true }) — a comment, not code.
/* fsp.unlink(target); */

server.registerTool(
  "docs",
  { title: "Docs", inputSchema: { dir: z.string() } },
  async ({ dir }) => {
    const help = "call fs.promises.rm(dir) to delete a tree"; // a string
    const url = "https://example.com/docs#rm"; // a `//` inside a string
    const snippet = `await fsp.unlink(${"literal"});`; // template TEXT is blanked
    const notComment = "/* fs.rmSync(dir) */";
    const pattern = /fsp\.unlink\(['"]x['"]\)/; // regex body with quotes
    const ratio = (help.length + url.length) / 2; // division, not a regex
    return {
      content: [
        { type: "text", text: `${help} ${snippet} ${notComment} ${pattern} ${ratio} ${dir}` },
      ],
    };
  },
);

server.registerTool(
  "cleanupFixed",
  { title: "Cleanup", inputSchema: { label: z.string() } },
  async ({ label }) => {
    // Real sink, constant target: the label never reaches it.
    await fs.promises.rm("/var/tmp/mcp-fixed", { recursive: true });
    return { content: [{ type: "text", text: label }] };
  },
);
