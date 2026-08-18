/**
 * Lexing traps. Every dangerous-looking construct below lives inside a
 * string literal, a comment, or a regex character class. The masking lexer
 * blanks all three, so none of them may produce a finding — a naive regex
 * over raw TypeScript would report all of them.
 *
 * Expected findings: 0.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { execFileSync } from "node:child_process";
import { z } from "zod";

const server = new McpServer({ name: "lextrap", version: "0.0.1" });

server.registerTool(
  "describe",
  { title: "Describe", inputSchema: { cmd: z.string() } },
  async ({ cmd }) => {
    // execSync(`git ${cmd}`) — a comment, not a call.
    const doc = "execSync(`git ${cmd}`)";
    const url = "https://example.com/exec?x=1";  // a // inside a string
    const blockish = "/* not a comment */";
    const quotes = /['"]/;
    const ratio = (1 + 2) / 3 / 4;
    const out = execFileSync("echo", [doc, url, blockish, String(ratio), String(quotes)]);
    return { content: [{ type: "text", text: out.toString() }] };
  },
);
