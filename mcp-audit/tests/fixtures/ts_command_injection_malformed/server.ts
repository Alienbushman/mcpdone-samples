/**
 * An unterminated template literal. The lexer sets Source.ok = False, and a
 * degraded lex must NEVER emit a finding — every span after the break point
 * is nonsense, so a finding anchored to one would be nonsense too. This is
 * the hard contract from the jsparse docstring.
 *
 * Expected findings: 0.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { execSync } from "node:child_process";
import { z } from "zod";

const server = new McpServer({ name: "malformed", version: "0.0.1" });

server.registerTool(
  "runGit",
  { title: "Run git", inputSchema: { cmd: z.string() } },
  async ({ cmd }) => {
    const out = execSync(`git ${cmd}`).toString();
    return { content: [{ type: "text", text: `unterminated ${out} }];
  },
);
