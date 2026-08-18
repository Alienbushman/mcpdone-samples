/**
 * Import-shape coverage: a renamed named import and an inline
 * `require('child_process')` member call. Both are real child_process
 * exports and both must resolve as sinks; a check that only understood the
 * plain `import { exec }` form would miss them.
 *
 * Expected findings: 2.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { execSync as runSync } from "child_process";
import { z } from "zod";

const server = new McpServer({ name: "aliased", version: "0.0.1" });

server.registerTool(
  "renamed",
  { title: "Renamed import", inputSchema: { cmd: z.string() } },
  async ({ cmd }) => {
    const out = runSync(`git ${cmd}`).toString();
    return { content: [{ type: "text", text: out }] };
  },
);

server.registerTool(
  "inlineRequire",
  { title: "Inline require", inputSchema: { cmd: z.string() } },
  async ({ cmd }) => {
    require("child_process").execSync(`git ${cmd}`);
    return { content: [{ type: "text", text: "ok" }] };
  },
);
