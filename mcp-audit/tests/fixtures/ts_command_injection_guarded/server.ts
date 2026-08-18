/**
 * The guard-suppression cases. Both tools reach a real shell sink from a
 * real tool parameter, but each shows a validation / allow-list indicator in
 * the handler body. Suppression here is deliberate and deliberately broad:
 * we would rather miss a weak guard than cry wolf on a real one.
 *
 * Expected findings: 0.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { execSync, spawn } from "node:child_process";
import { z } from "zod";

const server = new McpServer({ name: "guarded", version: "0.0.1" });

const ALLOWED_COMMANDS = ["status", "log", "diff"];

server.registerTool(
  "runGit",
  { title: "Run git", inputSchema: { cmd: z.string() } },
  async ({ cmd }) => {
    if (!ALLOWED_COMMANDS.includes(cmd)) {
      throw new Error("not permitted");
    }
    const out = execSync(`git ${cmd}`).toString();
    return { content: [{ type: "text", text: out }] };
  },
);

server.registerTool(
  "runTool",
  { title: "Run a tool", inputSchema: { bin: z.string() } },
  async ({ bin }) => {
    const safe = sanitizeBinary(bin);
    spawn(safe, [], { shell: true });
    return { content: [{ type: "text", text: "ok" }] };
  },
);

function sanitizeBinary(name: string): string {
  return name.replace(/[^a-z]/g, "");
}
