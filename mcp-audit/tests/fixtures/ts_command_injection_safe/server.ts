/**
 * The correct way to wrap a CLI from an MCP tool: a fixed binary, an argv
 * array, no shell. This is the shape the check's own remediation recommends
 * and the dominant shape in the real-world corpus (mcp-server-kubernetes's
 * execFileSyncSafe, git-mcp-server's runtime adapter).
 *
 * Expected findings: 0.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { execFileSync, spawn } from "node:child_process";
import { z } from "zod";

const server = new McpServer({ name: "safe", version: "0.0.1" });

server.registerTool(
  "getResource",
  { title: "kubectl get", inputSchema: { resource: z.string() } },
  async ({ resource }) => {
    const out = execFileSync("kubectl", ["get", resource]).toString();
    return { content: [{ type: "text", text: out }] };
  },
);

server.registerTool(
  "checkout",
  { title: "git checkout", inputSchema: { branch: z.string() } },
  async ({ branch }) => {
    spawn("git", ["checkout", branch], { shell: false });
    return { content: [{ type: "text", text: "ok" }] };
  },
);

// A tool parameter reaches an argv element, but the executable is a
// module-level constant and no shell is requested.
const RG = "/usr/bin/rg";

server.registerTool(
  "grepFiles",
  { title: "ripgrep", inputSchema: { pattern: z.string() } },
  async ({ pattern }) => {
    const args = ["--json", pattern];
    spawn(RG, args);
    return { content: [{ type: "text", text: "ok" }] };
  },
);
