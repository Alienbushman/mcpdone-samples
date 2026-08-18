/**
 * Intentional ts_command_injection bad cases. Each registered tool reaches a
 * `child_process` shell sink from its first (schema-declared) parameter with
 * NO quoting, allow-list, or validation guard anywhere in the handler.
 *
 * Expected findings: 3 (one per sink call site).
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { execSync, spawn, execFile } from "node:child_process";
import { z } from "zod";

const server = new McpServer({ name: "bad", version: "0.0.1" });

// always_shell: the parameter lands in a template that /bin/sh parses.
server.registerTool(
  "runGit",
  { title: "Run git", inputSchema: { cmd: z.string() } },
  async ({ cmd }) => {
    const out = execSync(`git ${cmd}`).toString();
    return { content: [{ type: "text", text: out }] };
  },
);

// shell_option: an argv array, but `shell: true` re-parses it all.
server.registerTool(
  "openPath",
  { title: "Open a path", inputSchema: { bin: z.string(), target: z.string() } },
  async ({ bin, target }) => {
    spawn(bin, [target], { shell: true });
    return { content: [{ type: "text", text: "ok" }] };
  },
);

// tainted_executable: no shell, but the caller picks the binary.
server.registerTool(
  "launch",
  { title: "Launch", inputSchema: { userBin: z.string() } },
  async ({ userBin }) => {
    execFile(userBin, []);
    return { content: [{ type: "text", text: "ok" }] };
  },
);
