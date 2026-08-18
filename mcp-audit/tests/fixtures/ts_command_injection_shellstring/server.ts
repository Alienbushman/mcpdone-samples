/**
 * `shell` accepts a shell PATH as well as `true`. Node treats
 * `{ shell: '/bin/bash' }` exactly like `{ shell: true }`, so the argv array
 * gives no protection and the finding must fire.
 *
 * Expected findings: 1.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { spawnSync } from "node:child_process";
import { z } from "zod";

const server = new McpServer({ name: "shellstring", version: "0.0.1" });

server.registerTool(
  "runPipeline",
  { title: "Run a pipeline", inputSchema: { stage: z.string() } },
  async ({ stage }) => {
    spawnSync("make", [stage], { shell: "/bin/bash" });
    return { content: [{ type: "text", text: "ok" }] };
  },
);
