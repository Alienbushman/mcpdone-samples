/**
 * Low-level `setRequestHandler(CallToolRequestSchema, ...)` dispatch, with
 * taint arriving through the S8 destructuring idiom and then propagating
 * through a local `const`. The sibling ListTools handler must stay silent —
 * it is a catalogue, not an execution path.
 *
 * Expected findings: 1.
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import * as cp from "node:child_process";

const server = new Server({ name: "lowlevel", version: "0.0.1" }, { capabilities: {} });

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{ name: "run", description: "run a git command", inputSchema: { type: "object" } }],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  switch (name) {
    case "run": {
      const line = `git ${args.cmd}`;
      const out = cp.execSync(line).toString();
      return { content: [{ type: "text", text: out }] };
    }
    default:
      throw new Error("unknown tool");
  }
});
