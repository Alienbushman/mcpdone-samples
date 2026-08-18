/**
 * Low-level `setRequestHandler` dispatch. The CallToolRequestSchema handler
 * destructures `arguments` off `request.params` and deletes a caller-chosen
 * path; the ListToolsRequestSchema handler in the same file carries no tool
 * arguments at all and must be ignored by the argument-0 gate.
 *
 * Expected findings: 1 (the `remove_file` case).
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import * as fsp from "node:fs/promises";

const server = new Server(
  { name: "lowlevel", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async (request) => {
  // Not a tool invocation: `request.params.cursor` is a pagination token.
  await fsp.rm(request.params.cursor as string);
  return { tools: [] };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: toolArgs } = request.params;
  switch (name) {
    case "remove_file": {
      await fsp.unlink(toolArgs.target as string);
      return { content: [{ type: "text", text: "removed" }] };
    }
    default:
      throw new Error(`unknown tool ${name}`);
  }
});
