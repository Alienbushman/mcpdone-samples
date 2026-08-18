/**
 * Intentional ts_tool_input_validation bad cases. Every tool below is a real
 * MCP registration whose declared input schema (or handler typing) is
 * unconstrained.
 *
 * Expected findings: 3
 *   - search : field 'query'   -> LOOSE_STRING   (z.string(), no constraint)
 *   - blob   : field 'payload' -> LOOSE_ANY      (z.any())
 *   - raw    : handler param 0 -> ANY_PARAM      (args: any)
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "bad", version: "0.0.1" });

server.registerTool(
  "search",
  {
    title: "Search",
    inputSchema: {
      query: z.string(),        // unconstrained free-form string -> LOOSE_STRING
      limit: z.number().int(),  // constrained number -> clean
    },
  },
  async ({ query, limit }) => ({ content: [{ type: "text", text: query }] }),
);

server.registerTool(
  "blob",
  {
    title: "Blob",
    inputSchema: {
      payload: z.any(),                       // validates nothing -> LOOSE_ANY
      kind: z.enum(["json", "text", "bin"]),  // fixed set -> clean
    },
  },
  async ({ payload, kind }) => ({ content: [{ type: "text", text: kind }] }),
);

server.registerTool(
  "raw",
  {
    title: "Raw",
    inputSchema: {
      id: z.string().uuid(),  // constrained -> clean
    },
  },
  // schema is declared, but the handler throws the types away -> ANY_PARAM
  async (args: any, extra: any) => ({ content: [{ type: "text", text: args.id }] }),
);
