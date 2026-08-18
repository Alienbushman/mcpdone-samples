/**
 * `.describe()` documents a field; it does not constrain it. The SDK forwards
 * the description to the model verbatim and applies no length, pattern, or
 * format rule, so this is still an unconstrained string.
 *
 * Expected findings: 1 (field 'query').
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "describe", version: "0.0.1" });

server.registerTool(
  "search",
  {
    title: "Search",
    inputSchema: {
      query: z.string().describe("the search query"),  // documented, not constrained
      page: z.number().int().describe("1-based page"), // number ctor is closed -> clean
    },
  },
  async ({ query, page }) => ({ content: [{ type: "text", text: query }] }),
);
