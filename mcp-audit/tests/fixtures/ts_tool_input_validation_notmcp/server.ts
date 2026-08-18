/**
 * Not an MCP server. `registry.tool(...)` and `defineTool(...)` here belong to
 * an unrelated plugin framework, and its schemas are none of our business.
 *
 * Expected findings: 0.
 */
import { z } from "zod";
import { registry } from "./plugin-registry.js";

registry.registerTool(
  "search",
  { title: "Search", inputSchema: { query: z.string(), payload: z.any() } },
  async ({ query, payload }: any) => ({ query, payload }),
);

registry.tool("blob", "desc", { data: z.any() }, async (args: any) => args);
