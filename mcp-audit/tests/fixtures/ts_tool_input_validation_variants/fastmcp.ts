/**
 * fastmcp's addTool({ name, parameters, execute }). The schema key is
 * `parameters`, and it is a z.object(...) wrapper rather than a raw shape.
 *
 * Expected findings: 1 (field 'pattern').
 */
import { FastMCP } from "fastmcp";
import { z } from "zod";

const mcp = new FastMCP({ name: "variants", version: "0.0.1" });

mcp.addTool({
  name: "grep",
  description: "Search files",
  parameters: z.object({
    pattern: z.string(),                 // unconstrained -> LOOSE_STRING
    maxResults: z.number().int().max(100),
  }),
  execute: async (args) => String(args.pattern),
});
