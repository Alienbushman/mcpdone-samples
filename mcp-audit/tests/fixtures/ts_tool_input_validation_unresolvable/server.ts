/**
 * Schemas we cannot classify. Guessing at any of these is how false positives
 * ship, so every one of them is suppressed.
 *
 * Expected findings: 0.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { zodToJsonSchema } from "zod-to-json-schema";
import { z } from "zod";
import { type } from "arktype";
import * as v from "valibot";
import { SearchInput } from "./schemas.js";

const server = new McpServer({ name: "unresolvable", version: "0.0.1" });

// A tools/list JSON-Schema descriptor, not a runtime validator: it carries its
// own maxLength conventions that we do not model.
server.registerTool(
  "listish",
  { title: "Listish", inputSchema: zodToJsonSchema(SearchInput) },
  async (args) => ({ content: [{ type: "text", text: String(args) }] }),
);

// A hand-written JSON Schema object literal — same reason.
server.registerTool(
  "jsonschema",
  {
    title: "JSON Schema",
    inputSchema: {
      type: "object",
      properties: { query: { type: "string" } },
    },
  },
  async (args) => ({ content: [{ type: "text", text: String(args) }] }),
);

// A schema field built by another validator library. We do not model arktype
// or valibot chains, so we cannot say whether these are constrained.
server.registerTool(
  "otherlibs",
  {
    title: "Other libraries",
    inputSchema: {
      a: type("string"),
      b: v.string(),
      c: SearchInput,
    },
  },
  async (args) => ({ content: [{ type: "text", text: String(args) }] }),
);

// The whole config object is an identifier we do not resolve; schema presence
// is unknown, so nothing is claimed about it.
const CONFIG = { title: "Opaque", inputSchema: { q: z.string() } };
server.registerTool("opaque", CONFIG, async ({ q }) => ({
  content: [{ type: "text", text: String(q) }],
}));

// A spread config: same, presence of a schema key is not decidable.
server.registerTool("spread", { ...CONFIG, title: "Spread" }, async ({ q }) => ({
  content: [{ type: "text", text: String(q) }],
}));

// Low-level dispatch: no registration config exists to inspect at all.
server.server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const args = request.params.arguments as any;
  return { content: [{ type: "text", text: String(args) }] };
});
