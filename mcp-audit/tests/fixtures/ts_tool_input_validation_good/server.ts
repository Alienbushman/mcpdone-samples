/**
 * Correct, well-constrained MCP tool registrations. Every string field carries
 * a length / pattern / format constraint, every other field uses a closed
 * constructor, and every handler destructures with real types.
 *
 * Expected findings: 0.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "good", version: "0.0.1" });

server.registerTool(
  "search",
  {
    title: "Search",
    inputSchema: {
      query: z.string().min(1).max(200),               // bounded
      mode: z.enum(["fuzzy", "exact"]),                // closed set
      limit: z.number().int().positive(),              // closed
      cursor: z.string().regex(/^[A-Za-z0-9_-]+$/),    // pattern-constrained
    },
  },
  async ({ query, mode, limit, cursor }) => ({
    content: [{ type: "text", text: `${query}${mode}${limit}${cursor}` }],
  }),
);

server.registerTool(
  "fetchDoc",
  {
    title: "Fetch document",
    inputSchema: {
      url: z.string().url(),                    // format-constrained
      etag: z.string().length(32).optional(),   // constrained then wrapped
      tags: z.array(z.string().max(40)),        // array constructor is closed
      body: z.object({ note: z.string() }),     // nested: top-level only, clean
    },
  },
  async ({ url, etag, tags, body }: { url: string; etag?: string; tags: string[]; body: { note: string } }) => ({
    content: [{ type: "text", text: url }],
  }),
);

// A zero-argument tool: no inputSchema is the CORRECT encoding here, and the
// handler's first parameter is the server context, not tool arguments.
server.tool("ping", "Health probe", async () => ({
  content: [{ type: "text", text: "pong" }],
}));
