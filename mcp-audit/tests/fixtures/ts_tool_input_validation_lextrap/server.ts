/**
 * Lexing traps. Every unconstrained-looking schema below lives inside a
 * string, a comment, or a regex literal, and every real schema is constrained.
 * A finding here means the check is matching raw text instead of the mask.
 *
 * Expected findings: 0.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "lextrap", version: "0.0.1" });

// server.registerTool("commented", { inputSchema: { q: z.string() } }, async () => {});

const DOC = "inputSchema: { q: z.any(), r: z.string() } // not code";
const TEMPLATE = `payload: z.any() /* still not code */`;

server.registerTool(
  "quoted",
  {
    title: "Quoted",
    description: "Pass z.any() here, or a bare z.string(), or // whatever",
    inputSchema: {
      // The regex contains a quote and a slash; a naive scanner desynchronises
      // here and every span after it is garbage.
      token: z.string().regex(/^['"a-z/]{1,64}$/),
      note: z.string().max(280),
    },
  },
  async ({ token, note }) => ({ content: [{ type: "text", text: token + note + DOC + TEMPLATE }] }),
);
