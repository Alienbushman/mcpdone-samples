/**
 * Reduced from `servers-archived/src/redis/src/index.ts:188-202` — the only
 * place in a 25-repo TypeScript corpus where a sink-NAMED call sits inside an
 * MCP tool handler with an attacker-controlled argument and no guard.
 *
 * `redisClient.del(key)` deletes a Redis key, not a file. Every stage of this
 * check runs on it — the CallTool handler resolves, `key` is correctly marked
 * tainted, no containment guard is present — and the import gate is the ONLY
 * thing that declines: `redisClient` comes from the `redis` package, not from
 * `del`/`rimraf`/`fs`. Firing here would ship a false positive against an
 * official archived server, with a remediation ("canonicalize with realpath")
 * that is meaningless for a Redis key. This is the v0.3 defect class exactly.
 *
 * The file also imports `node:fs` (for an unrelated constant read), so the
 * file-level "does this file import any delete-capable module" short-circuit
 * does NOT apply: execution reaches the per-call-site receiver gate, which is
 * the gate this test exists to pin.
 *
 * Expected findings: 0.
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { createClient } from "redis";
import fs from "node:fs";

const BANNER = fs.readFileSync("/etc/mcp/banner.txt", "utf8");

const redisClient = createClient({ url: "redis://localhost:6379" });
const server = new Server({ name: "redis", version: "1.0.0" }, { capabilities: { tools: {} } });

const DeleteArgumentsSchema = z.object({ key: z.union([z.string(), z.array(z.string())]) });

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  if (name === "delete") {
    const { key } = DeleteArgumentsSchema.parse(args);
    if (Array.isArray(key)) {
      await redisClient.del(key); // a Redis key, not a path
      return { content: [{ type: "text", text: `Deleted ${key.length} keys` }] };
    }
    await redisClient.del(key); // ditto
    return { content: [{ type: "text", text: `Deleted key: ${key}` }] };
  }
  throw new Error(`Unknown tool: ${name}`);
});
