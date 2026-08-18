/**
 * Sink names that are NOT Node filesystem calls. `rm`, `remove`, `del`, and
 * `unlink` are ordinary method names on caches, stores, and in-memory
 * virtual filesystems; this file imports no fs module at all, so nothing
 * here may resolve to a sink.
 *
 * Expected findings: 0.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "localfs", version: "1.0.0" });

const store = new Map<string, string>();

// A local object that happens to expose fs-shaped method names.
const fileSystem = {
  rm(key: string) {
    store.delete(key);
  },
  unlink(key: string) {
    store.delete(key);
  },
};

server.registerTool(
  "dropEntry",
  { title: "Drop an entry", inputSchema: { key: z.string() } },
  async ({ key }) => {
    fileSystem.rm(key); // local object, not node:fs
    fileSystem.unlink(key); // ditto
    return { content: [{ type: "text", text: "dropped" }] };
  },
);

server.registerTool(
  "dropCached",
  { title: "Drop a cached entry", inputSchema: { key: z.string() } },
  async ({ key }) => {
    const cache = { remove: (k: string) => store.delete(k) };
    cache.remove(key); // a cache, not fs-extra
    return { content: [{ type: "text", text: "dropped" }] };
  },
);
