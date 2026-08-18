// Shared false-positive trap fixture for the TypeScript engine.
//
// Everything in this file is CORRECT code. It collects, in one place, every
// shape that made one of the four ts_* checks fire wrongly during adversarial
// verification, plus the lexing decoys that a naive regex scanner trips on.
// All four checks must return zero findings here. A finding in this file is a
// bug in the check, never in the fixture -- so do not "fix" this file to make
// a check pass.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { execFile, execFileSync } from "child_process";
import express from "express";
import * as fs from "fs";
import * as path from "path";
import { z } from "zod";

const server = new McpServer({ name: "noise-common", version: "1.0.0" });
const WORKSPACE = "/srv/workspace";

// A local helper that happens to be named `tool`. Gate 1 requires a member
// call, so a bare tool(...) must never be read as a registration.
function tool<T>(descriptor: T): T {
  return descriptor;
}
const notARegistration = tool({ name: "decoy", run: async (dir: string) => fs.rmSync(dir, { recursive: true }) });

// ---------------------------------------------------------------- lexing decoys
// None of the following is code. A scanner that matches raw source instead of
// the masked text fires on every one of them.
//   exec(`rm -rf ${userInput}`)
/* fs.rmSync(args.dir, { recursive: true });
   new StreamableHTTPServerTransport({ sessionIdGenerator: undefined }); */
const DOC_STRING = "call exec(`rm -rf ${dir}`) to clean up, or fs.rm(p, {recursive:true})";
const TEMPLATE_DOC = `the shell form is exec("rm -rf " + dir) and it is unsafe`;
const SPLIT_ON_SLASH = "a/b//c".split("/");
const VERSION_RE = /^v(\d+)\/exec\((.*)\)$/;

// ------------------------------------------------------ command execution (safe)
// Fixed allow-list table. The binary is chosen by table lookup, never spliced.
// This is the exact shape ts_command_injection's own remediation recommends,
// and it fired as a HIGH before _taint_is_spliced landed.
const BINARIES: Record<string, string> = {
  git: "/usr/bin/git",
  hg: "/usr/bin/hg",
};

server.registerTool(
  "vcs_status",
  {
    description: "Report status for a checkout.",
    inputSchema: {
      vcs: z.enum(["git", "hg"]),
      // Constrained zod idioms outside the v3 core. Each of these applies a
      // real constraint; a check that allow-lists constraining methods by name
      // reports all of them as unconstrained.
      branch: z.string().nonempty(),
      remote: z.string().lowercase(),
      host: z.string().hostname(),
      addr: z.string().ipv4(),
      id: z.string().guid(),
      phone: z.string().e164().optional(),
      note: z.string().check(z.maxLength(80)).optional(),
      depth: z.number().int().positive().max(50),
    },
    outputSchema: {
      // An outputSchema is not an input. Bare strings here are not findings.
      summary: z.string(),
      raw: z.string(),
    },
  },
  async ({ vcs, branch, depth }) => {
    const bin = BINARIES[vcs];
    // Array argv, no shell. The tainted values are separate argv elements.
    const out = execFileSync(bin, ["log", "-n", String(depth), branch], {
      cwd: WORKSPACE,
    });
    return { content: [{ type: "text", text: out.toString() }] };
  },
);

// A tool with no inputSchema at all. Its callback parameter 0 is the server
// context, NOT tool arguments -- rule R2. Treating it as attacker-controlled
// fires on a tool that accepts no input whatsoever.
server.tool("list_workspace", "List the workspace root.", async (extra) => {
  const entries = fs.readdirSync(WORKSPACE);
  return { content: [{ type: "text", text: entries.join("\n") }] };
});

// ------------------------------------------------------- filesystem (contained)
// Canonicalize-and-confine. resolve() + startsWith is a real containment guard.
function assertUnderWorkspace(candidate: string): string {
  const resolved = path.resolve(WORKSPACE, candidate);
  if (!resolved.startsWith(WORKSPACE + path.sep) && resolved !== WORKSPACE) {
    throw new Error("path escapes the workspace");
  }
  return resolved;
}

server.registerTool(
  "remove_artifact",
  {
    description: "Delete a build artifact inside the workspace.",
    inputSchema: { target: z.string().min(1).max(512) },
  },
  async ({ target }) => {
    const safe = assertUnderWorkspace(target);
    fs.rmSync(safe, { recursive: true, force: true });
    return { content: [{ type: "text", text: "removed" }] };
  },
);

// Closed-set schema: two possible values, no traversal is expressible. The
// message "an attacker can delete arbitrary files" would be simply false here.
server.registerTool(
  "purge_cache",
  {
    description: "Purge one of the managed cache directories.",
    inputSchema: { which: z.enum(["logs", "cache"]) },
  },
  async ({ which }) => {
    fs.rmSync(path.join(WORKSPACE, which), { recursive: true, force: true });
    return { content: [{ type: "text", text: "purged" }] };
  },
);

// Taint laundered through an opaque call's return value. `scratch` is the
// callee's own temp directory, not anything the caller named. "Do work in a
// scratch dir, then clean it up" is the most common filesystem shape there is.
declare function runBuild(source: string): Promise<{ tmpDir: string }>;

server.registerTool(
  "build",
  {
    description: "Build a target and clean up after itself.",
    inputSchema: { source: z.string().min(1).max(256) },
  },
  async ({ source }) => {
    const result = await runBuild(source);
    fs.rmSync(result.tmpDir, { recursive: true, force: true });
    return { content: [{ type: "text", text: "built" }] };
  },
);

// Prompts and resources share the tool overload ladder but are never tools.
server.registerPrompt("explain", { argsSchema: { topic: z.string() } }, async ({ topic }) => ({
  messages: [{ role: "user", content: { type: "text", text: topic } }],
}));

// ------------------------------------------------------------ transport (armed)
const app = express();

// Independent host gate, spelled the Express way. This IS the mitigation the
// dns check's remediation asks for.
const ALLOWED_HOSTS = new Set(["127.0.0.1:3000", "localhost:3000"]);
app.use((req, res, next) => {
  if (!ALLOWED_HOSTS.has(req.headers.host ?? "")) {
    return res.status(403).end();
  }
  if (req.headers["x-api-key"] !== process.env.MCP_SECRET) {
    return res.status(401).end();
  }
  return next();
});

const transport = new StreamableHTTPServerTransport({
  sessionIdGenerator: () => crypto.randomUUID(),
  enableDnsRebindingProtection: true,
  allowedHosts: ["127.0.0.1:3000", "localhost:3000"],
  allowedOrigins: ["http://127.0.0.1:3000"],
});

await server.connect(transport);
app.listen(3000, "127.0.0.1");

export { notARegistration, DOC_STRING, TEMPLATE_DOC, SPLIT_ON_SLASH, VERSION_RE, execFile };
