// Counterweight to `ts_dns_rebinding_hostname`: the host-guard regex accepts
// a request-anchored read of the Host header, and it must NOT be widened all
// the way to a bare `hostname` identifier. This file is
// `mcp-server-browserbase/src/transport.ts` in miniature — a verified true
// positive whose http bootstrap takes `hostname` as an ordinary parameter and
// passes it straight to `listen()`. That is a bind address, not a validation
// of the inbound header. Naming a thing is not checking it.
//
// NOTE for anyone editing this file: the guard regexes run against RAW text,
// so a comment that spells the guarded expression out suppresses the check.
// That is deliberate (a comment about it is still author awareness), but it
// means this fixture's prose has to avoid the literal token.
//
// Expected findings: 1 (line 29).
import http from "node:http";
import crypto from "node:crypto";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

export function startHttpTransport(port: number, hostname: string | undefined) {
  const sessions = new Map<string, StreamableHTTPServerTransport>();

  const httpServer = http.createServer(async (req, res) => {
    if (req.method !== "POST") {
      res.statusCode = 400;
      res.end("Invalid request");
      return;
    }
    const sessionId = crypto.randomUUID();
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => sessionId,
    });
    sessions.set(sessionId, transport);
    await transport.handleRequest(req, res);
  });

  httpServer.listen(port, hostname, () => {
    console.log(`listening on ${hostname ?? "0.0.0.0"}:${port}`);
  });
}
