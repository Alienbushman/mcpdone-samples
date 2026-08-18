// Realistic correct code: a framework that re-exports the transport's
// configurability to its own caller. We cannot see what the caller passes,
// so we do not guess.
//
// Expected findings: 0.
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { StreamableHTTPServerTransportOptions } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

export function createTransport(opts: StreamableHTTPServerTransportOptions) {
  // spread: the deployer decides the security options, not this library
  return new StreamableHTTPServerTransport({ ...opts });
}

export function createTransportFrom(options: StreamableHTTPServerTransportOptions) {
  // an options object we cannot resolve to a literal in this file
  return new StreamableHTTPServerTransport(options);
}
