// Lexing traps. Every "construction" below lives inside a comment, a string,
// a template literal, or a regex, so none of them is code. The only real
// transport is stdio.
//
// Expected findings: 0.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

// new StreamableHTTPServerTransport({ sessionIdGenerator: undefined })
/*
  new SSEServerTransport("/messages", res)
  new StreamableHTTPServerTransport({})
*/

const DOCS = "new StreamableHTTPServerTransport({ sessionIdGenerator: undefined })";
const SNIPPET = `new SSEServerTransport("/messages", res)`;
const HOMEPAGE = "https://example.com/docs#new-StreamableHTTPServerTransport";

// a regex containing a quote character, and a division that follows a `)`
const QUOTES = /['"]/g;
const HALF = (DOCS.length + 2) / 2;

const server = new McpServer({ name: "traps", version: "1.0.0" });

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.log(SNIPPET, HOMEPAGE, QUOTES, HALF);
}

main();
