import path from "node:path";
import { readFile } from "node:fs/promises";

export async function readRequestedFile(filePath) {
  // ruleid: mcp-client-path-file-read-js
  const absolutePath = path.resolve(filePath);
  const data = await readFile(absolutePath);
  return data;
}

export async function readServerFile() {
  const trustedPath = path.join("/srv/mcp/public", "notice.txt");
  // ok: mcp-client-path-file-read-js
  const absolutePath = path.resolve(trustedPath);
  const data = await readFile(absolutePath);
  return data;
}
