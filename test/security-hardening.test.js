import { test } from "node:test";
import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import net from "node:net";

const HERE = dirname(fileURLToPath(import.meta.url));
const SERVER = join(HERE, "..", "src", "server.js");
const HTTP_SERVER = join(HERE, "..", "src", "http-server.js");
const fixedEnv = Object.fromEntries(
  Array.from({ length: 13 }, (_, index) => [`LAB_S${index + 1}`, "fixed"]),
);

async function call(client, name, args) {
  const result = await client.callTool({ name, arguments: args });
  return { isError: Boolean(result.isError), text: result.content?.[0]?.text ?? "" };
}

async function withServer(fn) {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [SERVER],
    env: { ...process.env, ...fixedEnv },
    stderr: "ignore",
  });
  const client = new Client({ name: "security-hardening-test", version: "1.0.0" });
  await client.connect(transport);
  try {
    return await fn(client);
  } finally {
    await client.close();
  }
}

test("fixed tools return one unavailable response for missing and foreign notes", async () => {
  await withServer(async (client) => {
    for (const [name, args] of [
      ["note_get", { token: "alice-token", id: "n_globex_1" }],
      ["note_update", { token: "alice-token", id: "n_globex_1", body: "no mutation" }],
    ]) {
      const foreign = await call(client, name, args);
      const missing = await call(client, name, { ...args, id: "n_missing_xyz" });
      assert.equal(foreign.isError, true);
      assert.equal(missing.isError, true);
      assert.equal(foreign.text, missing.text);
      assert.match(foreign.text, /requested note is unavailable/);
    }
  });
});

test("HTTP transport binds to loopback by default", async () => {
  const port = 31112;
  const proc = spawn(process.execPath, [HTTP_SERVER], {
    env: { ...process.env, ...fixedEnv, PORT: String(port) },
    stdio: ["ignore", "ignore", "pipe"],
  });
  let stderr = "";
  try {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("HTTP server did not start")), 8_000);
      proc.stderr.on("data", (chunk) => {
        stderr += String(chunk);
        if (stderr.includes(`up on 127.0.0.1:${port}`)) {
          clearTimeout(timer);
          resolve();
        }
      });
      proc.once("error", reject);
      proc.once("exit", (code) => reject(new Error(`HTTP server exited early: ${code}`)));
    });
    await new Promise((resolve, reject) => {
      const socket = net.createConnection({ host: "127.0.0.1", port });
      socket.once("connect", () => { socket.destroy(); resolve(); });
      socket.once("error", reject);
    });
  } finally {
    proc.kill();
  }
});
