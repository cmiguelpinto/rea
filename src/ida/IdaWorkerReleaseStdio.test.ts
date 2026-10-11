import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createIdaMcpConnection } from "./IdaMcpConnection.js";
import {
  closeDatabaseSchema,
  openDatabaseSchema,
  strictDatabaseListSchema,
} from "./IdaProtocolValues.js";
import { closeVerifiedIdaWorker } from "./IdaWorkerRelease.js";

/** Source-owned stdio MCP supervisor fixture; never imports or executes IDA. */
const releaseId = "123456789abc4def8abc123456789abc";
const supervisorScript = String.raw`
import { createInterface } from "node:readline";
const token = "123456789abc4def8abc123456789abc";
let session;
let released;
const send = (id, result) =>
  process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id, result }) + "\n");
const tool = (name) => ({ name, inputSchema: { type: "object" } });
const reply = (id, data) => send(id, {
  content: [{ type: "text", text: JSON.stringify(data) }],
});
for await (const line of createInterface({ input: process.stdin })) {
  const request = JSON.parse(line);
  if (request.method === "initialize") {
    send(request.id, {
      protocolVersion: request.params.protocolVersion,
      capabilities: { tools: {} },
      serverInfo: { name: "source-owned-release-supervisor", version: "1" },
    });
  } else if (request.method === "tools/list") {
    send(request.id, {
      tools: ["idb_open", "idb_close", "idb_list", "server_health"].map(tool),
    });
  } else if (request.method === "tools/call") {
    const name = request.params.name;
    const args = request.params.arguments || {};
    if (name === "idb_open") {
      session = {
        session_id: args.preferred_session_id,
        input_path: args.input_path,
      };
      released = undefined;
      reply(request.id, {
        success: true,
        session: { ...session, release_id: token },
      });
    } else if (name === "server_health") {
      released = session;
      session = undefined;
      send(request.id, {
        isError: true,
        content: [{ type: "text", text: "Worker for session is not reachable" }],
      });
    } else if (name === "idb_close") {
      const owned = session || released;
      if (
        args.database !== owned?.session_id ||
        args.save !== false ||
        args.expected_input_path !== owned?.input_path ||
        args.release_id !== token
      ) {
        reply(request.id, { error: "Release identity mismatch" });
      } else {
        const closed = owned;
        released = closed;
        session = undefined;
        reply(request.id, {
          success: true,
          session_id: closed.session_id,
          backend: "worker",
          owned: true,
          saved: null,
          release: {
            status: "terminated",
            verified: true,
            session_id: closed.session_id,
            input_path: closed.input_path,
            release_id: token,
            backend: "worker",
            owned: true,
            worker_pid: 4242,
            exit_code: -9,
          },
        });
      }
    } else if (name === "idb_list") {
      const sessions = session === undefined
        ? []
        : [{ ...session, owned: true, backend: "worker", is_active: true }];
      reply(request.id, {
        sessions,
        ...(args.strict_discovery === true
          ? { count: sessions.length, registry_scan_complete: true }
          : {}),
      });
    } else {
      reply(request.id, { error: "Unexpected tool" });
    }
  }
}
`;

describe("IDA PR #551 real stdio MCP release contract", () => {
  it.each(["normal", "reaped"] as const)(
    "round-trips %s worker and idempotent close over SDK stdio",
    async (mode) => {
      const root = await mkdtemp(join(tmpdir(), "rea-ida-release-stdio-"));
      const script = join(root, "supervisor.mjs");
      const inputPath = join(root, "source-owned.bin");
      const bytes = Buffer.from(
        "safe IDA MCP transport fixture; never executed",
      );
      await writeFile(script, supervisorScript);
      await writeFile(inputPath, bytes);
      const connection = createIdaMcpConnection(
        {
          command: process.execPath,
          args: [script],
          env: {},
          mode: "headless",
          timeoutMs: 4000,
          workspaceRoot: root,
        },
        process.env,
      );
      try {
        expect(await connection.connect()).toEqual([
          "idb_open",
          "idb_close",
          "idb_list",
          "server_health",
        ]);
        const sessionId = "rea-transport-fixture";
        const opened = openDatabaseSchema.parse(
          await connection.call("idb_open", {
            input_path: inputPath,
            preferred_session_id: sessionId,
            mode: "force_headless",
          }),
        );
        expect(opened.session.release_id).toBe(releaseId);
        if (mode === "reaped")
          await expect(
            connection.call("server_health", { database: sessionId }),
          ).rejects.toThrow("not reachable");
        const result = await closeVerifiedIdaWorker({
          connection,
          database: sessionId,
          privateSessionId: sessionId,
          inputPath,
          sha256: createHash("sha256").update(bytes).digest("hex"),
          openCompleted: true,
          releaseId: opened.session.release_id,
        });
        expect(result).toBe("release-verified");
        const repeated = closeDatabaseSchema.parse(
          await connection.call("idb_close", {
            database: sessionId,
            save: false,
            expected_input_path: inputPath,
            release_id: releaseId,
          }),
        );
        expect(repeated.release).toMatchObject({
          verified: true,
          status: "terminated",
          session_id: sessionId,
          input_path: inputPath,
          release_id: releaseId,
        });
        expect(
          strictDatabaseListSchema.parse(
            await connection.call("idb_list", { strict_discovery: true }),
          ).sessions,
        ).toEqual([]);
      } finally {
        await connection.close();
        await rm(root, { recursive: true, force: true });
      }
    },
  );
});
