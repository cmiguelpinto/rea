import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { jsonValueSchema, type JsonValue } from "../domain/jsonValue.js";
import type { IdaMcpConnection } from "./IdaMcpConnection.js";
import {
  closeVerifiedIdaWorker,
  readIdaSessionInventory,
} from "./IdaWorkerRelease.js";

const releaseId = "123456789abc4def8abc123456789abc";
const roots: string[] = [];
afterEach(async () => {
  for (const path of roots.splice(0))
    await rm(path, { recursive: true, force: true });
});

const fixture = async () => {
  const root = await mkdtemp(join(tmpdir(), "rea-ida-release-test-"));
  roots.push(root);
  const inputPath = join(root, "source-owned.bin");
  const bytes = Buffer.from("harmless source-owned IDA release fixture");
  await writeFile(inputPath, bytes);
  const sha256 = createHash("sha256").update(bytes).digest("hex");
  const database = "rea-source-owned-session";
  const calls: Array<{
    name: string;
    args: Readonly<Record<string, JsonValue>>;
  }> = [];
  const connection: IdaMcpConnection = {
    async connect() {
      return ["idb_close"];
    },
    async call(name, args) {
      calls.push({ name, args });
      if (name !== "idb_close") throw new Error("unexpected tool");
      return { error: "Session not found" };
    },
    serverInfo: () => null,
    async close() {},
  };
  const options = {
    connection,
    database,
    privateSessionId: database,
    inputPath,
    sha256,
    openCompleted: true,
    releaseId,
  };
  const proof = (): Record<string, JsonValue> => ({
    status: "terminated",
    verified: true,
    session_id: database,
    input_path: inputPath,
    release_id: releaseId,
    backend: "worker",
    owned: true,
    worker_pid: 4242,
    exit_code: -9,
  });
  const success = (): Record<string, JsonValue> => ({
    success: true,
    session_id: database,
    backend: "worker",
    owned: true,
    saved: null,
    release: proof(),
  });
  const reply = (result: JsonValue) => {
    connection.call = async (name, args) => {
      calls.push({ name, args });
      return result;
    };
  };
  return {
    options,
    connection,
    calls,
    reply,
    proof,
    success,
    database,
    inputPath,
  };
};

describe("IDA PR #551 verified worker close", () => {
  it("refuses a foreign session before any upstream request", async () => {
    const { options, calls, reply, success } = await fixture();
    reply(success());
    await expect(
      closeVerifiedIdaWorker({ ...options, database: "foreign" }),
    ).rejects.toThrow("outside its private worker ownership");
    expect(calls).toEqual([]);
  });

  it("keeps legacy close when the original open had no release token", async () => {
    const { options, calls, reply, success, database } = await fixture();
    const result = success();
    delete result.release;
    reply(result);
    await expect(
      closeVerifiedIdaWorker({ ...options, releaseId: undefined }),
    ).resolves.toBe("close-confirmed");
    expect(calls).toEqual([
      { name: "idb_close", args: { database, save: false } },
    ]);
  });

  it("sends the exact owned open-generation token and private input, never saves", async () => {
    const { options, reply, success, calls, database, inputPath } =
      await fixture();
    reply(success());
    await expect(closeVerifiedIdaWorker(options)).resolves.toBe(
      "release-verified",
    );
    expect(calls).toEqual([
      {
        name: "idb_close",
        args: {
          database,
          save: false,
          expected_input_path: inputPath,
          release_id: releaseId,
        },
      },
    ]);
  });

  it("accepts nonzero or negative exit code only with a terminal receipt", async () => {
    const { options, reply, success } = await fixture();
    const value = success();
    (value.release as Record<string, JsonValue>).exit_code = 12;
    reply(value);
    await expect(closeVerifiedIdaWorker(options)).resolves.toBe(
      "release-verified",
    );
  });

  it("keeps private ownership when a reaped session returns Session not found", async () => {
    const { options, calls } = await fixture();
    await expect(closeVerifiedIdaWorker(options)).rejects.toThrow();
    expect(calls).toHaveLength(1);
    expect(calls[0]?.args.save).toBe(false);
  });

  it("refuses uncompleted open and pre-close input tampering without sending close", async () => {
    const { options, calls, reply, success, inputPath } = await fixture();
    reply(success());
    await expect(
      closeVerifiedIdaWorker({ ...options, openCompleted: false }),
    ).rejects.toThrow("completed owned open");
    await writeFile(inputPath, "changed before close");
    await expect(closeVerifiedIdaWorker(options)).rejects.toThrow(
      "changed before",
    );
    expect(calls).toEqual([]);
  });
});

describe("IDA PR #551 fail-closed receipt validation", () => {
  it.each([
    "missing-receipt",
    "not-verified",
    "not-terminated",
    "wrong-session",
    "wrong-input",
    "wrong-release-id",
    "unowned",
    "gui",
    "missing-pid",
    "invalid-pid",
    "missing-exit",
    "null-exit",
    "saved",
    "foreign-close-session",
    "foreign-close-owner",
    "foreign-close-backend",
  ] as const)("rejects %s", async (kind) => {
    const { options, reply, success, inputPath } = await fixture();
    const response = success();
    const release = response.release as Record<string, JsonValue>;
    if (kind === "missing-receipt") delete response.release;
    if (kind === "not-verified") release.verified = false;
    if (kind === "not-terminated") release.status = "releasing";
    if (kind === "wrong-session") release.session_id = "other";
    if (kind === "wrong-input") release.input_path = inputPath + ".other";
    if (kind === "wrong-release-id")
      release.release_id = "fedcba9876544cba8765fedcba987654";
    if (kind === "unowned") release.owned = false;
    if (kind === "gui") release.backend = "gui";
    if (kind === "missing-pid") delete release.worker_pid;
    if (kind === "invalid-pid") release.worker_pid = 0;
    if (kind === "missing-exit") delete release.exit_code;
    if (kind === "null-exit") release.exit_code = null;
    if (kind === "saved") response.saved = true;
    if (kind === "foreign-close-session") response.session_id = "other";
    if (kind === "foreign-close-owner") response.owned = false;
    if (kind === "foreign-close-backend") response.backend = "gui";
    reply(response);
    await expect(closeVerifiedIdaWorker(options), kind).rejects.toThrow();
  });

  it("rejects malformed close output, expired proof and unsupported upstream errors", async () => {
    const { options, reply } = await fixture();
    reply({ success: true, session_id: options.database, backend: "worker" });
    await expect(closeVerifiedIdaWorker(options)).rejects.toThrow();
    reply({ error: "Worker release unknown for session" });
    await expect(closeVerifiedIdaWorker(options)).rejects.toThrow();
  });

  it("keeps ownership if the private bytes change during verified close", async () => {
    const { options, connection, inputPath, success } = await fixture();
    connection.call = async () => {
      await writeFile(inputPath, "changed while closing");
      return success();
    };
    await expect(closeVerifiedIdaWorker(options)).rejects.toThrow(
      "changed during",
    );
  });
});

describe("IDA PR #551 strict registry discovery", () => {
  it("requests a complete scan for a token-backed worker", async () => {
    const { connection, reply, calls } = await fixture();
    reply({ sessions: [], count: 0, registry_scan_complete: true });
    const inventory = await readIdaSessionInventory(connection, releaseId);
    expect(inventory.sessions).toEqual([]);
    expect(calls).toEqual([
      { name: "idb_list", args: { strict_discovery: true } },
    ]);
  });

  it("preserves existing inventory arguments for older supervisors", async () => {
    const { connection, reply, calls } = await fixture();
    reply({ sessions: [] });
    expect(
      (await readIdaSessionInventory(connection, undefined)).sessions,
    ).toEqual([]);
    expect(calls).toEqual([{ name: "idb_list", args: {} }]);
  });

  it.each([
    ["missing completeness", { sessions: [], count: 0 }],
    [
      "explicit incomplete",
      { sessions: [], count: 0, registry_scan_complete: false },
    ],
    [
      "inconsistent count",
      { sessions: [], count: 1, registry_scan_complete: true },
    ],
    [
      "discovery error",
      { error: "Failed to list sessions: Instance discovery incomplete" },
    ],
    ["missing sessions", { count: 0, registry_scan_complete: true }],
  ] as const)(
    "refuses %s even with an empty-looking inventory",
    async (_label, response) => {
      const { connection, reply } = await fixture();
      reply(jsonValueSchema.parse(response));
      await expect(
        readIdaSessionInventory(connection, releaseId),
      ).rejects.toThrow();
    },
  );
});
