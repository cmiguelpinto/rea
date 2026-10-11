#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { parseBinaryTarget } from "../dist/application/BinaryTargetResolver.js";
import {
  inspectArmReadelf,
  assertArmLoadedImage,
  assertArmProbe,
} from "../tests/conformance/ghidra/arm-checks.mjs";
import { parseEvidence } from "../dist/domain/evidence.js";
import { parseAnalysisSnapshot } from "../dist/domain/analysisSnapshot.js";
import { functionDossierSchema } from "../dist/domain/hopperValues.js";
import { inspectGhidraInstallation } from "../dist/ghidra/GhidraInstallation.js";
import { buildArmFixture } from "../tests/conformance/ghidra/arm-fixture.mjs";
import {
  requireMcpToolError,
  requireMcpOperationResult,
} from "./lib/mcp-verifier-results.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";

// Optional cross-target lane. No tool acquisition and no target execution.
if (!["linux", "darwin"].includes(process.platform))
  throw new Error(
    "ARM verification requires a supported Linux/macOS Ghidra host",
  );
if (process.env.GHIDRA_INSTALL_DIR === undefined)
  throw new Error("Missing prerequisite: caller-supplied GHIDRA_INSTALL_DIR");
const installation = inspectGhidraInstallation({
  environment: process.env,
  installDir: process.env.GHIDRA_INSTALL_DIR,
  ...(process.env.JAVA_HOME === undefined
    ? {}
    : { javaHome: process.env.JAVA_HOME }),
});
if (installation.status !== "available")
  throw new Error(
    `Ghidra prerequisite unavailable: ${JSON.stringify(installation)}`,
  );
const execute = promisify(execFile);
const entrypoint = fileURLToPath(new URL("./rea.mjs", import.meta.url));
const run = createVerifierRun();
const workspace = await mkdtemp(join(tmpdir(), "rea-arm-proof-"));
const runtime = join(workspace, "runtime");
await mkdir(runtime);
const env = {
  PATH: process.env.PATH ?? "/usr/bin:/bin",
  TMPDIR: runtime,
  REA_LOG_LEVEL: "silent",
  REA_ANALYSIS_PROVIDER: "ghidra",
  REA_PROCESS_RUN_ID: run.run_id,
  GHIDRA_INSTALL_DIR: installation.installDir,
  JAVA_HOME: installation.javaHome,
  HOPPER_LAUNCHER_PATH: "/rea-unconfigured-deep-provider/hopper",
};
for (const setting of ["GHIDRA_HEADLESS_MAXMEM", "GHIDRA_MAXMEM"]) {
  if (process.env[setting] !== undefined) env[setting] = process.env[setting];
}
const reports = [];
let primaryFailure;
try {
  const fixture = await buildArmFixture(workspace);
  const independent = await inspectArmReadelf(fixture.path);
  const resolved = await parseBinaryTarget(fixture.path);
  if (!resolved.ok) throw resolved.error;
  assert.equal(resolved.value.architecture, "arm");
  assert.deepEqual(
    resolved.value.arm,
    {
      elfClass: 32,
      byteOrder: "little",
      type: 2,
      flags: independent.flags,
    },
    "REA ELF interpretation disagrees with GNU readelf",
  );
  assert.equal(resolved.value.sha256, fixture.sha256);
  const snapshotPath = join(workspace, "arm.snapshot.json");
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [entrypoint, "mcp"],
    env,
    stderr: "pipe",
  });
  const client = new Client({ name: "rea-real-arm-proof", version: "1" });
  let stderr = "";
  transport.stderr?.on("data", (chunk) => {
    stderr = (stderr + chunk.toString()).slice(-65536);
  });
  const call = async (name, args = {}) => {
    const reply = await client.callTool({ name, arguments: args }, undefined, {
      timeout: 180000,
    });
    return requireMcpOperationResult(reply, name);
  };
  try {
    await client.connect(transport);
    const selected = await call("open_binary", {
      path: fixture.path,
      provider_id: "ghidra",
    });
    assert.equal(selected.architecture, "arm");
    assert.equal(selected.sha256, fixture.sha256);
    const image = await call("inspect_native_load_image");
    assertArmLoadedImage(image.observations, fixture.sha256);
    const procedures = await call("list_procedures");
    const entry = procedures.find((p) => p.value === "rea_arm_entry");
    const leaf = procedures.find((p) => p.value === "rea_arm_leaf");
    const thumb = procedures.find((p) => p.value === "rea_arm_probe_thumb");
    assert.ok(entry, "Entry function missing from real Ghidra inventory");
    assert.ok(leaf, "Leaf function missing from real Ghidra inventory");
    assert.ok(
      thumb,
      "Thumb-2 interworked function missing from real Ghidra inventory",
    );
    assert.equal(
      BigInt(entry.address),
      BigInt(independent.symbols.rea_arm_entry),
    );
    const armProbe = await call("inspect_native_instruction", {
      address: independent.symbols.rea_arm_probe_arm,
    });
    const thumbBase = BigInt(independent.symbols.rea_arm_probe_thumb);
    const thumbMovw = await call("inspect_native_instruction", {
      address: `0x${thumbBase.toString(16)}`,
    });
    const thumbMovt = await call("inspect_native_instruction", {
      address: `0x${(thumbBase + 4n).toString(16)}`,
    });
    assertArmProbe(armProbe, thumbMovw, thumbMovt);
    assert.equal(armProbe.architecture, "ARM:LE:32:v7");
    assert.equal(thumbMovw.architecture, "ARM:LE:32:v7");
    assert.equal(thumbMovt.architecture, "ARM:LE:32:v7");
    const global = await call("read_bytes", {
      address: independent.symbols.rea_arm_global,
      length: 4,
    });
    assert.equal(global.returned_bytes, 4);
    const marker = await call("read_bytes", {
      address: independent.symbols.rea_arm_marker,
      length: Buffer.byteLength("rea-arm-source-owned-fixture\0"),
    });
    assert.equal(
      marker.bytes_hex,
      Buffer.from("rea-arm-source-owned-fixture\0").toString("hex"),
    );
    const callees = await call("procedure_callees", {
      procedure: entry.address,
    });
    assert.ok(
      callees.includes(leaf.address),
      "Expected direct call not recovered",
    );
    assert.ok(
      callees.includes(thumb.address),
      "Expected interworking call into the Thumb probe not recovered",
    );
    const dossier = functionDossierSchema.parse(
      await call("analyze_function", { procedure: entry.address }),
    );
    assert.ok(dossier.pseudocode.trim().length > 0);
    const saved = await call("close_binary", { snapshot_path: snapshotPath });
    assert.ok(saved.evidence_records > 0);
    const snapshot = parseAnalysisSnapshot(
      JSON.parse(await readFile(snapshotPath, "utf8")),
    );
    assert.equal(snapshot.target.architecture, "arm");
    const parameters = snapshot.binding.analysis_profile.parameters;
    assert.equal(parameters.language_id, "ARM:LE:32:v7");
    assert.equal(parameters.language_selection, "provider-pinned-v1");
    assert.equal(
      parameters.arm_support_lane,
      "elf32-exec-le-eabi5-v7-pinned-v1",
    );
    assert.deepEqual(parameters.arm_elf, {
      elf_class: 32,
      byte_order: "little",
      type: 2,
      flags: independent.flags,
      float_abi: "hard",
    });
    for (const evidence of snapshot.evidence_bundle.records)
      assert.equal(parseEvidence(evidence).subject?.architecture, "arm");
    await call("open_binary", {
      path: fixture.path,
      provider_id: "ghidra",
      snapshot_path: snapshotPath,
    });
    assert.deepEqual(await call("list_procedures"), procedures);
    await call("close_binary");
  } catch (cause) {
    throw new Error(`ARM verification failed; MCP stderr: ${stderr}`, {
      cause,
    });
  } finally {
    try {
      await client.close();
    } finally {
      await transport.close();
    }
  }

  // Typed refusals for shapes the verified lane does not cover: a legacy EABI
  // version (field zeroed to 0x04000000) and a BE8 mixed-endian declaration.
  const refusals = [];
  for (const [label, mask, set] of [
    ["legacy-eabi", 0xff000000, 0x04000000],
    ["be8", 0x00800000, 0x00800000],
  ]) {
    const original = await readFile(fixture.path);
    const patched = Buffer.from(original);
    patched.writeUInt32LE((patched.readUInt32LE(36) & ~mask) | set, 36);
    const variantPath = join(workspace, `arm-${label}.elf`);
    await writeFile(variantPath, patched);
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [entrypoint, "mcp"],
      env,
      stderr: "pipe",
    });
    const client = new Client({ name: "rea-real-arm-refusal", version: "1" });
    try {
      await client.connect(transport);
      const rejected = await client.callTool(
        {
          name: "open_binary",
          arguments: { path: variantPath, provider_id: "ghidra" },
        },
        undefined,
        { timeout: 60000 },
      );
      const error = requireMcpToolError(rejected);
      const text = JSON.stringify(error);
      assert.match(text, label === "legacy-eabi" ? /EABI5/u : /BE8/u);
      refusals.push({ variant: label, error });
    } finally {
      try {
        await client.close();
      } finally {
        await transport.close();
      }
    }
  }

  // Same public operation through CLI, not a private injected provider.
  const cli = await execute(
    process.execPath,
    [
      entrypoint,
      "function",
      fixture.path,
      "rea_arm_entry",
      "--provider",
      "ghidra",
      "--json",
    ],
    { env, timeout: 240000, maxBuffer: 16 * 1024 * 1024 },
  );
  const evidence = parseEvidence(JSON.parse(cli.stdout));
  assert.equal(evidence.subject?.architecture, "arm");
  assert.equal(evidence.subject?.digest.sha256, fixture.sha256);
  const cliDossier = functionDossierSchema.parse(evidence.normalized_result);
  assert.ok(cliDossier.pseudocode.trim().length > 0);
  assert.equal(
    createHash("sha256")
      .update(await readFile(fixture.path))
      .digest("hex"),
    fixture.sha256,
    "Analysis modified the source executable",
  );
  reports.push({
    ...fixture,
    independent_reader: independent,
    effective_language: "ARM:LE:32:v7",
    checks: [
      "independent ELF and symbols",
      "pinned ARM:LE:32:v7 language checked after import",
      "ARM and Thumb-2 probe encodings",
      "typed refusals for legacy EABI and BE8",
      "snapshot round-trip and CLI parity",
    ],
    refusals,
    status: "passed",
  });
} catch (cause) {
  primaryFailure = cause;
}
const completed = await completeVerifierRun(run);
if (
  completed.process_lineage.status !== "verified" ||
  completed.process_lineage.descendants.length !== 0
)
  throw new Error(
    `Cleanup unverified; retained diagnostic workspace: ${workspace}`,
    { cause: primaryFailure },
  );
if (primaryFailure !== undefined)
  throw new Error(`ARM verification failed; retained workspace: ${workspace}`, {
    cause: primaryFailure,
  });
await rm(workspace, { recursive: true, force: true });
console.log(JSON.stringify({ ...completed, fixtures: reports }, null, 2));
