import { EventEmitter } from "node:events";
import {
  access,
  chmod,
  mkdir,
  mkdtemp,
  rm,
  symlink,
  truncate,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it, onTestFinished, vi } from "vitest";
import { z } from "zod";
import { HarCaptureAdapter } from "../../../src/browser/history/HarCaptureAdapter.js";
import { HistoricalCaptureDecoder } from "../../../src/browser/history/HistoricalCaptureDecoder.js";
import type { HistoricalCaptureFormatAdapter } from "../../../src/browser/history/HistoricalCaptureFormatAdapter.js";
import { MitmproxyCaptureAdapter } from "../../../src/browser/history/MitmproxyCaptureAdapter.js";
import {
  HAR_CAPTURE_PROVIDER_IDENTITY,
  MITMPROXY_CAPTURE_PROVIDER_IDENTITY,
} from "../../../src/browser/history/CaptureRelease.js";
import {
  inspectWebNetworkCaptureInputSchema,
  WEB_NETWORK_CAPTURE_LIMITS,
} from "../../../src/domain/webNetworkCapture.js";
import { OwnedCommandFailure } from "../../../src/process/OwnedCommand.js";
import { PrivateRuntimeRoot } from "../../../src/process/PrivateRuntimeRoot.js";
import { ProviderProcessSupervisor } from "../../../src/process/ProviderProcess.js";
import type { ProviderProcessSnapshot } from "../../../src/process/ProviderProcess.js";
import { historicalHar } from "../../fixtures/historicalHar.js";
import { decodeHarCapture } from "../../../src/browser/history/HarCapture.js";
import { projectAnalysisError } from "../../../src/domain/analysisErrorProjection.js";

const linux = it.skipIf(process.platform !== "linux");

const emptySnapshot: ProviderProcessSnapshot = {
  stdout: { text: "", bytes: 0, observedBytes: 0 },
  stderr: { text: "", bytes: 0, observedBytes: 0 },
  exitCode: 0,
  signal: null,
};

const retainedProcessSupervisor = (): ProviderProcessSupervisor => {
  const processHandle = Object.assign(new EventEmitter(), {
    pid: 42_424,
    stdout: null,
    stderr: null,
    exitCode: null,
    signalCode: null,
    kill: () => false,
  });
  return new ProviderProcessSupervisor({
    process: processHandle,
    ownsProcessLifetime: true,
  });
};

linux("refuses a directory configured as the mitmdump executable", async () => {
  const root = await mkdtemp(join(tmpdir(), "rea-mitmdump-command-"));
  onTestFinished(() => rm(root, { recursive: true, force: true }));
  const command = join(root, "mitmdump");
  await mkdir(command);

  await expect(
    new MitmproxyCaptureAdapter({ REA_MITMDUMP_COMMAND: command }).command(
      join(root, "request.json"),
      join(root, "runtime"),
    ),
  ).rejects.toMatchObject({
    _tag: "AnalysisCapabilityUnavailableError",
    reason: expect.stringContaining(command),
  });
});

linux("allows a symlink to a regular mitmdump executable", async () => {
  const root = await mkdtemp(join(tmpdir(), "rea-mitmdump-command-symlink-"));
  onTestFinished(() => rm(root, { recursive: true, force: true }));
  const command = join(root, "mitmdump");
  const target = join(root, "mitmdump-bin");
  await writeFile(target, "#!/bin/sh\n", { mode: 0o700 });
  await symlink(target, command);

  await expect(
    new MitmproxyCaptureAdapter({ REA_MITMDUMP_COMMAND: command }).command(
      join(root, "request.json"),
      join(root, "runtime"),
    ),
  ).resolves.toMatchObject({ command });
});

it.each([true, false])(
  "binds decoder replies to the complete selected provider identity (matching name: %s)",
  async (matching) => {
    const root = await mkdtemp(join(tmpdir(), "rea-capture-identity-"));
    onTestFinished(() => rm(root, { recursive: true, force: true }));
    const path = join(root, "capture.har");
    const text = JSON.stringify(historicalHar());
    await writeFile(path, text);
    const decoder = new HistoricalCaptureDecoder(
      [
        {
          format: "har",
          identity: HAR_CAPTURE_PROVIDER_IDENTITY,
          supervision: "internal-helper",
          command: async (_, runtimePath) => {
            const value = decodeHarCapture(text, []);
            if (!matching) value.decoder.name = "different adapter";
            await writeFile(
              join(runtimePath, "reply.json"),
              JSON.stringify({ ok: true, value }),
            );
            return { command: process.execPath, arguments: ["-e", ""] };
          },
        },
      ],
      process.env,
    );
    const result = await decoder.inspect(
      inspectWebNetworkCaptureInputSchema.parse({
        capture_path: path,
        format: "har",
      }),
    );
    expect(result.ok).toBe(matching);
    if (!result.ok) expect(result.error._tag).toBe("AnalysisOutputError");
    else expect(result.value.decoder).toEqual(HAR_CAPTURE_PROVIDER_IDENTITY);
  },
);

it("classifies an oversized selected capture before creating an owned decoder", async () => {
  const root = await mkdtemp(join(tmpdir(), "rea-historical-limit-"));
  onTestFinished(() => rm(root, { recursive: true, force: true }));
  const path = join(root, "input.har");
  await writeFile(path, "");
  await truncate(path, WEB_NETWORK_CAPTURE_LIMITS.inputBytes + 1);
  const decoder = new HistoricalCaptureDecoder(
    [
      {
        format: "har",
        identity: HAR_CAPTURE_PROVIDER_IDENTITY,
        supervision: "internal-helper",
        command: async () => {
          throw new Error("Oversized input must not launch decoding");
        },
      },
    ],
    process.env,
  );
  const result = await decoder.inspect(
    inspectWebNetworkCaptureInputSchema.parse({
      capture_path: path,
      format: "har",
    }),
  );
  if (result.ok) throw new Error("Oversized input must fail");
  expect(result.error._tag).toBe("AnalysisInputError");
  expect(projectAnalysisError(result.error)).toMatchObject({
    category: "invalid_input",
    details: {
      issues: [
        {
          path: ["capture_path"],
          reason: "out_of_range",
          expected: {
            maximum_capture_bytes: WEB_NETWORK_CAPTURE_LIMITS.inputBytes,
          },
        },
      ],
    },
  });
});

it("does not misclassify decoder filesystem failures as missing selected input", async () => {
  const root = await mkdtemp(join(tmpdir(), "rea-historical-command-"));
  onTestFinished(() => rm(root, { recursive: true, force: true }));
  const path = join(root, "input.har");
  await writeFile(path, JSON.stringify(historicalHar()));
  const decoder = new HistoricalCaptureDecoder(
    [
      {
        format: "har",
        identity: HAR_CAPTURE_PROVIDER_IDENTITY,
        supervision: "internal-helper",
        command: async () => {
          throw Object.assign(
            new Error("Configured decoder command file missing"),
            { code: "ENOENT" },
          );
        },
      },
    ],
    process.env,
  );
  const result = await decoder.inspect(
    inspectWebNetworkCaptureInputSchema.parse({
      capture_path: path,
      format: "har",
    }),
  );
  if (result.ok) throw new Error("Failed decoder command must fail");
  expect(result.error._tag).toBe("ProviderAdapterError");
  expect(projectAnalysisError(result.error)).toMatchObject({
    details: {
      diagnostics: {
        phase: "decoder",
        reason: "Configured decoder command file missing",
      },
    },
  });
});

it.each(["missing-capture", "missing-reply", "failed-command"])(
  "redacts declared paths and diagnostics while preserving the %s failure",
  async (mode) => {
    const root = await mkdtemp(join(tmpdir(), "rea-historical-sensitive-"));
    onTestFinished(() => rm(root, { recursive: true, force: true }));
    const path = join(root, "explicit-private-value.har");
    if (mode !== "missing-capture")
      await writeFile(path, JSON.stringify(historicalHar()));
    const decoder = new HistoricalCaptureDecoder(
      [
        {
          format: "har",
          identity: HAR_CAPTURE_PROVIDER_IDENTITY,
          supervision: "internal-helper",
          command: async () => ({
            command: process.execPath,
            arguments: [
              "-e",
              mode === "failed-command"
                ? 'process.stderr.write("explicit-private-value ordinary diagnostic"); process.exit(2)'
                : "process.exit(0)",
            ],
          }),
        },
      ],
      process.env,
    );
    const result = await decoder.inspect(
      inspectWebNetworkCaptureInputSchema.parse({
        capture_path: path,
        format: "har",
        sensitive_values: ["explicit-private-value", "REDACTED"],
      }),
    );
    if (result.ok) throw new Error("Failure required");
    const projected = projectAnalysisError(result.error);
    const serialized = JSON.stringify(projected);
    expect(serialized).not.toContain("explicit-private-value");
    expect(serialized).not.toContain("REDACTED");
    expect(result.error._tag).toBe(
      mode === "missing-capture"
        ? "AnalysisInputError"
        : mode === "missing-reply"
          ? "AnalysisOutputError"
          : "ProviderAdapterError",
    );
    if (mode === "missing-capture") expect(serialized).toContain("ENOENT");
    if (mode === "failed-command")
      expect(serialized).toContain('"exit_code":2');
  },
);

it("reports an absent owned reply as output failure and removes its private snapshot root", async () => {
  const root = await mkdtemp(join(tmpdir(), "rea-historical-decoder-"));
  onTestFinished(() => rm(root, { recursive: true, force: true }));
  const path = join(root, "input.har");
  await writeFile(path, JSON.stringify(historicalHar()));
  let privatePath: string | undefined;
  const decoder = new HistoricalCaptureDecoder(
    [
      {
        format: "har",
        identity: HAR_CAPTURE_PROVIDER_IDENTITY,
        supervision: "internal-helper",
        command: async (_, runtimePath) => {
          privatePath = runtimePath;
          return {
            command: process.execPath,
            arguments: ["-e", "process.exit(0)"],
          };
        },
      },
    ],
    process.env,
  );
  const result = await decoder.inspect(
    inspectWebNetworkCaptureInputSchema.parse({
      capture_path: path,
      format: "har",
    }),
  );
  if (result.ok) throw new Error("Owned reply is required");
  expect(result.error._tag).toBe("AnalysisOutputError");
  expect(result.error.message).toContain("ENOENT");
  if (privatePath === undefined)
    throw new Error("Private root was not acquired");
  await expect(access(privatePath)).rejects.toMatchObject({ code: "ENOENT" });
});

it("cancels after snapshot acquisition before launch and removes private input declarations", async () => {
  const root = await mkdtemp(join(tmpdir(), "rea-historical-cancel-"));
  onTestFinished(() => rm(root, { recursive: true, force: true }));
  const path = join(root, "input.har");
  await writeFile(path, JSON.stringify(historicalHar()));
  let privatePath: string | undefined;
  const controller = new AbortController();
  const decoder = new HistoricalCaptureDecoder(
    [
      {
        format: "har",
        identity: HAR_CAPTURE_PROVIDER_IDENTITY,
        supervision: "internal-helper",
        command: async (_, runtimePath) => {
          privatePath = runtimePath;
          controller.abort();
          return {
            command: process.execPath,
            arguments: ["-e", "process.exit(3)"],
          };
        },
      },
    ],
    process.env,
  );
  const result = await decoder.inspect(
    inspectWebNetworkCaptureInputSchema.parse({
      capture_path: path,
      format: "har",
      sensitive_values: ["explicit-private-declaration"],
    }),
    { signal: controller.signal },
  );
  if (result.ok) throw new Error("Cancelled acquisition must fail");
  expect(result.error._tag).toBe("AnalysisCancelledError");
  if (privatePath === undefined)
    throw new Error("Private root was not acquired");
  await expect(access(privatePath)).rejects.toMatchObject({ code: "ENOENT" });
});

it.each([
  { reason: "input-limit", tag: "AnalysisInputError" },
  { reason: "resource-limit", tag: "AnalysisResourceConstraintError" },
  { reason: "decoder", tag: "ProviderAdapterError" },
  { reason: "limit", tag: "AnalysisOutputError" },
])(
  "preserves $reason decoder failures through the public error boundary",
  async ({ reason, tag }) => {
    const root = await mkdtemp(join(tmpdir(), "rea-historical-reply-"));
    onTestFinished(() => rm(root, { recursive: true, force: true }));
    const path = join(root, "input.har");
    await writeFile(path, JSON.stringify(historicalHar()));
    let privatePath: string | undefined;
    const decoder = new HistoricalCaptureDecoder(
      [
        {
          format: "har",
          identity: HAR_CAPTURE_PROVIDER_IDENTITY,
          supervision: "internal-helper",
          command: async (_, runtimePath) => {
            privatePath = runtimePath;
            await writeFile(
              join(runtimePath, "reply.json"),
              JSON.stringify({
                ok: false,
                reason,
                message: "Specific decoder constraint",
                pointer: "/extension/child",
              }),
            );
            return {
              command: process.execPath,
              arguments: ["-e", "process.exit(0)"],
            };
          },
        },
      ],
      process.env,
    );
    const result = await decoder.inspect(
      inspectWebNetworkCaptureInputSchema.parse({
        capture_path: path,
        format: "har",
      }),
    );
    if (result.ok) throw new Error("Failure required");
    expect(result.error._tag).toBe(tag);
    const projected = projectAnalysisError(result.error);
    if (reason === "input-limit") {
      expect(projected).toMatchObject({
        category: "invalid_input",
        details: {
          issues: [
            {
              path: ["capture_path", "/extension/child"],
              reason: "out_of_range",
              expected: {
                maximum_capture_nesting: WEB_NETWORK_CAPTURE_LIMITS.depth,
              },
            },
          ],
        },
      });
    } else if (tag === "ProviderAdapterError") {
      expect(projected).toMatchObject({
        details: {
          diagnostics: {
            phase: "decoder",
            reason: "Specific decoder constraint",
            failure_kind: reason,
            pointer: "/extension/child",
          },
        },
      });
    }
    if (privatePath === undefined)
      throw new Error("Private root was not acquired");
    await expect(access(privatePath)).rejects.toMatchObject({ code: "ENOENT" });
  },
);

it.skipIf(process.platform === "win32" || process.getuid?.() === 0)(
  "reports a real filesystem permission denial separately from missing capture input",
  async () => {
    const root = await mkdtemp(join(tmpdir(), "rea-historical-denied-"));
    onTestFinished(() => rm(root, { recursive: true, force: true }));
    const path = join(root, "unreadable.har");
    await writeFile(path, JSON.stringify(historicalHar()), { mode: 0o000 });
    const decoder = new HistoricalCaptureDecoder(
      [
        {
          format: "har",
          identity: HAR_CAPTURE_PROVIDER_IDENTITY,
          supervision: "internal-helper",
          command: async () => {
            throw new Error("Permission-denied input must not launch decoding");
          },
        },
      ],
      process.env,
    );
    const result = await decoder.inspect(
      inspectWebNetworkCaptureInputSchema.parse({
        capture_path: path,
        format: "har",
      }),
    );
    await chmod(path, 0o600);
    if (result.ok) throw new Error("Permission denial required");
    expect(projectAnalysisError(result.error)).toMatchObject({
      code: "access_denied",
      category: "unavailable",
      retryable: false,
      details: {
        operation: "inspect_web_network_capture",
        path,
        system_code: "EACCES",
      },
    });
    expect(projectAnalysisError(result.error).remediation.action).toContain(
      "read access",
    );
  },
);

it.each(["format", "process"])(
  "preserves the structured %s failure when runtime cleanup fails",
  async (kind) => {
    const root = await mkdtemp(join(tmpdir(), "rea-historical-cleanup-"));
    onTestFinished(() => rm(root, { recursive: true, force: true }));
    const path = join(root, "capture-private.har");
    await writeFile(path, JSON.stringify(historicalHar()));
    const decoder = new HistoricalCaptureDecoder(
      [
        {
          format: "har",
          identity: HAR_CAPTURE_PROVIDER_IDENTITY,
          supervision: "internal-helper",
          command: async (_, runtimePath) => {
            if (kind === "format")
              await writeFile(
                join(runtimePath, "reply.json"),
                JSON.stringify({
                  ok: false,
                  reason: "format",
                  message: "Malformed retained record",
                  pointer: "/metadata/capture-private",
                }),
              );
            return {
              command: process.execPath,
              arguments: [
                "-e",
                kind === "format"
                  ? "process.exit(0)"
                  : 'process.stderr.write("Specific provider fault"); process.exit(3)',
              ],
            };
          },
        },
      ],
      process.env,
      async () => {
        const runtime = await PrivateRuntimeRoot.create({
          prefix: "rea-cleanup-proof-",
        });
        onTestFinished(() => runtime.close());
        return {
          path: runtime.path,
          close: async () => {
            throw new Error("Deliberate cleanup denial");
          },
        };
      },
    );
    const result = await decoder.inspect(
      inspectWebNetworkCaptureInputSchema.parse({
        capture_path: path,
        format: "har",
        sensitive_values: ["capture-private"],
      }),
    );
    if (result.ok) throw new Error("Cleanup failure required");
    const projected = projectAnalysisError(result.error);
    expect(projected).toMatchObject({
      code: "cleanup_incomplete",
      details: {
        diagnostics: {
          previous_error:
            kind === "format"
              ? {
                  category: "invalid_input",
                  details: {
                    issues: [
                      {
                        path: ["capture_path", "/metadata"],
                        reason: "invalid_format",
                        message: "Malformed retained record",
                      },
                    ],
                  },
                }
              : {
                  code: "execution_failure",
                  details: {
                    diagnostics: {
                      phase: "decoder",
                      exit_code: 3,
                      stderr: "Specific provider fault",
                    },
                  },
                },
        },
      },
    });
    expect(JSON.stringify(projected)).not.toContain("capture-private");
  },
);

it("retains the original provider failure when retrying cleanup across formats", async () => {
  const root = await mkdtemp(join(tmpdir(), "rea-historical-process-owner-"));
  const capturePath = join(root, "capture.har");
  const text = JSON.stringify(historicalHar());
  await writeFile(capturePath, text);
  const privateRoots: Array<Pick<PrivateRuntimeRoot, "path" | "close">> = [];
  onTestFinished(async () => {
    await Promise.allSettled(privateRoots.map((runtime) => runtime.close()));
    await rm(root, { recursive: true, force: true });
  });
  const supervisor = retainedProcessSupervisor();
  const stop = vi.spyOn(supervisor, "stop");
  stop
    .mockResolvedValueOnce({
      status: "incomplete",
      reason: "child is still live",
    })
    .mockResolvedValue({ status: "already-exited" });
  let runCount = 0;
  const decoder = new HistoricalCaptureDecoder(
    [
      {
        format: "mitmproxy",
        identity: MITMPROXY_CAPTURE_PROVIDER_IDENTITY,
        supervision: "process-group",
        command: async () => {
          return { command: process.execPath, arguments: ["-e", ""] };
        },
      },
      {
        format: "har",
        identity: HAR_CAPTURE_PROVIDER_IDENTITY,
        supervision: new HarCaptureAdapter().supervision,
        command: async () => ({
          command: process.execPath,
          arguments: ["-e", ""],
        }),
      },
    ],
    process.env,
    async () => {
      const runtime = await PrivateRuntimeRoot.create({
        prefix: "rea-historical-process-owner-",
      });
      privateRoots.push(runtime);
      return runtime;
    },
    async () => {
      runCount += 1;
      if (runCount === 1)
        throw new OwnedCommandFailure(
          "timeout",
          "Command deadline elapsed.",
          {
            ...emptySnapshot,
            exitCode: null,
            stdout: { text: "partial output", bytes: 14, observedBytes: 14 },
            stderr: { text: "last diagnostic", bytes: 15, observedBytes: 15 },
          },
          "child is still live",
          undefined,
          ["run:historical-capture", "pid:42424"],
          supervisor,
        );
      return emptySnapshot;
    },
  );
  const input = inspectWebNetworkCaptureInputSchema.parse({
    capture_path: capturePath,
    format: "mitmproxy",
    sensitive_values: ["last diagnostic"],
  });

  const first = await decoder.inspect(input);
  if (first.ok) throw new Error("Incomplete process cleanup must fail");
  expect(first.error.cleanupIncomplete).toBe(true);
  expect(projectAnalysisError(first.error)).toMatchObject({
    code: "cleanup_incomplete",
    details: {
      cleanup: "incomplete",
      resources: expect.arrayContaining(["pid:42424"]),
      diagnostics: {
        previous_error: {
          failure_kind: "timeout",
          stdout: "partial output",
          stderr: "[REDACTED]",
          exit_code: null,
        },
      },
    },
  });
  expect(stop).not.toHaveBeenCalled();
  const retainedPath = privateRoots[0]?.path;
  if (retainedPath === undefined) throw new Error("Runtime was not acquired");
  await expect(access(retainedPath)).resolves.toBeUndefined();

  const second = await decoder.inspect({
    ...input,
    format: "har",
    sensitive_values: [],
  });
  if (second.ok) throw new Error("A failed cleanup retry must block decoding");
  expect(second.error.cleanupIncomplete).toBe(true);
  expect(second.error).toMatchObject({ providerId: "mitmproxy" });
  expect(projectAnalysisError(second.error)).toMatchObject({
    code: "cleanup_incomplete",
    details: {
      resources: expect.arrayContaining([retainedPath, "pid:42424"]),
      diagnostics: {
        previous_error: {
          failure_kind: "timeout",
          stdout: "partial output",
          stderr: "[REDACTED]",
          exit_code: null,
        },
      },
    },
  });
  expect(second.error.cleanupResources).toEqual([
    retainedPath,
    "run:historical-capture",
    "pid:42424",
  ]);
  expect(runCount).toBe(1);
  expect(stop).toHaveBeenCalledTimes(1);

  await decoder.close();
  await expect(access(retainedPath)).rejects.toMatchObject({ code: "ENOENT" });
  const closed = await decoder.inspect(input);
  expect(closed.ok).toBe(false);
  expect(runCount).toBe(1);
});

it("preserves each retained owner failure when concurrent cleanup retries fail", async () => {
  const root = await mkdtemp(
    join(tmpdir(), "rea-historical-concurrent-owner-"),
  );
  const capturePath = join(root, "capture.har");
  await writeFile(capturePath, JSON.stringify(historicalHar()));
  const runtimePaths = new Map<string, string>();
  const privateRoots: Array<Pick<PrivateRuntimeRoot, "path" | "close">> = [];
  onTestFinished(async () => {
    await Promise.allSettled(privateRoots.map((runtime) => runtime.close()));
    await rm(root, { recursive: true, force: true });
  });

  const formats = ["mitmproxy", "har"] as const;
  const supervisors = new Map(
    formats.map((format) => [format, retainedProcessSupervisor()]),
  );
  const stops = formats.map((format) => {
    const supervisor = supervisors.get(format);
    if (supervisor === undefined)
      throw new Error(`Missing ${format} supervisor`);
    return vi
      .spyOn(supervisor, "stop")
      .mockResolvedValueOnce({
        status: "incomplete",
        reason: `${format} child is still live`,
      })
      .mockResolvedValue({ status: "already-exited" });
  });
  const adapters: HistoricalCaptureFormatAdapter[] = formats.map((format) => ({
    format,
    identity:
      format === "har"
        ? HAR_CAPTURE_PROVIDER_IDENTITY
        : MITMPROXY_CAPTURE_PROVIDER_IDENTITY,
    supervision: format === "har" ? "internal-helper" : "process-group",
    command: async (_requestPath, runtimePath) => {
      runtimePaths.set(format, runtimePath);
      return { command: process.execPath, arguments: [format] };
    },
  }));
  let runCount = 0;
  const decoder = new HistoricalCaptureDecoder(
    adapters,
    process.env,
    async () => {
      const runtime = await PrivateRuntimeRoot.create({
        prefix: "rea-historical-concurrent-owner-",
      });
      privateRoots.push(runtime);
      return runtime;
    },
    async ({ arguments: args }) => {
      runCount += 1;
      const format = args[0];
      if (format !== "mitmproxy" && format !== "har")
        throw new Error(`Unexpected capture format: ${String(format)}`);
      const stdout = `${format} partial output`;
      const stderr = `${format} diagnostic`;
      const output = (text: string) => ({
        text,
        bytes: text.length,
        observedBytes: text.length,
      });
      throw new OwnedCommandFailure(
        "timeout",
        `${format} command deadline elapsed.`,
        {
          ...emptySnapshot,
          exitCode: null,
          stdout: output(stdout),
          stderr: output(stderr),
        },
        `${format} child is still live`,
        undefined,
        [`run:${format}`, `pid:${format === "har" ? 42425 : 42424}`],
        supervisors.get(format),
      );
    },
  );
  const input = (
    format: "mitmproxy" | "har",
    sensitive_values: readonly string[] = [],
  ) =>
    inspectWebNetworkCaptureInputSchema.parse({
      capture_path: capturePath,
      format,
      sensitive_values,
    });

  await Promise.all(
    formats.map((format) =>
      decoder.inspect(
        input(format, format === "mitmproxy" ? ["mitmproxy diagnostic"] : []),
      ),
    ),
  );
  for (const stop of stops) expect(stop).not.toHaveBeenCalled();

  const retry = await decoder.inspect(input("har"));
  if (retry.ok) throw new Error("Failed retained cleanup must block decoding");
  expect(retry.error).toMatchObject({
    providerId: "web-network-capture",
    cleanupIncomplete: true,
  });
  expect(runCount).toBe(2);
  const projection = projectAnalysisError(retry.error);
  expect(projection.code).toBe("cleanup_incomplete");
  const { cleanup_failures: cleanupFailures } = z
    .object({
      cleanup_failures: z.array(
        z.looseObject({
          provider_id: z.string(),
          operation: z.string(),
          resources: z.array(z.string()),
        }),
      ),
    })
    .parse(projection.details?.diagnostics);
  expect(cleanupFailures).toHaveLength(2);
  for (const { format, pid } of [
    { format: "mitmproxy", pid: "42424" },
    { format: "har", pid: "42425" },
  ]) {
    const failure = cleanupFailures.find(
      ({ provider_id }) => provider_id === format,
    );
    expect(failure?.operation).toBe("inspect_web_network_capture");
    expect(failure?.resources).toEqual([
      runtimePaths.get(format),
      `run:${format}`,
      `pid:${pid}`,
    ]);
    expect(failure).toMatchObject({
      reason: `${format} child is still live`,
      previous_error: {
        code: "cleanup_incomplete",
        details: {
          diagnostics: {
            previous_error: {
              failure_kind: "timeout",
              stdout: `${format} partial output`,
              stderr:
                format === "mitmproxy" ? "[REDACTED]" : `${format} diagnostic`,
            },
          },
        },
      },
    });
  }
  await decoder.close();
  for (const stop of stops) expect(stop).toHaveBeenCalledTimes(2);
});

it("retries private-root cleanup before admitting the next capture", async () => {
  const root = await mkdtemp(join(tmpdir(), "rea-historical-root-owner-"));
  const capturePath = join(root, "capture.har");
  const text = JSON.stringify(historicalHar());
  await writeFile(capturePath, text);
  const paths: string[] = [];
  const privateRoots: Array<Pick<PrivateRuntimeRoot, "path" | "close">> = [];
  onTestFinished(async () => {
    await Promise.allSettled(privateRoots.map((runtime) => runtime.close()));
    await rm(root, { recursive: true, force: true });
  });
  let failFirstClose = true;
  let runtimeCount = 0;
  const decoder = new HistoricalCaptureDecoder(
    [
      {
        format: "har",
        identity: HAR_CAPTURE_PROVIDER_IDENTITY,
        supervision: new HarCaptureAdapter().supervision,
        command: async (_, runtimePath) => {
          const value = decodeHarCapture(text, []);
          await writeFile(
            join(runtimePath, "reply.json"),
            JSON.stringify({ ok: true, value }),
          );
          return { command: process.execPath, arguments: ["-e", ""] };
        },
      },
    ],
    process.env,
    async () => {
      const runtime = await PrivateRuntimeRoot.create({
        prefix: "rea-historical-root-owner-",
      });
      privateRoots.push(runtime);
      paths.push(runtime.path);
      runtimeCount += 1;
      return {
        path: runtime.path,
        close: async () => {
          if (runtimeCount === 1 && failFirstClose) {
            failFirstClose = false;
            throw new Error("root cleanup remains incomplete");
          }
          await runtime.close();
        },
      };
    },
  );
  const input = inspectWebNetworkCaptureInputSchema.parse({
    capture_path: capturePath,
    format: "har",
  });

  const first = await decoder.inspect(input);
  if (first.ok) throw new Error("Root cleanup failure must be reported");
  expect(first.error.cleanupIncomplete).toBe(true);
  expect(projectAnalysisError(first.error)).toMatchObject({
    code: "cleanup_incomplete",
    details: { diagnostics: { reason: "root cleanup remains incomplete" } },
  });
  const retainedPath = paths[0];
  if (retainedPath === undefined) throw new Error("Runtime was not acquired");
  await expect(access(retainedPath)).resolves.toBeUndefined();

  const second = await decoder.inspect(input);
  expect(second.ok).toBe(true);
  expect(runtimeCount).toBe(2);
  await expect(access(retainedPath)).rejects.toMatchObject({ code: "ENOENT" });
  const secondPath = paths[1];
  if (secondPath === undefined)
    throw new Error("Second runtime was not acquired");
  await expect(access(secondPath)).rejects.toMatchObject({ code: "ENOENT" });
  await decoder.close();
});
