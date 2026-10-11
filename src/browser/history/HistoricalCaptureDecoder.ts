import {
  CAPTURE_PROCESS_MEMORY_LIMIT_REASON,
  historicalCaptureFailure,
  captureMemoryFailure,
} from "./CaptureFailures.js";
import {
  HAR_CAPTURE_HEAP_ENFORCED,
  HAR_CAPTURE_HEAP_LIMITS,
  HAR_CAPTURE_PROCESS_MEMORY_LIMIT_BYTES,
} from "./CaptureRelease.js";
import { projectAnalysisError } from "../../domain/analysisErrorProjection.js";
import type { HistoricalCaptureFormatAdapter } from "./HistoricalCaptureFormatAdapter.js";
import { randomUUID } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { ExecutionOptions } from "../../application/AnalysisProvider.js";
import { readStableArtifact } from "../../artifacts/readStableArtifact.js";
import {
  ArtifactResourceCleanupFailure,
  ArtifactResourceScope,
  type ArtifactResourceOwner,
} from "../../artifacts/ArtifactResourceScope.js";
import { ArtifactReaderFailure } from "../../artifacts/ArtifactReader.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCapabilityUnavailableError,
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { ProviderAdapterError } from "../../domain/providerAdapterError.js";
import { ProviderCleanupError } from "../../domain/providerCleanupError.js";
import { err, ok, type Result } from "../../domain/result.js";
import {
  WEB_NETWORK_CAPTURE_LIMITS,
  webNetworkCaptureSchema,
  type InspectWebNetworkCaptureInput,
  type WebNetworkCapture,
} from "../../domain/webNetworkCapture.js";
import {
  OwnedCommandFailure,
  runOwnedCommand,
} from "../../process/OwnedCommand.js";
import { PrivateRuntimeRoot } from "../../process/PrivateRuntimeRoot.js";
import { ProviderProcessSupervisor } from "../../process/ProviderProcess.js";
import { redactExplicitFailure } from "../../domain/explicitSensitiveFailure.js";

const OPERATION = "inspect_web_network_capture";
const decodedSchema = webNetworkCaptureSchema.omit({
  artifact: true,
  format: true,
  runtime_attribution: true,
  limitations: true,
});
const replySchema = z.discriminatedUnion("ok", [
  z.strictObject({ ok: z.literal(true), value: decodedSchema }),
  z.strictObject({
    ok: z.literal(false),
    reason: z.enum([
      "format",
      "unsupported",
      "input-limit",
      "resource-limit",
      "decoder",
      "limit",
    ]),
    message: z.string(),
    pointer: z.string(),
  }),
]);

/** One owned snapshot/process/root lifecycle for replaceable historical format decoders. */
export class HistoricalCaptureDecoder {
  readonly #resources = new ArtifactResourceScope();

  constructor(
    readonly adapters: readonly HistoricalCaptureFormatAdapter[],
    readonly environment: Readonly<NodeJS.ProcessEnv>,
    readonly createRuntime: () => Promise<
      Pick<PrivateRuntimeRoot, "path" | "close">
    > = () => PrivateRuntimeRoot.create({ prefix: "rea-web-capture-" }),
    readonly runCommand: typeof runOwnedCommand = runOwnedCommand,
  ) {}

  /** Snapshot the selected artifact, decode it offline, and release private credentials and processes. */
  async inspect(
    input: InspectWebNetworkCaptureInput,
    options?: ExecutionOptions,
  ): Promise<Result<WebNetworkCapture, AnalysisError>> {
    try {
      return await this.#resources.run(() => this.#inspect(input, options));
    } catch (cause: unknown) {
      const retained =
        cause instanceof ArtifactResourceCleanupFailure &&
        cause.failures.length === 1
          ? cause.failures[0]
          : undefined;
      if (
        retained?.owner instanceof HistoricalCaptureRuntimeOwner &&
        retained.owner.previousFailure instanceof ProviderCleanupError
      ) {
        const previous = retained.owner.previousFailure;
        const { owner, cause: ownerCause } = retained;
        const cleanup = ArtifactReaderFailure.cleanupObservation(
          ownerCause,
          owner.resource,
        );
        return err(
          redactExplicitFailure(
            new ProviderCleanupError(
              previous.providerId,
              cleanup.resources,
              {
                ...previous.diagnostics,
                reason: cleanup.reason,
              },
              {
                operation: previous.operation,
                cause,
              },
            ),
            input.sensitive_values,
          ),
        );
      }
      if (
        cause instanceof ArtifactResourceCleanupFailure &&
        cause.failures.length > 1
      ) {
        const cleanupFailures = cause.failures.map(
          ({ owner, cause: ownerCause }) => {
            const cleanup = ArtifactReaderFailure.cleanupObservation(
              ownerCause,
              owner.resource,
            );
            const previous =
              owner instanceof HistoricalCaptureRuntimeOwner
                ? owner.previousFailure
                : undefined;
            return {
              owner: owner.kind,
              resources: [...cleanup.resources],
              reason: cleanup.reason,
              ...(previous === undefined
                ? {}
                : {
                    provider_id: previous.providerId,
                    operation: previous.operation,
                    previous_error: projectAnalysisError(previous),
                  }),
            };
          },
        );
        const error = new ProviderCleanupError(
          "web-network-capture",
          cause.cleanup?.resources ?? [
            ...new Set(cleanupFailures.flatMap(({ resources }) => resources)),
          ],
          {
            ...(cause.cleanup === undefined
              ? {}
              : { reason: cause.cleanup.reason }),
            cleanup_failures: cleanupFailures,
          },
          { operation: OPERATION, cause },
        );
        return err(redactExplicitFailure(error, input.sensitive_values));
      }
      const error =
        cause instanceof ArtifactReaderFailure && cause.cleanup !== undefined
          ? new ProviderCleanupError(
              input.format,
              cause.cleanup.resources,
              { reason: cause.cleanup.reason },
              { operation: OPERATION, cause },
            )
          : historicalCaptureFailure(input, cause, "decoder", options);
      return err(redactExplicitFailure(error, input.sensitive_values));
    }
  }

  /** Stop admission, wait for active inspections, and retry retained cleanup. */
  close(): Promise<void> {
    return this.#resources.close();
  }

  async #inspect(
    input: InspectWebNetworkCaptureInput,
    options?: ExecutionOptions,
  ): Promise<Result<WebNetworkCapture, AnalysisError>> {
    let runtimeOwner: HistoricalCaptureRuntimeOwner | undefined;
    let result: Result<WebNetworkCapture, AnalysisError>;
    let phase: "capture-read" | "decoder" = "capture-read";
    let failureResources: readonly string[] = [];
    try {
      const adapter = this.adapters.find(
        (candidate) => candidate.format === input.format,
      );
      if (adapter === undefined)
        throw new AnalysisCapabilityUnavailableError(
          input.format,
          OPERATION,
          "No adapter is configured for the selected capture format.",
        );
      const snapshot = await readStableArtifact(
        input.capture_path,
        WEB_NETWORK_CAPTURE_LIMITS.inputBytes,
        options?.signal,
      );
      phase = "decoder";
      const runtime = await this.createRuntime();
      runtimeOwner = new HistoricalCaptureRuntimeOwner(runtime);
      const snapshotPath = join(runtime.path, "capture.snapshot");
      const requestPath = join(runtime.path, "request.json");
      const replyPath = join(runtime.path, "reply.json");
      await writeFile(snapshotPath, snapshot.bytes, {
        mode: 0o600,
        flag: "wx",
        ...(options?.signal === undefined ? {} : { signal: options.signal }),
      });
      await writeFile(
        requestPath,
        JSON.stringify({
          snapshot_path: snapshotPath,
          reply_path: replyPath,
          sensitive_values: input.sensitive_values,
        }),
        { mode: 0o600, flag: "wx" },
      );
      const command = await adapter.command(requestPath, runtime.path);
      const environment: NodeJS.ProcessEnv = {
        ...this.environment,
        UV_THREADPOOL_SIZE: "1",
      };
      delete environment.NODE_OPTIONS;
      const completed = await this.runCommand(
        {
          ...command,
          runId: `rea-web-capture-${randomUUID()}`,
          cwd: runtime.path,
          hostEnvironment: environment,
        },
        {
          timeoutMs: WEB_NETWORK_CAPTURE_LIMITS.timeoutMs,
          diagnosticBytes: 1024 * 1024,
        },
        {
          ...(adapter.supervision === "internal-helper"
            ? { supervision: adapter.supervision }
            : {}),
          ...(options?.signal === undefined ? {} : { signal: options.signal }),
        },
      );
      // A decoder that survived a failed allocation may still reply; its
      // reply is not trusted as complete once the limit was reached.
      if (completed.memoryLimitReached === true)
        throw captureMemoryFailure(input, CAPTURE_PROCESS_MEMORY_LIMIT_REASON);
      let reply: z.output<typeof replySchema>;
      try {
        const replyFile = await readStableArtifact(
          replyPath,
          WEB_NETWORK_CAPTURE_LIMITS.outputBytes,
          options?.signal,
        );
        reply = replySchema.parse(JSON.parse(replyFile.bytes.toString("utf8")));
      } catch (cause: unknown) {
        if (options?.signal?.aborted)
          throw new AnalysisCancelledError(OPERATION);
        throw new AnalysisOutputError(
          OPERATION,
          `Owned capture decoder reply failed for ${input.capture_path}: ${replyFailureReason(cause)}`,
          { cause },
        );
      }
      if (!reply.ok) {
        if (reply.reason === "format")
          throw new AnalysisInputError(OPERATION, undefined, [
            {
              path: ["capture_path", reply.pointer],
              reason: "invalid_format",
              message: reply.message,
            },
          ]);
        if (reply.reason === "input-limit")
          throw new AnalysisInputError(OPERATION, undefined, [
            {
              path: ["capture_path", reply.pointer],
              reason: "out_of_range",
              message: reply.message,
              expected: {
                maximum_capture_nesting: WEB_NETWORK_CAPTURE_LIMITS.depth,
              },
            },
          ]);
        if (reply.reason === "resource-limit")
          throw captureMemoryFailure(input, reply.message);
        if (reply.reason === "decoder")
          throw new ProviderAdapterError(input.format, OPERATION, {
            diagnostics: {
              phase: "decoder",
              failure_kind: reply.reason,
              reason: reply.message,
              pointer: reply.pointer,
            },
          });
        if (reply.reason === "unsupported")
          throw new AnalysisCapabilityUnavailableError(
            input.format,
            OPERATION,
            reply.message,
          );
        throw new AnalysisOutputError(OPERATION, reply.message);
      }
      if (
        reply.value.decoder.id !== adapter.identity.id ||
        reply.value.decoder.name !== adapter.identity.name ||
        reply.value.decoder.version !== adapter.identity.version
      )
        throw new AnalysisOutputError(
          OPERATION,
          "Capture decoder changed the selected upstream profile identity.",
        );
      result = ok({
        ...reply.value,
        artifact: {
          path: input.capture_path,
          sha256: snapshot.sha256,
          bytes: snapshot.bytes.length,
        },
        format: input.format,
        runtime_attribution: "unknown",
        limitations: [
          "This is retained producer evidence, without live browser transaction IDs, scenario provenance, execution attribution or deployment authenticity. Recorded URLs are never fetched.",
          "Every record is decoded before selection; no partial success is returned on malformed input or a resource limit.",
          "Known authentication headers/cookies and explicitly marked literal values are excluded. Unknown extension names do not establish sensitivity.",
          `A 32 MiB input, 96 MiB reply and 64-level nesting budget bound complete evidence. ${harMemoryLimitation()}; native decoding uses a 768 MiB Linux address-space limit. Each owned command has a 30-second deadline with independent cleanup.`,
        ],
      });
    } catch (cause: unknown) {
      const ownedFailure =
        cause instanceof OwnedCommandFailure ? cause : undefined;
      failureResources = ownedFailure?.resources ?? [];
      const failure = redactExplicitFailure(
        historicalCaptureFailure(input, cause, phase, options),
        input.sensitive_values,
      );
      result = err(failure);
      if (
        ownedFailure?.cleanupOwner !== undefined &&
        runtimeOwner !== undefined
      ) {
        runtimeOwner.rememberFailure(failure);
        runtimeOwner.retainProcess(
          ownedFailure.cleanupOwner,
          ownedFailure.resources,
        );
        // The command already attempted bounded cleanup. Retain both resources
        // for the next inspect/close instead of repeating that attempt here.
        this.#resources.retain(runtimeOwner);
        return result;
      }
    }
    if (runtimeOwner !== undefined) {
      const cleanup = await this.#resources.release(runtimeOwner);
      if (cleanup.kind === "failed") {
        const error = new ProviderCleanupError(
          input.format,
          [...new Set([...runtimeOwner.resources, ...failureResources])],
          {
            capture_path: input.capture_path,
            previous_error: result.ok
              ? null
              : projectAnalysisError(result.error),
            reason:
              cleanup.cause instanceof Error
                ? cleanup.cause.message
                : String(cleanup.cause),
          },
          { operation: OPERATION, cause: cleanup.cause },
        );
        const redacted = redactExplicitFailure(error, input.sensitive_values);
        runtimeOwner.rememberFailure(redacted);
        return err(redacted);
      }
    }
    return result.ok && options?.signal?.aborted
      ? err(new AnalysisCancelledError(OPERATION))
      : result;
  }
}

/** One private capture directory whose child must stop before files are removed. */
class HistoricalCaptureRuntimeOwner implements Extract<
  ArtifactResourceOwner,
  { readonly kind: "historical-capture-runtime" }
> {
  readonly kind = "historical-capture-runtime";
  #runtime: Pick<PrivateRuntimeRoot, "path" | "close"> | undefined;
  #supervisor: ProviderProcessSupervisor | undefined;
  #processResources: readonly string[] = [];
  #previousFailure: ProviderCleanupError | undefined;

  constructor(runtime: Pick<PrivateRuntimeRoot, "path" | "close">) {
    this.#runtime = runtime;
  }

  get resource(): string {
    return this.resources.join(", ");
  }

  get resources(): readonly string[] {
    return [
      ...new Set([
        ...(this.#runtime === undefined ? [] : [this.#runtime.path]),
        ...this.#processResources,
      ]),
    ];
  }

  retainProcess(
    supervisor: ProviderProcessSupervisor,
    resources: readonly string[],
  ): void {
    this.#supervisor = supervisor;
    this.#processResources = resources;
  }

  rememberFailure(failure: AnalysisError): void {
    if (failure instanceof ProviderCleanupError)
      this.#previousFailure = failure;
  }

  get previousFailure(): ProviderCleanupError | undefined {
    return this.#previousFailure;
  }

  async close(): Promise<void> {
    if (this.#supervisor !== undefined) {
      const stopped = await this.#supervisor.stop();
      if (stopped.status === "incomplete")
        throw this.#retryFailure(stopped.reason);
      this.#supervisor = undefined;
      this.#processResources = [];
    }
    const runtime = this.#runtime;
    if (runtime === undefined) return;
    try {
      await runtime.close();
    } catch (cause: unknown) {
      throw this.#retryFailure(
        cause instanceof Error ? cause.message : String(cause),
        cause,
      );
    }
    this.#runtime = undefined;
  }

  #retryFailure(reason: string, cause?: unknown): ArtifactReaderFailure {
    return new ArtifactReaderFailure("unavailable", reason, {
      ...(cause === undefined ? {} : { cause }),
      cleanup: { reason, resources: this.resources },
    });
  }
}

/** The HAR decoder runs on this executable; only Node.js enforces its V8 heap flags. */
const harMemoryLimitation = (): string => {
  if (HAR_CAPTURE_HEAP_ENFORCED)
    return `HAR uses a ${String(HAR_CAPTURE_HEAP_LIMITS.oldGenerationMiB)} MiB Node old-generation heap`;
  return HAR_CAPTURE_PROCESS_MEMORY_LIMIT_BYTES === null
    ? "HAR runs on Bun, which does not enforce REA's V8 heap flags"
    : `HAR runs on Bun, which does not enforce REA's V8 heap flags, under a ${String(HAR_CAPTURE_PROCESS_MEMORY_LIMIT_BYTES)}-byte Windows Job Object commit limit`;
};

const replyFailureReason = (cause: unknown): string => {
  if (cause instanceof ArtifactReaderFailure) return cause.message;
  if (cause instanceof z.ZodError)
    return `Reply violates its schema at ${cause.issues[0]?.path.map(String).join(".") ?? "root"}.`;
  if (cause instanceof SyntaxError) return "Reply is malformed JSON.";
  if (cause instanceof Error && "code" in cause)
    return `Reply file could not be read (${String(cause.code)}).`;
  return "Reply could not be validated.";
};
