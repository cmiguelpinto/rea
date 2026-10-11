import type { JavaScriptSourceAnalysisPort } from "../domain/javascript/javascriptSourceAnalysis.js";
import type { OwnedFileHandle } from "../filesystem/OwnedFileHandle.js";
import type { OwnedDirectoryHandle } from "../filesystem/OwnedDirectoryHandle.js";

import type { ArtifactReader } from "./ArtifactReader.js";
import { ArtifactReaderFailure } from "./ArtifactReader.js";
import type { SafeOutputTree } from "./SafeOutputTree.js";

/** One artifact resource and its format-specific cleanup owner. */
export type ArtifactResourceOwner =
  | {
      readonly kind: "javascript-source-analysis";
      readonly resource: string;
      readonly analysis: JavaScriptSourceAnalysisPort;
    }
  | {
      readonly kind: "directory-handle";
      readonly resource: string;
      readonly handle: OwnedDirectoryHandle;
    }
  | {
      readonly kind: "reader";
      readonly resource: string;
      readonly reader: ArtifactReader;
    }
  | {
      readonly kind: "file-handle";
      readonly resource: string;
      readonly handle: OwnedFileHandle;
    }
  | {
      readonly kind: "output-tree";
      readonly resource: string;
      readonly tree: SafeOutputTree;
    }
  | {
      readonly kind: "historical-capture-runtime";
      readonly resource: string;
      close(): Promise<void>;
    };

export interface ArtifactResourceCleanupFailureEntry {
  readonly owner: ArtifactResourceOwner;
  readonly cause: unknown;
}

/** Failed drain that keeps each resource owner paired with its cleanup failure. */
export class ArtifactResourceCleanupFailure extends ArtifactReaderFailure {
  constructor(
    readonly failures: readonly ArtifactResourceCleanupFailureEntry[],
    message: string,
    options: {
      readonly resources: readonly string[];
      readonly reason: string;
    },
  ) {
    super("unavailable", message, {
      cause: new AggregateError(
        failures.map(({ cause }) => cause),
        "One or more artifact resources remain owned",
      ),
      cleanup: options,
    });
    this.name = "ArtifactResourceCleanupFailure";
  }
}

export type ArtifactCleanupAttempt =
  | { readonly kind: "released" }
  | { readonly kind: "failed"; readonly cause: unknown };

/** Caller-owned scope that retains failed artifact cleanup for a later close. */
export class ArtifactResourceScope {
  readonly #pending = new Set<ArtifactResourceOwner>();
  readonly #active = new Set<Promise<unknown>>();
  #draining: Promise<void> | undefined;
  #closed = false;

  /** Admit a resource operation while the scope remains open. */
  async run<T>(operation: () => Promise<T>): Promise<T> {
    while (true) {
      if (this.#closed)
        throw new ArtifactReaderFailure(
          "unavailable",
          "Artifact resource scope is closed",
        );
      if (this.#draining !== undefined) await this.#draining;
      if (this.#closed)
        throw new ArtifactReaderFailure(
          "unavailable",
          "Artifact resource scope is closed",
        );
      if (this.#pending.size > 0) {
        await this.#retryCleanup();
        continue;
      }
      const running = Promise.resolve().then(operation);
      this.#active.add(running);
      try {
        return await running;
      } finally {
        this.#active.delete(running);
      }
    }
  }

  /** Retain an owner whose acquisition boundary already reported failed cleanup. */
  retain(owner: ArtifactResourceOwner): void {
    this.#pending.add(owner);
  }

  /** Attempt cleanup now and retain the same owner if it fails. */
  async release(owner: ArtifactResourceOwner): Promise<ArtifactCleanupAttempt> {
    try {
      await cleanup(owner);
      this.#pending.delete(owner);
      return { kind: "released" };
    } catch (cause: unknown) {
      this.retain(owner);
      return { kind: "failed", cause };
    }
  }

  /** Retry retained owners without closing resource admission. */
  #retryCleanup(): Promise<void> {
    if (this.#draining !== undefined) return this.#draining;
    this.#draining = this.#drainAndRetry().finally(() => {
      this.#draining = undefined;
    });
    return this.#draining;
  }

  /** Stop admission, wait for active operations, and retry every retained owner. */
  close(): Promise<void> {
    this.#closed = true;
    return this.#retryCleanup();
  }

  async #drainAndRetry(): Promise<void> {
    while (this.#active.size > 0) await Promise.allSettled(this.#active);
    const failures: ArtifactResourceCleanupFailureEntry[] = [];
    for (const owner of this.#pending) {
      try {
        await cleanup(owner);
        this.#pending.delete(owner);
      } catch (cause: unknown) {
        failures.push({ owner, cause });
      }
    }
    if (failures.length === 0) return;
    const observations = failures.map(({ owner, cause }) =>
      ArtifactReaderFailure.cleanupObservation(cause, owner.resource),
    );
    const resources = [
      ...new Set(observations.flatMap(({ resources }) => resources)),
    ];
    throw new ArtifactResourceCleanupFailure(
      failures,
      `Artifact cleanup remains incomplete: ${resources.join(", ")}`,
      {
        reason: observations.map(({ reason }) => reason).join("; "),
        resources,
      },
    );
  }
}

const cleanup = async (owner: ArtifactResourceOwner): Promise<void> => {
  switch (owner.kind) {
    case "javascript-source-analysis":
      await owner.analysis.close();
      return;
    case "reader":
      await owner.reader.close();
      return;
    case "file-handle":
    case "directory-handle":
      await owner.handle.close();
      return;
    case "output-tree":
      await owner.tree.rollback();
      return;
    case "historical-capture-runtime":
      await owner.close();
  }
};
