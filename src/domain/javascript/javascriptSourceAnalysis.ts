import type { AnalysisError } from "../analysisErrorBase.js";
import type { AnalysisResourceConstraintError } from "../analysisErrorCore.js";
import type { Result } from "../result.js";
import type { JavaScriptArtifactFile } from "./javascriptArtifactFiles.js";
import type { JavaScriptStaticAnalysis } from "./javascriptStaticAnalysisTypes.js";
import type { JavaScriptModuleSemanticIr } from "./javascriptModuleSemanticIr.js";
import type { JavaScriptSemanticFileProjection } from "./javascriptSemanticFileProjection.js";

/** Portable facts collected from one inert source. */
export interface JavaScriptAnalyzedSource {
  readonly javascript: JavaScriptStaticAnalysis;
  readonly module: JavaScriptModuleSemanticIr | null;
  readonly projection: JavaScriptSemanticFileProjection | null;
  readonly applicationProjectionFailure?: AnalysisResourceConstraintError;
}

/** Execution failure alongside facts already collected by the consumer. */
export interface JavaScriptSourceAnalysisFailure {
  readonly error: AnalysisError;
  readonly javascript: JavaScriptStaticAnalysis | null;
  readonly module: JavaScriptModuleSemanticIr | null;
  readonly projection: JavaScriptSemanticFileProjection | null;
  readonly applicationProjectionFailure?: AnalysisResourceConstraintError;
}

/** Operational choices for source analysis, independent of transport framing. */
export interface JavaScriptSourceAnalysisLimits {
  readonly heapMb: number;
  readonly timeoutMs: number;
}

/** Sequential source-analysis authority with independently verified cleanup. */
export interface JavaScriptSourceAnalysisPort {
  analyze(
    file: JavaScriptArtifactFile,
    nodeBudget: number,
    signal?: AbortSignal,
  ): Promise<Result<JavaScriptAnalyzedSource, JavaScriptSourceAnalysisFailure>>;
  /**
   * Read semantic graphs deferred until later sources no longer require the
   * worst-case static reserve. Absent when the analyzer has nothing to retry.
   */
  admitDeferredSemanticGraphs?(signal?: AbortSignal): Promise<{
    readonly admitted: readonly {
      readonly file: JavaScriptArtifactFile;
      readonly projection: JavaScriptSemanticFileProjection;
    }[];
    readonly rejected: readonly {
      readonly file: JavaScriptArtifactFile;
      readonly error: AnalysisResourceConstraintError;
    }[];
  }>;
  close(): Promise<void>;
}
