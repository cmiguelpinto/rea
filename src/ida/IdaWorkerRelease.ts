import { AnalysisProtocolError } from "../domain/analysisErrorCore.js";
import type { IdaMcpConnection } from "./IdaMcpConnection.js";
import {
  closeDatabaseSchema,
  databaseListSchema,
  idaWorkerReleaseSchema,
  strictDatabaseListSchema,
} from "./IdaProtocolValues.js";
import { idaFileDigest, sameIdaHostPath } from "./IdaWorkspace.js";

/** A release token requires #551's complete registry scan, not legacy discovery. */
export const readIdaSessionInventory = async (
  connection: IdaMcpConnection,
  releaseId: string | undefined,
) => {
  const strict = releaseId !== undefined;
  const inventory = await connection.call(
    "idb_list",
    strict ? { strict_discovery: true } : {},
  );
  return strict
    ? strictDatabaseListSchema.parse(inventory)
    : databaseListSchema.parse(inventory);
};

/**
 * Consumes ida-pro-mcp #551's real idb_close release receipt.
 * Legacy upstreams (no idb_open release_id) keep their original close flow;
 * they cannot recover reaped workers by inventing proof from empty inventory.
 */
export const closeVerifiedIdaWorker = async (options: {
  readonly connection: IdaMcpConnection;
  readonly database: string;
  readonly privateSessionId: string;
  readonly inputPath: string;
  readonly sha256: string;
  readonly openCompleted: boolean;
  readonly releaseId?: string | undefined;
}): Promise<"close-confirmed" | "release-verified"> => {
  const {
    connection,
    database,
    privateSessionId,
    inputPath,
    sha256,
    openCompleted,
    releaseId,
  } = options;
  // Reject a foreign session before even sending idb_close to the supervisor.
  // A post-failure release receipt cannot undo an unsafe close request.
  if (database !== privateSessionId)
    throw new AnalysisProtocolError(
      "IDA close refused a session outside its private worker ownership.",
    );
  if (releaseId !== undefined) {
    if (!openCompleted)
      throw new AnalysisProtocolError(
        "IDA release proof cannot be requested without a completed owned open.",
      );
    if ((await idaFileDigest(inputPath)) !== sha256)
      throw new AnalysisProtocolError(
        "IDA private input changed before requesting worker release.",
      );
  }
  const closed = closeDatabaseSchema.parse(
    await connection.call("idb_close", {
      database,
      save: false,
      ...(releaseId === undefined
        ? {}
        : { expected_input_path: inputPath, release_id: releaseId }),
    }),
  );
  if (
    closed.session_id !== database ||
    closed.saved === true ||
    closed.owned !== true ||
    closed.backend !== "worker"
  )
    throw new AnalysisProtocolError(
      "IDA database close did not confirm the requested owned, unsaved session release.",
    );
  if (releaseId === undefined) return "close-confirmed";
  const proof = idaWorkerReleaseSchema.parse(closed.release);
  if (
    proof.session_id !== database ||
    proof.release_id !== releaseId ||
    !sameIdaHostPath(proof.input_path, inputPath)
  )
    throw new AnalysisProtocolError(
      "IDA release receipt does not match this owned worker generation and input.",
    );
  if ((await idaFileDigest(inputPath)) !== sha256)
    throw new AnalysisProtocolError(
      "IDA private input changed during worker release.",
    );
  return "release-verified";
};
