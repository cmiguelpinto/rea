import { isMap, isSeq } from "yaml";
import type { YAMLMap } from "yaml";
import {
  parse as parseYaml,
  parseDocument as parseYamlDocument,
  stringify as stringifyYaml,
} from "yaml";

import type {
  ClientConfigurationDocument,
  ClientConfigurationFormat,
} from "./ClientConfigurationDocument.js";

/**
 * DeepSeek Harness registers MCP clients through a Cordis YAML patch sequence
 * rather than a server table: each file is a list of operations, and an
 * `insert` operation carries entries identified by `id`. REA owns exactly one
 * entry id and never touches unrelated patches.
 */
export const DSH_ENTRY_ID = "rea-mcp";
/** The Harness MCP client package every REA registration loads. */
export const DSH_CLIENT_PACKAGE = "@deepseek-ai/dsh-mcp-client";
/** Document key holding the patch list inside the generic client machinery. */
const PATCHES_KEY = "dshPatches";

const isInsertEntry = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" &&
  value !== null &&
  !Array.isArray(value) &&
  Reflect.get(value, "id") === DSH_ENTRY_ID;

const parsePatchList = (text: string): readonly unknown[] => {
  if (text.replace(/^\uFEFF/, "").trim() === "") return [];
  const value: unknown = parseYaml(text);
  if (!Array.isArray(value))
    throw new SyntaxError(
      "DeepSeek Harness cordis.patch.yml must be a YAML list of patch operations",
    );
  return value;
};

/**
 * Parse the home patch into the shared client-document shape: the patch list
 * is retained verbatim under `dshPatches`, and the REA entry's `config`
 * becomes the `rea` server record the setup and doctor machinery reads.
 */
export const parseDshCordisDocument = (
  text: string,
): ClientConfigurationDocument => {
  const patches = parsePatchList(text);
  const config = dshEntryConfig(patches);
  return {
    document: { [PATCHES_KEY]: [...patches] },
    servers: config === undefined ? {} : { rea: config },
    serversPath: [PATCHES_KEY],
    dialect: "dsh",
    legacyServers: {},
  };
};

/**
 * The effective config of the REA entry under Cordis patch semantics: patches
 * apply in order, an insert replaces the row named by id, and a later direct
 * `{ id, config }` operation replaces that row's whole config. The entry reads
 * back only when the winning writer left the canonical Harness MCP client
 * package as its name; a wrong or missing package name reads back as absent so
 * the next setup rewrites exactly one canonical entry.
 */
const dshEntryConfig = (
  patches: readonly unknown[],
): Record<string, unknown> | undefined => {
  let name: unknown;
  let config: Record<string, unknown> | undefined;
  let disabled: unknown;
  const configOf = (value: unknown): Record<string, unknown> =>
    typeof value === "object" && value !== null && !Array.isArray(value)
      ? { ...(value as Record<string, unknown>) }
      : {};
  for (const op of patches) {
    if (typeof op !== "object" || op === null || Array.isArray(op)) continue;
    const inserted = Reflect.get(op, "insert");
    if (Array.isArray(inserted)) {
      for (const entry of inserted) {
        if (!isInsertEntry(entry)) continue;
        name = Reflect.get(entry, "name");
        config = configOf(Reflect.get(entry, "config"));
        disabled = Reflect.get(entry, "disabled");
      }
      continue;
    }
    // A direct patch to the row replaces its config and, when present, its
    // name; the repository verifier uses these operations natively.
    if (Reflect.get(op, "id") !== DSH_ENTRY_ID) continue;
    const opName = Reflect.get(op, "name");
    if (opName !== undefined) name = opName;
    if (Reflect.has(op as object, "config"))
      config = configOf(Reflect.get(op, "config"));
    if (Reflect.has(op as object, "disabled"))
      disabled = Reflect.get(op, "disabled");
  }
  if (name !== DSH_CLIENT_PACKAGE) return undefined;
  // Cordis keeps activation beside the config, and a disabled row never loads
  // REA tools; project it into the server record so doctor and setup treat a
  // matching command on a disabled row as stale instead of aligned.
  return disabled === true ? { ...config, disabled: true } : config;
};

/** The canonical row REA writes for its entry, minus Cordis activation state. */
const canonicalDshEntry = (
  entry: Record<string, unknown>,
  desired: Record<string, unknown>,
): Record<string, unknown> => {
  const { disabled: _superseded, ...envelope } = entry;
  return { ...envelope, name: DSH_CLIENT_PACKAGE, config: { ...desired } };
};

/**
 * Return the document with the REA entry upserted into its patch list. The
 * first id-matching insert is replaced in place, later duplicates and direct
 * patches to the entry are dropped so exactly one canonical row remains, and
 * a fresh insert operation is appended when no insertion carried the entry;
 * removing a direct-only patch does not count as carrying it.
 */
export const withDshServer = (
  parsed: ClientConfigurationDocument,
  desired: Record<string, unknown>,
): Record<string, unknown> => {
  let carriedByInsert = false;
  const patches = (parsed.document[PATCHES_KEY] as readonly unknown[]).flatMap(
    (op) => {
      if (typeof op !== "object" || op === null || Array.isArray(op))
        return [op];
      const inserted = Reflect.get(op, "insert");
      if (Array.isArray(inserted)) {
        let replacedHere = false;
        const next = inserted.flatMap((entry) => {
          if (!isInsertEntry(entry)) return [entry];
          // Keep the first carrying operation in place; collapse the rest.
          if (carriedByInsert || replacedHere) return [];
          replacedHere = true;
          carriedByInsert = true;
          return [canonicalDshEntry(entry as Record<string, unknown>, desired)];
        });
        if (!replacedHere && next.length === inserted.length) return [op];
        return next.length === 0
          ? []
          : [{ ...(op as Record<string, unknown>), insert: next }];
      }
      // Direct patches to the REA row are superseded by the rewritten entry.
      if (Reflect.get(op, "id") === DSH_ENTRY_ID) return [];
      return [op];
    },
  );
  if (!carriedByInsert)
    patches.push({
      insert: [
        { id: DSH_ENTRY_ID, name: DSH_CLIENT_PACKAGE, config: { ...desired } },
      ],
    });
  return { ...parsed.document, [PATCHES_KEY]: patches };
};

/**
 * Return the document with every REA entry removed: entries inside insert
 * operations, direct patches to the entry, and insert operations that hold
 * nothing else after removal.
 */
export const removeDshServer = (
  parsed: ClientConfigurationDocument,
): Record<string, unknown> => {
  const patches = (parsed.document[PATCHES_KEY] as readonly unknown[])
    .map((op) => {
      if (typeof op !== "object" || op === null || Array.isArray(op)) return op;
      const inserted = Reflect.get(op, "insert");
      if (!Array.isArray(inserted)) return op;
      return {
        ...(op as Record<string, unknown>),
        insert: inserted.filter((entry) => !isInsertEntry(entry)),
      };
    })
    .filter((op) => {
      if (typeof op !== "object" || op === null || Array.isArray(op))
        return true;
      // A direct patch to the REA row goes away with the entry.
      if (Reflect.get(op, "id") === DSH_ENTRY_ID) return false;
      const inserted = Reflect.get(op, "insert");
      return !(
        Array.isArray(inserted) &&
        inserted.every((entry) => !isInsertEntry(entry)) &&
        inserted.length === 0
      );
    });
  return { ...parsed.document, [PATCHES_KEY]: patches };
};

/**
 * Serialize the patch list, editing an existing file's YAML document in place
 * so user comments, formatting, and operation scope survive a registration
 * update: the first insertion carrying the REA entry keeps its position and
 * neighbor entries (a grouped insert stays grouped), the entry node itself is
 * rewritten in place, later carrying insertions and direct REA patches
 * collapse away, and a fresh root insertion is appended only when no
 * insertion carried the entry.
 */
export const serializeDshDocument = (
  document: Record<string, unknown>,
  originalText: string | undefined,
): string => {
  const desired = dshEntryConfig(document[PATCHES_KEY] as readonly unknown[]);
  const freshPatchList = (): readonly unknown[] =>
    desired === undefined
      ? []
      : [
          {
            insert: [
              { id: DSH_ENTRY_ID, name: DSH_CLIENT_PACKAGE, config: desired },
            ],
          },
        ];
  if (
    originalText === undefined ||
    originalText.replace(/^\uFEFF/, "").trim() === ""
  )
    return `${stringifyYaml(freshPatchList())}`;
  const yamlDocument = parseYamlDocument(originalText);
  const root = yamlDocument.contents;
  if (!isSeq(root)) {
    // The file was a patch list when parsed; a root that no longer is cannot
    // be edited in place, so a fresh patch list is emitted instead.
    return `${stringifyYaml(freshPatchList())}`;
  }
  let carried = false;
  type PatchItem = (typeof root.items)[number];
  root.items = root.items.flatMap((item): PatchItem[] => {
    if (!isMap(item)) return [item];
    const insert = item.get("insert");
    if (!isSeq(insert)) {
      // Direct patches to the REA row are superseded by the rewritten entry
      // and would otherwise override it again at their position.
      return (item.get("id") as unknown) === DSH_ENTRY_ID ? [] : [item];
    }
    const carrying = insert.items
      .map((entry, index) =>
        isMap(entry) && (entry.get("id") as unknown) === DSH_ENTRY_ID
          ? index
          : -1,
      )
      .filter((index) => index >= 0);
    if (carrying.length === 0) return [item];
    if (carried) {
      removeSeqItems(insert, carrying);
      return insert.items.length === 0 ? [] : [item];
    }
    carried = true;
    for (const index of carrying.slice(1).reverse())
      insert.items.splice(index, 1);
    const entry = insert.items[carrying[0] as number];
    if (isMap(entry)) {
      if (desired === undefined) {
        insert.items.splice(carrying[0] as number, 1);
        return insert.items.length === 0 ? [] : [item];
      }
      // Seq members type as node-keyed maps; scalar keys need the loose view.
      const entryMap = entry as unknown as YAMLMap<unknown, unknown>;
      entryMap.set("name", yamlDocument.createNode(DSH_CLIENT_PACKAGE));
      entryMap.set("config", yamlDocument.createNode(desired));
      // Setup registers an enabled row; Cordis activation is REA-owned here.
      entryMap.delete("disabled");
    }
    return [item];
  });
  if (!carried && desired !== undefined) {
    const appended = yamlDocument.createNode({
      insert: [{ id: DSH_ENTRY_ID, name: DSH_CLIENT_PACKAGE, config: desired }],
    });
    root.items.push(appended as unknown as (typeof root.items)[number]);
  }
  return yamlDocument.toString({ lineWidth: 0 });
};

const removeSeqItems = (
  sequence: { items: unknown[] },
  indexes: readonly number[],
): void => {
  for (const index of [...indexes].reverse()) sequence.items.splice(index, 1);
};

/** Registration entry config shape for the Harness MCP client. */
export const dshClientRegistrationEntry = (
  command: readonly string[],
  environment: Readonly<Record<string, string>> = {},
): Record<string, unknown> => {
  const [executable = "rea", ...args] = command;
  return {
    serverName: "rea",
    transport: "stdio",
    command: executable,
    args,
    ...(Object.keys(environment).length === 0
      ? {}
      : { env: { ...environment } }),
  };
};

/** Type-only anchor keeping the format union honest for future callers. */
export type DshConfigurationFormat = Extract<ClientConfigurationFormat, "dsh">;
