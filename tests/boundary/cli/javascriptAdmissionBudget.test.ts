import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import { expect } from "vitest";

import { JAVASCRIPT_ANALYSIS_RESOURCE_DEFAULTS } from "../../../src/domain/javascript/javascriptAnalysisResourceControls.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { cliTest } from "../../support/cli/cliFixture.js";

const largeModule = `${Array.from(
  { length: 800 },
  (_, index) =>
    `export function method_${String(index)}(input) { const value = input + ${String(index)}; const pair = { value }; return pair.value; }`,
).join("\n")}\n`;

const evidenceOf = (json: unknown) =>
  json as {
    normalized_result?: {
      statistics?: {
        parsed_javascript_files?: number;
        parse_failures?: number;
        visited_ast_nodes?: number;
      };
      semantic_graph?: {
        nodes?: readonly {
          label?: string;
          properties?: { name?: string };
        }[];
        relations?: readonly unknown[];
      };
    };
    remediation?: { action?: string };
    message?: string;
  };

const hasMethod0 = (json: unknown): boolean => {
  const nodes = evidenceOf(json).normalized_result?.semantic_graph?.nodes ?? [];
  return nodes.some(
    (node) => node.label === "method_0" || node.properties?.name === "method_0",
  );
};

cliTest(
  "admits an earlier generated module when one later source remains",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-js-admission-");
    await writeFile(join(root, "a-large.mjs"), largeModule);
    await writeFile(join(root, "z-tiny.mjs"), "export const tiny = 1;\n");
    const output = await cli.run({
      arguments: ["analyze", root, "--json"],
      environment: { NODE_OPTIONS: "--max-old-space-size=512" },
      timeoutMs: 120_000,
    });
    expect(JAVASCRIPT_ANALYSIS_RESOURCE_DEFAULTS.heapMb).toBe(1024);
    expect(output.exitCode).toBe(0);
    expect(output.stderr).not.toMatch(/exhausted its heap/iu);
    const result = evidenceOf(output.json).normalized_result;
    expect(result?.statistics).toMatchObject({
      parsed_javascript_files: 2,
      parse_failures: 0,
      visited_ast_nodes: 17_609,
    });
    expect(hasMethod0(output.json)).toBe(true);
    expect((result?.semantic_graph?.relations ?? []).length).toBeGreaterThan(0);
    expect(JSON.stringify(output.json)).not.toContain(
      "Review the reported worker memory limits",
    );
  },
  120_000,
);

cliTest(
  "keeps the earlier module when ten later sources remain",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-js-admission-many-");
    await writeFile(join(root, "a-large.mjs"), largeModule);
    await Promise.all(
      Array.from({ length: 10 }, (_, index) =>
        writeFile(
          join(root, `z-${String(index).padStart(2, "0")}.mjs`),
          `export const tiny_${String(index)} = 1;\n`,
        ),
      ),
    );
    const output = await cli.run({
      arguments: ["analyze", root, "--json"],
      environment: { NODE_OPTIONS: "--max-old-space-size=512" },
      timeoutMs: 180_000,
    });
    expect(JAVASCRIPT_ANALYSIS_RESOURCE_DEFAULTS.heapMb).toBe(1024);
    expect(output.exitCode).toBe(0);
    expect(output.stderr).not.toMatch(/exhausted its heap/iu);
    const result = evidenceOf(output.json).normalized_result;
    expect(result?.statistics).toMatchObject({
      parsed_javascript_files: 11,
      parse_failures: 0,
    });
    expect((result?.statistics?.visited_ast_nodes ?? 0) > 17_609).toBe(true);
    expect(hasMethod0(output.json)).toBe(true);
    expect((result?.semantic_graph?.relations ?? []).length).toBeGreaterThan(0);
    expect(JSON.stringify(output.json)).not.toContain(
      "Review the reported worker memory limits",
    );
  },
  180_000,
);

cliTest(
  "names the parent admission budget when the semantic graph still does not fit",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-js-admission-tight-");
    await writeFile(join(root, "a-large.mjs"), largeModule);
    await writeFile(join(root, "z-tiny.mjs"), "export const tiny = 1;\n");
    const output = await cli.run({
      arguments: ["analyze", root, "--json"],
      environment: { NODE_OPTIONS: "--max-old-space-size=320" },
      timeoutMs: 120_000,
    });
    expect(output.stderr).not.toMatch(/exhausted its heap/iu);
    const text = JSON.stringify(output.json);
    expect(text).not.toContain("Review the reported worker memory limits");
    expect(text).toContain("parent's result-admission budget");
    expect(text).toContain("parent_admission_budget_bytes");
    expect(hasMethod0(output.json)).toBe(false);
    const statistics = evidenceOf(output.json).normalized_result?.statistics;
    if (output.exitCode === 0)
      expect(statistics).toMatchObject({ parse_failures: 0 });
  },
  120_000,
);
