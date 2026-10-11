import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { parse as parseYaml } from "yaml";

import { readClientRegistrationStatuses } from "../../../src/application/ClientRegistrationStatus.js";
import { npxRegistrationCommand } from "../../../src/application/ClientRegistrationIdentity.js";
import { configureClientConfiguration } from "../../../src/application/SetupClientConfiguration.js";
import {
  clientSkillDirectories,
  supportedClients,
} from "../../../src/application/SupportedClients.js";
import { systemUninstallHost } from "../../../src/application/Uninstall.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { clearClientLocationEnvironment } from "../../fixtures/clientEnvironment.js";

/**
 * The registration command setup writes on the host running the tests. Windows
 * wraps it in `cmd.exe /d /c`, so the expected entry follows the host too.
 */
const command = npxRegistrationCommand(process.platform);

beforeEach(clearClientLocationEnvironment);
afterEach(() => vi.unstubAllEnvs());

const dshClient = (
  env: Parameters<typeof supportedClients>[2],
  platform: NodeJS.Platform = "linux",
) =>
  supportedClients(join("/home/a"), platform, env).find(
    ({ name }) => name === "dsh",
  );

describe("DeepSeek Harness configuration paths", () => {
  it("resolves the home Cordis patch under the Harness home", () => {
    expect(dshClient({})).toEqual({
      name: "dsh",
      displayName: "DeepSeek Harness",
      configPath: join("/home/a", ".dsh", "cordis.patch.yml"),
      markerPath: join("/home/a", ".dsh"),
      format: "dsh",
    });
    // The home patch applies to every profile; DSH_HOME relocates it.
    expect(dshClient({ DSH_HOME: "/custom/harness" })?.configPath).toBe(
      join("/custom/harness", "cordis.patch.yml"),
    );
    expect(
      clientSkillDirectories(join("/home/a"), ["dsh"], {
        DSH_AGENTS_HOME: "/custom/agents",
      }),
    ).toEqual([{ client: "dsh", directory: join("/custom/agents", "skills") }]);
  });
});

const harnessClient = async () => {
  const home = await createTestTempDirectory("rea-dsh-");
  const client = supportedClients(home, process.platform, {}).find(
    ({ name }) => name === "dsh",
  );
  if (client?.markerPath === undefined)
    throw new Error("missing DeepSeek Harness client");
  await mkdir(client.markerPath, { recursive: true });
  return { home, client };
};

describe("DeepSeek Harness Cordis patch registration", () => {
  it("appends the rea-mcp insert, preserves user patches, and reads back", async () => {
    const { home, client } = await harnessClient();
    await writeFile(
      client.configPath,
      `# Harness home patch
- insert:
    - id: user-tool
      name: "@deepseek-ai/dsh-mcp-client"
      config:
        serverName: other
        transport: stdio
        command: other-server
`,
    );

    expect(
      (await configureClientConfiguration(client, {}, command)).status,
    ).toBe("configured");
    const text = await readFile(client.configPath, "utf8");
    expect(text).toContain("# Harness home patch");
    expect(parseYaml(text)).toEqual([
      {
        insert: [
          {
            id: "user-tool",
            name: "@deepseek-ai/dsh-mcp-client",
            config: {
              serverName: "other",
              transport: "stdio",
              command: "other-server",
            },
          },
        ],
      },
      {
        insert: [
          {
            id: "rea-mcp",
            name: "@deepseek-ai/dsh-mcp-client",
            config: {
              serverName: "rea",
              transport: "stdio",
              command: command[0],
              args: command.slice(1),
            },
          },
        ],
      },
    ]);

    expect(await configureClientConfiguration(client, {}, command)).toEqual({
      status: "unchanged",
    });
    expect(
      (
        await readClientRegistrationStatuses(home, undefined, {
          platform: process.platform,
          environment: {},
        })
      ).find(({ client: name }) => name === "dsh"),
    ).toMatchObject({ state: "aligned", command });

    expect((await systemUninstallHost(home).removeClient(client)).status).toBe(
      "removed",
    );
    expect(parseYaml(await readFile(client.configPath, "utf8"))).toEqual([
      {
        insert: [
          {
            id: "user-tool",
            name: "@deepseek-ai/dsh-mcp-client",
            config: {
              serverName: "other",
              transport: "stdio",
              command: "other-server",
            },
          },
        ],
      },
    ]);
  });

  it("replaces an existing rea-mcp entry without duplicating it", async () => {
    const { client } = await harnessClient();
    await writeFile(
      client.configPath,
      `- insert:
    - id: rea-mcp
      name: "@deepseek-ai/dsh-mcp-client"
      config:
        serverName: rea
        transport: stdio
        command: stale-launcher
        args: [mcp]
`,
    );

    expect(
      (await configureClientConfiguration(client, {}, command)).status,
    ).toBe("configured");
    const patches = parseYaml(
      await readFile(client.configPath, "utf8"),
    ) as unknown[];
    expect(patches).toHaveLength(1);
    expect((patches[0] as { insert: unknown[] }).insert).toHaveLength(1);
    expect(textOf(await readFile(client.configPath, "utf8"))).not.toContain(
      "stale-launcher",
    );
  });

  it("rewrites a wrong-package rea-mcp entry into the canonical one", async () => {
    const { client } = await harnessClient();
    await writeFile(
      client.configPath,
      `- insert:
    - id: rea-mcp
      name: not-the-harness-client
      config:
        serverName: rea
        transport: stdio
        command: stale-launcher
        args: [mcp]
`,
    );

    // The non-canonical entry reads back as absent, so setup rewrites it with
    // the canonical package name rather than reporting unchanged.
    expect(
      (await configureClientConfiguration(client, {}, command)).status,
    ).toBe("configured");
    const patches = parseYaml(await readFile(client.configPath, "utf8")) as {
      insert: { id: string; name: string }[];
    }[];
    expect(patches).toHaveLength(1);
    expect(patches[0]?.insert).toHaveLength(1);
    expect(patches[0]?.insert[0]?.id).toBe("rea-mcp");
    expect(patches[0]?.insert[0]?.name).toBe("@deepseek-ai/dsh-mcp-client");
    expect(textOf(await readFile(client.configPath, "utf8"))).not.toContain(
      "not-the-harness-client",
    );
  });
});

describe("DeepSeek Harness registration identity", () => {
  it("applies a direct config patch before judging the registration", async () => {
    const { home, client } = await harnessClient();
    await writeFile(
      client.configPath,
      `- insert:
    - id: rea-mcp
      name: "@deepseek-ai/dsh-mcp-client"
      config:
        serverName: rea
        transport: stdio
        command: ${command[0]}
        args: [${command.slice(1).join(", ")}]
- id: rea-mcp
  config:
    serverName: rea
    transport: stdio
    command: redirected-launcher
    args: [mcp]
`,
    );

    // The later direct patch replaces the row's config, so the effective
    // command is the redirect and the registration is stale, not aligned.
    expect(
      (
        await readClientRegistrationStatuses(home, undefined, {
          platform: process.platform,
          environment: {},
        })
      ).find(({ client: name }) => name === "dsh"),
    ).toMatchObject({ state: "stale" });

    // Setup rewrites one canonical entry and drops the superseded direct op.
    expect(
      (await configureClientConfiguration(client, {}, command)).status,
    ).toBe("configured");
    const text = await readFile(client.configPath, "utf8");
    expect(text).not.toContain("redirected-launcher");
    expect(text).not.toMatch(/^- id: rea-mcp$/mu);
    const patches = parseYaml(text) as unknown[];
    expect(patches).toHaveLength(1);
  });

  it("collapses duplicate rea entries into one canonical row", async () => {
    const { client } = await harnessClient();
    await writeFile(
      client.configPath,
      `- insert:
    - id: rea-mcp
      name: "@deepseek-ai/dsh-mcp-client"
      config:
        serverName: rea
        transport: stdio
        command: first-launcher
        args: [mcp]
- insert:
    - id: rea-mcp
      name: "@deepseek-ai/dsh-mcp-client"
      config:
        serverName: rea
        transport: stdio
        command: second-launcher
        args: [mcp]
`,
    );

    expect(
      (await configureClientConfiguration(client, {}, command)).status,
    ).toBe("configured");
    const patches = parseYaml(await readFile(client.configPath, "utf8")) as {
      insert: unknown[];
    }[];
    const reaRows = patches.flatMap(({ insert }) =>
      insert.filter(
        (entry) =>
          typeof entry === "object" &&
          entry !== null &&
          (entry as { id?: unknown }).id === "rea-mcp",
      ),
    );
    expect(reaRows).toHaveLength(1);
  });

  it("reports a foreign server name as stale instead of aligned", async () => {
    const { home, client } = await harnessClient();
    await writeFile(
      client.configPath,
      `- insert:
    - id: rea-mcp
      name: "@deepseek-ai/dsh-mcp-client"
      config:
        serverName: other
        transport: stdio
        command: ${command[0]}
        args: [${command.slice(1).join(", ")}]
`,
    );

    expect(
      (
        await readClientRegistrationStatuses(home, undefined, {
          platform: process.platform,
          environment: {},
        })
      ).find(({ client: name }) => name === "dsh"),
    ).toMatchObject({ state: "stale" });
  });

  it("creates the patch list for an absent file and empties it on uninstall", async () => {
    const { home, client } = await harnessClient();
    expect(
      (await configureClientConfiguration(client, {}, command)).status,
    ).toBe("configured");
    const created = parseYaml(
      await readFile(client.configPath, "utf8"),
    ) as unknown[];
    expect(created).toEqual([
      {
        insert: [
          {
            id: "rea-mcp",
            name: "@deepseek-ai/dsh-mcp-client",
            config: {
              serverName: "rea",
              transport: "stdio",
              command: command[0],
              args: command.slice(1),
            },
          },
        ],
      },
    ]);
    expect((await systemUninstallHost(home).removeClient(client)).status).toBe(
      "removed",
    );
    expect(await readFile(client.configPath, "utf8")).toBe("[]\n");
  });
});

describe("DeepSeek Harness repair boundaries", () => {
  it("repairs a direct-only registration by appending the insert", async () => {
    const { client } = await harnessClient();
    await writeFile(
      client.configPath,
      `- id: rea-mcp
  name: "@deepseek-ai/dsh-mcp-client"
  config:
    serverName: rea
    transport: stdio
    command: stale-launcher
    args: [mcp]
`,
    );

    // An incomplete manual registration has no insertion to rewrite, so the
    // repair appends one canonical row instead of leaving the entry absent.
    expect(
      (await configureClientConfiguration(client, {}, command)).status,
    ).toBe("configured");
    expect(parseYaml(await readFile(client.configPath, "utf8"))).toEqual([
      {
        insert: [
          {
            id: "rea-mcp",
            name: "@deepseek-ai/dsh-mcp-client",
            config: {
              serverName: "rea",
              transport: "stdio",
              command: command[0],
              args: command.slice(1),
            },
          },
        ],
      },
    ]);
  });

  it("updates a grouped entry in place and drops the superseding disable op", async () => {
    const { client } = await harnessClient();
    await writeFile(
      client.configPath,
      `# agent group carrying several tools
- id: agent-group
  insert:
    - id: user-tool
      name: "@deepseek-ai/dsh-mcp-client"
      config:
        serverName: other
        transport: stdio
        command: other-server
    - id: rea-mcp
      name: "@deepseek-ai/dsh-mcp-client"
      config:
        serverName: rea
        transport: stdio
        command: stale-launcher
        args: [mcp]
- id: rea-mcp
  disabled: true
`,
    );

    expect(
      (await configureClientConfiguration(client, {}, command)).status,
    ).toBe("configured");
    const text = await readFile(client.configPath, "utf8");
    expect(text).toContain("# agent group carrying several tools");
    expect(text).not.toMatch(/^- id: rea-mcp$/mu);
    // The entry keeps its position inside the group; nothing moves to a new
    // root-level insertion.
    expect(parseYaml(text)).toEqual([
      {
        id: "agent-group",
        insert: [
          {
            id: "user-tool",
            name: "@deepseek-ai/dsh-mcp-client",
            config: {
              serverName: "other",
              transport: "stdio",
              command: "other-server",
            },
          },
          {
            id: "rea-mcp",
            name: "@deepseek-ai/dsh-mcp-client",
            config: {
              serverName: "rea",
              transport: "stdio",
              command: command[0],
              args: command.slice(1),
            },
          },
        ],
      },
    ]);
  });
});

describe("DeepSeek Harness registration state", () => {
  it("diagnoses a disabled entry as stale and re-enables it on repair", async () => {
    const { home, client } = await harnessClient();
    await writeFile(
      client.configPath,
      `- insert:
    - id: rea-mcp
      name: "@deepseek-ai/dsh-mcp-client"
      disabled: true
      config:
        serverName: rea
        transport: stdio
        command: ${command[0]}
        args: [${command.slice(1).join(", ")}]
`,
    );

    // The command matches, but Cordis never activates a disabled row, so the
    // registration reads as stale rather than aligned.
    expect(
      (
        await readClientRegistrationStatuses(home, undefined, {
          platform: process.platform,
          environment: {},
        })
      ).find(({ client: name }) => name === "dsh"),
    ).toMatchObject({ state: "stale" });

    expect(
      (await configureClientConfiguration(client, {}, command)).status,
    ).toBe("configured");
    const patches = parseYaml(await readFile(client.configPath, "utf8")) as {
      insert: { disabled?: unknown }[];
    }[];
    expect(patches[0]?.insert[0]?.disabled).toBeUndefined();
    expect(
      (await configureClientConfiguration(client, {}, command)).status,
    ).toBe("unchanged");
  });

  it("retains the existing registration environment across a repair", async () => {
    const { client } = await harnessClient();
    await writeFile(
      client.configPath,
      `- insert:
    - id: rea-mcp
      name: "@deepseek-ai/dsh-mcp-client"
      config:
        serverName: rea
        transport: stdio
        command: stale-launcher
        args: [mcp]
        env:
          GHIDRA_INSTALL_DIR: /caller/nondefault/ghidra
`,
    );

    expect(
      (await configureClientConfiguration(client, {}, command)).status,
    ).toBe("configured");
    const patches = parseYaml(await readFile(client.configPath, "utf8")) as {
      insert: { config: { env?: Record<string, string> } }[];
    }[];
    expect(patches[0]?.insert[0]?.config.env).toEqual({
      GHIDRA_INSTALL_DIR: "/caller/nondefault/ghidra",
    });
  });
});

const textOf = (value: unknown): string => String(value);
