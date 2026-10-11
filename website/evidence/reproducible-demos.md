# Reproducible demo evidence

This record supports the [public demo index](../public/demos/index.html) and
tracks the D01–D03 starter scenarios from
[issue #778](https://github.com/morluto/rea/issues/778). Results below separate
source observations, static analysis, browser captures and missing provider or
agent evidence. The verifier runs are not recordings or resource benchmarks.

## D01 · Electron CSV export

- Target: the six source files in `website/public/examples/notes-electron/`.
- Run environment: Windows x64, Node.js 24.18.0, npm 11.16.0, REA 6.4.0 at
  source revision `0ecf3f2438ec`; the package-matched Windows native artifact
  verifier passed. The generated addon is ignored and is not part of this
  change.
- Public CLI analysis Evidence ID: `ev_46841fb660ac9c02a2932b465177397114a4aaaed9fecdebd79b6904d976bd30`.
- Public CLI feature trace Evidence ID:
  `ev_3ece6d552f75f7d4ecb4e303e12703dec3a966a1d479fd1c3aad4685dce68b5e`.
- Public CLI semantic trace Evidence ID for property `invoke`:
  `ev_68c6438a3907198bd130fe5b7fd7fb201372dbd1ab80311a4fd131e97210b6f8`.
- Root artifact SHA-256 for the recorded Windows CRLF bytes:
  `3c11d59338104ba96399bfd05bebf4359ac6a293f49d2b095566456842f4396e`.
- A Linux checkout with LF line endings gives
  `0ee325d4eaf7f94b62b2962044995fe1efe9f1d31411eb035118b19b1f56f7bb` for the
  same six files; the graph remains 29 nodes and 42 edges. These hashes identify
  exact bytes, so the line-ending difference is expected. Evidence IDs also
  include checkout paths and may differ between runs.
- The analyzer parsed all six source files. Its application graph had 29 nodes
  and 42 edges. `trace_application_feature` for the exact
  `notes:export` seed returned complete coverage of 29 nodes and 42 edges.
- The semantic graph contained 180 nodes and 108 relationships. A
  `forward-influence` query seeded by property `invoke` returned `ambiguous`
  status, partial coverage, one seed match and one relevant unknown. A literal
  semantic query for `notes:export` returned no seed match; that string is
  represented in the application graph's IPC channel evidence instead. Neither
  result establishes a runtime invocation.
- A real agent transcript was not produced. The isolated Codex evaluation
  failed because this host did not have a usable login for its disposable
  account. Its temporary target, auth file and report were removed. Agent
  routing, answer quality and transcript citations therefore remain
  unverified.
- Public reproduction: run the pinned `npx rea-agents@6.4.0` commands from
  outside the repository checkout, using an absolute fixture path as shown on
  the demo page. For a source-checkout run, use `node scripts/rea.mjs` from the
  repository root after `npm ci` and `npm run build`. The evidence in this
  record was separately rerun from the source checkout; that Windows run
  required the matching native artifact. The fixture and its published source
  digests are recorded in
  [`guide-examples.md`](guide-examples.md).

## D02 · Native function

- Source fixture: `tests/conformance/c/fixture.c`. It defines
  `rea_entry`, `rea_branch` and `rea_leaf`, along with the marker strings
  `REA_C_ENTRY` and `REA_C_LEAF`.
- `npm run build:fixtures` and `npm run verify:fixtures` are the source-owned
  fixture generation and integrity checks. The fixture builder supports Linux
  and macOS and writes generated files beneath ignored `build/conformance/`.
- The local Windows host did not have a C compiler or a configured Ghidra,
  IDA or Hopper provider. The real native analysis and cleanup lifecycle were
  not run. No pseudocode, assembly, function references or native-provider
  result are asserted here.
- A future provider run should record its provider ID/version, host and target
  digest, source-backed function evidence, `close_binary` result, verifier
  report and cleanup outcome. The public-page CLI recipe uses Ghidra; use the
  documented operation actually supported by the selected provider.

## D03 · Browser action comparison

- Fixture: the `/portfolio-demo` route served by
  `scripts/fixtures/browser-verifier-site.mjs` on a loopback-only HTTP server.
  It returns one of two predetermined results after a button click.
- Workflow: two real `capture-browser-scenario` CLI runs each click Export
  notes and wait for `#result[data-state='ready']`; the verifier then invokes
  `compare-web-captures` on their normalized results.
- Run environment: REA 6.4.0 at upstream source revision `13e03e94363a`, with
  this branch's verifier changes, Node.js 24.18.0, npm 11.16.0 and Chrome
  154.0.8037.99. Verifier run ID: `b8b2d376-d5a4-495a-b558-dedfc0884d1d`.
  The captures aligned at the same
  step IDs. The overall comparison was `changed`; the result step contained
  one changed DOM artifact. The baseline text was `Exported 2 notes`; the
  changed text was `Exported 3 notes`.
- Cleanup: both launched browser processes were terminated, both temporary
  profiles were removed, the loopback server and page proxy were closed, and
  the temporary comparison input directory was removed.
- The verifier could not sample its own Windows process lineage because it
  retains no native Job Object lease. The browser provider's owned-process
  cleanup result was verified separately; this does not provide CPU or memory
  measurements.
- Reproduction command: `npm run verify:browser`. This covers the real Chrome
  provider against the source-owned fixture; it does not demonstrate behavior
  on an arbitrary external website.

## Measurements and publication

Time to first result, total scenario duration, process-family CPU and RSS, and
temporary working-space usage were not captured with a controlled process-tree
measurement. Their values are unknown. No video recording or clean-install
usability run is included. The D01 agent transcript and D02 provider workflow
remain follow-up work, so this evidence does not satisfy every completion item
in issue #778 or support closing it.
