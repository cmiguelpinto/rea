import { describe, expect, it } from "vitest";

import { ROLLDOWN_MODULE_INTEROP } from "./javascriptModuleInterop.fixture.js";
import { analyzeJavaScriptStaticSource } from "./javascriptStaticAnalysis.js";

const CAPTURED_INTEROP = ROLLDOWN_MODULE_INTEROP.replace(
  "__defProp = Object.defineProperty",
  "__defProp = define",
);
const WINDOW = `let electron = require("electron");
  electron = __toESM(electron, 1); new electron.BrowserWindow({});`;

describe("captured intrinsic invocation reads", () => {
  it.each([
    '(0, Object.defineProperty.call)(null,Object,"create",{value:replacement});',
    '(0, Object.defineProperty.apply)(null,[Object,"create",{value:replacement}]);',
  ])(
    "does not invent a receiver for a detached invocation member: %s",
    (invoke) => {
      const result = analyzeJavaScriptStaticSource(`
      ${invoke}
      ${ROLLDOWN_MODULE_INTEROP} ${WINDOW}
    `);
      expect(result.electron.browser_windows).toHaveLength(1);
    },
  );

  it("retains callee-prefix effects before classifying the invocation", () => {
    const result = analyzeJavaScriptStaticSource(`
      const define = Object.defineProperty;
      const metadata = {};
      (Object.defineProperty = replacement, Object.defineProperty)(metadata,"x",{value:1});
      ${CAPTURED_INTEROP} ${WINDOW}
    `);
    expect(result.electron.browser_windows).toEqual([]);
  });

  it("retains a callee selected before an argument replaces its global property", () => {
    const result = analyzeJavaScriptStaticSource(`
      const define = Object.defineProperty;
      const metadata = {};
      Object.defineProperty(metadata,"x",(Object.defineProperty = replacement,{value:1}));
      ${CAPTURED_INTEROP} ${WINDOW}
    `);
    expect(result.electron.browser_windows).toHaveLength(1);
  });

  it.each([
    'define.call(null,metadata,"x",{value:1});',
    'define.apply(null,[metadata,"x",{value:1}]);',
    'const change = define.bind(null,metadata,"x"); change({value:1});',
    'const also = define; also.call(null,metadata,"x",{value:1});',
  ])("retains a function captured before global replacement: %s", (invoke) => {
    const result = analyzeJavaScriptStaticSource(`
      const define = Object.defineProperty;
      Object.defineProperty = replacement;
      const metadata = {}; ${invoke}
      ${CAPTURED_INTEROP} ${WINDOW}
    `);
    expect(result.electron.browser_windows).toHaveLength(1);
  });

  it.each([
    ["call", 'define.call(null,metadata,"x",{value:1});'],
    ["apply", 'define.apply(null,[metadata,"x",{value:1}]);'],
    [
      "bind",
      'const change = define.bind(null,metadata,"x"); change({value:1});',
    ],
  ])(
    "checks the later %s property read on a captured function",
    (method, invoke) => {
      for (const owner of ["define", "Function.prototype"]) {
        const result = analyzeJavaScriptStaticSource(`
        const define = Object.defineProperty;
        ${owner}.${method} = replacement;
        const metadata = {}; ${invoke}
        ${CAPTURED_INTEROP} ${WINDOW}
      `);
        expect(result.electron.browser_windows, owner).toEqual([]);
      }
    },
  );
});
