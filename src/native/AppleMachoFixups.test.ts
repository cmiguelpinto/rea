import { describe, expect, it } from "vitest";

import {
  decodeChainedPointer,
  parsePointerFixups,
} from "./AppleMachoFixups.js";
import { parsePropertyAttributes } from "./AppleObjcProperties.js";
import type { Segment } from "./AppleMachoSelection.js";

const BASE = 0x100000000n;
const IMPORTS = [
  {
    symbol: "_OBJC_CLASS_$_NSObject",
    library: "/usr/lib/libobjc.A.dylib",
    weak: false,
    addend: 0n,
  },
  {
    symbol: "_free",
    library: "/usr/lib/libSystem.B.dylib",
    weak: true,
    addend: 4n,
  },
];

const field = (value: bigint, from: number): bigint => value << BigInt(from);

describe("chained pointer decoding", () => {
  it("decodes DYLD_CHAINED_PTR_64 and _64_OFFSET rebases and binds", () => {
    const rebase = 0x4000n | field(0x80n, 36) | field(3n, 51);
    expect(decodeChainedPointer(BASE + 0x4000n, 2, BASE, IMPORTS)).toEqual({
      kind: "rebase",
      target: BASE + 0x4000n,
    });
    expect(decodeChainedPointer(rebase, 6, BASE, IMPORTS)).toEqual({
      kind: "rebase",
      target: (0x80n << 56n) + BASE + 0x4000n,
    });
    const bind = 1n | field(2n, 24) | field(1n, 63);
    expect(decodeChainedPointer(bind, 6, BASE, IMPORTS)).toEqual({
      kind: "bind",
      symbol: "_free",
      library: "/usr/lib/libSystem.B.dylib",
      weak: true,
      addend: 6n,
    });
  });

  it("decodes arm64e plain, authenticated and 24-bit binds", () => {
    expect(decodeChainedPointer(0x8000n, 9, BASE, IMPORTS)).toEqual({
      kind: "rebase",
      target: BASE + 0x8000n,
    });
    expect(decodeChainedPointer(BASE + 0x8000n, 1, BASE, IMPORTS)).toEqual({
      kind: "rebase",
      target: BASE + 0x8000n,
    });
    const authRebase = 0x8000n | field(0x1234n, 32) | field(1n, 63);
    expect(decodeChainedPointer(authRebase, 1, BASE, IMPORTS)).toEqual({
      kind: "rebase",
      target: BASE + 0x8000n,
    });
    const authBind = 0n | field(1n, 62) | field(1n, 63);
    expect(decodeChainedPointer(authBind, 9, BASE, IMPORTS)).toMatchObject({
      kind: "bind",
      symbol: "_OBJC_CLASS_$_NSObject",
      addend: 0n,
    });
    const bind24 = 1n | field(0x7ffffn, 32) | field(1n, 62);
    expect(decodeChainedPointer(bind24, 12, BASE, IMPORTS)).toMatchObject({
      kind: "bind",
      symbol: "_free",
      addend: 3n,
    });
    expect(() =>
      decodeChainedPointer(field(1n, 62) | 9n, 9, BASE, IMPORTS),
    ).toThrow("Chained bind ordinal 9 has no import");
    expect(() => decodeChainedPointer(1n, 3, BASE, IMPORTS)).toThrow(
      "Unsupported chained pointer format 3",
    );
  });
});

/** Build `LC_DYLD_CHAINED_FIXUPS` data with one fixup segment and the given imports. */
const chainedData = (format: 1 | 2 | 3): Buffer => {
  const symbols = Buffer.from("\0_OBJC_CLASS_$_NSObject\0_free\0");
  const importSize = format === 3 ? 16 : format === 2 ? 8 : 4;
  const imports = Buffer.alloc(importSize * 2);
  const entry = (
    index: number,
    {
      ordinal,
      weak,
      nameOffset,
      addend,
    }: {
      ordinal: number;
      weak: boolean;
      nameOffset: number;
      addend: number;
    },
  ) => {
    const at = index * importSize;
    if (format === 3) {
      imports.writeBigUInt64LE(
        BigInt(ordinal & 0xffff) |
          (BigInt(weak ? 1 : 0) << 16n) |
          (BigInt(nameOffset) << 32n),
        at,
      );
      imports.writeBigInt64LE(BigInt(addend), at + 8);
    } else {
      imports.writeUInt32LE(
        ((nameOffset << 9) | ((weak ? 1 : 0) << 8) | (ordinal & 0xff)) >>> 0,
        at,
      );
      if (format === 2) imports.writeInt32LE(addend, at + 4);
    }
  };
  entry(0, { ordinal: 1, weak: false, nameOffset: 1, addend: 0 });
  entry(1, { ordinal: 2, weak: true, nameOffset: 24, addend: 7 });
  // starts_in_image: two segments, only the second has fixups.
  const starts = Buffer.alloc(12 + 24);
  starts.writeUInt32LE(2, 0);
  starts.writeUInt32LE(0, 4);
  starts.writeUInt32LE(12, 8);
  starts.writeUInt32LE(24, 12);
  starts.writeUInt16LE(0x4000, 16);
  starts.writeUInt16LE(6, 18);
  starts.writeBigUInt64LE(0x4000n, 20);
  starts.writeUInt16LE(1, 32);
  starts.writeUInt16LE(8, 34);
  const header = Buffer.alloc(28);
  header.writeUInt32LE(0, 0);
  header.writeUInt32LE(28, 4);
  header.writeUInt32LE(28 + starts.length, 8);
  header.writeUInt32LE(28 + starts.length + imports.length, 12);
  header.writeUInt32LE(2, 16);
  header.writeUInt32LE(format, 20);
  header.writeUInt32LE(0, 24);
  const data = Buffer.alloc(0x8000);
  Buffer.concat([header, starts, imports, symbols]).copy(data);
  data.writeBigUInt64LE(1n | field(1n, 63), 0x4008);
  return data;
};

const SEGMENTS: Segment[] = [
  { address: BASE, size: 0x4000n, offset: 0, executable: true },
  { address: BASE + 0x4000n, size: 0x4000n, offset: 0x4000, executable: false },
];

describe("pointer fixup tables", () => {
  it("reports unsupported pointer formats even when no pointer is visited", () => {
    const data = chainedData(1);
    data.writeUInt16LE(99, 46);
    const fixups = parsePointerFixups(
      data,
      {
        chained: { offset: 0, size: data.length },
        binds: [],
        rebases: [],
        dylibs: [],
      },
      SEGMENTS,
      BASE,
    );
    expect(fixups.failures).toContain("Unsupported chained pointer format 99");
  });

  it("keeps unread LC_DYLD_INFO rebase bytes when chained fixups are present", () => {
    const data = chainedData(1);
    const fixups = parsePointerFixups(
      data,
      {
        chained: { offset: 0, size: data.length },
        binds: [],
        rebases: [{ offset: 8, size: 12 }],
        dylibs: [],
      },
      SEGMENTS,
      BASE,
    );
    expect(fixups).toMatchObject({
      kind: "chained",
      unreadRebaseBytes: 12,
    });
  });

  it("does not decode unreferenced imports while constructing fixup facts", () => {
    const data = chainedData(1);
    // The second import's name leaves the pool. Preserve the first import
    // and defer that distinct failure until its pointer is examined.
    data.writeUInt32LE(0xffff_ff00, data.readUInt32LE(8) + 4);
    const fixups = parsePointerFixups(
      data,
      {
        chained: { offset: 0, size: 128 },
        binds: [],
        rebases: [],
        dylibs: [],
      },
      SEGMENTS,
      BASE,
    );
    expect(fixups.decode(BASE + 0x4008n, field(1n, 63))).toMatchObject({
      kind: "bind",
      symbol: "_OBJC_CLASS_$_NSObject",
    });
    expect(fixups.issues).toEqual([]);
    expect(fixups.decode(BASE + 0x4008n, 1n | field(1n, 63))).toMatchObject({
      kind: "unsupported",
    });
    expect(fixups.issues).toMatchObject([
      { code: "chained_pointer_decode_failed" },
    ]);
  });

  for (const format of [1, 2, 3] as const)
    it(`reads chained import format ${format}`, () => {
      const data = chainedData(format);
      const fixups = parsePointerFixups(
        data,
        {
          chained: { offset: 0, size: data.length },
          binds: [],
          rebases: [],
          dylibs: ["/usr/lib/libobjc.A.dylib", "/usr/lib/libSystem.B.dylib"],
        },
        SEGMENTS,
        BASE,
      );
      expect(fixups).toMatchObject({
        kind: "chained",
        formats: ["DYLD_CHAINED_PTR_64_OFFSET"],
      });
      expect(fixups.decode(BASE + 0x4008n, 1n | field(1n, 63))).toMatchObject({
        kind: "bind",
        symbol: "_free",
        library: "/usr/lib/libSystem.B.dylib",
        weak: true,
        addend: format === 1 ? 0n : 7n,
      });
      // Pointers outside fixup segments are stored plainly.
      expect(fixups.decode(BASE + 0x10n, 0x1234n)).toEqual({
        kind: "rebase",
        target: 0x1234n,
      });
    });
});
describe("chained pointer membership", () => {
  it("retains a valid later page after an earlier chain fails", () => {
    const data = chainedData(1);
    data.copyWithin(66, 64, 128);
    data.writeUInt32LE(66, 8);
    data.writeUInt32LE(74, 12);
    data.writeUInt32LE(26, 40);
    data.writeUInt16LE(0x1000, 44);
    data.writeUInt16LE(2, 60);
    data.writeUInt16LE(8, 64);
    data.writeBigUInt64LE(field(0xfffn, 51), 0x4008);
    data.writeBigUInt64LE(0x1234n, 0x5008);
    const fixups = parsePointerFixups(
      data,
      {
        chained: { offset: 0, size: 160 },
        binds: [],
        rebases: [],
        dylibs: [],
      },
      SEGMENTS,
      BASE,
    );
    expect(fixups.issues).toMatchObject([
      { code: "chained_pointer_walk_failed" },
    ]);
    expect(fixups.decode(BASE + 0x5008n, data.readBigUInt64LE(0x5008))).toEqual(
      { kind: "rebase", target: BASE + 0x1234n },
    );
  });
  it.each([2, 6, 1, 9, 12])(
    "decodes only chain members for pointer format %i",
    (pointerFormat) => {
      const data = chainedData(1);
      data.writeUInt16LE(pointerFormat, 46);
      const generic = pointerFormat === 2 || pointerFormat === 6;
      const bindBit = generic ? 63 : 62;
      data.writeBigUInt64LE(field(4n, 51) | field(1n, bindBit), 0x4008);
      const second = generic ? 0x4018 : 0x4028;
      data.writeBigUInt64LE(1n | field(1n, bindBit), second);
      const plain = BASE + 0x1234n;
      data.writeBigUInt64LE(plain, 0x4010);
      const fixups = parsePointerFixups(
        data,
        {
          chained: { offset: 0, size: 128 },
          binds: [],
          rebases: [],
          dylibs: [],
        },
        SEGMENTS,
        BASE,
      );
      expect(fixups.issues).toEqual([]);
      expect(
        fixups.decode(BASE + 0x4008n, data.readBigUInt64LE(0x4008)),
      ).toMatchObject({
        kind: "bind",
        symbol: "_OBJC_CLASS_$_NSObject",
      });
      expect(
        fixups.decode(BASE + BigInt(second), data.readBigUInt64LE(second)),
      ).toMatchObject({
        kind: "bind",
        symbol: "_free",
      });
      expect(fixups.decode(BASE + 0x4010n, plain)).toEqual({
        kind: "rebase",
        target: plain,
      });
      expect(fixups.decode(BASE + 0x4030n, 0n)).toEqual({
        kind: "rebase",
        target: 0n,
      });
    },
  );

  it("keeps NONE pages and pages absent from the table plain, and decodes a chained zero", () => {
    const data = chainedData(1);
    data.writeBigUInt64LE(0n, 0x4008);
    const commands = {
      chained: { offset: 0, size: 128 },
      binds: [],
      rebases: [],
      dylibs: [],
    } as const;
    const fixups = parsePointerFixups(data, commands, SEGMENTS, BASE);
    expect(fixups.decode(BASE + 0x4008n, 0n)).toEqual({
      kind: "rebase",
      target: BASE,
    });
    data.writeUInt16LE(0xffff, 62);
    data.writeUInt16LE(99, 46);
    data.writeUInt16LE(0x1000, 44);
    const unknown = parsePointerFixups(data, commands, SEGMENTS, BASE);
    expect(unknown.decode(BASE + 0x4008n, BASE + 8n)).toEqual({
      kind: "rebase",
      target: BASE + 8n,
    });
    expect(unknown.decode(BASE + 0x5008n, BASE + 16n)).toEqual({
      kind: "rebase",
      target: BASE + 16n,
    });
  });
});
describe("malformed chained pointer coverage", () => {
  it.each(["link", "multi"])(
    "reports malformed %s chains without claiming complete fixups",
    (malformed) => {
      const data = chainedData(1);
      if (malformed === "link")
        data.writeBigUInt64LE(field(0xfffn, 51), 0x4008);
      else data.writeUInt16LE(0x8000, 62);
      const fixups = parsePointerFixups(
        data,
        {
          chained: { offset: 0, size: 128 },
          binds: [],
          rebases: [],
          dylibs: [],
        },
        SEGMENTS,
        BASE,
      );
      expect(fixups.issues).toMatchObject([
        { code: "chained_pointer_walk_failed" },
      ]);
      if (malformed === "link")
        expect(
          fixups.decode(BASE + 0x4008n, data.readBigUInt64LE(0x4008)),
        ).toEqual({ kind: "rebase", target: BASE });
      expect(fixups.decode(BASE + 0x4010n, 0n)).toMatchObject({
        kind: "unsupported",
      });
    },
  );

  it.each([
    [0, 1, "header version"],
    [4, 126, "starts table"],
    [8, 63, "starts table"],
    [40, 22, "page starts"],
    [48, 0x1000, "segment offset"],
  ] as const)(
    "rejects malformed chained structure at byte %i",
    (at, value, message) => {
      const data = chainedData(1);
      data.writeUInt32LE(value, at);
      expect(() =>
        parsePointerFixups(
          data,
          {
            chained: { offset: 0, size: 128 },
            binds: [],
            rebases: [],
            dylibs: [],
          },
          SEGMENTS,
          BASE,
        ),
      ).toThrow(message);
    },
  );
});
describe("chained import library identity", () => {
  it.each([1, 2, 3] as const)(
    "retains positive and special library ordinals for import format %i",
    (format) => {
      const data = chainedData(format);
      const importAt = data.readUInt32LE(8);
      const width = format === 3 ? 16 : 8;
      const maximum = format === 3 ? 0xfff0 : 0xf0;
      const libraries = Array.from(
        { length: maximum },
        (_, index) => `/library-${index + 1}`,
      );
      for (const ordinal of [
        1 << (width - 1),
        maximum,
        maximum + 1,
        (1 << width) - 1,
      ]) {
        if (format === 3)
          data.writeBigUInt64LE(
            (data.readBigUInt64LE(importAt) & ~0xffffn) | BigInt(ordinal),
            importAt,
          );
        else
          data.writeUInt32LE(
            (data.readUInt32LE(importAt) & ~0xff) | ordinal,
            importAt,
          );
        data.writeBigUInt64LE(field(1n, 63), 0x4008);
        const fixups = parsePointerFixups(
          data,
          {
            chained: { offset: 0, size: 160 },
            binds: [],
            rebases: [],
            dylibs: libraries,
          },
          SEGMENTS,
          BASE,
        );
        expect(
          fixups.decode(BASE + 0x4008n, data.readBigUInt64LE(0x4008)),
        ).toMatchObject({
          kind: "bind",
          library: ordinal <= maximum ? libraries[ordinal - 1] : null,
        });
      }
    },
  );
});
describe("legacy pointer fixup streams", () => {
  it("interprets legacy bind, weak-bind and lazy-bind opcodes", () => {
    const opcodes = Buffer.from([
      0x11, // SET_DYLIB_ORDINAL_IMM 1
      0x40,
      ...Buffer.from("_OBJC_CLASS_$_NSObject\0"),
      0x51, // SET_TYPE_IMM pointer
      0x71,
      0x08, // SET_SEGMENT_AND_OFFSET segment 1 + 8
      0x90, // DO_BIND
      0xc0,
      0x02,
      0x08, // DO_BIND_ULEB_TIMES_SKIPPING_ULEB 2 times, skip 8
      0x00,
    ]);
    const lazy = Buffer.from([
      0x71,
      0x30,
      0x12,
      0x40,
      ...Buffer.from("_free\0"),
      0x90,
      0x00,
      0x71,
      0x38,
      0x12,
      0x40,
      ...Buffer.from("_malloc\0"),
      0x90,
      0x00,
    ]);
    const data = Buffer.concat([opcodes, lazy]);
    const fixups = parsePointerFixups(
      data,
      {
        chained: null,
        binds: [
          { offset: 0, size: opcodes.length, stream: "bind" },
          { offset: opcodes.length, size: lazy.length, stream: "lazy" },
        ],
        rebases: [],
        dylibs: ["/usr/lib/libobjc.A.dylib", "/usr/lib/libSystem.B.dylib"],
      },
      SEGMENTS,
      BASE,
    );
    expect(fixups.kind).toBe("dyld-info");
    expect(fixups.failures).toEqual([]);
    for (const offset of [0x08n, 0x10n, 0x20n])
      expect(fixups.decode(BASE + 0x4000n + offset, 0n)).toMatchObject({
        kind: "bind",
        symbol: "_OBJC_CLASS_$_NSObject",
        library: "/usr/lib/libobjc.A.dylib",
      });
    expect(fixups.decode(BASE + 0x4038n, 0n)).toMatchObject({
      symbol: "_malloc",
      library: "/usr/lib/libSystem.B.dylib",
    });
    expect(fixups.decode(BASE + 0x4018n, 0x99n)).toEqual({
      kind: "rebase",
      target: 0x99n,
    });
  });
});

describe("Objective-C property attributes", () => {
  it("parses type, ownership, accessors and quoted class names", () => {
    expect(
      parsePropertyAttributes(
        "title",
        'T@"NSString<NSCopying, NSSecureCoding>",C,N,GcustomTitle,V_title',
      ),
    ).toEqual({
      name: "title",
      type_encoding: '@"NSString<NSCopying, NSSecureCoding>"',
      atomicity: "nonatomic",
      attributes: [
        { name: "T", value: '@"NSString<NSCopying, NSSecureCoding>"' },
        { name: "C", value: "" },
        { name: "N", value: "" },
        { name: "G", value: "customTitle" },
        { name: "V", value: "_title" },
      ],
      is_readonly: false,
      getter: "customTitle",
      setter: null,
    });
    expect(parsePropertyAttributes("count", "Tq,R")).toMatchObject({
      type_encoding: "q",
      is_readonly: true,
      atomicity: "atomic",
    });
    expect(parsePropertyAttributes("count", "Tq,R,N").atomicity).toBe(
      "nonatomic",
    );
    expect(parsePropertyAttributes("count", "").atomicity).toBeNull();
    expect(parsePropertyAttributes("count", "R").atomicity).toBeNull();
  });
});
