import type { GhidraLanguageOverride } from "../config/ghidraLanguageOverride.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import type { JsonValue } from "../domain/jsonValue.js";

/** EF_ARM masks and flags read from the ELF32 header without interpretation. */
const EABI_VERSION_MASK = 0xff000000;
const EF_ARM_EABI_VER5 = 0x05000000;
const EF_ARM_BE8 = 0x00800000;
const EF_ARM_ABI_FLOAT_SOFT = 0x00000200;
const EF_ARM_ABI_FLOAT_HARD = 0x00000400;

/**
 * Verified 32-bit ARM admission: little-endian ELF32 ET_EXEC with EABI5.
 * Hard-float (armhf) and unspecified float conventions are admitted; the
 * import language is pinned because Ghidra header auto-selection has several
 * plausible wrong answers for ARM/Thumb-2 interworked images.
 */
export const isVerifiedArmAdmission = (target: BinaryTarget): boolean =>
  ghidraArmUnsupportedReason(target) === null;

/** Keep family recognition separate from the deliberately bounded Ghidra lane. */
export const ghidraArmUnsupportedReason = (
  target: BinaryTarget,
): string | null => {
  if (
    target.kind !== "executable" ||
    target.format !== "elf" ||
    target.architecture !== "arm"
  )
    return null;
  const metadata = target.arm;
  if (metadata === undefined)
    return "ARM analysis requires ELF header metadata; a family name alone does not select an ISA or ABI.";
  if (metadata.elfClass !== 32)
    return "This Ghidra ARM lane supports ELF32 only; ELF64 AArch64 images use the separately verified arm64 lane.";
  if (metadata.byteOrder !== "little")
    return "This Ghidra ARM lane supports little-endian images only; big-endian armeb and mixed-endian targets need separate verification.";
  if (metadata.type !== 2)
    return "This Ghidra ARM lane supports ET_EXEC only; PIE (ET_DYN), shared images and relocatable objects need separate load verification.";
  if ((metadata.flags & EABI_VERSION_MASK) !== EF_ARM_EABI_VER5)
    return "This Ghidra ARM lane requires EABI5; legacy ABIs and other EABI versions need separate verification.";
  if ((metadata.flags & EF_ARM_BE8) !== 0)
    return "EF_ARM_BE8 mixed-endian images need separate verification in this Ghidra lane.";
  if ((metadata.flags & EF_ARM_ABI_FLOAT_SOFT) !== 0)
    return "EF_ARM_ABI_FLOAT_SOFT is outside this Ghidra lane; the verified lane covers hard-float and unspecified float conventions.";
  return null;
};

/** Commit source ELF interpretation without confusing target ISA with host CPU. */
export const ghidraArmProfileParameters = (
  target: BinaryTarget,
  languageOverride?: GhidraLanguageOverride,
): Readonly<Record<string, JsonValue>> => {
  if (
    target.kind !== "executable" ||
    target.format !== "elf" ||
    target.architecture !== "arm" ||
    target.arm === undefined
  )
    return {};
  // A deliberate caller-selected language wins over the provider pin; the pin
  // exists because header auto-selection misselects for interworked images.
  return {
    arm_elf: {
      elf_class: target.arm.elfClass,
      byte_order: target.arm.byteOrder,
      type: target.arm.type,
      flags: target.arm.flags,
      float_abi:
        (target.arm.flags & EF_ARM_ABI_FLOAT_HARD) !== 0
          ? "hard"
          : (target.arm.flags & EF_ARM_ABI_FLOAT_SOFT) !== 0
            ? "soft"
            : "unspecified",
    },
    arm_support_lane: "elf32-exec-le-eabi5-v7-pinned-v1",
    ...(languageOverride === undefined
      ? {
          language_id: "ARM:LE:32:v7",
          compiler_spec_id: "default",
          language_selection: "provider-pinned-v1",
        }
      : {}),
  };
};

/** Read the provider-pinned import language back from a resolved profile. */
export const ghidraPinnedArmLanguage = (
  parameters: Readonly<Record<string, unknown>>,
): GhidraLanguageOverride | undefined => {
  if (parameters.language_selection !== "provider-pinned-v1") return undefined;
  const languageId = parameters.language_id;
  const compilerSpecId = parameters.compiler_spec_id;
  if (typeof languageId !== "string" || typeof compilerSpecId !== "string")
    return undefined;
  return compilerSpecId === "language-default"
    ? { languageId }
    : { languageId, compilerSpecId };
};
