# 32-bit ARM (armhf) analysis through Ghidra

This lane extends native ELF analysis for 32-bit ARM images; it does not execute
ARM code or rehost firmware. It addresses
[#1745](https://github.com/morluto/rea/issues/1745): the `arm` entry in the
provider-neutral architecture set is now backed by a verified lane instead of a
bare allowlist, and Ghidra header auto-selection is not used for the admitted
shape because it has several plausible wrong answers for ARM/Thumb-2 interworked
images.

## Admission boundary

ELF `EM_ARM` targets retain class, byte order, `e_type`, and raw `e_flags` as
provider-neutral facts. Recognition does not mean every ARM variant is
supported.

The lane admits little-endian ELF32 `ET_EXEC` images declaring EABI5.
Hard-float (`armhf`, `EF_ARM_ABI_FLOAT_HARD`) and unspecified float conventions
are covered; `EF_ARM_ABI_FLOAT_SOFT` is refused. ELF64 AArch64 images use the
separate `arm64` lane. Big-endian `armeb`, `EF_ARM_BE8` mixed-endian images,
older or legacy ABIs, PIE (`ET_DYN`), shared images and relocatable objects are
not covered: provider selection returns the specific unsupported constraint
rather than guessing a compatible profile.

## Pinned import language

For the admitted shape REA pins `-processor ARM:LE:32:v7` with the default
compiler spec and checks the bridge-reported `language_id` after import, the
same mechanism the DOS lanes use. A caller-selected
`REA_GHIDRA_LANGUAGE_ID`/`REA_GHIDRA_COMPILER_SPEC_ID` still wins over the pin;
combining the pinned profile with an environment override is a typed refusal
that asks for a reopen without the override.

The profile records the lane identity `elf32-exec-le-eabi5-v7-pinned-v1`, the
raw header facts, and the declared float ABI basis (`hard`, `soft`, or
`unspecified`) without interpreting it into a calling-convention claim.
Sessions carry the limitation that the ELF float ABI declaration does not
change the modeled calling convention.

## Verification

`npm run verify:ghidra:arm` builds a source-owned freestanding fixture with
Clang (`arm-linux-gnueabihf`, ARMv7-A, hard float) containing both an ARM-mode
probe and a Thumb-2 interworked probe with fixed reviewable encodings, checks
REA's ELF interpretation against GNU readelf, asserts the pinned language
after import, decodes both instruction-set states, walks a snapshot round-trip,
and proves typed refusals for legacy-EABI and BE8 header variants plus CLI/MCP
parity. No third-party binary is analyzed and no target code is executed.
