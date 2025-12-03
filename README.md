SFrame (Nim) — minimal implementation and walkers

This repo contains a minimal Nim implementation of the SFrame v2 format (see docs/sframe-spec.md), including:

- Core types and encode/decode: `sframe.nim`
- AMD64 stack walker + simulated memory: `sframe/amd64_walk.nim`
- AArch64 stack walker + simulated memory: `sframe/aarch64_walk.nim`

Running tests

- `nim c -r tests/tfile.nim`
- `nim c -r tests/twalk_amd64.nim`
- `nim c -r tests/twalk_aarch64.nim`

Quick usage (AMD64)

```
import sframe
import sframe/amd64_walk

# Build or parse an SFrameSection named `sec` and compute `sectionBase`.

# Initialize simulated memory for example purposes (your tracer would read live memory):
var mem = initSimMemory(0x70000000'u64, 0x1000)

# Starting registers for the topmost frame (PC/SP/FP):
let startPc = sectionBase + 0x1000'u64 + 4'u64
let startSp = 0x70000020'u64
let startFp = 0'u64

# Walk up to 16 frames; returns a list of PCs
let frames = walkStackAmd64(sec, sectionBase, startPc, startSp, startFp, mem, maxFrames = 16)
```

For AArch64, import `sframe/aarch64_walk` and call `walkStackAarch64` with the same arguments.

Notes

- The walkers use SFrame FRE semantics to compute CFA, RA, and FP locations.
- AMD64 uses `header.cfaFixedRaOffset` for RA; AArch64 uses RA/FP offsets from FRE.
- This is a minimal implementation for testing and experimentation; not a full tracer.

