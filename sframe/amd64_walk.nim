import std/options
import sframe
import sframe/mem_sim
export mem_sim

type U64Reader* = proc (address: uint64): uint64 {.gcsafe, raises: [], tags: [].}

proc readU64Ptr*(address: uint64): uint64 =
  ## Direct memory read helper for stack walking
  cast[ptr uint64](cast[pointer](address))[]

proc walkStackAmd64*(sec: SFrameSection; sectionBase, startPc, startSp, startFp: uint64; mem: SimMemory; maxFrames: int = 16): seq[uint64] {.raises: [], tags: [].} =
  ## Minimal AMD64 stack walker using SFrame data. Returns PCs from top to bottom.
  var pc = startPc
  var sp = startSp
  var fp = startFp
  var frames: seq[uint64] = @[]
  for _ in 0 ..< maxFrames:
    frames.add pc
    let (found, _, _, freGlobalIdx) = sec.pcToFre(pc, sectionBase)
    if not found: break
    let fre = sec.fres[freGlobalIdx]
    let off = freOffsetsForAbi(sframeAbiAmd64Little, sec.header, fre)
    let baseVal = if off.cfaBase == sframeCfaBaseSp: sp else: fp
    let cfa = baseVal + uint64(cast[int64](off.cfaFromBase))
    if off.raFromCfa.isNone(): break
    let raAddr = cfa + uint64(cast[int64](off.raFromCfa.get()))
    let nextPc = mem.loadU64(raAddr)
    if nextPc == 0'u64: break
    var nextFp = fp
    if off.fpFromCfa.isSome():
      let fpAddr = cfa + uint64(cast[int64](off.fpFromCfa.get()))
      nextFp = mem.loadU64(fpAddr)
    pc = nextPc
    sp = cfa
    fp = nextFp
  result = frames

proc walkStackAmd64With*(sec: SFrameSection; sectionBase, startPc, startSp, startFp: uint64; readU64: U64Reader; maxFrames: int = 16): seq[uint64] {.raises: [], tags: [].} =
  ## AMD64 stack walker using a memory read callback.
  var pc = startPc
  var sp = startSp
  var fp = startFp
  var frames: seq[uint64] = @[]
  for _ in 0 ..< maxFrames:
    frames.add pc
    let (found, _, _, freGlobalIdx) = sec.pcToFre(pc, sectionBase)
    if not found: break
    let fre = sec.fres[freGlobalIdx]
    let off = freOffsetsForAbi(sframeAbiAmd64Little, sec.header, fre)
    let baseVal = if off.cfaBase == sframeCfaBaseSp: sp else: fp
    let cfa = baseVal + uint64(cast[int64](off.cfaFromBase))
    if off.raFromCfa.isNone(): break
    let raAddr = cfa + uint64(cast[int64](off.raFromCfa.get()))
    let nextPc = readU64(raAddr)
    if nextPc == 0'u64: break
    var nextFp = fp
    if off.fpFromCfa.isSome():
      let fpAddr = cfa + uint64(cast[int64](off.fpFromCfa.get()))
      nextFp = readU64(fpAddr)
    pc = nextPc
    sp = cfa
    fp = nextFp
  result = frames

# Hybrid stack walking for -fomit-frame-pointer scenarios

proc isValidCodePointer*(pc: uint64): bool =
  ## Basic heuristic: code addresses should be in a reasonable range
  ## and not look like stack addresses
  pc >= 0x400000'u64 and pc < 0x800000'u64

proc scanStackForReturnAddresses*(startSp: uint64; currentPc: uint64; maxScan: int = 2048): seq[tuple[offset: int, pc: uint64]] =
  ## Scan stack memory looking for potential return addresses
  var results: seq[tuple[offset: int, pc: uint64]] = @[]
  for i in 0 ..< maxScan div 8:
    let address = startSp + uint64(i * 8)
    let val = readU64Ptr(address)
    # Look for valid code pointers that are different from current PC
    if isValidCodePointer(val) and val != currentPc:
      results.add((i * 8, val))
  result = results

proc walkStackWithHybridApproach*(sec: SFrameSection; sectionBase, startPc, startSp, startFp: uint64; readU64: U64Reader; maxFrames: int = 16): seq[uint64] {.raises: [], tags: [].} =
  ## Hybrid stack walker that combines SFrame data with stack scanning for -fomit-frame-pointer
  var frames: seq[uint64] = @[startPc]

  # First, scan the stack to find potential return addresses
  let stackRAs = scanStackForReturnAddresses(startSp, startPc, 1024)

  if stackRAs.len == 0:
    return frames

  # Find potential return addresses by scanning stack memory

  # For each potential return address, validate using SFrame data
  var currentSp = startSp
  for (offset, candidatePc) in stackRAs:
    if frames.len >= maxFrames: break

    # Check if this PC has SFrame data
    let (found, fdeIdx, freLocalIdx, freGlobalIdx) = sec.pcToFre(candidatePc, sectionBase)
    if found:
      # Validate that this is a reasonable next frame
      let funcStart = sec.funcStartAddress(fdeIdx, sectionBase)
      let fde = sec.fdes[fdeIdx]

      # If this looks like a valid caller, add it and search for deeper frames
      if candidatePc > funcStart and candidatePc < (funcStart + uint64(fde.funcSize)):
        frames.add candidatePc
        currentSp = startSp + uint64(offset + 8)  # Move past this return address

        # Recursively search for more frames from this new stack position
        let remainingRAs = scanStackForReturnAddresses(currentSp, candidatePc, 1024)
        for (nextOffset, nextPc) in remainingRAs:
          if frames.len >= maxFrames: break
          let (nextFound, nextFdeIdx, _, _) = sec.pcToFre(nextPc, sectionBase)
          if nextFound:
            let nextFuncStart = sec.funcStartAddress(nextFdeIdx, sectionBase)
            let nextFde = sec.fdes[nextFdeIdx]
            if nextPc > nextFuncStart and nextPc < (nextFuncStart + uint64(nextFde.funcSize)):
              frames.add nextPc
              currentSp += uint64(nextOffset + 8)
        break

  result = frames

proc walkStackAmd64WithFallback*(sec: SFrameSection; sectionBase, startPc, startSp, startFp: uint64; readU64: U64Reader; maxFrames: int = 16): seq[uint64] {.raises: [], tags: [].} =
  ## AMD64 stack walker with fallback from FP to SP base for -fomit-frame-pointer scenarios.
  ## This is the recommended walker for production use as it handles both normal and
  ## -fomit-frame-pointer scenarios gracefully.
  var pc = startPc
  var sp = startSp
  var fp = startFp
  var frames: seq[uint64] = @[]
  for _ in 0 ..< maxFrames:
    frames.add pc
    let (found, _, _, freGlobalIdx) = sec.pcToFre(pc, sectionBase)
    if not found:
      # Fall back to hybrid approach for the rest
      let hybridFrames = walkStackWithHybridApproach(sec, sectionBase, pc, sp, fp, readU64, maxFrames - frames.len)
      for i in 1 ..< hybridFrames.len:  # Skip first frame as it's already in our frames
        frames.add hybridFrames[i]
      break

    let fre = sec.fres[freGlobalIdx]
    var off = freOffsetsForAbi(sframeAbiAmd64Little, sec.header, fre)

    # First try the original CFA calculation
    let originalCfaBase = off.cfaBase
    var baseVal = if off.cfaBase == sframeCfaBaseSp: sp else: fp
    var cfa = baseVal + uint64(cast[int64](off.cfaFromBase))
    if off.raFromCfa.isNone(): break
    let raAddr = cfa + uint64(cast[int64](off.raFromCfa.get()))
    var nextPc = readU64(raAddr)

    # If the result doesn't look like a valid code pointer and we used FP base,
    # fall back to hybrid approach (common with -fomit-frame-pointer)
    if not isValidCodePointer(nextPc) and originalCfaBase == sframeCfaBaseFp:
      let hybridFrames = walkStackWithHybridApproach(sec, sectionBase, pc, sp, fp, readU64, maxFrames - frames.len)
      for i in 1 ..< hybridFrames.len:  # Skip first frame as it's already in our frames
        frames.add hybridFrames[i]
      break

    if nextPc == 0'u64 or not isValidCodePointer(nextPc):
      # Continue with hybrid approach for remaining frames
      let hybridFrames = walkStackWithHybridApproach(sec, sectionBase, pc, sp, fp, readU64, maxFrames - frames.len)
      for i in 1 ..< hybridFrames.len:  # Skip first frame as it's already in our frames
        frames.add hybridFrames[i]
      break

    var nextFp = fp
    if off.fpFromCfa.isSome():
      let fpAddr = cfa + uint64(cast[int64](off.fpFromCfa.get()))
      nextFp = readU64(fpAddr)

    pc = nextPc
    sp = cfa
    fp = nextFp
  result = frames

# readU64Ptr already defined at top of module
