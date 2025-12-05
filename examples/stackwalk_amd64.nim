import std/[os, osproc, strutils, strformat, sequtils, options]
import sframe
import sframe/amd64_walk

## NOTE: requires binutils 2.44+ (?)
##
when defined(gcc) or true:
  {.emit: """
  static inline void* nframe_get_fp(void) { return __builtin_frame_address(0); }
  static inline void* nframe_get_ra(void) { return __builtin_return_address(0); }
  static inline void* nframe_get_fp_n(int n) { return __builtin_frame_address(n); }
  static inline void* nframe_get_ra_n(int n) { return __builtin_return_address(n); }
  static inline void* nframe_get_sp(void) {
    void* sp;
#if defined(__x86_64__) || defined(__amd64__)
    __asm__ __volatile__("mov %%rsp, %0" : "=r"(sp));
#elif defined(__aarch64__)
    __asm__ __volatile__("mov %0, sp" : "=r"(sp));
#else
    sp = __builtin_frame_address(0);
#endif
    return sp;
  }
  """.}
  proc nframe_get_fp(): pointer {.importc.}
  proc nframe_get_ra(): pointer {.importc.}
  proc nframe_get_fp_n(n: cint): pointer {.importc.}
  proc nframe_get_ra_n(n: cint): pointer {.importc.}
  proc nframe_get_sp(): pointer {.importc.}

proc getSframeBase(exe: string): uint64 =
  let objdump = "/usr/local/bin/x86_64-unknown-freebsd15.0-objdump"
  let hdr = execProcess(objdump & " -h " & exe)
  for line in hdr.splitLines():
    if line.contains(" .sframe ") or (line.contains(".sframe") and line.contains("VMA")):
      # expect: " 16 .sframe       00000073  0000000000400680 ..."
      let parts = line.splitWhitespace()
      if parts.len >= 4:
        return parseHexInt(parts[3]).uint64
  return 0'u64

proc readU64Ptr(address: uint64): uint64 =
  cast[ptr uint64](cast[pointer](address))[]

proc isValidCodePointer(pc: uint64): bool =
  # Basic heuristic: code addresses should be in a reasonable range
  # and not look like stack addresses
  pc >= 0x400000'u64 and pc < 0x800000'u64

proc walkStackAmd64WithFallback(sec: SFrameSection; sectionBase, startPc, startSp, startFp: uint64; readU64: U64Reader; maxFrames: int = 16): seq[uint64] {.raises: [], tags: [].} =
  ## AMD64 stack walker with fallback from FP to SP base for -fomit-frame-pointer scenarios.
  var pc = startPc
  var sp = startSp
  var fp = startFp
  var frames: seq[uint64] = @[]
  for _ in 0 ..< maxFrames:
    frames.add pc
    let (found, _, _, freGlobalIdx) = sec.pcToFre(pc, sectionBase)
    if not found: break
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
    # fall back to simplified SP-based calculation (for -fomit-frame-pointer case)
    if not isValidCodePointer(nextPc) and originalCfaBase == sframeCfaBaseFp:
      # For -fomit-frame-pointer, try simple SP-based layouts
      # This is a heuristic fallback when SFrame data assumes FP but FP isn't available
      for spOffset in [0'i32, 8'i32, 16'i32]:
        let testRaAddr = sp + uint64(spOffset)
        let testPc = readU64(testRaAddr)
        if isValidCodePointer(testPc):
          nextPc = testPc
          cfa = sp + uint64(spOffset + 8)  # CFA is just past the RA
          off.cfaBase = sframeCfaBaseSp
          break

    if nextPc == 0'u64 or not isValidCodePointer(nextPc): break

    var nextFp = fp
    if off.fpFromCfa.isSome():
      let fpAddr = cfa + uint64(cast[int64](off.fpFromCfa.get()))
      nextFp = readU64(fpAddr)

    pc = nextPc
    sp = cfa
    fp = nextFp
  result = frames

proc buildFramesFrom(startPc, startSp, startFp: uint64): seq[uint64] =
  let exe = getAppFilename()
  # Work on a temp copy to avoid Text file busy issues with objcopy on running binary
  let exeCopy = getTempDir() / "self.copy"
  try: discard existsOrCreateDir(getTempDir()) except: discard
  try:
    copyFile(exe, exeCopy)
  except CatchableError:
    discard
  # Extract .sframe to a temp path
  let tmp = getTempDir() / "self.out.sframe"
  let objcopy = "/usr/local/bin/x86_64-unknown-freebsd15.0-objcopy"
  let cmd = objcopy & " --dump-section .sframe=" & tmp & " " & exeCopy
  discard execShellCmd(cmd)
  let sdata = readFile(tmp)
  var bytes = newSeq[byte](sdata.len)
  for i in 0 ..< sdata.len: bytes[i] = byte(sdata[i])
  let sec = decodeSection(bytes)
  let sectionBase = getSframeBase(exeCopy)

  # For -fomit-frame-pointer case, we need to handle the case where SFrame data
  # still references FP base but FP is not actually available. We'll use a custom
  # walker that can fall back from FP to SP-based calculation.
  walkStackAmd64WithFallback(sec, sectionBase, startPc, startSp, startFp, readU64Ptr, maxFrames = 16)

proc buildFrames(): seq[uint64] =
  # Capture current frame state and walk (starting at caller of this function)
  var local = 0
  let sp = cast[uint64](addr local)
  let fp = cast[uint64](nframe_get_fp())
  let pc = cast[uint64](nframe_get_ra())
  buildFramesFrom(pc, sp, fp)

var lastFrames: seq[uint64] = @[]

proc nframe_entry_build*() =
  # Start from the immediate caller of this function.
  # Note: This example demonstrates SFrame parsing but may not work perfectly with
  # -fomit-frame-pointer due to GCC still generating FP-centric SFrame data.
  let fp0 = cast[uint64](nframe_get_fp())
  let sp0 = cast[uint64](nframe_get_sp())
  let pc0 = cast[uint64](nframe_get_ra())
  echo fmt"Starting stack trace from PC: 0x{pc0.toHex()} SP: 0x{sp0.toHex()} FP: 0x{fp0.toHex()}"

  # Load and parse SFrame section
  let exe = getAppFilename()
  let exeCopy = getTempDir() / "self.copy"
  try: discard existsOrCreateDir(getTempDir()) except: discard
  try: copyFile(exe, exeCopy) except: discard
  let tmp = getTempDir() / "self.out.sframe"
  let objcopy = "/usr/local/bin/x86_64-unknown-freebsd15.0-objcopy"
  let cmd = objcopy & " --dump-section .sframe=" & tmp & " " & exeCopy
  discard execShellCmd(cmd)
  let sdata = readFile(tmp)
  var bytes = newSeq[byte](sdata.len)
  for i in 0 ..< sdata.len: bytes[i] = byte(sdata[i])
  let sec = decodeSection(bytes)
  let sectionBase = getSframeBase(exeCopy)

  echo fmt"SFrame section: base=0x{sectionBase.toHex()}, {sec.fdes.len} functions, {sec.fres.len} frame entries"
  echo fmt"Header: RA offset={sec.header.cfaFixedRaOffset}, FP offset={sec.header.cfaFixedFpOffset}"

  # Show SFrame data for current PC
  let (found, fdeIdx, freLocalIdx, freGlobalIdx) = sec.pcToFre(pc0, sectionBase)
  if found:
    let fde = sec.fdes[fdeIdx]
    let fre = sec.fres[freGlobalIdx]
    let off = freOffsetsForAbi(sframeAbiAmd64Little, sec.header, fre)
    echo fmt"Found FDE[{fdeIdx}]: function 0x{sec.funcStartAddress(fdeIdx, sectionBase).toHex()}"
    echo fmt"Found FRE[{freLocalIdx}]: CFA base={off.cfaBase}, offset={off.cfaFromBase}"
    let raInfo = if off.raFromCfa.isSome(): $off.raFromCfa.get() else: "fixed"
    let fpInfo = if off.fpFromCfa.isSome(): $off.fpFromCfa.get() else: "none"
    echo fmt"RA recovery: {raInfo}"
    echo fmt"FP recovery: {fpInfo}"
  else:
    echo "No SFrame data found for current PC"

  lastFrames = buildFramesFrom(pc0, sp0, fp0)

#proc cdeep7() {.importc.}
proc deep0() {.noinline.} = nframe_entry_build()
proc deep1() {.noinline.} = deep0()
proc deep2() {.noinline.} = deep1()
proc deep3() {.noinline.} = deep2()
proc deep4() {.noinline.} = deep3()
proc deep5() {.noinline.} = deep4()
proc deep6() {.noinline.} = deep5()
proc deep7() {.noinline.} = deep6()


when isMainModule:
  echo "SFrame Stack Walking Example"
  echo "============================"
  echo "This example demonstrates parsing SFrame sections and attempting stack walks."
  echo "Note: With -fomit-frame-pointer, GCC may still generate FP-centric SFrame data"
  echo "which limits the effectiveness of the stack walk in some cases."
  echo ""

  # Test with a deeper call stack
  deep7()
  let frames = lastFrames
  echo "Stack trace (top->bottom):"
  for i, pc in frames:
    echo fmt"  {i:>2}: 0x{pc.toHex.toLowerAscii()}"
  # Symbolize via addr2line
  let exe = getAppFilename()
  let addr2 = "/usr/local/bin/x86_64-unknown-freebsd15.0-addr2line"
  let addrArgs = frames.mapIt("0x" & it.toHex.toLowerAscii()).join(" ")
  let cmd = addr2 & " -e " & exe & " -f -C -p " & addrArgs
  try:
    let sym = execProcess(cmd)
    let lines = sym.splitLines().filterIt(it.len > 0)
    echo "Symbols:"
    for i, line in lines:
      echo fmt"  {i:>2}: {line}"
  except CatchableError as e:
    echo "addr2line failed: ", e.msg
