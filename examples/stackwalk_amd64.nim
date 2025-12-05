import std/[os, osproc, strutils, strformat, sequtils, options]
import sframe
import sframe/amd64_walk

## NOTE: requires binutils 2.44+ (?)
##
when defined(gcc) or true:
  {.emit: """
  static inline void* nframe_get_fp(void) { return __builtin_frame_address(0); }
  static inline void* nframe_get_ra(void) { return __builtin_return_address(0); }
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

# Walking functions have been moved to sframe/amd64_walk.nim

proc loadSframeSection(): (SFrameSection, uint64) =
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
  result = (sec, sectionBase)


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
  let (sec, sectionBase) = loadSframeSection()

  echo fmt"SFrame section: base=0x{sectionBase.toHex()}, {sec.fdes.len} functions, {sec.fres.len} frame entries"
  echo fmt"Header: RA offset={sec.header.cfaFixedRaOffset}, FP offset={sec.header.cfaFixedFpOffset}"

  # Show SFrame data for current PC
  let (found, fdeIdx, freLocalIdx, freGlobalIdx) = sec.pcToFre(pc0, sectionBase)
  if found:
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

  # Stack layout analysis complete, now attempt stack walking
  lastFrames = walkStackAmd64WithFallback(sec, sectionBase, pc0, sp0, fp0, readU64Ptr, maxFrames = 16)

# Force functions to not be inlined and add some computation to prevent optimization
proc deep0() {.noinline.} =
  var x = 0
  for i in 0 ..< 10: x += i
  if x > 0: nframe_entry_build()

proc deep1() {.noinline.} =
  var x = 0
  for i in 0 ..< 10: x += i
  if x > 0: deep0()

proc deep2() {.noinline.} =
  var x = 0
  for i in 0 ..< 10: x += i
  if x > 0: deep1()

proc deep3() {.noinline.} =
  var x = 0
  for i in 0 ..< 10: x += i
  if x > 0: deep2()

proc deep4() {.noinline.} =
  var x = 0
  for i in 0 ..< 10: x += i
  if x > 0: deep3()

proc deep5() {.noinline.} =
  var x = 0
  for i in 0 ..< 10: x += i
  if x > 0: deep4()

proc deep6() {.noinline.} =
  var x = 0
  for i in 0 ..< 10: x += i
  if x > 0: deep5()

proc deep7() {.noinline.} =
  var x = 0
  for i in 0 ..< 10: x += i
  if x > 0: deep6()


when isMainModule:
  echo "SFrame Stack Walking Example"
  echo "============================"
  echo "This example demonstrates parsing SFrame sections and attempting stack walks."
  echo "Note: With -fomit-frame-pointer, GCC may still generate FP-centric SFrame data"
  echo "which limits the effectiveness of the stack walk in some cases."
  echo ""

  # Test with the full deep call stack to see more frames
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
