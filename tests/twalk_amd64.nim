import std/[unittest, options]
import sframe, sframe/amd64_walk

suite "SFrame minimal":

  test "Stack walk example AMD64":
    # Build a section with two functions (A and B), both PCINC, 1 FRE each.
    var sec = SFrameSection(
      header: SFrameHeader(
        preamble: SFramePreamble(magic: SFRAME_MAGIC, version: SFRAME_VERSION_2, flags: uint8(SFRAME_F_FDE_SORTED)),
        abiArch: uint8(sframeAbiAmd64Little),
        cfaFixedFpOffset: 0'i8,
        cfaFixedRaOffset: -8'i8, # AMD64: RA at CFA-8
        auxHdrLen: 0'u8,
        auxData: @[]
      ),
      fdes: @[
        SFrameFDE(funcStartAddress: 0x1000'i32, funcSize: 0x100, funcStartFreOff: 0, funcNumFres: 1, funcInfo: fdeInfo(sframeFreAddr1, sframeFdePcInc), funcRepSize: 0, funcPadding2: 0),
        SFrameFDE(funcStartAddress: 0x2000'i32, funcSize: 0x100, funcStartFreOff: 0, funcNumFres: 1, funcInfo: fdeInfo(sframeFreAddr1, sframeFdePcInc), funcRepSize: 0, funcPadding2: 0)
      ],
      fres: @[
        SFrameFRE(startAddr: 0, info: freInfo(sframeCfaBaseSp, 2, sframeFreOff1B), offsets: @[int32(16), int32(-16)]),
        SFrameFRE(startAddr: 0, info: freInfo(sframeCfaBaseSp, 2, sframeFreOff1B), offsets: @[int32(16), int32(-16)])
      ]
    )
    discard encodeSection(sec)
    let sectionBase = 0x500000'u64
    # Simulated stack memory
    var mem = initSimMemory(0x70000000'u64, 0x1000)
    let sp0 = 0x70000020'u64
    let cfa0 = sp0 + 16 # from FRE[0]
    let pcA = sectionBase + 0x1000'u64 + 4'u64
    let pcB = sectionBase + 0x2000'u64 + 8'u64
    # RA for frame A points into B
    mem.storeU64(cfa0 + uint64(-8'i64), pcB)
    # Saved FP for frame A (not used, but populated per FRE)
    mem.storeU64(cfa0 + uint64(-16'i64), 0xCAFEBABECAFED00Du64)
    # Next frame (B) CFA and RA=0 to stop walk
    let sp1 = cfa0
    let cfa1 = sp1 + 16
    mem.storeU64(cfa1 + uint64(-8'i64), 0'u64)
    mem.storeU64(cfa1 + uint64(-16'i64), 0xFEEDFACEFEEDD00Du64)
    let frames = walkStackAmd64(sec, sectionBase, pcA, sp0, 0'u64, mem, maxFrames = 8)
    # Expect two frames: pcA then pcB
    check frames.len == 2
    check frames[0] == pcA
    check frames[1] == pcB
