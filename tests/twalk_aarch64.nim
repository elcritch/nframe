import std/[unittest]
import sframe
import sframe/aarch64_walk

suite "AArch64 stack walking":
  test "Stack walk example AArch64":
    # Build a section with two functions (A and B), both PCINC, 1 FRE each.
    # AArch64 tracks RA and FP in FRE offsets (N=3 typical), but we keep it simple with N=3.
    var sec = SFrameSection(
      header: SFrameHeader(
        preamble: SFramePreamble(magic: SFRAME_MAGIC, version: SFRAME_VERSION_2, flags: uint8(SFRAME_F_FDE_SORTED)),
        abiArch: uint8(sframeAbiAarch64Little),
        cfaFixedFpOffset: 0'i8,
        cfaFixedRaOffset: 0'i8,
        auxHdrLen: 0'u8,
        auxData: @[]
      ),
      fdes: @[
        SFrameFDE(funcStartAddress: 0x1000'i32, funcSize: 0x100, funcStartFreOff: 0, funcNumFres: 1, funcInfo: fdeInfo(sframeFreAddr1, sframeFdePcInc), funcRepSize: 0, funcPadding2: 0),
        SFrameFDE(funcStartAddress: 0x2000'i32, funcSize: 0x100, funcStartFreOff: 0, funcNumFres: 1, funcInfo: fdeInfo(sframeFreAddr1, sframeFdePcInc), funcRepSize: 0, funcPadding2: 0)
      ],
      fres: @[
        # offsets: [CFA offset, RA offset, FP offset]
        SFrameFRE(startAddr: 0, info: freInfo(sframeCfaBaseSp, 3, sframeFreOff2B), offsets: @[int32(32), int32(24), int32(16)]),
        SFrameFRE(startAddr: 0, info: freInfo(sframeCfaBaseSp, 3, sframeFreOff2B), offsets: @[int32(32), int32(24), int32(16)])
      ]
    )
    discard encodeSection(sec)
    let sectionBase = 0x600000'u64
    var mem = initSimMemory(0x71000000'u64, 0x1000)
    let sp0 = 0x71000020'u64
    let cfa0 = sp0 + 32
    let pcA = sectionBase + 0x1000'u64 + 4'u64
    let pcB = sectionBase + 0x2000'u64 + 8'u64
    # Store RA at cfa0 + 24 => pcB
    mem.storeU64(cfa0 + 24, pcB)
    # Store FP at cfa0 + 16 (not required for test)
    mem.storeU64(cfa0 + 16, 0x1111222233334444'u64)
    # Next frame CFA and a terminating RA (0)
    let sp1 = cfa0
    let cfa1 = sp1 + 32
    mem.storeU64(cfa1 + 24, 0'u64)
    mem.storeU64(cfa1 + 16, 0x5555666677778888'u64)
    let frames = walkStackAarch64(sec, sectionBase, pcA, sp0, 0'u64, mem, maxFrames = 8)
    check frames.len == 2
    check frames[0] == pcA
    check frames[1] == pcB

