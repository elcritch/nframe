import sframe/amd64_walk
import std/strformat

var depthSink {.volatile.}: int

proc dumpTrace() =
  let frames = captureStackTrace()
  let symbols = symbolizeStackTrace(frames)
  echo "Stack trace (top -> bottom):"
  for i, sym in symbols:
    echo &"{i}: {sym}"

proc deep0() {.noinline.} =
  echo "SFrame captureStackTrace() output:"
  dumpTrace()

template mkDeep(procName, nextName: untyped) =
  proc procName() {.noinline.} =
    nextName()
    inc depthSink

mkDeep(deep1, deep0)
mkDeep(deep2, deep1)
mkDeep(deep3, deep2)
mkDeep(deep4, deep3)
mkDeep(deep5, deep4)
mkDeep(deep6, deep5)
mkDeep(deep7, deep6)

when isMainModule:
  depthSink = 0
  deep7()
