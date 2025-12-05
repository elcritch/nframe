import sframe/nim_stacktraces
import system/stacktraces
import std/[strformat, strutils]

when defined(gcc) or true:
  {.emit: """
  static inline void* nframe_ex_get_ip(void) {
    void* ip;
#if defined(__x86_64__) || defined(__amd64__)
    __asm__ __volatile__("leaq (%%rip), %0" : "=r"(ip));
#elif defined(__aarch64__)
    __asm__ __volatile__("adr %0, ." : "=r"(ip));
#else
    ip = __builtin_return_address(0);
#endif
    return ip;
  }
  """.}
  proc nframe_ex_get_ip(): pointer {.importc.}

proc deep0() {.noinline.} =
  # Print stacktrace using Nim's built-in API (overridden to use SFrame)
  echo "Nim getStackTrace() output:"
  # Ensure SFrame cache is loaded; normalize and print the active frame first.
  discard getProgramCounters(1) # triggers SFrame cache load
  let ip = cast[uint64](nframe_ex_get_ip())
  let top = mapPcToFuncStart(ip)
  echo fmt"  top: 0x{top.toHex.toLowerAscii()}"
  echo getStackTrace()
  #echo "\nstacktraces: ", $getStackTraceEntries()
  for i in 1..10:
    echo "i: ", $i

proc deep1() {.noinline.} = deep0()
proc deep2() {.noinline.} = deep1()
proc deep3() {.noinline.} = deep2()
proc deep4() {.noinline.} = deep3()
proc deep5() {.noinline.} = deep4()
proc deep6() {.noinline.} = deep5()
proc deep7() {.noinline.} = deep6()

when isMainModule:
  # This will print our override-derived backtrace
  deep7()
