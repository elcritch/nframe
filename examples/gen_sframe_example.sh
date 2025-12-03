#!/usr/bin/env sh
set -eu

OBJDUMP="/usr/local/bin/x86_64-unknown-freebsd15.0-objdump"
OBJCOPY="/usr/local/bin/x86_64-unknown-freebsd15.0-objcopy"
CC=${CC:-gcc}

cd "$(dirname "$0")"

echo "[build] compiling test_sframe.c with --gsframe"
${CC} -O2 -fasynchronous-unwind-tables -Wa,--gsframe test_sframe.c -o test_sframe

echo "[dump ] using ${OBJDUMP} --sframe"
${OBJDUMP} --sframe ./test_sframe || true

echo "[xtract] extracting .sframe to out.sframe with ${OBJCOPY}"
${OBJCOPY} --dump-section .sframe=out.sframe ./test_sframe

if [ -x ../tools/sframe_dump ]; then
  echo "[nim  ] running tools/sframe_dump on out.sframe"
  ../tools/sframe_dump out.sframe || true
else
  echo "[info ] compile tools/sframe_dump.nim to pretty-print raw section: nim c -r tools/sframe_dump.nim out.sframe"
fi

echo "[done ] artifacts: examples/test_sframe (ELF), examples/out.sframe (raw section)"

