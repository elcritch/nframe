# Per-file NimScript for examples/stackwalk_amd64.nim

switch("cc", "gcc")
switch("debugger", "native")
switch("passC", "-O2 -fasynchronous-unwind-tables -Wa,--gsframe")

