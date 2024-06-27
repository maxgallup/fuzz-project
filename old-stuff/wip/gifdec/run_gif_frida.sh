#!/bin/sh

export AFL_BENCH_UNTIL_CRASH=1
# export AFL_DEBUG_CHILD=1
# export AFL_DEBUG=1
# export AFL_FRIDA_VERBOSE=1
export AFL_FRIDA_JS_SCRIPT=./afl-gif.js
# export AFL_PRELOAD="/usr/lib/llvm-16/lib/clang/16/lib/linux/libclang_rt.asan-x86_64.so"
# export AFL_USE_FASAN=1

rm output.log
~/Projects/AFLplusplus/afl-fuzz -D -O -i ./io/input_dir -o ./io/output_dir_frida -- ./binaries/gif_frida @@ 2>&1 | tee output.log

