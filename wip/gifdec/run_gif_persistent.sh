#!/bin/sh

# export AFL_DEBUG=1
# export AFL_FRIDA_VERBOSE=1
export AFL_SKIP_CPUFREQ=1
export AFL_BENCH_UNTIL_CRASH=1
export AFL_FRIDA_JS_SCRIPT=./afl-gif-persistent.js
# export AFL_PRELOAD=./libclang_rt.asan-x86_64.so
# export AFL_USE_FASAN=1

~/Projects/AFLplusplus/afl-fuzz -O -i ./io/input_dir -o ./io/output_dir_frida_persistent -- ./binaries/gif_frida_persistent

