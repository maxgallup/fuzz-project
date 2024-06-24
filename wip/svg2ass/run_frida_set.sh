#!/bin/sh

# export AFL_BENCH_UNTIL_CRASH=1
export AFL_FRIDA_JS_SCRIPT=./afl-set.js
rm output.log
~/Projects/AFLplusplus/afl-fuzz -O -i ./io/input_dir -o ./io/output_dir_frida_set1 -- ./binaries/svg2ass/svg2ass_frida # 2>&1 | tee output.log

