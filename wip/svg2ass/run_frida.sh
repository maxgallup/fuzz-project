#!/bin/sh

# export AFL_BENCH_UNTIL_CRASH=1
rm output.log

~/Projects/AFLplusplus/afl-fuzz -O -i ./io/input_dir -o ./io/output_dir_frida_normal0 -- ./binaries/svg2ass/svg2ass_frida # 2>&1 | tee output.log

