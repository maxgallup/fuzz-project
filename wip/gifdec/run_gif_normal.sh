#!/bin/sh

# export AFL_DEBUG=1
export AFL_SKIP_CPUFREQ=1
export AFL_BENCH_UNTIL_CRASH=1
rm output.log

~/Projects/AFLplusplus/afl-fuzz -i ./io/input_dir -o ./io/output_dir_normal -- ./binaries/gif_normal  2>&1 | tee output.log

