#!/bin/sh

# export AFL_BENCH_UNTIL_CRASH=1
rm output.log
~/Projects/AFLplusplus/afl-fuzz -i ./io/input_dir -o ./io/output_dir_normal -- ./binaries/svg2ass/svg2ass_normal # 2>&1 | tee output.log

