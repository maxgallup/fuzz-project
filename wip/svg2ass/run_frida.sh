#!/bin/sh

# export AFL_DEBUG=1
# export AFL_FRIDA_VERBOSE=1
export AFL_BENCH_UNTIL_CRASH=1
rm output.log

$AFL_PATH/afl-fuzz -O -i ./io/input_dir -o ./io/output_dir_frida -- ./binaries/svg2ass_frida # 2>&1 | tee output.log

