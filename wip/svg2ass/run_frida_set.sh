#!/bin/sh

export AFL_BENCH_UNTIL_CRASH=1
# export AFL_FRIDA_VERBOSE=1
# export AFL_DEBUG=1
export AFL_FRIDA_JS_SCRIPT=./afl-set.js
rm output.log

$AFL_PATH/afl-fuzz -O -i ./io/input_dir -o ./io/output_dir_frida_set -- ./binaries/svg2ass_frida # 2>&1 | tee output.log

