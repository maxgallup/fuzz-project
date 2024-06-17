#!/bin/sh

# export AFL_DEBUG=1
# export AFL_FRIDA_VERBOSE=1
export AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
AFL_FRIDA_JS_SCRIPT=./afl-maze.js $AFL_FUZZ -O -i ./maze_input_dir -o ./maze_output_dir -- ./binaries/maze

