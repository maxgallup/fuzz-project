#!/bin/sh

# export AFL_BENCH_UNTIL_CRASH=1
#

~/Projects/AFLplusplus/afl-fuzz -i ./io/input_dir -o ./io/output_dir_normal -- ./binaries/tiffloader/tiff_normal @@
