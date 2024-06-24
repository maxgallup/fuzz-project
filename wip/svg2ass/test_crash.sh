#!/bin/bash

# CRASH_DIR="./io/output_dir_frida_inc2/default/crashes"
# CRASH_DIR="./io/output_dir_frida_set1/default/crashes"
CRASH_DIR="./io/output_dir_frida_normal0/default/crashes"
BINARY="./binaries/svg2ass/svg2ass_sanitized"
LOG_DIR="./asan_logs"

mkdir -p $LOG_DIR
rm ./asan_logs/*


counter=1

for crash in $CRASH_DIR/id:*; do
    crash_file=$(basename $crash)
    log_file="$LOG_DIR/$counter.log"
    echo $log_file;
    export ASAN_OPTIONS="log_path=${log_file}"
    echo $ASAN_OPTIONS;
    CMD="$BINARY < $crash";
    $BINARY < $crash >/dev/null
    counter=$((counter + 1))
    
    # Set ASAN_OPTIONS to log to the desired file
    # $BINARY < $crash
done

python3 script.py
