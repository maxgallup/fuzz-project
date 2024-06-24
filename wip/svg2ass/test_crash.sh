#!/bin/bash

CRASH_DIR=$1
BINARY="./binaries/svg2ass_sanitized"
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
done

python3 script.py
