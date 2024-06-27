#!/bin/sh

rm crash_log.txt

for f in $(ls $1);
do
    ./binaries/gif_sanitized ${1}/${f}; 2>> crash_log.txt
done

