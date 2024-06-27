#!/bin/bash

# Iterate over all directories in /proc
for pid in /proc/[0-9]*; do
    # Extract the PID from the directory name
    pid=${pid#/proc/}

    # Check if the process has a maps file
    if [ -f "/proc/$pid/maps" ]; then
        # Check if libfreetype is used by the process
        if sudo grep -q "libfreetype" "/proc/$pid/maps"; then
            # Print the process binary
            exe_path=$(sudo readlink -f "/proc/$pid/exe")
            echo "Process ID: $pid"
            echo "Binary: $exe_path"
            echo "------"
        fi
    fi
done

