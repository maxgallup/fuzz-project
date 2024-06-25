#!/usr/bin/python

import os
import sys
import subprocess
import time
import os
import json
import multiprocessing
from datetime import datetime

NUM_CORES = multiprocessing.cpu_count() - 1
TIMEOUT = 1200
REFRESH = 30
RUNS = 50

prog_names = []

def setup_dirs(dirs):
    for d in dirs:
        if not os.path.exists(d):
            os.mkdir(d)

def stop_fuzzers():
    cmd = ["tmux", "kill-server"]
    subprocess.run(cmd)

def currently_running():
    cmd = ["tmux", "ls"]
    res = subprocess.run(cmd, stdout=subprocess.PIPE)
    tmux_res = res.stdout.decode('utf-8')
    if tmux_res == '':
        return set()
    elif 'no server running' in tmux_res:
        return set([a for a in range(0, NUM_CORES)])
    else:
        result_set = set()
        for line in tmux_res.split('\n'):
            if line != '':
                result_set.add(line.split(':')[0].strip())
        return result_set

def start_fuzzer(name):
    print(f"    starting {name}")
    prog_name = ''
    for prog in prog_names:
        if prog in name:
            prog_name = prog

    cmd = ["bash", "-c", f"export AFL_BENCH_UNTIL_CRASH=1 AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_FRIDA_JS_SCRIPT=./frida/{prog_name}.js; tmux new-session -d -s {name} $AFL_PATH/afl-fuzz -O -i ./inputs/{prog_name} -o ./outputs/{name} -- ./binaries/{prog_name} > /dev/null 2>&1"]

    if 'afl' in prog_name:
        cmd = ["bash", "-c", f"export AFL_BENCH_UNTIL_CRASH=1 AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1; tmux new-session -d -s {name} $AFL_PATH/afl-fuzz -O -i ./inputs/{prog_name} -o ./outputs/{name} -- ./binaries/{prog_name} > /dev/null 2>&1"]
        

    subprocess.run(cmd)


def kill_fuzzer(name):
    print(f">>> Killing {name}...")
    cmd = "bash", "-c", f"tmux kill-session -t {name}"
    subprocess.run(cmd)


def main():
    directory = os.fsencode("./binaries")
        
    for file in os.listdir(directory):
        filename = os.fsdecode(file)
        prog_names.append(file.decode('utf-8'))


    binaries = []
    out_dirs = []
    for prog in prog_names:
        for i in range(RUNS):
            binary = f"{prog}{i}"
            binaries.append(binary)
            out_dirs.append(f"./outputs/{binary}")


    setup_dirs(out_dirs)

    # Holds the set of currently running fuzzers (by name)
    active_set = set()

    # Holds (fuzzer name, running_time) so that we can fill fuzzers that take
    # too long
    programs = {}
    start = 0
    all_scheduled = False
    count = 0

    # We check if fuzzers have finished with a REFRESH interval and schedule new ones
    # accordingly
    while True:
        active_set = currently_running()

        # Update how long each program has been running for
        for i in active_set:
            if i in programs:
                programs[i] += REFRESH
            else:
                programs[i] = REFRESH

        # Kill fuzzers that run longer than TIMEOUT
        for key, value in programs.items():
            if value >= TIMEOUT and (key in active_set):
                kill_fuzzer(key)

        # Get the latest active set, since zombies may have been killed
        active_set = currently_running()

        # We want to schedule at most the number of cores that we have available
        free_slots = NUM_CORES - len(active_set)


        # Exit if we have tested all binaries
        if start >= len(binaries):
            print(">>> all scheduled")
            all_scheduled = True


        if not all_scheduled:
            # Make sure we don't read out of bounds
            until = start + free_slots
            if until >= len(binaries):
                until = len(binaries)

            to_schedule = binaries[start : until]
            start = start + free_slots

            print(f">>> Going to schedule {len(to_schedule)} new fuzzers")

            for p in to_schedule:
                start_fuzzer(p)
        else:
            if not active_set:
                print(f"--- Testing complete ---")
                exit(0)

        time.sleep(REFRESH)
        count = count + 1


if __name__ == '__main__':
    main()

