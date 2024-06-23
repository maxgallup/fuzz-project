
#!/usr/bin/python

import os
import subprocess
import time
import os
import json
import multiprocessing
from datetime import datetime

BASIC_GAME_INPUT = "dddddddddddddddddddddd"
DATA_DIR = "data"


NUM_CORES = multiprocessing.cpu_count() - 1

prog_names = [
    'mario-easy-afl', 'mario-easy-ijon',
    'mario-mid-afl', 'mario-mid-ijon',
    'mario-hard-afl', 'mario-hard-ijon',
    'maze-small-afl', 'maze-small-ijon',
    'maze-big-afl', 'maze-big-ijon'
]

TIMEOUT = 600
REFRESH = 30
RUNS = 50
TOTAL = len(prog_names) * RUNS

binaries = []
for prog in prog_names:
    for i in range(RUNS):
        binaries.append(f"{prog}{i}")


in_dirs = [f"./{DATA_DIR}/{name}_idir" for name in binaries]
out_dirs = [f"./{DATA_DIR}/{name}_odir" for name in binaries]

procs = []

def sec_to_min(t):
    if t < 0:
        return t
    return f"{int(int(t) / int(60))}m:{(int(t) % int(60))}s"

def parse_file(filename):
    data = {}
    with open(filename, "r") as f:
        file_content = f.read()
    for line in file_content.strip().split("\n"):
        key, value = line.split(":")
        data[key.strip()] = value.strip()
    return data

def get_info(data):
    run_time_hms = sec_to_min(int(data["run_time"]))
    binary = data["afl_banner"]
    execs_per_sec = float(data['execs_per_sec'])
    execs_done = data['execs_done']
    return {
        "run_time_hms": run_time_hms,
        "binary": binary,
        "execs_per_sec": execs_per_sec,
        "execs_done": execs_done
    }

def save_results():
    # This program will return as JSON object of the 
    results = []
    for file in os.listdir(os.fsencode("./data")):
        filename = os.fsdecode(file)
        if filename.endswith("odir"):
            t = os.path.join(filename)
            stat_file = f"./data/{t}/default/fuzzer_stats"

            try:
                with open(stat_file, "r") as f:
                lines = f.readlines()
                for line in lines:
                    if "unique_crashes    : 1" in line:

                        data = {}

                        data['binary'] = lines[24].split(':')[1].strip()

                        start_time = int(lines[0].split(':')[1].strip())
                        end_time = int(lines[1].split(':')[1].strip())
                        data['run_time_hms'] = sec_to_min(end_time - start_time)

                        data['execs_done'] = lines[4].split(':')[1].strip()
                        data['execs_per_sec'] = lines[5].split(':')[1].strip()

                        results.append(data)
            except:
                pass

    if not os.path.exists("results"):
            os.mkdir("results")

    res_filename = f"results/run-{datetime.today().strftime('%m-%d@%H-%M-%S')}.json"

    if len(results) != 0:
        with open(res_filename, 'w') as f:
            json.dump(results, f)

def make_dir(path):
    if not os.path.exists(path):
        os.mkdir(path)


# idempotently setup all directories
def setup_dirs():
    make_dir(DATA_DIR)

    # make input dirs with input files if they don't already exist
    for in_dir in in_dirs:
        make_dir(in_dir)
        with open(f'{in_dir}/input.txt','w') as f:
            f.write(BASIC_GAME_INPUT)

    # create output directories if they don't exist
    for out_dir in out_dirs:
        make_dir(out_dir)



def stop_fuzzers():
    cmd = ["tmux", "kill-server"]
    subprocess.run(cmd)


def currently_running():
    cmd = ["tmux", "ls"]
    res = subprocess.run(cmd, capture_output=True)
    if res.stdout == b'':
        return set()
    else:
        result_set = set()
        for line in res.stdout.decode('utf-8').split('\n'):
            if line != '':
                result_set.add(line.split(':')[0].strip())
        return result_set


def start_fuzzer(name):
    print(f"    starting {name}")
    prog_name = ''
    for prog in prog_names:
        if prog in name:
            prog_name = prog

    cmd = ["bash", "-c", f"export AFL_BENCH_UNTIL_CRASH=1 AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1; tmux new-session -d -s {prog_name} /home/dev/afl-fuzz -i ./{DATA_DIR}/{name}_idir -o ./{DATA_DIR}/{name}_odir -- ./binaries/{prog_name}  > /dev/null 2>&1"]

    subprocess.run(cmd)



def clean_dirs():
    cmd = ["bash", "-c", "rm -rf ./data/*odir"]
    subprocess.run(cmd)


def kill_fuzzer(name):
    print(f">>> Killing {name}...")
    cmd = "bash", "-c", f"tmux kill-session -t {name}"
    subprocess.run(cmd)


def main():
    # Input and output directories are necessary for each test
    clean_dirs()
    setup_dirs()

    # Holds the set of currently running fuzzers (by name)
    active_set = set()

    # Holds (fuzzer name, running_time) so that we can fill fuzzers that take
    # too long
    programs = {}
    start = 0

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
            if value >= TIMEOUT:
                kill_fuzzer(key)
                del programs[key]

        # Get the latest active set, since zombies may have been killed
        active_set = currently_running()

        # We want to schedule at most the number of cores that we have available
        free_slots = NUM_CORES - len(active_set)


        # Exit if we have tested all binaries
        if start >= len(binaries):
            print("--- Testing Finished ---")
            exit(0)

        # Make sure we don't read out of bounds
        until = start + free_slots
        if until >= len(binaries):
            until = len(binaries)

        to_schedule = binaries[start : until]
        start = start + free_slots

        print(f">>> Going to schedule {len(to_schedule)} new fuzzers")

        for p in to_schedule:
            start_fuzzer(p)

        time.sleep(REFRESH)
        save_results()



if __name__ == '__main__':
    main()

