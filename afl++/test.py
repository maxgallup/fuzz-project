#!/usr/bin/python

import os
import subprocess
import asyncio


BASIC_GAME_INPUT = "dddddddddddddddddddddd"
DATA_DIR = "data"

binaries = [
    'mario-easy',
    'mario-mid',
    'mario-hard',
    'maze-small',
    'maze-big',
]

in_dirs = [f"./{DATA_DIR}/{name}_idir" for name in binaries]
out_dirs = [f"./{DATA_DIR}/{name}_odir" for name in binaries]

procs = []


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


async def run_fuzzers():
    for i in range(len(in_dirs)):

        cmd = f"bash -c 'export AFL_BENCH_UNTIL_CRASH=1 AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_FRIDA_JS_SCRIPT=./frida/{binaries[i]}.js; tmux new-session -d -s {binaries[i]} $AFL_PATH/afl-fuzz -O -i {in_dirs[i]} -o {out_dirs[i]} -- ./binaries/{binaries[i]} > /dev/null 2>&1'"
        procs.append(await asyncio.create_subprocess_shell(cmd))
        print(f'Started: {binaries[i]}...')

    for (i, proc) in enumerate(procs):
        await proc.wait()



async def main():
    setup_dirs()
    await run_fuzzers()
    
    print('All fuzzers started. Use "tmux ls" to view names and "tmux attach-session -t <name> to attach."')


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())

