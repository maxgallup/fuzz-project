#!/usr/bin/python

import os
import json

import polars as pl


def human_to_sec(human_string: str):
    minutes, seconds = human_string.split(":")
    minutes = float(minutes[:-1])
    seconds = float(seconds[:-1])

    return float(seconds + (minutes * 60))


def string_to_float(s):
    return float(s)

def main():
    # Set the directory path
    dir_path = './results/'

    # Get a list of files in the directory
    files = os.listdir(dir_path)

    # Sort the files by modification time
    files.sort(key=lambda x: os.path.getmtime(os.path.join(dir_path, x)))

    # Open the most recently modified file
    most_recent_file = files[-1]
    df = pl.read_json(os.path.join(dir_path, most_recent_file))

    df = df.with_columns(pl.col('run_time_hms').map_elements(human_to_sec, return_dtype=float).alias('run_time'))

    df = df.with_columns(pl.col('execs_done').cast(pl.Float64))

    df = df.group_by(pl.col('binary')).agg(pl.col(['run_time', 'execs_per_sec', 'execs_done']).mean())

    res = df.select(
        pl.all().map_alias(lambda col_name: f"avg {col_name}")
    )

    print(res)


if __name__ == '__main__':
    main()
