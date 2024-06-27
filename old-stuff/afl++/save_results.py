#!/usr/bin/python

import os
from datetime import datetime
import json




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
                data = parse_file(stat_file)
                if data['saved_crashes'] == '1':
                    results.append(get_info(data))
            except:
                pass

    if not os.path.exists("results"):
            os.mkdir("results")

    res_filename = f"results/run-{datetime.today().strftime('%m-%d@%H-%M-%S')}.json"

    if len(results) != 0:
        with open(res_filename, 'w') as f:
            json.dump(results, f)



if __name__ == '__main__':
    save_results()
