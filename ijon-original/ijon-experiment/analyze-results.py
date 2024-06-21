#!/usr/bin/python

import os
import json
from datetime import datetime

# This program will return as JSON object of the 
results = []
for file in os.listdir(os.fsencode("./data")):
    filename = os.fsdecode(file)
    if filename.endswith("odir"):
        t = os.path.join(filename)
        stat_file = f"./data/{t}/fuzzer_stats"

        with open(stat_file, "r") as f:
            lines = f.readlines()
            for line in lines:
                if "unique_crashes    : 1" in line:

                    data = {}

                    data['name'] = lines[24].split(':')[1].strip()

                    start_time = int(lines[0].split(':')[1].strip())
                    end_time = int(lines[1].split(':')[1].strip())
                    data['time'] = end_time - start_time

                    data['execs'] = lines[4].split(':')[1].strip()
                    data['execs_per_sec'] = lines[5].split(':')[1].strip()

                    results.append(data)

if not os.path.exists("results"):
        os.mkdir("results")

res_filename = f"results/run-{datetime.today().strftime('%m-%d@%H-%M')}.json"

with open(res_filename, 'w') as f:
    json.dump(results, f)

