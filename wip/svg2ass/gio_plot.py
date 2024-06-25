import datetime
import sys
import os
import json
import numpy as np
import matplotlib.pyplot as plt

import polars as pl

def parse_file(filename):
    data = {}
    with open(filename, "r") as f:
        file_content = f.read()
    for line in file_content.strip().split("\n"):
        key, value = line.split(":")
        data[key.strip()] = value.strip()
    return data

def get_info(data):
    # run_time_hms = str(datetime.timedelta(seconds=int(data["run_time"])))
    return {
        "binary": data["afl_banner"],
        "run_time": float(data["run_time"]),
        "execs_done": float(data["execs_done"]),
        "execs_per_sec": float(data["execs_per_sec"])
    }


def get_average_and_std(infos):
    run_time = [info["run_time"] for info in infos]
    execs_done = [info["execs_done"] for info in infos]
    execs_per_sec = [info["execs_per_sec"] for info in infos]
    
    return {
        "average": {
            "run_time": round(np.mean(run_time), 2),
            "execs_done": round(np.mean(execs_done), 2),
            "execs_per_sec": round(np.mean(execs_per_sec), 2),
        },
        "std": {
            "run_time": round(np.std(run_time), 2),
            "execs_done": round(np.std(execs_done), 2),
            "execs_per_sec": round(np.std(execs_per_sec), 2),
        }
    }

def plot_data(average_infos, std_infos, average_set_infos, std_set_infos):
    labels = ['run_time', 'execs_done', 'execs_per_sec']
    infos_means = [average_infos['run_time'], average_infos['execs_done'], average_infos['execs_per_sec']]
    infos_stds = [std_infos['run_time'], std_infos['execs_done'], std_infos['execs_per_sec']]
    set_infos_means = [average_set_infos['run_time'], average_set_infos['execs_done'], average_set_infos['execs_per_sec']]
    set_infos_stds = [std_set_infos['run_time'], std_set_infos['execs_done'], std_set_infos['execs_per_sec']]

    x = np.arange(len(labels))  # the label locations
    width = 0.35  # the width of the bars

    fig, ax = plt.subplots()
    rects1 = ax.bar(x - width/2, infos_means, width, yerr=infos_stds, label='AFL++ Frida Mode', capsize=5)
    rects2 = ax.bar(x + width/2, set_infos_means, width, yerr=set_infos_stds, label='AFL++ Frida Mode + IJON SET', capsize=5)

    # Add some text for labels, title and custom x-axis tick labels, etc.
    ax.set_xlabel('Metrics')
    ax.set_ylabel('Values')
    ax.set_title('Metrics')
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_yscale('log')
    ax.legend()

    fig.tight_layout()

    plt.show()


def get_average(infos):
    run_time = 0
    execs_per_sec = 0
    execs_done = 0
    for info in infos:
        run_time += info["run_time"]
        execs_done += info["execs_done"]
        execs_per_sec += info["execs_per_sec"]

    return {
        "run_time": round(run_time / len(infos), 2),
        "execs_done": round(execs_done / len(infos), 2),
        "execs_per_sec": round(execs_per_sec / len(infos), 2),
    }


# if __name__ == "__main__":
#     infos = []
#     set_infos = []
#     dir_stats = "./io/stats"
#     for filepath in map(lambda x: os.path.join(dir_stats, x), os.listdir(dir_stats)):
#         if "set" in filepath:
#             set_infos.append(get_info(parse_file(filepath)))
#         else:
#             infos.append(get_info(parse_file(filepath)))
#     print(set_infos)
#     print(infos)
# 
#     print("\n[!] ijon set average")
#     print(get_average(set_infos))
# 
#     print("\n[!] no ijon set average")
#     print(get_average(infos))

def human_to_sec(human_string: str):
    minutes, seconds = human_string.split(":")
    minutes = float(minutes[:-1])
    seconds = float(seconds[:-1])

    return float(seconds + (minutes * 60))

def load_result(path):
    df = pl.read_json(path)
    df = df.with_columns(pl.col('run_time_hms').map_elements(human_to_sec, return_dtype=float).alias('run_time'))

    df = df.with_columns(pl.col('execs_done').cast(pl.Float64))
    df = df.with_columns(pl.col('execs_per_sec').cast(pl.Float64))
    df = df.to_dict(as_series=False)

    # for x in df:
    #     print (type(df['run_time'][-1]))
        # for y in df[x]:
        #     print (y,':', df[x][y])

    return df

if __name__ == "__main__":
    infos = []
    set_infos = []




    # dir_stats = "./io/stats"
    # for filepath in map(lambda x: os.path.join(dir_stats, x), os.listdir(dir_stats)):
    #     if "json" in filepath:
    #         continue
    #     if "set" in filepath:
    #         set_infos.append(get_info(parse_file(filepath)))
    #     else:
    #         infos.append(get_info(parse_file(filepath)))
    infos = load_result("./results/afl.json")
    set_infos = load_result("./results/ijon.json")
    


    average_infos = get_average_and_std(infos)["average"]
    std_infos = get_average_and_std(infos)["std"]
    average_set_infos = get_average_and_std(set_infos)["average"]
    std_set_infos = get_average_and_std(set_infos)["std"]

    # with open("./io/stats/afl_frida.json", "w") as f:
    #     json.dump(infos, f, indent=4)
    # with open("./io/stats/afl_frida_ijon_set.json", "w") as f:
    #     json.dump(set_infos, f, indent=4)


    plot_data(average_infos, std_infos, average_set_infos, std_set_infos)
