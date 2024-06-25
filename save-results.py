import os
import json
from datetime import datetime

def parse_file(filename):
    data = {}
    with open(filename, "r") as f:
        file_content = f.read()
    for line in file_content.strip().split("\n"):
        key, value = line.split(":")
        data[key.strip()] = value.strip()
    return data

def get_info(data):
    run_time = int(data["last_update"]) - int(data["start_time"])
    binary = str(data["afl_banner"])
    execs_per_sec = float(data['execs_per_sec'])
    execs_done = int(data['execs_done'])
    return {
        "run_time": run_time,
        "binary": binary,
        "execs_per_sec": execs_per_sec,
        "execs_done": execs_done
    }



def main():
    for eval_dir in os.listdir(os.fsencode(".")):
        evaluation = os.path.join(os.fsdecode(eval_dir))
        if 'eval' in evaluation:
            print(f"Looking through {evaluation}")
            results = []
            for output_dir in os.listdir(os.fsencode(f"./{evaluation}/outputs")):
                output = os.path.join(os.fsdecode(output_dir))
                stat_file = f"./{evaluation}/outputs/{output}/default/fuzzer_stats"

                if not os.path.exists(stat_file):
                    stat_file = f"./{evaluation}/outputs/{output}/fuzzer_stats"

                try:
                    data = parse_file(stat_file)

                    if 'saved_crashes' in data:
                        if float(data['saved_crashes']) > 0:
                            results.append(get_info(data))
                        else:
                            print(f"INFO: {output} didn't have any saved crashes")
                    elif 'unique_crashes' in data:
                        if float(data['unique_crashes']) > 0:
                            results.append(get_info(data))
                        else:
                            print(f"INFO: {output} didn't have any saved crashes")

                except Exception as e:
                    print(e)
                    pass

            if not os.path.exists("results"):
                    os.mkdir("results")

            res_filename = f"./{evaluation}/results/run-{datetime.today().strftime('%m-%d@%H-%M-%S')}.json"

            if len(results) != 0:
                print(f"Writing results to {res_filename}")
                with open(res_filename, 'w') as f:
                    json.dump(results, f)



if __name__ == '__main__':
    main()

