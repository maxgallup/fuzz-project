import os
import re

input_dir = './asan_logs'
output_dir = './normalized_backtraces'

os.makedirs(output_dir, exist_ok=True)

unique_vulns = {}

def normalize_backtrace(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()
    
    normalized_lines = []
    key = ""
    for line in lines:
        if "#0" in line:
            key = line
            break
    if key in unique_vulns:
        unique_vulns[key] += 1
    else:
        unique_vulns[key] = 1
    
    return normalized_lines

for log_file in os.listdir(input_dir):
    input_file_path = os.path.join(input_dir, log_file)
    normalized_file_path = os.path.join(output_dir, log_file)
    
    normalized_backtrace = normalize_backtrace(input_file_path)

for unique_vuln, val in unique_vulns.items():
    print(f"{unique_vuln.strip()} | count: {val}")
    
    # with open(normalized_file_path, 'w') as file:
    #     file.writelines(normalized_backtrace)
