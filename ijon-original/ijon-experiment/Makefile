.PHONY: build test

.EXPORT_ALL_VARIABLES:
AFL_SKIP_CPUFREQ=1
AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1


make_dirs:
	@mkdir -p mario-easy-afl_input_dir mario-easy-afl_output_dir && echo "dddddddddddd" > mario-easy-afl_input_dir/input.txt
	@mkdir -p mario-easy-ijon-set_input_dir mario-easy-ijon-set_output_dir && echo "dddddddddddd" > mario-easy-ijon-set_input_dir/input.txt
	@mkdir -p mario-easy-ijon-max_input_dir mario-easy-ijon-max_output_dir && echo "dddddddddddd" > mario-easy-ijon-max_input_dir/input.txt
	
	@mkdir -p mario-mid-afl_input_dir mario-mid-afl_output_dir && echo "dddddddddddd" > mario-mid-afl_input_dir/input.txt
	@mkdir -p mario-mid-ijon-set_input_dir mario-mid-ijon-set_output_dir && echo "dddddddddddd" > mario-mid-ijon-set_input_dir/input.txt
	@mkdir -p mario-mid-ijon-max_input_dir mario-mid-ijon-max_output_dir && echo "dddddddddddd" > mario-mid-ijon-max_input_dir/input.txt

	@mkdir -p mario-hard-afl_input_dir mario-hard-afl_output_dir && echo "dddddddddddd" > mario-hard-afl_input_dir/input.txt
	@mkdir -p mario-hard-ijon-set_input_dir mario-hard-ijon-set_output_dir && echo "dddddddddddd" > mario-hard-ijon-set_input_dir/input.txt
	@mkdir -p mario-hard-ijon-max_input_dir mario-hard-ijon-max_output_dir && echo "dddddddddddd" > mario-hard-ijon-max_input_dir/input.txt



build: make_dirs
	@/root/afl-clang-fast ./src/mario-easy-afl.c -o ./binaries/mario-easy-afl
	@/root/afl-clang-fast ./src/mario-easy-ijon-max.c -o ./binaries/mario-easy-ijon-max
	@/root/afl-clang-fast ./src/mario-easy-ijon-set.c -o ./binaries/mario-easy-ijon-set
	
	@/root/afl-clang-fast ./src/mario-mid-afl.c -o ./binaries/mario-mid-afl
	@/root/afl-clang-fast ./src/mario-mid-ijon-max.c -o ./binaries/mario-mid-ijon-max
	@/root/afl-clang-fast ./src/mario-mid-ijon-set.c -o ./binaries/mario-mid-ijon-set
	
	@/root/afl-clang-fast ./src/mario-hard-afl.c -o ./binaries/mario-hard-afl
	@/root/afl-clang-fast ./src/mario-hard-ijon-max.c -o ./binaries/mario-hard-ijon-max
	@/root/afl-clang-fast ./src/mario-hard-ijon-set.c -o ./binaries/mario-hard-ijon-set


test: build
	@export AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1; tmux new-session -d -s mario-easy-afl "/root/afl-fuzz -i mario-easy-afl_input_dir/ -o mario-easy-afl_output_dir/ -- ./binaries/mario-easy-afl"
	@export AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1; tmux new-session -d -s mario-easy-ijon-max "/root/afl-fuzz -i mario-easy-ijon-max_input_dir/ -o mario-easy-ijon-max_output_dir/ -- ./binaries/mario-easy-ijon-max"
	@export AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1; tmux new-session -d -s mario-easy-ijon-set "/root/afl-fuzz -i mario-easy-ijon-set_input_dir/ -o mario-easy-ijon-set_output_dir/ -- ./binaries/mario-easy-ijon-set"

	@export AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1; tmux new-session -d -s mario-mid-afl "/root/afl-fuzz -i mario-mid-afl_input_dir/ -o mario-mid-afl_output_dir/ -- ./binaries/mario-mid-afl"
	@export AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1; tmux new-session -d -s mario-mid-ijon-max "/root/afl-fuzz -i mario-mid-ijon-max_input_dir/ -o mario-mid-ijon-max_output_dir/ -- ./binaries/mario-mid-ijon-max"
	@export AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1; tmux new-session -d -s mario-mid-ijon-set "/root/afl-fuzz -i mario-mid-ijon-set_input_dir/ -o mario-mid-ijon-set_output_dir/ -- ./binaries/mario-mid-ijon-set"
	
	@export AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1; tmux new-session -d -s mario-hard-afl "/root/afl-fuzz -i mario-hard-afl_input_dir/ -o mario-hard-afl_output_dir/ -- ./binaries/mario-hard-afl"
	@export AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1; tmux new-session -d -s mario-hard-ijon-max "/root/afl-fuzz -i mario-hard-ijon-max_input_dir/ -o mario-hard-ijon-max_output_dir/ -- ./binaries/mario-hard-ijon-max"
	@export AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1; tmux new-session -d -s mario-hard-ijon-set "/root/afl-fuzz -i mario-hard-ijon-set_input_dir/ -o mario-hard-ijon-set_output_dir/ -- ./binaries/mario-hard-ijon-set"



clean:
	rm -rf *output_dir*
	rm binaries/*

