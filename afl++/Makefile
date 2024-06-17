PHONY: maze mario

# These are shell variables available in all targets
.EXPORT_ALL_VARIABLES:
AFL_DEBUG = 1
AFL_FRIDA_VERBOSE = 1
AFL_SKIP_CPUFREQ = 1
AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES = 1


build_mario:
	@mkdir -p mario_input_dir mario_output_dir
	@gcc -no-pie -g -O0 ./binaries/mario.c -o ./binaries/mario

build_maze:
	@mkdir -p maze_input_dir maze_output_dir
	@gcc -no-pie -g -O0 ./binaries/maze.c -o ./binaries/maze



# something like
# fuzzer -O -i small_input_dir/ -o small_output_dir/ -- ../binaries/small
maze: build_maze
	@echo Todo run fuzzer with afl-maze.js

mario: build_mario 
	@echo Todo run fuzzer with afl-mario.js




