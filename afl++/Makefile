PHONY: maze mario build

# These are shell variables available in all targets
.EXPORT_ALL_VARIABLES:
AFL_DEBUG = 1
AFL_FRIDA_VERBOSE = 1
AFL_SKIP_CPUFREQ = 1
AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES = 1

check_var:
	@if [ -z $$AFL_PATH ]; then echo "Error: set AFL_PATH to the root directory of afl++ without a trailing slash, for example: ~/projects/AFLplusplus"; exit 1; fi

build_frida: check_var
	$(MAKE) -C $$AFL_PATH/frida_mode

build_custom_afl: check_var
	$(MAKE) -C $$AFL_PATH

build_mario:
	@mkdir -p mario_input_dir mario_output_dir 
	@gcc -no-pie -g -O0 ./binaries/mario.c -o ./binaries/mario

build_maze:
	@mkdir -p maze_input_dir maze_output_dir
	@gcc -no-pie -g -O0 ./binaries/maze.c -o ./binaries/maze

build: build_mario build_maze build_custom_afl build_frida

maze: check_var
	@AFL_FRIDA_JS_SCRIPT=./afl-maze.js $$AFL_PATH/afl-fuzz -O -i maze_input_dir/ -o maze_output_dir/ -- ./binaries/maze

mario: check_var
	@AFL_FRIDA_JS_SCRIPT=./afl-mario.js $$AFL_PATH/afl-fuzz -O -i mario_input_dir/ -o mario_output_dir/ -- ./binaries/mario

