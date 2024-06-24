# These are shell variables available in all targets
# .EXPORT_ALL_VARIABLES:
# AFL_DEBUG = 1
# AFL_FRIDA_VERBOSE = 1
# AFL_SKIP_CPUFREQ = 1
# AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES = 1

check_var:
	@if [ -z $$AFL_PATH ]; then echo "Error: set AFL_PATH to the root directory of afl++ without a trailing slash, for example: ~/projects/AFLplusplus"; exit 1; fi

build_frida: check_var
	$(MAKE) -C $$AFL_PATH/frida_mode

build_custom_afl: check_var
	$(MAKE) -C $$AFL_PATH


# build: check_var build_frida build_custom_afl
# 	@echo "Building binaries"
# 	gcc -no-pie -g -O0 ./src/maze-big.c -o ./binaries/maze-big
# 	gcc -no-pie -g -O0 ./src/maze-small.c -o ./binaries/maze-small
# 	gcc -no-pie -g -O0 ./src/mario-easy.c -o ./binaries/mario-easy
# 	gcc -no-pie -g -O0 ./src/mario-mid.c -o ./binaries/mario-mid
# 	gcc -no-pie -g -O0 ./src/mario-hard.c -o ./binaries/mario-hard


test: check_var
	python3 test.py

clean:
	rm -rf data/*odir*
