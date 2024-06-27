# Reproduce Results
Clone our [fork of AFL++](https://github.com/meowmeowxw/AFLplusplus) and checkout the `ijon` branch.
First, build the AFLplusplus by going into the root directory and running `make` as well as
`cd frida_mode && make`. Then, inside this directory, set the `AFL_PATH` variable to the destination
of the cloned fork, make sure to not include the trailing slash:
`export AFL_PATH=/path/to/AFLplusplus`. 

After this is done, starting the fuzzers for testing can be done with `python test.py`.

The following binaries were not included in testing, because the time until they find the first
crash took too long:
* mario-mid-afl
* mario-hard-afl
* maze-big-afl

