# Reproduce Results
The evaluations in this directory contain original source code from the
[IJON project](https://github.com/RUB-SysSec/ijon). The project uses AFL which relies on an older
version of clang, so we provide a Docker container to run the tests inside of.

1. Run the `./docker-interactive.sh` script to get a shell inside of the container.
2. Once in the container, run `python3 test.py` to start the fuzzers (specifying `python3` is 
important, since it will not work with the default python installation).
