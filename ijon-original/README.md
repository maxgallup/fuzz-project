# IJON

This directory `/ijon` contains afl source code directly from ijon. This directory is only used when building the docker image. The test code is in `/ijon/ijon-experiment`.

In that directory we have:

* `/ijon/ijon-experiment/src` - our IJON annotated source files
* `/ijon/ijon-experiment/binaries` - source compiled with afl-clang-fast
* `/ijon/ijon-experiment/mario*` - input and output dirs for fuzzing

From this directory execute `./run-docker.sh` to build and enter the docker container for afl's clang dependencies.

Then, `cd ijon-experiment/` and run `make test` to start the campaign. It will attach the fuzzers to tmux, view it with `tmux ls` and attach with `tmux attach-session -t session_name`.













