#!/bin/bash

docker build -t ijon .

docker run -it --rm -v ./ijon-experiment:/home/dev/ijon-experiment:z ijon

