#!/bin/bash

docker build -t ijon .

docker run -it --rm -v ./ijon-experiment:/root/ijon-experiment:z ijon

