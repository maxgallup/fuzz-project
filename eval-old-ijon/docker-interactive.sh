#!/bin/bash

docker build -t ijon .

docker run -it --rm -v "$(pwd)":/home/dev/:z ijon

