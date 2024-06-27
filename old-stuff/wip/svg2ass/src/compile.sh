#!/bin/sh

gcc -g -O0 -no-pie svg2ass.c vect.c colors.c nxml.c -o ../binaries/svg2ass_frida -lm
gcc -fsanitize=address -g -O0 -no-pie svg2ass.c vect.c colors.c nxml.c -o ../binaries/svg2ass_sanitized -lm
