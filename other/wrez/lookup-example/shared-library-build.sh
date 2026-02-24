#!/bin/sh

gcc -Wall -fPIC -g -ggdb -c -o shared-library.o shared-library.c
ld -Bshareable -o libshared-library.so shared-library.o
gcc -L`pwd` -o shared-library-use shared-library-use.c -lshared-library

