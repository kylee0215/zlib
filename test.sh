#!/bin/bash

gcc gz2.c -g -o gz2 -lz
rm test.zip > /dev/null 2>&1
./gz2 test.zip test.txt
