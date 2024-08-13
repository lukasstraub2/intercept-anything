#!/bin/bash

set -e

gcc -fPIC -O1 -g proc_self_maps.c -o proc_self_maps
gcc -fPIC -O1 -g rlimit_nofile.c -o rlimit_nofile

./proc_self_maps
./rlimit_nofile
