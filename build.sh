#!/bin/bash

set -e

cc -fPIC -fvisibility=hidden -shared -O1 -g -Wall -Wno-unused-function -Wno-comment -Wno-nonnull-compare -Wmissing-prototypes -o intercept_glibc.so intercept_glibc.c
