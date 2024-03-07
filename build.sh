#!/bin/bash

set -e

cc -fPIC -shared -O1 -g -Wall -Wno-unused-function -Wno-comment -Wno-nonnull-compare -o rootlink.so rootlink.c
