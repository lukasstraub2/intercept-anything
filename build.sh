#!/bin/bash

set -e

cc -fPIC -fvisibility=hidden -fno-omit-frame-pointer -shared -O1 -g -Wall -Wno-unused-function -Wno-comment -Wno-nonnull-compare -Wmissing-prototypes -o rootlink.so \
	util.c intercept_glibc.c rootshim.c rootlink.c noxattrs.c signalshim.c hardlinkshim.c main.c
