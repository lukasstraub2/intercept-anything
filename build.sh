#!/bin/bash

set -e

cc -fPIC -shared -O1 -g -Wall -Wno-unused-function -Wno-comment -Wno-nonnull-compare -o rootlink.so rootlink.c
cc -fPIC -shared -O1 -g -Wall -Wno-unused-function -Wno-comment -Wno-nonnull-compare -o noxattrs.so noxattrs.c
cc -fPIC -shared -O1 -g -Wall -Wno-unused-function -Wno-comment -Wno-nonnull-compare -o procfs.so procfs.c
cc -fPIC -shared -O1 -g -Wall -Wno-unused-function -Wno-comment -Wno-nonnull-compare -o sigsys2enosys.so sigsys2enosys.c
