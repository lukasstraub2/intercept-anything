#!/bin/bash

set -e

cc -fPIC -shared -O1 -g -Wall -Wno-unused-function -Wno-comment -Wno-nonnull-compare -Wmissing-prototypes -o rootlink.so rootlink.c
cc -fPIC -shared -O1 -g -Wall -Wno-unused-function -Wno-comment -Wno-nonnull-compare -Wmissing-prototypes -o noxattrs.so noxattrs.c
cc -fPIC -shared -O1 -g -Wall -Wno-unused-function -Wno-comment -Wno-nonnull-compare -Wmissing-prototypes -o nolink.so nolink.c
cc -fPIC -shared -O1 -g -Wall -Wno-unused-function -Wno-comment -Wno-nonnull-compare -Wmissing-prototypes -o procfs.so procfs.c
cc -fPIC -shared -O1 -g -Wall -Wno-unused-function -Wno-comment -Wno-nonnull-compare -Wmissing-prototypes -o sigsys2enosys.so sigsys2enosys.c
