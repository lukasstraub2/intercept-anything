#!/bin/bash

set -e

cc -fPIC -shared -o rootlink.so rootlink.c
