#!/bin/bash

# exit when any command fails
set -eu -o pipefail

# Install cbindgen if not installed
if ! command -v cbindgen &> /dev/null
then
    cargo install --force cbindgen
fi

TARGET=release
OPTIMIZATION=O3

if [ "${1:-}" = "--debug" ]; then
    TARGET=debug
    OPTIMIZATION=ggdb
fi

echo "Building with target=$TARGET and optimization level=$OPTIMIZATION"
echo

# if release build, build the library first
if [ "$TARGET" = "release" ]; then
    cargo build --release
else
    cargo build
fi

cbindgen --lang c --crate rcore --output rcore.h

export LD_LIBRARY_PATH=./target/$TARGET:$LD_LIBRARY_PATH

gcc main.c -O3 -o main -L./target/$TARGET -lrcore -ldl -lm

# If you want to run the program
# ./main