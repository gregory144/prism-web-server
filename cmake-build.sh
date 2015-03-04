#!/bin/sh
set -ex

mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make
make install

