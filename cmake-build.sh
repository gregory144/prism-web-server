#!/bin/sh
set -ex

mkdir build && cd build
$CMAKE_BIN/cmake -DCMAKE_BUILD_TYPE=Release ..
make
$CMAKE_BIN/ctest --output-on-failure -VV

