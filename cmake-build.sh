#!/bin/sh
set -ex

mkdir build && cd build
../cmake/bin/cmake -DCMAKE_BUILD_TYPE=Release ..
make
../cmake/bin/ctest --output-on-failure -VV

