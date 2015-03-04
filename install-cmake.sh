#!/bin/sh
set -ex

wget http://www.cmake.org/files/v3.1/cmake-3.1.3-Linux-x86_64.tar.gz
tar -xzf cmake-3.1.3-Linux-x86_64.tar.gz
cd cmake-3.1.3-Linux-x86_64
mv cmake-3.1.3-Linux-x86_64 cmake
