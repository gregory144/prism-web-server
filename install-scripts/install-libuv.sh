#!/bin/sh
set -ex

wget http://libuv.org/dist/v1.4.2/libuv-v1.4.2.tar.gz
tar -xzf libuv-v1.4.2.tar.gz
cd libuv-v1.4.2
sh autogen.sh
./configure
make
sudo make install
