#!/bin/sh
set -ex

wget http://ftp.gnu.org/gnu/bison/bison-3.0.4.tar.gz
tar -xzf bison-3.0.4.tar.gz
cd bison-3.0.4
./configure
make
sudo make install
