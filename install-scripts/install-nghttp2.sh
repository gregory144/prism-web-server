#!/bin/sh
set -ex

wget https://github.com/tatsuhiro-t/nghttp2/archive/v0.7.5.zip
unzip v0.7.5.zip
cd nghttp2-0.7.5

autoreconf -i
automake
autoconf
./configure
make
make install
