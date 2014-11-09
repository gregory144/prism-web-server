        ____     ____     ____   _____    __  ___
       / __ \   / __ \   /  _/  / ___/   /  |/  /
      / /_/ /  / /_/ /   / /    \__ \   / /|_/ /
     / ____/  / _, _/  _/ /    ___/ /  / /  / /
    /_/      /_/ |_|  /___/   /____/  /_/  /_/



<pre>
DATA TRACE [2014-11-04 10:52:34.436] 5052 4920 2a20 4854 5450 2f32 2e30 0d0a   <b>PRI</b> * HTTP/2.0..
DATA TRACE [2014-11-04 10:52:34.437] 0d0a 534d 0d0a 0d0a                       ..<b>SM</b>....
</pre>


An interoperable HTTP2 server.

## Build from git

1. ./autogen.sh
1. ./configure CC=clang
1. ./make
1. ./src/prism


## Dependencies

* libuv
* pthreads
* openssl libssl/libcrypto (1.0.2 for ALPN)
* zlib

* joyent http parser [https://github.com/joyent/http-parser] (already in repo, see src/http/h1_1/http_parser.c)

## TODO

#### Required features

* serious security checks
* listen on secure port + non-secure port at the same time
* graceful shutdown
* better error handling for libuv calls
* doxygen documentation
* main thread does the listen()ing and workers accept/read/write
* complete spec compliance
  * ignore unknown frame types
  * error on violation of incoming max concurrent streams
  * goaway on bad hpack indexes

#### Up next

* output data frame padding config option
* runtime configuration from config file
* access/error log
* switch from heap based priority queue to linked list?

* finite state machine for handling stream status
* plugin system that allows access to connections, streams, frames, requests, responses (callbacks)
  * plugin versioning system - each call has a version number that is checked on plugin load

#### Performance:

* fast huffman coding + decoding - more than one bit at a time
* better hpack encoding algorithm - use indexing
* stream priority
* improve gzip compression to use deflateBound to predict size of output
