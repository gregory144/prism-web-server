## Dependencies

* libuv: v0.11.18

## TODO

* API for processing requests/responses
* API for processing streams and frames
* finite state machine for handling stream status
* switch from heap based priority queue to linked list?
* error on violation of incoming max concurrent streams
* better goaway handling, goaway on bad hpack indexes
* better error handling for libuv calls
* fast huffman coding + decoding - more than one bit at a time
* better hpack encoding algorithm - use indexing
* stream priority
* data frame padding
* improve gzip compression to use deflateBound to predict size of output
* runtime configuration
* dynamically load request/data handler from shared library
* upgrade from 1.1
* handle request in thread pool
