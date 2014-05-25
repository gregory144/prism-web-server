## Dependencies

* libuv: v0.11.18

## TODO

* API for processing requests/responses
* finite state machine for handling stream status
* switch from heap based priority queue to linked list?
* max concurrent streams
* POST/PUT/PATCH requests (parse data frame)
* better goaway handling
* goaway on bad hpack indexes
* stream priority
* fast huffman coding + decoding based - more than one bit at a time
* ping
* push promise
* upgrade from 1.1
* API for processing streams and frames
* better error handling for libuv calls
* better hpack encoding algorithm - use indexing
* data frame padding
