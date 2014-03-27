## Dependencies

* libuv: v0.11.18

## TODO

* API for processing requests/responses
* flow control (window update)
* switch from heap based priority queue to linked list?
* buffer writes instead of writing small packets
* cookies
* streams data structure
* max concurrent streams
* POST/PUT/PATCH requests (parse data frame)
* better goaway handling
* goaway on bad hpack indexes
* stream priority
* ping
* header continuations
* push promise
* upgrade from 1.1
* API for processing streams and frames
* better error handling for libuv calls
* better hpack encoding algorithm - use indexing
* data frame padding
