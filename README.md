## Dependencies

* libuv: v0.11.18

## TODO

* API for processing requests/responses
* scheme, authority, port, query string
* send decoded query parameters to request callback
* cookies
* duplicate header, parameter keys
* streams data structure
* max concurrent streams
* POST/PUT/PATCH requests (parse data frame)
* better goaway handling
* goaway on bad hpack indexes
* flow control (window update)
* stream priority
* ping
* continuations
* push promise
* upgrade from 1.1
* API for processing streams and frames
* better error handling for libuv calls
* data frame padding
