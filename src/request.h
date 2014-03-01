#ifndef HTTP_REQUEST_H
#define HTTP_REQUEST_H

#include "hpack.h"

typedef struct http_parser_t* _http_parser_t;
typedef struct http_stream_t* _http_stream_t;

typedef hpack_headers_t http_headers_t;

typedef struct http_params_t {
  // TODO
} http_params_t;

typedef struct http_request_t {

  _http_parser_t parser;
  _http_stream_t stream;

  http_headers_t* headers;
  http_params_t* params;

} http_request_t;

char* http_request_header_get(http_request_t* request, char* name);

#endif
