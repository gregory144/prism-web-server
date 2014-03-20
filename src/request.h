#ifndef HTTP_REQUEST_H
#define HTTP_REQUEST_H

#include "hpack.h"

typedef struct http_parser_t* _http_parser_t;
typedef struct http_stream_t* _http_stream_t;

typedef struct http_request_t {

  _http_parser_t parser;
  _http_stream_t stream;

  hash_table_t* headers;
  hash_table_t* params;

  char* method;

  char* scheme;

  char* host;

  int port;

  char* path;

  char* query_string;

} http_request_t;

#define http_request_init(a, b, c) \
  http_request_init_internal((_http_parser_t)a, (_http_stream_t)b, c)

http_request_t* http_request_init_internal(_http_parser_t parser, 
    _http_stream_t stream, hash_table_t* headers);

char* http_request_header_get(http_request_t* request, char* name);

char* http_request_param_get(http_request_t* request, char* name);

char* http_request_method(http_request_t* request);

char* http_request_scheme(http_request_t* request);

char* http_request_host(http_request_t* request);

int http_request_port(http_request_t* request);

char* http_request_path(http_request_t* request);

char* http_request_query_string(http_request_t* request);

void http_request_free(http_request_t* request);

#endif
