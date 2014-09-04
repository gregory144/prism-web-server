#ifndef HTTP_REQUEST_H
#define HTTP_REQUEST_H

#include "multimap.h"
#include "hpack/hpack.h"

typedef struct http_connection_t * _http_connection_t;
typedef struct http_stream_t * _http_stream_t;

typedef struct http_request_t {

  _http_connection_t connection;
  _http_stream_t stream;

  header_list_t * headers;
  multimap_t * params;

  char * method;

  char * scheme;

  char * host;

  int port;

  char * path;

  char * query_string;

  void * data;

} http_request_t;

#define http_request_init(a, b, c) \
  http_request_init_internal((_http_connection_t)a, (_http_stream_t)b, c)

http_request_t * http_request_init_internal(const _http_connection_t connection,
    const _http_stream_t stream, header_list_t * const headers);

void http_request_header_add(const http_request_t * const request, char * name, char * value);

char * http_request_header_get(const http_request_t * const request, char * name);

char * http_request_param_get(const http_request_t * const request, char * name);

multimap_values_t * http_request_param_get_values(const http_request_t * const request, char * name);

char * http_request_method(const http_request_t * const request);

char * http_request_scheme(const http_request_t * const request);

char * http_request_host(const http_request_t * const request);

int http_request_port(const http_request_t * const request);

char * http_request_path(const http_request_t * const request);

char * http_request_query_string(const http_request_t * const request);

void http_request_free(http_request_t * const request);

#endif
