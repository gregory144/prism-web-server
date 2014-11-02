#ifndef HTTP_REQUEST_H
#define HTTP_REQUEST_H

#include "multimap.h"
#include "hpack/hpack.h"

typedef struct http_request_t {

  void * handler_data;

  void * data;

  log_context_t * log;

  header_list_t * headers;
  multimap_t * params;

  char * method;

  char * scheme;

  char * authority;

  char * host;

  int port;

  char * path;

  char * query_string;

} http_request_t;

http_request_t * http_request_init(void * handler_data, log_context_t * log, header_list_t * const headers);

void http_request_header_add(const http_request_t * const request, char * name, char * value);

char * http_request_header_get(const http_request_t * const request, char * name);

char * http_request_param_get(const http_request_t * const request, char * name);

multimap_values_t * http_request_param_get_values(const http_request_t * const request, char * name);

char * http_request_method(const http_request_t * const request);

char * http_request_scheme(const http_request_t * const request);

char * http_request_authority(const http_request_t * const request);

char * http_request_host(const http_request_t * const request);

int http_request_port(const http_request_t * const request);

char * http_request_path(const http_request_t * const request);

char * http_request_query_string(const http_request_t * const request);

void http_request_free(http_request_t * const request);

#endif
