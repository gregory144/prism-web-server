#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "request.h"

http_request_t* http_request_init_internal(_http_parser_t parser,
    _http_stream_t stream, hash_table_t* headers) {
  http_request_t* request = malloc(sizeof(http_request_t));

  request->parser = (_http_parser_t)parser;
  request->stream = (_http_stream_t)stream;

  request->headers = headers;
  request->params = hash_table_init_with_string_keys();

  // TODO populate params from headers

  return request;
}

char* http_request_header_get(http_request_t* request, char* name) {
  return hash_table_get(request->headers, name);
}

char* http_request_param_get(http_request_t* request, char* name) {
  return hash_table_get(request->params, name);
}

void http_request_free(http_request_t* request) {
  hash_table_free(request->headers, free, free);
  hash_table_free(request->params, free, free);

  free(request);
}
