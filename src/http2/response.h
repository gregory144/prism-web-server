#ifndef HTTP_RESPONSE_H
#define HTTP_RESPONSE_H

#include "request.h"

typedef struct http_response_t {

  http_request_t * request;

  uint16_t status;

  header_list_t * headers;

} http_response_t;

http_response_t * http_response_init(http_request_t * const request);

void http_response_header_add(const http_response_t * const response, char * name, char * value);

void http_response_pseudo_header_add(const http_response_t * const response, char * name, char * value);

void http_response_status_set(http_response_t * const response, const uint16_t status);

void http_response_free(http_response_t * const response);

#endif
