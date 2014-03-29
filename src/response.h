#ifndef HTTP_RESPONSE_H
#define HTTP_RESPONSE_H

#include "request.h"

typedef struct http_response_t {

  http_request_t* request;

  uint16_t status;

  multimap_t* headers;

} http_response_t;

http_response_t* http_response_init(http_request_t* request);

void http_response_header_add(http_response_t* response, char* name, char* value);

void http_response_status_set(http_response_t* response, uint16_t status);

void http_response_free(http_response_t* response);

#endif
