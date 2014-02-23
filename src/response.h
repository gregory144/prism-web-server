#ifndef HTTP_RESPONSE_H
#define HTTP_RESPONSE_H

#include "request.h"

typedef struct http_response_t {

  http_request_t* request;

  http_headers_t* headers;

} http_response_t;

#endif
