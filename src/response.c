#include <stdlib.h>

#include "response.h"

void http_response_free(http_response_t* response) {

  http_request_free(response->request);

  if (response->headers) hpack_headers_free(response->headers);

  free(response);
}

