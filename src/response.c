#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "response.h"

http_response_t* http_response_init(http_request_t* request) {
  http_response_t* response = malloc(sizeof(http_response_t));
  response->headers = multimap_init_with_string_keys();
  response->request = request;
  return response;
}

void http_response_header_add(http_response_t* response, char* name, char* value) {

  char *name_copy, *value_copy;
  COPY_STRING(name_copy, name, strlen(name));
  COPY_STRING(value_copy, value, strlen(value));

  multimap_put(response->headers, name_copy, value_copy);
}

void http_response_status_set(http_response_t* response, uint16_t status) {
  response->status = status;
}

void http_response_free(http_response_t* response) {

  http_request_free(response->request);

  multimap_free(response->headers, free, free);

  free(response);
}

