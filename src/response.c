#include <stdlib.h>
#include <string.h>

#include "response.h"

http_response_t* http_response_init(http_request_t* request) {
  http_response_t* response = malloc(sizeof(http_response_t));
  response->headers = multimap_init_with_string_keys();
  response->request = request;
  return response;
}

void http_response_header_add(http_response_t* response, char* name, char* value) {
  size_t name_length = strlen(name);
  char* name_copy = malloc(sizeof(char) * (name_length + 1));
  strncpy(name_copy, name, name_length);
  name_copy[name_length] = '\0';

  size_t value_length = strlen(value);
  char* value_copy = malloc(sizeof(char) * (value_length + 1));
  strncpy(value_copy, value, value_length);
  value_copy[value_length] = '\0';

  multimap_put(response->headers, name_copy, value_copy);
}

void http_response_free(http_response_t* response) {

  http_request_free(response->request);

  multimap_free(response->headers, free, free);

  free(response);
}

