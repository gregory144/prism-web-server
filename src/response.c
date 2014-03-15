#include <stdlib.h>
#include <string.h>

#include "response.h"

http_headers_t* http_response_header_add(http_response_t* response, char* name, char* value) {
  http_headers_t* headers = response->headers;
  http_headers_t* header = malloc(sizeof(http_headers_t));

  size_t name_length = strlen(name);
  header->name = malloc(sizeof(char) * (name_length + 1));
  strncpy(header->name, name, name_length);
  header->name[name_length] = '\0';
  header->name_length = name_length;

  size_t value_length = strlen(value);
  header->value = malloc(sizeof(char) * (value_length + 1));
  strncpy(header->value, value, value_length);
  header->value[value_length] = '\0';
  header->value_length = value_length;

  if (headers) {
    header->next = headers;
  } else {
    header->next = NULL;
  }
  response->headers = headers;
  return header;
}

void http_response_free(http_response_t* response) {

  http_request_free(response->request);

  if (response->headers) hpack_headers_free(response->headers);

  free(response);
}

