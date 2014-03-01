#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "request.h"

char* http_request_header_get(http_request_t* request, char* name) {
  http_headers_t* header = request->headers;
  while (header) {
    fprintf(stderr, "Comparing %s and %s\n", name, header->name);
    if (strcmp(header->name, name) == 0) {
      return header->value;
    }
    header = header->next;
  }
  return NULL;
}

