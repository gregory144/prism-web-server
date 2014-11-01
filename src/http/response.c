#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "response.h"

http_response_t * http_response_init(http_request_t * const request)
{
  http_response_t * response = malloc(sizeof(http_response_t));
  response->headers = header_list_init(NULL);
  response->request = request;
  return response;
}

void http_response_header_add(const http_response_t * const response, char * name, char * value)
{
  char * name_copy, * value_copy;
  size_t name_length = strlen(name);
  size_t value_length = strlen(value);
  COPY_STRING(name_copy, name, name_length);
  COPY_STRING(value_copy, value, value_length);

  header_list_push(response->headers, name_copy, name_length, true, value_copy, value_length, true);
}

void http_response_pseudo_header_add(const http_response_t * const response, char * name, char * value)
{
  char * name_copy, * value_copy;
  size_t name_length = strlen(name);
  size_t value_length = strlen(value);
  COPY_STRING(name_copy, name, name_length);
  COPY_STRING(value_copy, value, value_length);

  header_list_unshift(response->headers, name_copy, name_length, true, value_copy, value_length, true);
}

void http_response_status_set(http_response_t * const response, const uint16_t status)
{
  response->status = status;
}

void http_response_free(http_response_t * const response)
{
  http_request_free(response->request);
  response->request = NULL;

  header_list_free(response->headers);
  response->headers = NULL;

  free(response);
}

