#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "util.h"

#include "request.h"

/**
 * Parses the ':authority' special header
 * into the host and port
 */
static void parse_authority(http_request_t * const request)
{
  char * authority = http_request_header_get(request, ":authority");

  if (authority) {
    char * port = strchr(authority, ':');

    if (port) {
      COPY_STRING(request->host, authority, port - authority);
      request->port = strtoul(port + 1, NULL, 10);
    } else {
      request->host = strdup(authority);
      request->port = 80;
    }
  } else {
    request->host = NULL;
    request->port = 0;
  }
}

/**
 * Parses the ':path' special header into a plain
 * path and a query string
 */
static bool parse_path(http_request_t * const request)
{
  char * path = http_request_header_get(request, ":path");

  if (!path) {
    log_error("No :path header provided");
    return false;
  }

  char * query = strchr(path, '?');

  if (query) {
    COPY_STRING(request->path, path, query - path);
  } else {
    request->path = strdup(path);
  }

  request->query_string = query ? strdup(query + 1) : NULL;
  return true;
}

static unsigned char ascii_to_hex(const unsigned char in)
{
  if (in >= '0' && in <= '9') {
    return in - '0';
  } else if (in >= 'A' && in <= 'F') {
    return in - 'A' + 10;
  }

  return 0;
}

/*
 * Letters (A–Z and a–z), numbers (0–9) and the characters '.','-','~' and '_' are left as-is
 * SPACE is encoded as '+' or "%20" [8]
 * All other characters are encoded as %HH hex representation with any non-ASCII characters
 *    first encoded as UTF-8 (or other specified encoding)
 * The octet corresponding to the tilde ("~") character is often encoded as "%7E" by older
 * URI processing implementations; the "%7E" can be replaced by "~" without changing its interpretation.
 *
 * The encoding of SPACE as '+' and the selection of "as-is" characters distinguishes this encoding from RFC 1738.
 */
static char * url_decode(char * encoded, const size_t length)
{
  char * decoded = malloc(sizeof(char) * length + 1);
  size_t decoded_index = 0;
  size_t encoded_index = 0;

  while (encoded_index < length) {
    unsigned char c = encoded[encoded_index++];

    if (c == '+') {
      decoded[decoded_index++] = ' ';
    } else if (c == '%' && encoded_index + 2 <= length) {
      unsigned char digit1 = ascii_to_hex(encoded[encoded_index++]);
      unsigned char digit2 = ascii_to_hex(encoded[encoded_index++]);
      unsigned char decimal = (digit1 << 4) | digit2;
      decoded[decoded_index++] = decimal;
    } else {
      decoded[decoded_index++] = c;
    }
  }

  decoded[decoded_index] = '\0';
  return decoded;
}

/**
 * Parses the query string into parameters
 */
static void parse_parameters(multimap_t * const params, char * query_string)
{
  if (query_string) {
    size_t query_string_len = strlen(query_string);
    char * buf = query_string;
    char * end_buf = buf + query_string_len;
    char * key = NULL;
    size_t key_len = 0;
    char * value = NULL;
    size_t value_len = 0;

    while (buf < end_buf) {
      char * end = strpbrk(buf, "=&;#");
      size_t len = end ? end - buf : end_buf - buf;
      char next = end ? *end : 0;

      switch (next) {
        case '=': {
          key = buf;
          key_len = len;
        }
        break;

        case '&':
        case ';':
        case '#':
        case '\0': {
          if (key) {
            value = buf;
            value_len = len;
          } else {
            // key with no value
            key = buf;
            key_len = len;
            value = "";
            value_len = 0;
          }

          char * decoded_key = url_decode(key, key_len);
          char * decoded_value = url_decode(value, value_len);

          multimap_put(params, decoded_key, decoded_value);
          key = NULL;
          value = NULL;
        }
        break;
      }

      buf += len + 1;
    }
  }
}

http_request_t * http_request_init(void * handler_data, header_list_t * const header_list)
{
  http_request_t * request = malloc(sizeof(http_request_t));

  request->handler_data = handler_data;
  request->data = NULL;

  request->params = multimap_init_with_string_keys();

  request->path = NULL;
  request->query_string = NULL;
  request->host = NULL;
  request->method = NULL;
  request->scheme = NULL;

  if (header_list) {

    request->headers = header_list;

    char * method = http_request_header_get(request, ":method");

    if (!method) {
      log_error("Missing :method header");
      http_request_free(request);
      return NULL;
    }

    request->method = strdup(method);

    char * scheme = http_request_header_get(request, ":scheme");

    if (!scheme) {
      log_error("Missing :scheme header");
      http_request_free(request);
      return NULL;
    }

    request->scheme = strdup(scheme);

    if (!parse_path(request)) {
      http_request_free(request);
      return NULL;
    }

    parse_authority(request);
    parse_parameters(request->params, request->query_string);

    header_list_remove_pseudo_headers(header_list);

  } else {

    request->headers = header_list_init(NULL);

    request->path = NULL;
    request->query_string = NULL;
    request->host = NULL;
    request->method = NULL;
    request->scheme = NULL;

  }

  return request;
}

void http_request_header_add(const http_request_t * const request, char * name, char * value)
{

  char * name_copy, * value_copy;
  size_t name_length = strlen(name);
  size_t value_length = strlen(value);
  COPY_STRING(name_copy, name, name_length);
  COPY_STRING(value_copy, value, value_length);

  header_list_push(request->headers, name_copy, name_length, true, value_copy, value_length, true);
}

/**
 * Returns the first header value for the given name
 * (ignores any other defined header values)
 *
 */
char * http_request_header_get(const http_request_t * const request, char * const name)
{
  header_list_linked_field_t * entry = header_list_get(request->headers, name, NULL);

  if (entry) {
    return entry->field.value;
  }

  return NULL;
}

/**
 * Returns the first param value for the given name
 * (ignores any other defined parameter values)
 */
char * http_request_param_get(const http_request_t * const request, char * name)
{
  multimap_values_t * values = multimap_get(request->params, name);
  return values ? values->value : NULL;
}

/**
 * Returns a reference to the first header value for the given name.
 */
multimap_values_t * http_request_param_get_values(const http_request_t * const request, char * name)
{
  return multimap_get(request->params, name);
}

char * http_request_method(const http_request_t * const request)
{
  return request->method;
}

char * http_request_scheme(const http_request_t * const request)
{
  return request->scheme;
}

char * http_request_host(const http_request_t * const request)
{
  return request->host;
}

char * http_request_path(const http_request_t * const request)
{
  return request->path;
}

int http_request_port(const http_request_t * const request)
{
  return request->port;
}

char * http_request_query_string(const http_request_t * const request)
{
  return request->query_string;
}

void http_request_free(http_request_t * const request)
{
  header_list_free(request->headers);
  multimap_free(request->params, free, free);

  if (request->path) {
    free(request->path);
  }

  if (request->query_string) {
    free(request->query_string);
  }

  if (request->host) {
    free(request->host);
  }

  if (request->method) {
    free(request->method);
  }

  if (request->scheme) {
    free(request->scheme);
  }

  free(request);
}
