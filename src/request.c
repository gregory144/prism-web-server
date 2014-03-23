#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "util.h"
#include "request.h"

/**
 * Parses the ':authority' special header
 * into the host and port
 */
void parse_authority(http_request_t* request) {
  char* authority = http_request_header_get(request, ":authority");
  char* port = strchr(authority, ':');
  if (port) {
    COPY_STRING(request->host, authority, port - authority);
    request->port = strtoul(port + 1, NULL, 10);
  } else {
    request->host = strdup(authority);
    request->port = 80;
  }
}

/**
 * Parses the ':path' special header into a plain
 * path and a query string
 */
void parse_path(http_request_t* request) {
  char* path = http_request_header_get(request, ":path");
  if (path) {
    char* query = strchr(path, '?');
    if (query) {
      COPY_STRING(request->path, path, query - path);
    } else {
      request->path = strdup(path);
    }
    request->query_string = query ? strdup(query + 1) : NULL;
  } else {
    request->path = NULL;
    request->query_string = NULL;
  }
}

unsigned char ascii_to_hex(unsigned char in) {
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
char* url_decode(char* encoded, size_t length) {
  char* decoded = malloc(sizeof(char) * length + 1);
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
void parse_parameters(multimap_t* params, char* query_string) {
  if (query_string) {
    size_t query_string_len = strlen(query_string);
    char* buf = query_string;
    char* end_buf = buf + query_string_len;
    char* key = NULL;
    size_t key_len = 0;
    char* value = NULL;
    size_t value_len = 0;
    while (buf < end_buf) {
      char* end = strpbrk(buf, "=&;#");
      size_t len = end ? end - buf : end_buf - buf;
      char next = end ? *end : 0;
      switch(next) {
        case '=':
          {
            key = buf;
            key_len = len;
          }
          break;
        case '&':
        case ';':
        case '#':
        case '\0':
          {
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

            char* decoded_key = url_decode(key, key_len);
            char* decoded_value = url_decode(value, value_len);

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

/**
 * Removes all headers that start with ':'
 * from the set of headers that will be exposed
 */
void remove_special_headers(multimap_t* headers) {
  size_t found = 0;
  char* special_names[headers->size];

  multimap_iter_t iter;
  multimap_iterator_init(&iter, headers);
  while (multimap_iterate(&iter)) {
    char* key = iter.key;
    if (*key == ':') {
      special_names[found++] = key;
    }
  }
  size_t i;
  for (i = 0; i < found; i++) {
    multimap_remove(headers, special_names[i], free, free);
  }
}

http_request_t* http_request_init_internal(_http_connection_t connection,
    _http_stream_t stream, multimap_t* headers) {
  http_request_t* request = malloc(sizeof(http_request_t));

  request->connection = (_http_connection_t)connection;
  request->stream = (_http_stream_t)stream;

  request->headers = headers;
  request->params = multimap_init_with_string_keys();

  request->method = strdup(http_request_header_get(request, ":method"));
  request->scheme = strdup(http_request_header_get(request, ":scheme"));

  parse_authority(request);
  parse_path(request);
  parse_parameters(request->params, request->query_string);

  remove_special_headers(headers);

  return request;
}

/**
 * Returns the first header value for the given name
 * (ignores any other defined header values)
 */
char* http_request_header_get(http_request_t* request, char* name) {
  multimap_values_t* values = multimap_get(request->headers, name);
  return values ? values->value : NULL;
}

/**
 * Returns a reference to the first header value for the given name.
 */
multimap_values_t* http_request_header_get_values(http_request_t* request, char* name) {
  return multimap_get(request->headers, name);
}

/**
 * Returns the first param value for the given name
 * (ignores any other defined parameter values)
 */
char* http_request_param_get(http_request_t* request, char* name) {
  multimap_values_t* values = multimap_get(request->params, name);
  return values ? values->value : NULL;
}

/**
 * Returns a reference to the first header value for the given name.
 */
multimap_values_t* http_request_param_get_values(http_request_t* request, char* name) {
  return multimap_get(request->params, name);
}

char* http_request_method(http_request_t* request) {
  return request->method;
}

char* http_request_scheme(http_request_t* request) {
  return request->scheme;
}

char* http_request_host(http_request_t* request) {
  return request->host;
}

char* http_request_path(http_request_t* request) {
  return request->path;
}

int http_request_port(http_request_t* request) {
  return request->port;
}

char* http_request_query_string(http_request_t* request) {
  return request->query_string;
}

void http_request_free(http_request_t* request) {
  multimap_free(request->headers, free, free);
  multimap_free(request->params, free, free);

  if (request->path) free(request->path);
  if (request->query_string) free(request->query_string);
  if (request->host) free(request->host);
  if (request->method) free(request->method);
  if (request->scheme) free(request->scheme);

  free(request);
}
