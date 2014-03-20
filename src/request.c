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
  char* authority = hash_table_get(request->headers, ":authority");
  char* port = strchr(authority, ':');
  if (port) {
    size_t host_len = port - authority;
    request->host = malloc(sizeof(char) * (host_len + 1));
    strncpy(request->host, authority, host_len);
    request->host[host_len] = '\0';
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
  char* path = hash_table_get(request->headers, ":path");
  if (path) {
    char* query = strchr(path, '?');
    if (query) {
      size_t path_len = query - path;
      request->path = malloc(sizeof(char) * (path_len + 1));
      strncpy(request->path, path, path_len);
      request->path[path_len] = '\0';
    } else {
      request->path = strdup(path);
    }
    request->query_string = query ? query + 1 : NULL;
  } else {
    request->path = NULL;
    request->query_string = NULL;
  }
}

/**
 * Parses the query string into parameters
 */
void parse_parameters(http_request_t* request) {
  if (request->query_string) {
    // TODO
  }
}

/**
 * Removes all headers that start with ':'
 * from the set of headers that will be exposed
 */
void remove_special_headers(hash_table_t* headers) {
  size_t found = 0;
  char* special_names[headers->size];

  hash_table_iter_t iter;
  hash_table_iterator_init(&iter, headers);
  while (hash_table_iterate(&iter)) {
    char* key = iter.key;
    if (*key == ':') {
      special_names[found++] = key;
    }
  }
  size_t i;
  for (i = 0; i < found; i++) {
    hash_table_remove(headers, special_names[i]);
  }
}

http_request_t* http_request_init_internal(_http_parser_t parser,
    _http_stream_t stream, hash_table_t* headers) {
  http_request_t* request = malloc(sizeof(http_request_t));

  request->parser = (_http_parser_t)parser;
  request->stream = (_http_stream_t)stream;

  request->headers = headers;
  request->params = hash_table_init_with_string_keys();

  request->method = hash_table_get(headers, ":method");
  request->scheme = hash_table_get(headers, ":scheme");

  parse_authority(request);
  parse_path(request);
  parse_parameters(request);

  remove_special_headers(headers);

  return request;
}

char* http_request_header_get(http_request_t* request, char* name) {
  return hash_table_get(request->headers, name);
}

char* http_request_param_get(http_request_t* request, char* name) {
  return hash_table_get(request->params, name);
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
  hash_table_free(request->headers, free, free);
  hash_table_free(request->params, free, free);

  if (request->path) {
    free(request->path);
  }

  if (request->host) {
    free(request->host);
  }

  free(request);
}
