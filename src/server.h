#include <uv.h>

#include "http.h"

#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

typedef struct http_server_data_s http_server_data_t;
struct http_server_data_s {
  uv_loop_t *loop;
};

typedef struct http_client_data_s http_client_data_t;
struct http_client_data_s {
  uv_stream_t *stream;

  http_parser_t *parser;

  /**
   * Keep track of some stats for each client
   */
  size_t bytes_read;
  size_t bytes_written;
  size_t uv_read_count;
  size_t uv_write_count;
};

typedef struct http_write_req_data_s http_write_req_data_t;
struct http_write_req_data_s {
  uv_stream_t* stream;
  uv_buf_t *buf;
};

typedef struct http_shutdown_data_s http_shutdown_data_t;
struct http_shutdown_data_s {
  uv_stream_t* stream;
};

/**
 * Starts the server
 */
int server_start();

#endif
