#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#include <uv.h>

#include "http2/http.h"
#include "tls.h"

#define SERVER_HOSTNAME "0.0.0.0"
#define SERVER_PORT 7000

typedef struct {
  uv_loop_t * loop;
  tls_server_ctx_t * tls_ctx;
} http_server_data_t;

typedef struct {
  uv_stream_t * stream;

  http_connection_t * connection;

  http_server_data_t * server_data;

  tls_client_ctx_t * tls_ctx;

  /**
   * Keep track of some stats for each client
   */
  size_t bytes_read;
  size_t bytes_written;
  size_t uv_read_count;
  size_t uv_write_count;
} http_client_data_t;

typedef struct {
  uv_stream_t * stream;
  uv_buf_t * buf;
} http_write_req_data_t;

typedef struct {
  uv_stream_t * stream;
} http_shutdown_data_t;

/**
 * Starts the server
 */
int server_start();

#endif
