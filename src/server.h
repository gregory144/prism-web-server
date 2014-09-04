#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#include <uv.h>

#include "util/blocking_queue.h"

#include "http2/http.h"
#include "tls.h"
#include "backend.h"

struct worker_s;

typedef struct {

  long port;
  char * hostname;
  bool use_tls;

  size_t num_workers;

  char * cert_file;
  char * private_key_file;

  char * backend_file;

} server_config_t;

typedef struct {

  server_config_t * config;

  backend_t backend;

  uv_loop_t loop;

  uv_signal_t sigpipe_handler;
  uv_signal_t sigint_handler;
  uv_tcp_t tcp_handler;

  tls_server_ctx_t * tls_ctx;

  struct worker_s ** workers;

  bool terminate;

  size_t client_ids;

} server_t;

typedef struct client_s {
  uv_tcp_t tcp;

  // used to nofity the server thread
  // that a write has been queued
  uv_async_t write_handle;

  // used to nofity the server the client
  // should be closed
  uv_async_t close_handle;

  // used to nofity the worker a write
  // has succeeded
  uv_async_t written_handle;

  size_t closed_async_handle_count;

  blocking_queue_t * write_queue;

  http_connection_t * connection;

  server_t * server;

  tls_client_ctx_t * tls_ctx;

  bool closing;
  bool uv_closed;
  bool http_closed;

  bool eof;

  /**
   * Keep track of some stats for each client
   */
  size_t octets_read;
  size_t octets_written;

  size_t id;
  bool closed;

  size_t worker_index;

} client_t;

typedef struct worker_s {

  server_t * server;

  size_t assigned_reads;

  uv_thread_t thread;
  uv_loop_t loop;

  uv_async_t async_handle;
  uv_async_t stop_handle;

  uv_mutex_t terminate_mutex;
  bool terminate;

  blocking_queue_t * read_queue;

} worker_t;

/**
 * Used for passing the buffer to a worker
 */
typedef struct {

  struct client_s * client;

  uint8_t * buffer;

  size_t length;

  bool eof;

} worker_buffer_t;

typedef struct {
  uv_stream_t * stream;
  uv_buf_t buf;
  uv_write_t req;
} http_write_req_data_t;

server_t * server_init(server_config_t * config);

int server_start(server_t * server);

void server_stop(server_t * server);

#endif
