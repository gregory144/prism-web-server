#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#include <uv.h>

#include "http2/http.h"
#include "tls.h"
#include "blocking_queue.h"

#define SERVER_HOSTNAME "0.0.0.0"
#define SERVER_PORT 7000

struct worker_s;

typedef struct {

  uv_loop_t * loop;
  tls_server_ctx_t * tls_ctx;

  int port;
  bool use_tls;
  bool enable_compression;

  struct worker_s ** workers;
  size_t num_workers;
  size_t num_workers_terminated;

} server_t;

typedef struct client_s {
  uv_stream_t * stream;

  uv_mutex_t async_mutex;

  uv_async_t * write_handle;
  uv_async_t * close_handle;
  blocking_queue_t * write_queue;

  http_connection_t * connection;

  server_t * server;

  tls_client_ctx_t * tls_ctx;

  struct worker_s * worker;

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

  uv_work_t work_req;

  uv_mutex_t * mutex;

  blocking_queue_t * read_queue;

  bool terminated;

} worker_t;

/**
 * Used for passing the buffer to a worker
 */
typedef struct {

  struct client_s * client;

  uint8_t * buffer;

  size_t length;

} worker_buffer_t;

typedef struct {
  uv_stream_t * stream;
  uv_buf_t * buf;
} http_write_req_data_t;

typedef struct {
  uv_stream_t * stream;
} http_shutdown_data_t;

server_t * server_init(int port, bool enable_compression, bool use_tls, char * key_file, char * cert_file);

int server_start(server_t * server);

void server_stop(server_t * server);

#endif
