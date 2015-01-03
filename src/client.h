#ifndef HTTP_CLIENT_H
#define HTTP_CLIENT_H

#include "config.h"

#include <uv.h>

#include "util/log.h"
#include "util/blocking_queue.h"
#include "util/atomic_int.h"

#include "http/http.h"
#include "tls.h"
#include "plugin.h"
#include "worker.h"

struct client_t {

  log_context_t * log;
  log_context_t * data_log;
  log_context_t * wire_log;

  uv_tcp_t tcp;

  struct plugin_invoker_t * plugin_invoker;

  // used to nofity the server thread
  // that a write has been queued
  uv_async_t write_handle;

  // used to nofity the server the client
  // should be closed
  uv_async_t close_handle;

  // used to nofity the worker a write
  // has succeeded
  uv_async_t written_handle;

  atomic_int_t read_counter;
  uv_async_t read_finished_handle;

  size_t closed_async_handle_count;

  blocking_queue_t * write_queue;

  http_connection_t * connection;

  struct worker_t * worker;

  tls_client_ctx_t * tls_ctx;

  bool closing;
  bool uv_closed;
  bool http_closed;
  bool reads_finished;

  bool eof;

  /**
   * Keep track of some stats for each client
   */
  size_t octets_read;
  size_t octets_written;

  size_t id;
  bool closed;

  size_t worker_index;

  bool selected_protocol;

};

struct client_t * client_init(struct worker_t * worker);

bool client_free(struct client_t * client);

#endif
