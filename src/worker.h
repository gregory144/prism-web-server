#ifndef HTTP_WORKER_H
#define HTTP_WORKER_H

#include "config.h"

#include <uv.h>

#include "util/log.h"
#include "util/blocking_queue.h"
#include "util/atomic_int.h"

#include "http/http.h"

#include "server_config.h"

#include "client.h"
#include "plugin.h"
#include "tls.h"


struct plugin_list_t;

struct worker_t {

  struct server_config_t * config;

  log_context_t * log;
  log_context_t * data_log;
  log_context_t * wire_log;

  size_t assigned_reads;

  uv_loop_t loop;

  uv_pipe_t queue;

  struct plugin_list_t * plugins;

  tls_server_ctx_t * tls_ctx;

};

/**
 * Used for passing the buffer to a worker
 */
struct worker_buffer_t {

  struct client_t * client;

  uint8_t * buffer;

  size_t length;

  bool eof;

};

struct http_write_req_data_t {
  uv_stream_t * stream;
  uv_buf_t buf;
  uv_write_t req;
};

bool worker_init(struct worker_t * worker, struct server_config_t * config);

int worker_run(struct worker_t * worker);

void worker_stop(struct worker_t * worker);

#endif
