#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#include "config.h"

#include <uv.h>

#include "util/log.h"

#include "http/http.h"
#include "tls.h"
#include "worker.h"
#include "plugin.h"
#include "server_config.h"

struct child_worker_t {
  uv_process_t req;
  uv_process_options_t options;
  uv_pipe_t pipe;
};

struct server_t {

  uv_loop_t loop;

  log_context_t * log;
  log_context_t * data_log;
  log_context_t * wire_log;

  struct server_config_t * config;

  uv_signal_t sigpipe_handler;
  uv_signal_t sigint_handler;

  struct child_worker_t ** workers;
  size_t round_robin_counter;

};

void server_init(struct server_t *, struct server_config_t * config);

int server_run(struct server_t * server);

void server_stop(struct server_t * server);

#endif
