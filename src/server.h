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

struct worker_process_t {
  struct server_t * server;
  uv_process_t req;
  uv_process_options_t options;
  uv_pipe_t pipe;
  bool stopped;
};

struct tcp_list_t {
  uv_tcp_t uv_server;
  struct tcp_list_t * next;
};

struct server_t {

  uv_loop_t loop;

  struct tcp_list_t * tcp_list;
  size_t active_listeners;

  log_context_t * log;
  log_context_t * data_log;
  log_context_t * wire_log;

  struct server_config_t * config;

  bool stopping;
  uv_signal_t sigpipe_handler;
  uv_signal_t sigint_handler;
  size_t active_signal_handlers;

  struct worker_process_t ** workers;
  size_t active_workers;
  size_t round_robin_counter;

};

void server_init(struct server_t *, struct server_config_t * config);

bool server_run(struct server_t * server);

void server_stop(struct server_t * server);

void server_free(struct server_t * server);

#endif
