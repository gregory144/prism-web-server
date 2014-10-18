#ifndef HTTP_plugin_H
#define HTTP_plugin_H

#include "log.h"

#include "http/http.h"

struct server_s;

struct worker_s;

typedef struct {

  log_context_t * log;

  char * plugin_file;

  uv_lib_t lib;

  struct plugin_handlers_s * handlers;

  void * data;

} plugin_t;

typedef void (*plugin_start_cb)(plugin_t * plugin);

typedef void (*plugin_stop_cb)(plugin_t * plugin);

typedef void (*plugin_request_cb)(plugin_t * plugin, struct worker_s * worker, http_request_t * request,
                                   http_response_t * response);

typedef void (*plugin_data_cb)(plugin_t * plugin, struct worker_s * worker, http_request_t * request,
                                http_response_t * response,
                                uint8_t * buf, size_t len, bool last, bool free_buf);

typedef struct plugin_handlers_s {

  plugin_request_cb request;
  plugin_data_cb data;
  plugin_start_cb start;
  plugin_stop_cb stop;

} plugin_handlers_t;

typedef void (*plugin_initializer)(plugin_t * plugin, struct server_s * server);

plugin_t * plugin_init(plugin_t * plugin, log_context_t * log, char * plugin_file,
    struct server_s * server);

void plugin_request_handler(plugin_t * plugin, struct worker_s * worker, http_request_t * request,
                             http_response_t * response);

void plugin_data_handler(plugin_t * plugin, struct worker_s * worker, http_request_t * request,
                          http_response_t * response,
                          uint8_t * buf, size_t length, bool last, bool free_buf);

void plugin_start(plugin_t * plugin);

void plugin_stop(plugin_t * plugin);

#endif
