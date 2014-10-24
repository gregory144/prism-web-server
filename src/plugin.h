#ifndef HTTP_PLUGIN_H
#define HTTP_PLUGIN_H

#include <uv.h>

#include "log.h"

#include "plugin_callbacks.h"

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

typedef bool (*plugin_internal_handler_va_cb)(plugin_t * plugin, struct worker_s * worker,
    enum plugin_callback_e cb, va_list args);

typedef struct plugin_handlers_s {

  plugin_start_cb start;
  plugin_internal_handler_va_cb handle;
  plugin_stop_cb stop;

} plugin_handlers_t;

typedef void (*plugin_initializer)(plugin_t * plugin, struct server_s * server);

plugin_t * plugin_init(plugin_t * plugin, log_context_t * log, char * plugin_file,
    struct server_s * server);

bool plugin_handler_va(plugin_t * plugin, struct worker_s * worker, enum plugin_callback_e cb, va_list args);

void plugin_start(plugin_t * plugin);

void plugin_stop(plugin_t * plugin);

#endif
