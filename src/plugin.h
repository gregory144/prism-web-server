#ifndef HTTP_PLUGIN_H
#define HTTP_PLUGIN_H

#include <uv.h>

#include "log.h"
#include "worker.h"
#include "client.h"
#include "plugin_callbacks.h"

struct plugin_t;
struct client_t;
struct worker_t;

typedef void (*plugin_start_cb)(struct plugin_t * plugin);

typedef void (*plugin_stop_cb)(struct plugin_t * plugin);

typedef bool (*plugin_internal_handler_va_cb)(struct plugin_t * plugin, struct client_t * client,
    enum plugin_callback_e cb, va_list args);

struct plugin_handlers_t {

  plugin_start_cb start;
  plugin_internal_handler_va_cb handle;
  plugin_stop_cb stop;

};

struct plugin_t {

  struct log_context_t * log;

  char * plugin_file;

  uv_lib_t lib;

  struct plugin_handlers_t * handlers;

  void * data;

};

struct plugin_list_t {

  struct plugin_list_t * next;

  struct plugin_t * plugin;

};

struct plugin_invoker_t {

  struct plugin_list_t * plugins;

  struct client_t * client;

};

typedef void (*plugin_initializer)(struct plugin_t * plugin, struct worker_t * worker);

struct plugin_t * plugin_init(struct plugin_t * plugin, struct log_context_t * log, char * plugin_file,
                       struct worker_t * worker);

bool plugin_handler_va(struct plugin_t * plugin, struct client_t * client, enum plugin_callback_e cb, va_list args);

void plugin_start(struct plugin_t * plugin);

void plugin_stop(struct plugin_t * plugin);

void plugin_free(struct plugin_t * plugin);

#endif
