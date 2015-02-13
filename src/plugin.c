#include "config.h"

#include <uv.h>

#include "worker.h"
#include "plugin.h"

#include "util.h"
#include "http/http.h"

struct plugin_t * plugin_init(struct plugin_t * plugin, struct log_context_t * log, char * plugin_file,
                       struct worker_t * worker)
{
  bool free_plugin = false;

  if (!plugin) {
    free_plugin = true;
    plugin = malloc(sizeof(struct plugin_t));
  }

  plugin->log = log;
  plugin->handlers = malloc(sizeof(struct plugin_handlers_t));

  plugin->data = NULL;
  uv_lib_t * lib = &plugin->lib;

  if (uv_dlopen(plugin_file, lib)) {
    log_append(plugin->log, LOG_FATAL, "Error loading plugin: %s", uv_dlerror(&plugin->lib));

    if (free_plugin) {
      free(plugin);
    }

    return NULL;
  } else {
    log_append(plugin->log, LOG_DEBUG, "Plugin loaded");
  }

  plugin_initializer init;

  if (uv_dlsym(lib, "plugin_initialize", (void **) &init)) {
    log_append(plugin->log, LOG_FATAL, "Error loading plugin initializer: %s", uv_dlerror(lib));

    if (free_plugin) {
      free(plugin);
    }

    return NULL;
  }

  init(plugin, worker);

  return plugin;
}

bool plugin_invoke(struct plugin_invoker_t * invoker, enum plugin_callback_e cb, ...)
{
  va_list args;
  struct plugin_list_t * current = invoker->plugins;

  while (current) {
    va_start(args, cb);
    struct plugin_t * plugin = current->plugin;
    bool ret = plugin->handlers->handle(plugin, invoker->client, cb, args);
    va_end(args);

    if (ret) {
      return true;
    }

    current = current->next;
  }

  return false;
}

void plugin_start(struct plugin_t * plugin)
{
  plugin->handlers->start(plugin);
}

void plugin_stop(struct plugin_t * plugin)
{
  plugin->handlers->stop(plugin);
}

void plugin_free(struct plugin_t * plugin)
{
  free(plugin->handlers);
  free(plugin);
}

