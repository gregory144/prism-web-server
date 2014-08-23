#include <uv.h>

#include "backend.h"

#include "util/util.h"
#include "http2/http.h"

backend_t * backend_init(backend_t * backend, char * backend_file)
{
  bool free_backend = false;
  if (!backend) {
    free_backend = true;
    backend = malloc(sizeof(backend_t));
  }
  uv_lib_t * lib = &backend->lib;

  if (uv_dlopen(backend_file, lib)) {
    log_fatal("Error loading backend: %s", uv_dlerror(&backend->lib));
    if (free_backend) {
      free(backend);
    }
    return NULL;
  } else {
    log_debug("Backend loaded");
  }

  backend_initializer init;
  if (uv_dlsym(lib, "backend_initialize", (void **) &init)) {
    log_fatal("Error loading backend initializer: %s", uv_dlerror(lib));
    if (free_backend) {
      free(backend);
    }
    return NULL;
  }

  init(backend);

  return backend;
}

void backend_start(backend_t * backend)
{
  backend->handlers.start();
}

void backend_stop(backend_t * backend)
{
  backend->handlers.stop();
}

