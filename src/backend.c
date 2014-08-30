#include <uv.h>

#include "backend.h"

#include "util/util.h"
#include "http2/http.h"

backend_t * backend_init(backend_t * backend, char * backend_file, struct server_s * server)
{
  bool free_backend = false;

  if (!backend) {
    free_backend = true;
    backend = malloc(sizeof(backend_t));
  }

  backend->handlers = malloc(sizeof(backend_handlers_t));

  backend->data = NULL;
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

  init(backend, server);

  return backend;
}

void backend_request_handler(backend_t * backend, struct worker_s * worker, http_request_t * request,
                             http_response_t * response)
{
  backend->handlers->request(backend, worker, request, response);
}

void backend_data_handler(backend_t * backend, struct worker_s * worker, http_request_t * request,
                          http_response_t * response,
                          uint8_t * buf, size_t length, bool last, bool free_buf)
{
  backend->handlers->data(backend, worker, request, response, buf, length, last, free_buf);
}

void backend_start(backend_t * backend)
{
  backend->handlers->start(backend);
}

void backend_stop(backend_t * backend)
{
  backend->handlers->stop(backend);

  free(backend->handlers);
}

