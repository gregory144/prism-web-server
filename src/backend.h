#ifndef HTTP_BACKEND_H
#define HTTP_BACKEND_H

#include "http2/http.h"

typedef void (*backend_start_cb)();

typedef void (*backend_stop_cb)();

typedef struct {

  request_cb request;

  data_cb data;

  backend_start_cb start;

  backend_stop_cb stop;

} backend_handlers_t;

typedef struct {

  char * backend_file;

  uv_lib_t lib;

  backend_handlers_t handlers;

} backend_t;

typedef void (*backend_initializer)(backend_t * backend);

backend_t * backend_init(backend_t * backend, char * backend_file);

void backend_start(backend_t * backend);

void backend_stop(backend_t * backend);

#endif
