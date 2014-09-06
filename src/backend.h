#ifndef HTTP_BACKEND_H
#define HTTP_BACKEND_H

#include "http/http.h"

struct server_s;

struct worker_s;

typedef struct {

  char * backend_file;

  uv_lib_t lib;

  struct backend_handlers_s * handlers;

  void * data;

} backend_t;

typedef void (*backend_start_cb)(backend_t * backend);

typedef void (*backend_stop_cb)(backend_t * backend);

typedef void (*backend_request_cb)(backend_t * backend, struct worker_s * worker, http_request_t * request,
                                   http_response_t * response);

typedef void (*backend_data_cb)(backend_t * backend, struct worker_s * worker, http_request_t * request,
                                http_response_t * response,
                                uint8_t * buf, size_t len, bool last, bool free_buf);

typedef struct backend_handlers_s {

  backend_request_cb request;
  backend_data_cb data;
  backend_start_cb start;
  backend_stop_cb stop;

} backend_handlers_t;

typedef void (*backend_initializer)(backend_t * backend, struct server_s * server);

backend_t * backend_init(backend_t * backend, char * backend_file, struct server_s * server);

void backend_request_handler(backend_t * backend, struct worker_s * worker, http_request_t * request,
                             http_response_t * response);

void backend_data_handler(backend_t * backend, struct worker_s * worker, http_request_t * request,
                          http_response_t * response,
                          uint8_t * buf, size_t length, bool last, bool free_buf);

void backend_start(backend_t * backend);

void backend_stop(backend_t * backend);

#endif
