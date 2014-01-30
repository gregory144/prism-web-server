#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#include <uv.h>

typedef struct http_write_req_data_s http_write_req_data_t;
struct http_write_req_data_s {
  uv_buf_t *buf;
};

typedef struct http_client_data_s http_client_data_t;
struct http_client_data_s {
  uv_tcp_t *tcp;
};

typedef struct http_server_data_s http_server_data_t;
struct http_server_data_s {
  uv_loop_t *loop;
};

int http_server_loop();

#endif
