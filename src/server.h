#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#include <uv.h>

typedef struct http_server_data_s http_server_data_t;
struct http_server_data_s {
  uv_loop_t *loop;
};

typedef struct http_client_data_s http_client_data_t;
struct http_client_data_s {
  uv_tcp_t *tcp;
  uv_buf_t *buf;
  size_t bytes_read;
  size_t bytes_written;
  long read_frame_seq_num;
};

typedef struct http_write_req_data_s http_write_req_data_t;
struct http_write_req_data_s {
  uv_stream_t* client;
  uv_buf_t *buf;
  long write_frame_seq_num;
};

typedef struct http_shutdown_data_s http_shutdown_data_t;
struct http_shutdown_data_s {
  uv_stream_t* stream;
};

/**
 * Starts the server
 */
int http_serve();

#endif
