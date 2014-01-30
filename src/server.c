#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>
#include <assert.h>

#include "util.h"
#include "server.h"

void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t* buf) {
  UNUSED(handle);
  buf->len = suggested_size;
  buf->base = calloc(suggested_size, 1);
  fprintf(stderr, "Allocating %ld bytes for buffer\n", suggested_size);
}

void echo_write(uv_write_t *req, int status) {
  assert(req != NULL);

  if (status) {
    fprintf(stderr, "uv_write error: %s\n", uv_strerror(status));
    assert(0);
  }
  http_write_req_data_t *write_req_data = req->data;
  free(write_req_data->buf->base);
  free(write_req_data->buf);
  free(write_req_data);
  free(req);
}

void on_connection_close(uv_handle_t* handle) {
  fprintf(stderr, "Closing client handle\n");
  http_client_data_t *client = handle->data;
  free(client->tcp);
  free(client);
}

void echo_read(uv_stream_t *client, ssize_t nread, const uv_buf_t* buf) {
  if (nread < 0) {

    free(buf->base);

    uv_close((uv_handle_t*) client, on_connection_close);
    return;
  }

  if (buf->base[0] == EOF) {
    fprintf(stderr, "Read EOF from stream\n");
  }

  uv_write_t *write_req = malloc(sizeof(uv_write_t));;
  http_write_req_data_t *write_req_data = malloc(sizeof(http_write_req_data_t));
  write_req->data = write_req_data;

  char* prefix_format = "Stream %ld: %s\n";
  size_t buf_size = sizeof(prefix_format) + nread + 32;
  char* write_str  = calloc(buf_size, 1);
  size_t ret = snprintf(write_str, buf_size, prefix_format, nread, buf->base);
  fprintf(stderr, "Read %ld bytes\n", nread);
  uv_buf_t *write_buf = malloc(sizeof(uv_buf_t));
  write_buf->base = write_str;
  write_buf->len = buf_size;
  write_req_data->buf = write_buf;
  if (ret > buf_size) {
    uv_close((uv_handle_t*) client, NULL);
    fprintf(stderr, "error echoing\n");
    assert(0);
  }

  uv_write(write_req, client, write_req_data->buf, 1, echo_write);

  free(buf->base);
}

void on_new_connection(uv_stream_t *server, int status) {
  if (status == -1) {
    // error!
    return;
  }

  http_server_data_t *server_data = server->data;

  uv_tcp_t *client = malloc(sizeof(uv_tcp_t));
  client->close_cb = on_connection_close;
  http_client_data_t *client_data = malloc(sizeof(http_client_data_t));
  client_data->tcp = client;
  client->data = client_data;
  uv_tcp_init(server_data->loop, client);
  if (uv_accept(server, (uv_stream_t*) client) == 0) {
    int err = uv_read_start((uv_stream_t*) client, alloc_buffer, echo_read);
    if (err < 0)
      fprintf(stderr, "Read error: %s\n", uv_strerror(err));
  }
  else {
    uv_close((uv_handle_t*) client, on_connection_close);
  }
}

int http_server_loop() {
  uv_loop_t* loop = uv_default_loop();

  uv_tcp_t server;
  http_server_data_t server_data;
  server_data.loop = loop;
  server.data = &server_data;
  uv_tcp_init(loop, &server);

  struct sockaddr_in bind_addr;
  uv_ip4_addr("0.0.0.0", 7000, &bind_addr);
  uv_tcp_bind(&server, (struct sockaddr*)&bind_addr, 0);
  int err = uv_listen((uv_stream_t*) &server, 128, on_new_connection);
  if (err < 0) {
    fprintf(stderr, "Listen error: %s\n", uv_strerror(err));
    return 1;
  }
  int ret = uv_run(loop, UV_RUN_DEFAULT);
  uv_loop_delete(loop); 
  return ret;
}

