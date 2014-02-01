#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>
#include <assert.h>

#include "util.h"
#include "server.h"

static long allocs = 0;
static long reads = 0;
static long writes = 0;

void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t* buf) {
  buf->len = suggested_size;
  buf->base = malloc(suggested_size);
  http_client_data_t *client_data = handle->data;
  client_data->buf = buf;
  allocs++;
}

void echo_write(uv_write_t *req, int status) {
  assert(req != NULL);

  http_write_req_data_t *write_req_data = req->data;
  http_client_data_t *client_data = write_req_data->client->data;
  if (status < 0) {
    fprintf(stderr, "uv_write error: %s, %ld\n", uv_strerror(status), write_req_data->write_frame_seq_num);
  } else {
    client_data->bytes_written += write_req_data->buf->len;
    writes++;
    //fprintf(stderr, "Wrote %ld bytes (%ld)\n", write_req_data->buf->len, write_req_data->write_frame_seq_num);
  }
  free(write_req_data->buf->base);
  free(write_req_data->buf);
  free(write_req_data);
  free(req);
}

void on_connection_close(uv_handle_t* handle) {
  http_client_data_t *client = handle->data;
  fprintf(stderr, "Closing client handle: (%ld = %ld)\n", client->bytes_read, client->bytes_written);
  free(client->tcp);
  free(client);
  fprintf(stderr, "Stats: allocs %ld, reads %ld, writes %ld\n", allocs, reads, writes);
}

void on_shutdown(uv_shutdown_t* shutdown_req, int status) {
  http_shutdown_data_t *shutdown_data = shutdown_req->data;
  if (status) {
    fprintf(stderr, "shutdown error: %s\n", uv_strerror(status));
    on_connection_close((uv_handle_t*)shutdown_data->stream);
  } else {
    fprintf(stderr, "closing...\n");
    uv_close((uv_handle_t*)shutdown_data->stream, on_connection_close);
  }
  free(shutdown_data);
  free(shutdown_req);
}

void echo_read(uv_stream_t *client, ssize_t nread, const uv_buf_t* buf) {
  http_client_data_t *client_data = client->data;

  if (nread == UV_EOF) {
    free(buf->base);

    fprintf(stderr, "shutting down... (%ld, %ld, %s)\n", nread, client_data->read_frame_seq_num, nread == UV_EOF ? "EOF" : "ERROR");
    uv_shutdown_t *shutdown_req = malloc(sizeof(uv_shutdown_t));
    http_shutdown_data_t *shutdown_data = malloc(sizeof(http_shutdown_data_t));
    shutdown_data->stream = client;
    shutdown_req->data = shutdown_data;
    uv_shutdown(shutdown_req, client, on_shutdown);

    return;
  } else if (nread < 0) {
    free(buf->base);

    fprintf(stderr, "read error: %s\n", uv_strerror(nread));
    uv_close((uv_handle_t*)client, on_connection_close);

    return;
  }

  client_data->bytes_read += nread;
  client_data->read_frame_seq_num++;
  fprintf(stderr, "Read %ld bytes (%ld)\n", nread, client_data->read_frame_seq_num);

  uv_write_t *write_req = malloc(sizeof(uv_write_t));
  http_write_req_data_t *write_req_data = malloc(sizeof(http_write_req_data_t));
  write_req_data->client = client;
  write_req->data = write_req_data;

  // copy read bytes to new buffer
  uv_buf_t *write_buf = malloc(sizeof(uv_buf_t));
  write_buf->base = malloc(nread);
  memcpy(write_buf->base, buf->base, nread);
  write_buf->len = nread;
  // keep track of the buffer so we can free it later
  write_req_data->buf = write_buf;
  write_req_data->write_frame_seq_num = client_data->read_frame_seq_num;

  uv_write(write_req, client, write_req_data->buf, 1, echo_write);

  free(buf->base);
  reads++;
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
  client_data->bytes_read = 0;
  client_data->bytes_written = 0;
  client_data->read_frame_seq_num = 0;
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

int http_serve() {
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

