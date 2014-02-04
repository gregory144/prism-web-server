#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>
#include <assert.h>

#include "util.h"
#include "server.h"
#include "http.h"

static long reads = 0;
static long writes = 0;

void server_alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t* buf) {
  UNUSED(handle);
  buf->len = suggested_size;
  buf->base = malloc(suggested_size);
}

void server_write(uv_write_t *req, int status) {
  assert(req != NULL);

  http_write_req_data_t *write_req_data = req->data;
  http_client_data_t *client_data = write_req_data->stream->data;

  if (status < 0) {
    fprintf(stderr, "uv_write error: %s, %ld\n", uv_strerror(status), client_data->uv_write_count);
  } else {
    client_data->uv_write_count++;
    client_data->bytes_written += write_req_data->buf->len;
    writes++;
    //fprintf(stderr, "Wrote %ld bytes (%ld)\n", write_req_data->buf->len, write_req_data->uv_write_count);
  }
  free(write_req_data->buf->base);
  free(write_req_data->buf);
  free(write_req_data);
  free(req);
}

void server_connection_close(uv_handle_t* handle) {
  http_client_data_t *client_data = handle->data;
  fprintf(stderr, "Closing client handle: (%ld = %ld)\n", client_data->bytes_read, client_data->bytes_written);
  free(client_data->stream);
  http_parser_free(client_data->parser);
  free(client_data);
  fprintf(stderr, "Stats: reads %ld, writes %ld\n", reads, writes);
}

void server_connection_shutdown(uv_shutdown_t* shutdown_req, int status) {
  http_shutdown_data_t *shutdown_data = shutdown_req->data;
  if (status) {
    fprintf(stderr, "shutdown error: %s\n", uv_strerror(status));
    server_connection_close((uv_handle_t*)shutdown_data->stream);
  } else {
    fprintf(stderr, "closing...\n");
    uv_close((uv_handle_t*)shutdown_data->stream, server_connection_close);
  }
  free(shutdown_data);
  free(shutdown_req);
}


void server_parse(uv_stream_t *client, char* buffer, size_t len) {
  http_client_data_t *client_data = client->data;
  client_data->bytes_read += len;
  client_data->uv_read_count++;
  fprintf(stderr, "Read %ld bytes (%ld)\n", len, client_data->uv_read_count);

  http_parser_t* parser = client_data->parser;
  http_parser_read(parser, buffer, len);

  free(buffer);
}

void server_stream_shutdown(uv_stream_t* stream) {
  http_client_data_t *client_data = stream->data;
  fprintf(stderr, "shutting down... (%ld)\n", client_data->uv_read_count);
  uv_shutdown_t *shutdown_req = malloc(sizeof(uv_shutdown_t));
  http_shutdown_data_t *shutdown_data = malloc(sizeof(http_shutdown_data_t));
  shutdown_data->stream = stream;
  shutdown_req->data = shutdown_data;
  uv_shutdown(shutdown_req, stream, server_connection_shutdown);
}

void server_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t* buf) {

  if (nread == UV_EOF) {
    free(buf->base);

    server_stream_shutdown(stream);

    return;
  } else if (nread < 0) {
    free(buf->base);

    fprintf(stderr, "read error: %s\n", uv_strerror(nread));
    uv_close((uv_handle_t*)stream, server_connection_close);

    return;
  }

  server_parse(stream, buf->base, nread);

  reads++;

}

void server_http_write(void* stream, char* buf, size_t len) {
  uv_write_t* write_req = malloc(sizeof(uv_write_t));
  http_write_req_data_t* write_req_data = malloc(sizeof(http_write_req_data_t));
  write_req_data->stream = stream;
  write_req->data = write_req_data;

  // copy read bytes to new buffer
  uv_buf_t *write_buf = malloc(sizeof(uv_buf_t));
  write_buf->base = malloc(len);
  memcpy(write_buf->base, buf, len);
  write_buf->len = len;
  // keep track of the buffer so we can free it later
  write_req_data->buf = write_buf;

  uv_write(write_req, stream, write_req_data->buf, 1, server_write);
}

void server_http_close(void* stream) {
  server_stream_shutdown(stream);
}

void server_connection_start(uv_stream_t *server, int status) {
  if (status == -1) {
    // error!
    return;
  }

  http_server_data_t *server_data = server->data;

  uv_tcp_t *client = malloc(sizeof(uv_tcp_t));
  client->close_cb = server_connection_close;
  http_client_data_t *client_data = malloc(sizeof(http_client_data_t));
  client_data->bytes_read = 0;
  client_data->bytes_written = 0;
  client_data->uv_read_count = 0;
  client_data->stream = (uv_stream_t*)client;
  client_data->parser = http_parser_init(client, server_http_write, server_http_close);
  client->data = client_data;
  uv_tcp_init(server_data->loop, client);
  if (uv_accept(server, (uv_stream_t*) client) == 0) {
    int err = uv_read_start((uv_stream_t*) client, server_alloc_buffer, server_read);
    if (err < 0)
      fprintf(stderr, "Read error: %s\n", uv_strerror(err));
  }
  else {
    uv_close((uv_handle_t*) client, server_connection_close);
  }
}

int server_start() {
  uv_loop_t* loop = uv_default_loop();

  uv_tcp_t server;
  http_server_data_t server_data;
  server_data.loop = loop;
  server.data = &server_data;
  uv_tcp_init(loop, &server);

  struct sockaddr_in bind_addr;
  uv_ip4_addr("0.0.0.0", 7000, &bind_addr);
  uv_tcp_bind(&server, (struct sockaddr*)&bind_addr, 0);
  int err = uv_listen((uv_stream_t*) &server, 128, server_connection_start);
  if (err < 0) {
    fprintf(stderr, "Listen error: %s\n", uv_strerror(err));
    return 1;
  }
  int ret = uv_run(loop, UV_RUN_DEFAULT);
  uv_loop_delete(loop); 
  return ret;
}

