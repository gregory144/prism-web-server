#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>
#include <assert.h>

#include "util.h"
#include "server.h"
#include "http.h"
#include "config.h"
#include "request.h"

static long reads = 0;
static long writes = 0;

http_headers_t* add_header(http_headers_t* headers, char* name, char* value) {
  http_headers_t* header = malloc(sizeof(http_headers_t));

  size_t name_length = strlen(name);
  header->name = malloc(sizeof(char) * (name_length + 1));
  strncpy(header->name, name, name_length);
  header->name[name_length] = '\0';
  header->name_length = name_length;

  size_t value_length = strlen(value);
  header->value = malloc(sizeof(char) * (value_length + 1));
  strncpy(header->value, value, value_length);
  header->value[value_length] = '\0';
  header->value_length = value_length;

  if (headers) {
    header->next = headers;
  } else {
    header->next = NULL;
  }
  return header;
}

void handle_request(http_request_t* request, http_response_t* response) {

  log_debug("Got headers:\n");

  hpack_headers_t* curr = request->headers;
  while (curr) {
    log_debug("%s: %s\n", curr->name, curr->value);
    curr = curr->next;
  }

  char* client_user_agent = http_request_header_get(request, "user-agent");
  if (!client_user_agent) {
    client_user_agent = "Unknown";
  }
  size_t resp_length = 100 + strlen(client_user_agent);
  char* resp_text = malloc(sizeof(char) * resp_length);
  snprintf(resp_text, resp_length, "Hello %s\n", client_user_agent);

  char* content_length = malloc(sizeof(char) * 1024);
  snprintf(content_length, 1024, "%ld", strlen(resp_text));

  response->headers = add_header(response->headers, ":status", "200");
  response->headers = add_header(response->headers, "content-length", content_length);
  free(content_length);
  response->headers = add_header(response->headers, "server", PACKAGE_STRING);
  char* date = date_rfc1123();
  response->headers = add_header(response->headers, "date", date);
  free(date);

  http_response_write(response, resp_text, strlen(resp_text));
}

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
    log_error("uv_write error: %s, %ld\n", uv_strerror(status), client_data->uv_write_count);
  } else {
    client_data->uv_write_count++;
    client_data->bytes_written += write_req_data->buf->len;
    writes++;
  }
  free(write_req_data->buf->base);
  free(write_req_data->buf);
  free(write_req_data);
  free(req);
}

void server_connection_close(uv_handle_t* handle) {
  http_client_data_t *client_data = handle->data;
  log_info("Closing client handle: (%ld = %ld)\n", client_data->bytes_read, client_data->bytes_written);
  free(client_data->stream);
  http_parser_free(client_data->parser);
  free(client_data);
  log_info("Stats: reads %ld, writes %ld\n", reads, writes);
}

void server_connection_shutdown(uv_shutdown_t* shutdown_req, int status) {
  http_shutdown_data_t *shutdown_data = shutdown_req->data;
  if (status) {
    log_error("shutdown error: %s\n", uv_strerror(status));
    server_connection_close((uv_handle_t*)shutdown_data->stream);
  } else {
    uv_close((uv_handle_t*)shutdown_data->stream, server_connection_close);
  }
  free(shutdown_data);
  free(shutdown_req);
}

void server_parse(uv_stream_t *client, char* buffer, size_t len) {
  http_client_data_t *client_data = client->data;
  client_data->bytes_read += len;
  client_data->uv_read_count++;
  log_info("Read %ld bytes (%ld)\n", len, client_data->uv_read_count);

  http_parser_t* parser = client_data->parser;
  http_parser_read(parser, buffer, len);

  free(buffer);
}

void server_stream_shutdown(uv_stream_t* stream) {
  http_client_data_t *client_data = stream->data;
  log_info("shutting down... (%ld)\n", client_data->uv_read_count);
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

    log_error("read error: %s\n", uv_strerror(nread));
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

  log_debug("uv_write: %s, %ld\n", buf, len);
  int i;
  for (i = 0; i < len; i++) {
    log_debug("%02x ", (unsigned char)buf[i]);
  }
  log_debug("\n");
  uv_write(write_req, stream, write_req_data->buf, 1, server_write);
  free(buf);
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
  client_data->parser = http_parser_init(client, handle_request, server_http_write, server_http_close);
  client->data = client_data;
  uv_tcp_init(server_data->loop, client);
  if (uv_accept(server, (uv_stream_t*) client) == 0) {
    int err = uv_read_start((uv_stream_t*) client, server_alloc_buffer, server_read);
    if (err < 0)
      log_error("Read error: %s\n", uv_strerror(err));
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
    log_error("Listen error: %s\n", uv_strerror(err));
    return 1;
  }
  int ret = uv_run(loop, UV_RUN_DEFAULT);
  uv_loop_delete(loop); 
  return ret;
}

