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
static long requests = 0;

void handle_request(http_request_t* request, http_response_t* response) {
  if (LOG_DEBUG) {
    log_debug("Method: '%s'\n", http_request_method(request));
    log_debug("Scheme: '%s'\n", http_request_scheme(request));
    log_debug("Host: '%s'\n", http_request_host(request));
    log_debug("Port: %d\n", http_request_port(request));
    log_debug("Path: '%s'\n", http_request_path(request));
    log_debug("Query: '%s'\n", http_request_query_string(request));

    log_debug("Got headers:\n");
    multimap_iter_t iter;
    multimap_iterator_init(&iter, request->headers);
    while (multimap_iterate(&iter)) {
      log_debug("'%s' (%ld): '%s' (%ld)\n", iter.key, strlen(iter.key), iter.value, strlen(iter.value));
    }

    log_debug("Got parameters:\n");

    multimap_iterator_init(&iter, request->params);
    while (multimap_iterate(&iter)) {
      log_debug("'%s' (%ld): '%s' (%ld)\n", iter.key, strlen(iter.key), iter.value, strlen(iter.value));
    }
  }

  char* resp_text;
  multimap_values_t* messages = http_request_param_get_values(request, "msg");
  if (!messages) {
    char* client_user_agent = http_request_header_get(request, "user-agent");
    if (!client_user_agent) {
      client_user_agent = "Unknown";
    }
    size_t resp_length = 100 + strlen(client_user_agent);
    char user_agent_message[resp_length + 1];
    snprintf(user_agent_message, resp_length, "Hello %s\n", client_user_agent);
    resp_text = strdup(user_agent_message);
  } else {
    // Append all messages.
    // First, count the size
    size_t messages_length = 0;
    multimap_values_t* current = messages;
    while (current) {
      messages_length += strlen(current->value) + 1;
      current = current->next;
    }
    resp_text = malloc(sizeof(char) * messages_length + 1);
    current = messages;
    size_t resp_text_index = 0;
    while (current) {
      size_t current_length = strlen(current->value);
      memcpy(resp_text + resp_text_index, current->value, current_length);
      resp_text_index += current_length;
      resp_text[resp_text_index++] = '\n';
      current = current->next;
    }
    resp_text[resp_text_index] = '\0';
  }

  size_t content_length = strlen(resp_text);
  char content_length_s[256];
  snprintf(content_length_s, 255, "%ld", content_length);

  http_response_header_add(response, ":status", "200");
  http_response_header_add(response, "content-length", content_length_s);
  http_response_header_add(response, "server", PACKAGE_STRING);
  char* date = date_rfc1123();
  http_response_header_add(response, "date", date);
  free(date);

  http_response_write(response, resp_text, content_length);

  if (LOG_INFO) {
    requests++;
    if (requests % 1000 == 0) {
      log_info("Request #%ld\n", requests);
    }
  }
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
    if (LOG_ERROR) log_error("Write error: %s, %ld\n", uv_strerror(status), client_data->uv_write_count);
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
  if (LOG_TRACE) log_trace("Closing client handle: (%ld = %ld)\n", client_data->bytes_read, client_data->bytes_written);
  free(client_data->stream);
  http_parser_free(client_data->parser);
  free(client_data);
  if (LOG_TRACE) log_trace("Stats: reads %ld, writes %ld\n", reads, writes);
}

void server_connection_shutdown(uv_shutdown_t* shutdown_req, int status) {
  http_shutdown_data_t *shutdown_data = shutdown_req->data;
  if (status) {
    if (LOG_ERROR) log_error("Shutdown error: %s\n", uv_strerror(status));
    server_connection_close((uv_handle_t*)shutdown_data->stream);
  } else {
    uv_close((uv_handle_t*)shutdown_data->stream, server_connection_close);
  }
  free(shutdown_data);
  free(shutdown_req);
}

void server_parse(uv_stream_t *client, uint8_t* buffer, size_t len) {
  http_client_data_t *client_data = client->data;
  client_data->bytes_read += len;
  client_data->uv_read_count++;
  if (LOG_TRACE) log_trace("Read %ld bytes (%ld)\n", len, client_data->uv_read_count);

  http_parser_t* parser = client_data->parser;
  http_parser_read(parser, buffer, len);

  free(buffer);
}

void server_stream_shutdown(uv_stream_t* stream) {
  http_client_data_t *client_data = stream->data;
  if (LOG_TRACE) log_trace("shutting down... (%ld)\n", client_data->uv_read_count);
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

    if (LOG_ERROR) log_error("Read error: %s\n", uv_strerror(nread));
    uv_close((uv_handle_t*)stream, server_connection_close);

    return;
  }

  server_parse(stream, (uint8_t*)buf->base, nread);

  reads++;

}

void server_http_write(void* stream, uint8_t* buf, size_t len) {
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

  if (LOG_TRACE) {
    log_trace("uv_write: %s, %ld\n", buf, len);
    size_t i;
    for (i = 0; i < len; i++) {
      log_trace("%02x ", (uint8_t)buf[i]);
    }
    log_trace("\n");
  }
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
    if (err < 0 && LOG_ERROR) {
      log_error("Read error: %s\n", uv_strerror(err));
    }
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
  if (err < 0 && LOG_ERROR) {
    log_error("Listen error: %s\n", uv_strerror(err));
    return 1;
  }
  int ret = uv_run(loop, UV_RUN_DEFAULT);
  uv_loop_delete(loop); 
  return ret;
}

