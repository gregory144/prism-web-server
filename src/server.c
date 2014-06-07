#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>
#include <assert.h>

#include "config.h"

#include "util/util.h"
#include "http2/http.h"
#include "http2/request.h"

#include "server.h"

static long reads = 0;
static long writes = 0;
static long requests = 0;

static void handle_request(http_request_t * request, http_response_t * response)
{
  if (LOG_DEBUG) {
    log_debug("Method: '%s'", http_request_method(request));
    log_debug("Scheme: '%s'", http_request_scheme(request));
    log_debug("Host: '%s'", http_request_host(request));
    log_debug("Port: %d", http_request_port(request));
    log_debug("Path: '%s'", http_request_path(request));
    log_debug("Query: '%s'", http_request_query_string(request));

    log_debug("Got headers:");
    multimap_iter_t iter;
    multimap_iterator_init(&iter, request->headers);

    while (multimap_iterate(&iter)) {
      log_debug("'%s' (%ld): '%s' (%ld)", iter.key, strlen(iter.key), iter.value, strlen(iter.value));
    }

    log_debug("Got parameters:");

    multimap_iterator_init(&iter, request->params);

    while (multimap_iterate(&iter)) {
      log_debug("'%s' (%ld): '%s' (%ld)", iter.key, strlen(iter.key), iter.value, strlen(iter.value));
    }
  }

  char * method = http_request_method(request);

  if (strncmp(method, "POST", 4) == 0) {

    http_response_status_set(response, 200);

    char * content_length = http_request_header_get(request, "content-length");

    if (content_length) {
      http_response_header_add(response, "content-length", content_length);
    }

    http_response_header_add(response, "server", PACKAGE_STRING);
    size_t date_buf_length = RFC1123_TIME_LEN + 1;
    char date_buf[date_buf_length];
    char * date = date_rfc1123(date_buf, date_buf_length);

    if (date) {
      http_response_header_add(response, "date", date);
    }

    http_response_write(response, NULL, 0, false);

    return;
  }

  char * resp_text;

  char * resp_len_s = http_request_param_get(request, "resp_len");
  long long resp_len = 0;

  if (resp_len_s) {
    resp_len = strtoll(resp_len_s, NULL, 10);
  }

  if (resp_len > 0) {
    resp_text = malloc(resp_len + 1);
    memset(resp_text, 'a', resp_len);
    resp_text[resp_len - 1] = '\n';
    resp_text[resp_len] = '\0';
  } else {
    multimap_values_t * messages = http_request_param_get_values(request, "msg");

    if (!messages) {
      char * client_user_agent = http_request_header_get(request, "user-agent");

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
      multimap_values_t * current = messages;

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
  }

  http_response_status_set(response, 200);

  size_t content_length = strlen(resp_text);

  char content_length_s[256];
  snprintf(content_length_s, 255, "%ld", content_length);
  http_response_header_add(response, "content-length", content_length_s);

  http_response_header_add(response, "server", PACKAGE_STRING);
  size_t date_buf_length = RFC1123_TIME_LEN + 1;
  char date_buf[date_buf_length];
  char * date = date_rfc1123(date_buf, date_buf_length);

  if (date) {
    http_response_header_add(response, "date", date);
  }

  http_request_t * pushed_request = http_push_init(request);

  if (pushed_request) {
    http_request_header_add(pushed_request, ":method", "GET");
    http_request_header_add(pushed_request, ":scheme", "http");
    http_request_header_add(pushed_request, ":authority", "localhost:7000");
    http_request_header_add(pushed_request, ":path", "/pushed_resource.txt");

    http_push_promise(pushed_request);

    if (pushed_request) {
      http_response_t * pushed_response = http_push_response_get(pushed_request);
      http_response_status_set(pushed_response, 200);

      char push_text[256];
      snprintf(push_text, 255, "Pushed Response at %s\n", date);

      size_t push_content_length = strlen(push_text);

      char push_content_length_s[256];
      snprintf(push_content_length_s, 255, "%ld", push_content_length);
      http_response_header_add(pushed_response, "content-length", push_content_length_s);

      http_response_header_add(pushed_response, "server", PACKAGE_STRING);

      if (date) {
        http_response_header_add(pushed_response, "date", date);
      }

      http_response_write(pushed_response, (uint8_t *) strdup(push_text), push_content_length, true);
    }


  }

  http_response_write(response, (uint8_t *) resp_text, content_length, true);

  if (LOG_INFO) {
    requests++;

    if (requests % 1000 == 0) {
      log_info("Request #%ld", requests);
    }
  }
}

static void handle_data(
  http_request_t * request,
  http_response_t * response,
  uint8_t * buf,
  size_t length,
  bool last)
{
  UNUSED(request);

  if (LOG_TRACE) {
    log_trace("Received %ld bytes of data from client (last? %s)", length, last ? "yes" : "no");
  }

  uint8_t * out = malloc(sizeof(uint8_t) * length);
  // convert all bytes to lowercase
  size_t i;

  for (i = 0; i < length; i++) {
    out[i] = *(buf + i) | 0x20;
  }

  http_response_write_data(response, out, length, last);

}

void server_alloc_buffer(uv_handle_t * handle, size_t suggested_size, uv_buf_t * buf)
{
  UNUSED(handle);
  buf->len = suggested_size;
  buf->base = malloc(suggested_size);
}

void server_write(uv_write_t * req, int status)
{
  assert(req != NULL);

  http_write_req_data_t * write_req_data = req->data;
  http_client_data_t * client_data = write_req_data->stream->data;

  if (status < 0) {
    if (LOG_ERROR) {
      log_error("Write error: %s, %ld", uv_strerror(status), client_data->uv_write_count);
    }
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

void server_connection_close(uv_handle_t * handle)
{
  http_client_data_t * client_data = handle->data;

  if (LOG_TRACE) {
    log_trace("Closing client handle: (%ld = %ld)", client_data->bytes_read, client_data->bytes_written);
  }

  free(client_data->stream);
  http_connection_free(client_data->connection);
  free(client_data);

  if (LOG_TRACE) {
    log_trace("Stats: reads %ld, writes %ld", reads, writes);
  }
}

void server_connection_shutdown(uv_shutdown_t * shutdown_req, int status)
{
  http_shutdown_data_t * shutdown_data = shutdown_req->data;

  if (status) {
    if (LOG_ERROR) {
      log_error("Shutdown error: %s", uv_strerror(status));
    }

    server_connection_close((uv_handle_t *)shutdown_data->stream);
  } else {
    uv_close((uv_handle_t *)shutdown_data->stream, server_connection_close);
  }

  free(shutdown_data);
  free(shutdown_req);
}

void server_parse(uv_stream_t * client, uint8_t * buffer, size_t len)
{
  http_client_data_t * client_data = client->data;
  client_data->bytes_read += len;
  client_data->uv_read_count++;

  if (LOG_TRACE) {
    log_trace("Read %ld bytes (%ld)", len, client_data->uv_read_count);
  }

  http_connection_t * connection = client_data->connection;
  http_connection_read(connection, buffer, len);
}

void server_stream_shutdown(uv_stream_t * stream)
{
  if (LOG_TRACE) {
    http_client_data_t * client_data = stream->data;
    log_trace("shutting down... (%ld)", client_data->uv_read_count);
  }

  uv_shutdown_t * shutdown_req = malloc(sizeof(uv_shutdown_t));
  http_shutdown_data_t * shutdown_data = malloc(sizeof(http_shutdown_data_t));
  shutdown_data->stream = stream;
  shutdown_req->data = shutdown_data;
  uv_shutdown(shutdown_req, stream, server_connection_shutdown);
}

void server_read(uv_stream_t * stream, ssize_t nread, const uv_buf_t * buf)
{

  if (nread == UV_EOF) {
    free(buf->base);

    server_stream_shutdown(stream);

    return;
  } else if (nread < 0) {
    free(buf->base);

    if (LOG_ERROR) {
      log_error("Read error: %s", uv_strerror(nread));
    }

    uv_close((uv_handle_t *)stream, server_connection_close);

    return;
  }

  server_parse(stream, (uint8_t *)buf->base, nread);

  reads++;

}

void server_http_write(void * stream, uint8_t * buf, size_t len)
{
  uv_write_t * write_req = malloc(sizeof(uv_write_t));
  http_write_req_data_t * write_req_data = malloc(sizeof(http_write_req_data_t));
  write_req_data->stream = stream;
  write_req->data = write_req_data;

  // copy bytes to write to new buffer
  uv_buf_t * write_buf = malloc(sizeof(uv_buf_t));
  write_buf->base = malloc(sizeof(char) * len);
  memcpy(write_buf->base, buf, len);
  write_buf->len = len;
  // keep track of the buffer so we can free it later
  write_req_data->buf = write_buf;

  if (LOG_DATA) {
    log_trace("uv_write: %s, %ld", buf, len);
    size_t i;

    for (i = 0; i < len; i++) {
      log_trace("%02x", (uint8_t)buf[i]);
    }
  }

  uv_write(write_req, stream, write_req_data->buf, 1, server_write);
}

void server_http_close(void * stream)
{
  server_stream_shutdown(stream);
}

void server_connection_start(uv_stream_t * server, int status)
{
  if (status == -1) {
    // error!
    return;
  }

  http_server_data_t * server_data = server->data;

  uv_tcp_t * client = malloc(sizeof(uv_tcp_t));
  client->close_cb = server_connection_close;
  http_client_data_t * client_data = malloc(sizeof(http_client_data_t));
  client_data->bytes_read = 0;
  client_data->bytes_written = 0;
  client_data->uv_read_count = 0;
  client_data->stream = (uv_stream_t *) client;
  client_data->connection = http_connection_init(client, handle_request, handle_data, server_http_write,
                            server_http_close);
  client->data = client_data;
  uv_tcp_init(server_data->loop, client);

  if (uv_accept(server, (uv_stream_t *) client) == 0) {
    int err = uv_read_start((uv_stream_t *) client, server_alloc_buffer, server_read);

    if (err < 0 && LOG_ERROR) {
      log_error("Read error: %s", uv_strerror(err));
    }
  } else {
    uv_close((uv_handle_t *) client, server_connection_close);
  }
}

int server_start()
{
  uv_loop_t * loop = uv_default_loop();

  uv_tcp_t server;
  http_server_data_t server_data;
  server_data.loop = loop;
  server.data = &server_data;
  uv_tcp_init(loop, &server);

  struct sockaddr_in bind_addr;
  uv_ip4_addr("0.0.0.0", 7000, &bind_addr);
  uv_tcp_bind(&server, (struct sockaddr *)&bind_addr, 0);
  int err = uv_listen((uv_stream_t *) &server, 128, server_connection_start);

  if (err < 0 && LOG_ERROR) {
    log_error("Listen error: %s", uv_strerror(err));
    return 1;
  }

  int ret = uv_run(loop, UV_RUN_DEFAULT);
  uv_loop_delete(loop);
  return ret;
}

