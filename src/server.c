#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include <uv.h>

#include "config.h"

#include "util/util.h"
#include "http2/http.h"
#include "http2/request.h"

#include "server.h"

#include "worker.c"

#define MAX_CLIENTS 0x4000

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

    if (http_push_promise(pushed_request)) {

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
}

static void handle_data(http_request_t * request, http_response_t * response, uint8_t * buf, size_t length, bool last,
                        bool free_buf)
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

  if (free_buf) {
    free(buf);
  }

}

static void server_sigpipe_handler(uv_signal_t * sigpipe_handler, int signum)
{
  log_warning("Caught SIGPIPE: %d", signum);

  uv_signal_stop(sigpipe_handler);
}

static void server_sigint_handler(uv_signal_t * sigint_handler, int signum)
{
  log_info("Caught SIGINT: %d", signum);

  server_t * server = sigint_handler->data;

  if (!server->terminate) {
    server_stop(server);
    server->terminate = true;
  }

  uv_signal_stop(sigint_handler);
}

static void uv_cb_alloc_buffer(uv_handle_t * handle, size_t suggested_size, uv_buf_t * buf)
{
  UNUSED(handle);
  buf->len = suggested_size;
  buf->base = malloc(suggested_size);
}

static void uv_cb_write(uv_write_t * req, int status)
{
  if (req == NULL) {
    abort();
  }

  http_write_req_data_t * write_req_data = req->data;
  client_t * client = write_req_data->stream->data;

  if (status < 0) {
    log_error("Write error: %s, client #%ld", uv_strerror(status), client->id);
  }

  free(write_req_data->buf->base);
  free(write_req_data->buf);
  free(write_req_data);
  free(req);
}

static void null_close_cb(uv_handle_t * handle)
{
  UNUSED(handle);

  free(handle);

  // noop
}

static void server_uv_async_cb_write(uv_async_t * async_handle)
{
  client_t * client = async_handle->data;

  while (true) {
    worker_buffer_t * worker_buffer = blocking_queue_try_pop(client->write_queue);

    if (!worker_buffer) {
      break;
    }

    log_debug("Writing for client: #%ld", client->id);
    uv_stream_t * stream = client->stream;

    uv_write_t * write_req = malloc(sizeof(uv_write_t));
    http_write_req_data_t * write_req_data = malloc(sizeof(http_write_req_data_t));
    write_req_data->stream = stream;
    write_req->data = write_req_data;

    uv_buf_t * write_buf = malloc(sizeof(uv_buf_t));
    write_buf->base = (char *) worker_buffer->buffer;
    write_buf->len = worker_buffer->length;
    // keep track of the buffer so we can free it later
    write_req_data->buf = write_buf;

    if (LOG_DATA) {
      log_trace("uv_write: %s, %ld", worker_buffer->buffer, worker_buffer->length);
      size_t i;

      for (i = 0; i < worker_buffer->length; i++) {
        log_trace("%02x", worker_buffer->buffer[i]);
      }
    }

    uv_write(write_req, stream, write_req_data->buf, 1, uv_cb_write);

    free(worker_buffer);
  }

}

static void uv_cb_close_connection(uv_handle_t * handle)
{

  client_t * client = handle->data;

  log_debug("Closing connection: reads = %ld octets, writes = %ld octets",
            client->octets_read, client->octets_written);

  free(client->stream);
  http_connection_free(client->connection);

  if (client->tls_ctx) {
    tls_client_free(client->tls_ctx);
  }

  uv_mutex_lock(&client->async_mutex);

  uv_close((uv_handle_t *) client->write_handle, null_close_cb);
  uv_close((uv_handle_t *) client->close_handle, null_close_cb);

  uv_mutex_unlock(&client->async_mutex);
  uv_mutex_destroy(&client->async_mutex);

  free(client);
}

static void uv_cb_shutdown(uv_shutdown_t * shutdown_req, int status)
{
  http_shutdown_data_t * shutdown_data = shutdown_req->data;

  if (status) {
    log_error("Shutdown error: %s", uv_strerror(status));

    uv_cb_close_connection((uv_handle_t *)shutdown_data->stream);
  } else {
    uv_close((uv_handle_t *)shutdown_data->stream, uv_cb_close_connection);
  }

  free(shutdown_data);
  free(shutdown_req);
}

static void server_connection_close(uv_stream_t * stream)
{
  // TODO error handling
  uv_shutdown_t * shutdown_req = malloc(sizeof(uv_shutdown_t));
  http_shutdown_data_t * shutdown_data = malloc(sizeof(http_shutdown_data_t));
  shutdown_data->stream = stream;
  shutdown_req->data = shutdown_data;
  uv_shutdown(shutdown_req, stream, uv_cb_shutdown);
}

static void uv_cb_read(uv_stream_t * stream, ssize_t nread, const uv_buf_t * buf)
{

  client_t * client = stream->data;

  if (nread == UV_EOF) {
    free(buf->base);

    log_debug("Shutting down from EOF, client: %ld", client->id);

    server_connection_close(stream);

    return;
  } else if (nread < 0) {
    free(buf->base);

    log_error("Read error: %s", uv_strerror(nread));

    uv_close((uv_handle_t *)stream, uv_cb_close_connection);

    return;
  }

  log_debug("Queueing from client: #%ld", client->id);
  worker_queue(client, (uint8_t *) buf->base, nread);

}

static void server_uv_async_cb_close(uv_async_t * async_handle)
{
  client_t * client = async_handle->data;
  server_connection_close(client->stream);
}

// pass the decrypted data on to the application
static bool tls_cb_write_to_app(void * data, uint8_t * buf, size_t length)
{
  client_t * client = data;

  log_trace("Passing %ld octets of data from TLS handler to application", length);
  worker_parse(client, (uint8_t *)buf, length);
  log_trace("Passed %ld octets of data from TLS handler to application", length);

  return true;
}

static void uv_cb_listen(uv_stream_t * tcp_server, int status)
{
  if (status == -1) {
    log_error("Listen failed: %d", status);
    // error!
    return;
  }

  server_t * server = tcp_server->data;

  // TODO error handling
  uv_tcp_t * tcp_client = malloc(sizeof(uv_tcp_t));
  tcp_client->close_cb = uv_cb_close_connection;

  client_t * client = malloc(sizeof(client_t));
  client->id = server->client_ids++;
  client->closed = false;
  client->tls_ctx = NULL;
  client->octets_written = 0;
  client->octets_read = 0;
  client->stream = (uv_stream_t *) tcp_client;
  client->worker_index = SIZE_MAX;

  client->write_queue = blocking_queue_init();

  uv_mutex_init(&client->async_mutex);
  uv_mutex_lock(&client->async_mutex);

  client->write_handle = malloc(sizeof(uv_async_t));
  uv_async_init(&server->loop, client->write_handle, server_uv_async_cb_write);
  client->write_handle->data = client;

  client->close_handle = malloc(sizeof(uv_async_t));
  uv_async_init(&server->loop, client->close_handle, server_uv_async_cb_close);
  client->close_handle->data = client;

  uv_mutex_unlock(&client->async_mutex);

  client->server = server;
  client->connection = http_connection_init(client, server->config->enable_compression, handle_request,
                       handle_data, worker_http_cb_write, worker_http_cb_close_connection);

  tcp_client->data = client;

  uv_tcp_init(&server->loop, tcp_client);

  if (uv_accept(tcp_server, (uv_stream_t *) tcp_client) == 0) {

    if (server->config->use_tls) {
      client->tls_ctx = tls_client_init(server->tls_ctx, client, worker_write_to_network,
                                        tls_cb_write_to_app);
    }

    int err = uv_read_start((uv_stream_t *) tcp_client, uv_cb_alloc_buffer, uv_cb_read);

    if (err < 0) {
      log_error("Read error: %s", uv_strerror(err));
    }
  } else {
    uv_close((uv_handle_t *) client, uv_cb_close_connection);
  }
}

server_t * server_init(server_config_t * config)
{

  if (config->use_tls) {
    tls_init();
  }

  server_t * server = malloc(sizeof(server_t));
  ASSERT_OR_RETURN_NULL(server);
  server->tls_ctx = NULL;
  server->config = config;
  server->client_ids = 0;

  server->terminate = false;

  if (config->use_tls) {
    server->tls_ctx = tls_server_init(config->private_key_file, config->cert_file);

    if (!server->tls_ctx) {
      free(server);
      return NULL;
    }
  }

  uv_loop_init(&server->loop);

  uv_signal_init(&server->loop, &server->sigpipe_handler);
  uv_signal_init(&server->loop, &server->sigint_handler);
  server->sigint_handler.data = server;

  return server;

}

static void server_free(server_t * server)
{
  size_t i;

  for (i = 0; i < server->config->num_workers; i++) {
    worker_t * worker = server->workers[i];
    worker_free(worker);
  }

  free(server->workers);

  if (server->tls_ctx) {
    tls_server_free(server->tls_ctx);
  }

  uv_close((uv_handle_t *)&server->sigint_handler, null_close_cb);
  uv_close((uv_handle_t *)&server->sigpipe_handler, null_close_cb);
  uv_close((uv_handle_t *)&server->tcp_handler, null_close_cb);

  uv_loop_close(&server->loop);

  free(server);

}

int server_start(server_t * server)
{
  // set up workers
  size_t i;
  server->workers = malloc(sizeof(worker_t *) * server->config->num_workers);

  for (i = 0; i < server->config->num_workers; i++) {
    worker_t * worker = worker_init();
    worker->server = server;

    uv_thread_create(&worker->thread, worker_work, worker);

    *(server->workers + i) = worker;
  }

  // set up connection listener
  server->tcp_handler.data = server;

  uv_tcp_init(&server->loop, &server->tcp_handler);

  struct sockaddr_in bind_addr;
  uv_ip4_addr(server->config->hostname, server->config->port, &bind_addr);
  uv_tcp_bind(&server->tcp_handler, (struct sockaddr *)&bind_addr, 0);

  int err = uv_listen((uv_stream_t *) &server->tcp_handler, 128, uv_cb_listen);

  if (err < 0) {
    log_error("Listen error: %s", uv_strerror(err));
    return 1;
  }

  log_info("Server starting on %s:%d", server->config->hostname, server->config->port);

  uv_signal_start(&server->sigpipe_handler, server_sigpipe_handler, SIGPIPE);
  uv_signal_start(&server->sigint_handler, server_sigint_handler, SIGINT);

  int ret = uv_run(&server->loop, UV_RUN_DEFAULT);

  server_free(server);

  return ret;

}

void server_stop(server_t * server)
{
  log_info("Server shutting down...");

  log_debug("Closing %ld workers", server->config->num_workers);

  // tell the workers to stop
  size_t i;

  for (i = 0; i < server->config->num_workers; i++) {
    worker_t * worker = server->workers[i];

    log_debug("Closing worker #%ld with %ld assigned reads (pushes: %ld, pops: %ld, length: %ld)",
              i, worker->assigned_reads, worker->read_queue->num_pushes, worker->read_queue->num_pops,
              worker->read_queue->length);

    uv_async_send(&worker->stop_handle);
  }

  // wait until the workers stop
  for (i = 0; i < server->config->num_workers; i++) {
    worker_t * worker = server->workers[i];

    uv_thread_join(&worker->thread);
  }

  uv_stop(&server->loop);
}
