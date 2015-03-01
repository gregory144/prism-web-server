#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <assert.h>
#include <unistd.h>

#include <uv.h>

#include "util/log.h"
#include "util/util.h"
#include "http/http.h"
#include "http/h2/h2.h"

#include "worker.h"
#include "client.h"

static void worker_sigpipe_handler(uv_signal_t * sigpipe_handler, int signum)
{
  struct worker_t * worker = sigpipe_handler->data;
  log_append(worker->log, LOG_WARN, "Caught SIGPIPE: %d", signum);
}

static void worker_sigint_handler(uv_signal_t * sigint_handler, int signum)
{
  struct worker_t * worker = sigint_handler->data;
  log_append(worker->log, LOG_DEBUG, "Caught SIGINT: %d", signum);
}

static void worker_sigterm_handler(uv_signal_t * sigterm_handler, int signum)
{
  struct worker_t * worker = sigterm_handler->data;
  log_append(worker->log, LOG_DEBUG, "Caught SIGTERM: %d", signum);

  worker_stop(worker);
}

static void worker_stop_continue(struct worker_t * worker)
{
  if (!worker->active_queue && worker->active_handlers < 1 && worker->open_clients == NULL) {
    log_append(worker->log, LOG_TRACE, "Closed worker handles...");

    struct plugin_list_t * current = worker->plugins;
    while (current) {
      plugin_stop(current->plugin);
      current = current->next;
    }
  }
}

static void handler_closed(uv_handle_t * handle)
{
  struct worker_t * worker = handle->data;

  worker->active_handlers--;

  worker_stop_continue(worker);
}

static void worker_queue_closed(uv_handle_t * handle)
{
  struct worker_t * worker = handle->data;

  worker->active_queue = false;

  worker_stop_continue(worker);
}

static void alloc_pipe_read_buffer(uv_handle_t * handle, size_t suggested_size, uv_buf_t * buf)
{
  UNUSED(handle);

  buf->base = malloc(suggested_size);
  buf->len = suggested_size;
}

static void alloc_buffer(uv_handle_t * handle, size_t suggested_size, uv_buf_t * buf)
{
  UNUSED(handle);

  buf->base = malloc(suggested_size);
  buf->len = suggested_size;
}

static void app_write_finished(uv_write_t * req, int status)
{
  struct client_t * client = req->data;
  struct worker_t * worker = client->worker;

  if (status) {
    log_append(worker->log, LOG_ERROR, "Write error: %s", uv_err_name(status));
  } else {
    log_append(worker->log, LOG_TRACE, "Write finished: #%zu", client->id);
  }

  client->pending_writes--;
  if (client->pending_writes == 0) {
    http_connection_t * connection = client->connection;
    http_finished_writes(connection);
  }

  free(req);
}

static bool worker_write_to_network(void * data, uint8_t * buffer, size_t length)
{
  struct client_t * client = data;
  client->pending_writes++;

  uv_write_t * req = (uv_write_t *) malloc(sizeof(uv_write_t));
  uv_buf_t wrbuf = uv_buf_init((char *) buffer, length);
  req->data = client;
  int r = uv_write(req, (uv_stream_t *) &client->tcp, &wrbuf, 1, app_write_finished);
  if (r < 0) {
    log_append(client->worker->log, LOG_ERROR, "Write client #%zu (%zu octets) failed: %s",
        client->id, length, uv_err_name(r));
  }

  return true;
}

static bool app_write_cb(void * data, uint8_t * buffer, size_t length)
{
  struct client_t * client = data;
  struct worker_t * worker = client->worker;

  log_append(worker->log, LOG_DEBUG, "Write client #%zu (%zu octets)", client->id, length);
  if (log_enabled(client->data_log)) {
    log_append(client->data_log, LOG_TRACE, "Writing data: (%zd octets)", length);
    log_buffer(client->data_log, LOG_TRACE, buffer, length);
  }

  if (client->tls_ctx) {
    log_append(worker->log, LOG_TRACE, "Passing %zu octets of data from application to TLS handler", length);
    bool ret = tls_encrypt_data_and_pass_to_network(client->tls_ctx, buffer, length);
    log_append(worker->log, LOG_TRACE, "Passed %zu octets of data from application to TLS handler", length);
    return ret;
  } else {
    return worker_write_to_network(client, buffer, length);
  }
}

static void app_close_finished(uv_handle_t * handle)
{
  struct client_t * client = handle->data;

  struct worker_t * worker = client->worker;

  if (client->prev) {
    client->prev->next = client->next;
    if (client->next) {
      client->next->prev = client->prev;
    }
  } else {
    worker->open_clients = client->next;
    if (worker->open_clients) {
      worker->open_clients->prev = NULL;
    }
  }

  log_append(client->log, LOG_TRACE,
      "Finishing closing connection: %zu", client->id);

  client_free(client);
}

static void uv_cb_shutdown(uv_shutdown_t * shutdown_req, int status)
{
  struct client_t * client = shutdown_req->data;

  if (status) {
    log_append(client->log, LOG_ERROR, "Shutdown error, client: %zu: %s", client->id, uv_strerror(status));
    if (!uv_is_closing((uv_handle_t *) &client->tcp)) {
      uv_close((uv_handle_t *) &client->tcp, app_close_finished);
    }
  } else if (!client->closing) {
    client->closing = true;
    log_append(client->log, LOG_TRACE, "Closing client handle: %zu", client->id);
    uv_close((uv_handle_t *) &client->tcp, app_close_finished);
  }
}

static void worker_close(struct client_t * client)
{
  uv_read_stop((uv_stream_t *) &client->tcp);
  log_append(client->log, LOG_TRACE, "Shuting down client: %zu", client->id);

  uv_shutdown_t * shutdown_req = &client->shutdown_req;
  shutdown_req->data = client;
  int status = uv_shutdown(shutdown_req, (uv_stream_t *) &client->tcp, uv_cb_shutdown);
  if (status < 0) {
    log_append(client->log, LOG_ERROR, "Shutdown failed to initialize, client: %zu: %s",
        client->id, uv_strerror(status));
  }
}

static void app_close_cb(void * data)
{
  struct client_t * client = data;
  log_append(client->log, LOG_TRACE, "Closing: %zu", client->id);
  worker_close(client);
}

static void worker_parse(struct client_t * client, uint8_t * buffer, size_t length)
{
  if (log_enabled(client->data_log)) {
    log_append(client->data_log, LOG_TRACE, "Reading data: (%zd octets)", length);
    log_buffer(client->data_log, LOG_TRACE, buffer, length);
  }

  if (client->tls_ctx && client->tls_ctx->selected_tls_version) {
    http_connection_set_tls_details(client->connection, client->tls_ctx->selected_tls_version,
                                    client->tls_ctx->selected_cipher, client->tls_ctx->cipher_key_size_in_bits);
  }

  if (!client->selected_protocol && client->tls_ctx && client->tls_ctx->selected_protocol) {
    http_connection_set_protocol(client->connection, client->tls_ctx->selected_protocol);
    client->selected_protocol = true;
  }

  log_append(client->log, LOG_DEBUG, "Read client #%zu (%zu octets)", client->id, length);

  http_connection_t * connection = client->connection;
  http_connection_read(connection, (uint8_t *) buffer, length);
}

// pass the decrypted data on to the application
static bool tls_cb_write_to_app(void * data, uint8_t * buf, size_t length)
{
  struct client_t * client = data;

  log_append(client->log, LOG_TRACE, "Passing %zu octets of data from TLS handler to application", length);
  worker_parse(client, (uint8_t *) buf, length);
  log_append(client->log, LOG_TRACE, "Passed %zu octets of data from TLS handler to application", length);

  return true;
}

static void worker_notify_eof(struct client_t * client)
{
  http_connection_t * connection = client->connection;
  http_connection_eof(connection);
}

static void worker_read_from_network(uv_stream_t * uv_client, ssize_t nread, const uv_buf_t * buf)
{
  struct client_t * client = uv_client->data;
  struct worker_t * worker = client->worker;

  if (nread < 0) {

    if (nread != UV_EOF) {
      log_append(worker->log, LOG_ERROR, "Error reading from network for client %ld: %s",
          client->id, uv_err_name(nread));
      uv_close((uv_handle_t *) uv_client, app_close_finished);
    } else {
      log_append(worker->log, LOG_DEBUG, "EOF for client: #%ld", client->id);
      client->eof = true;
      worker_notify_eof(client);
    }
    free(buf->base);
  } else if (client->tls_ctx) {

    tls_client_ctx_t * tls_client_ctx = client->tls_ctx;

    log_append(worker->log, LOG_TRACE, "Passing %zu octets of data from network to TLS handler",
        nread);

    if (!tls_decrypt_data_and_pass_to_app(tls_client_ctx, (uint8_t *) buf->base, nread)) {
      worker_close(client);
    }

    log_append(worker->log, LOG_TRACE, "Passed %zu octets of data from network to TLS handler", nread);

  } else {

    worker_parse(client, (uint8_t *) buf->base, nread);

  }
}

static void worker_assign_client_details(struct client_t * client, size_t index)
{
  log_append(client->log, LOG_TRACE, "Looking for address index: %lu", index);
  struct listen_address_t * curr = client->worker->config->address_list;
  for (size_t i = 0; i < index && curr != NULL; i++, curr = curr->next);
  if (!curr) {
    log_append(client->log, LOG_FATAL, "Could not find specified address config: %lu", index);
    abort();
  }
  if (curr->use_tls) {
    client->tls_ctx = tls_client_init(client->worker->tls_ctx, client, worker_write_to_network,
                                      tls_cb_write_to_app);
  } else {
    client->tls_ctx = NULL;
  }

  http_connection_set_details(client->connection, curr->use_tls, curr->hostname, curr->port);

  log_append(client->log, LOG_DEBUG, "Address is: %s://%s:%ld",
      curr->use_tls ? "https" : "http", curr->hostname, curr->port);
}

static void worker_on_new_connection(uv_stream_t * pipe_s, ssize_t nread, const uv_buf_t * buf)
{
  uv_pipe_t * pipe = (uv_pipe_t *) pipe_s;
  struct worker_t * worker = pipe->data;

  if (nread < 0) {
    if (nread != UV_EOF) {
      log_append(worker->log, LOG_ERROR, "Error reading file descriptor from pipe: %s", uv_err_name(nread));
    }
    uv_close((uv_handle_t *) pipe_s, NULL);
    return;
  }

  if (!uv_pipe_pending_count(pipe)) {
    log_append(worker->log, LOG_ERROR, "No pending file descriptors to read");
    return;
  }

  uv_handle_type pending = uv_pipe_pending_type(pipe);
  assert(pending == UV_TCP);

  struct client_t * client = malloc(sizeof(struct client_t));
  if (!client) {
    log_append(worker->log, LOG_ERROR, "Could not malloc client");
    return;
  }
  if (!client_init(client, worker)) {
    log_append(worker->log, LOG_ERROR, "Error initializing client");
    free(client);
    return;
  }

  client->prev = NULL;
  if (worker->open_clients) {
    worker->open_clients->prev = client;
  }
  client->next = worker->open_clients;
  worker->open_clients = client;

  client->connection = http_connection_init(client, &worker->config->http_log,
      &worker->config->hpack_log, worker->config->h2_protocol_version_string,
      worker->config->h2c_protocol_version_string, client->plugin_invoker,
      app_write_cb, app_close_cb);

  uv_tcp_init(&worker->loop, &client->tcp);
  uv_tcp_nodelay(&client->tcp, true);
  client->tcp.data = client;

  if (uv_accept(pipe_s, (uv_stream_t *) &client->tcp) == 0) {

    size_t index = (size_t) *buf->base;

    worker_assign_client_details(client, index);

    log_append(worker->log, LOG_DEBUG, "Accepted fd %d\n", client->tcp.io_watcher.fd);
    uv_read_start((uv_stream_t *) &client->tcp, alloc_buffer, worker_read_from_network);
  } else {
    uv_close((uv_handle_t *) &client->tcp, app_close_finished);
  }

  free(buf->base);
}

bool worker_use_tls(struct server_config_t * config)
{
  bool use_tls = false;
  struct listen_address_t * addr = config->address_list;
  while (addr) {
    if (addr->use_tls) {
      use_tls = true;
      break;
    }
    addr = addr->next;
  }
  return use_tls;
}

bool worker_init(struct worker_t * worker, struct server_config_t * config)
{
  h2_static_init();

  worker->stopping = false;
  worker->config = config;
  worker->plugins = NULL;
  worker->open_clients = NULL;

  struct plugin_config_t * plugin_config = config->plugin_configs;
  struct plugin_list_t * last = NULL;

  while (plugin_config) {
    struct plugin_list_t * current = malloc(sizeof(struct plugin_list_t));
    current->plugin = plugin_init(NULL, &config->plugin_log, plugin_config->filename,
                                  (struct worker_t *) worker);
    current->next = NULL;

    if (!current->plugin) {
      free(current);
      return false;
    }

    if (!worker->plugins) {
      worker->plugins = current;
    } else {
      last->next = current;
    }

    last = current;

    plugin_config = plugin_config->next;
  }

  int uv_error = uv_loop_init(&worker->loop);
  if (uv_error) {
    return false;
  }
  worker->loop.data = worker;

  worker->active_handlers = 0;
  uv_signal_init(&worker->loop, &worker->sigpipe_handler);
  worker->sigpipe_handler.data = worker;
  worker->active_handlers++;

  uv_signal_init(&worker->loop, &worker->sigint_handler);
  worker->sigint_handler.data = worker;
  worker->active_handlers++;

  uv_signal_init(&worker->loop, &worker->sigterm_handler);
  worker->sigterm_handler.data = worker;
  worker->active_handlers++;

  uv_pipe_init(&worker->loop, &worker->queue, 1);
  uv_pipe_open(&worker->queue, 0);
  worker->queue.data = worker;
  uv_read_start((uv_stream_t *) &worker->queue, alloc_pipe_read_buffer, worker_on_new_connection);
  worker->active_queue = true;

  worker->assigned_reads = 0;

  worker->log = &config->worker_log;
  worker->data_log = &config->data_log;

  if (worker_use_tls(config)) {
    tls_init(config->h2_protocol_version_string);

    worker->tls_ctx = tls_server_init(&config->tls_log, config->private_key_file, config->cert_file);
    ASSERT_OR_RETURN_FALSE(worker->tls_ctx);
  } else {
    worker->tls_ctx = NULL;
  }

  return true;
}

int worker_run(struct worker_t * worker)
{
  struct plugin_list_t * current = worker->plugins;

  while (current != NULL) {
    plugin_start(current->plugin);
    current = current->next;
  }

  uv_signal_start(&worker->sigpipe_handler, worker_sigpipe_handler, SIGPIPE);
  uv_signal_start(&worker->sigint_handler, worker_sigint_handler, SIGINT);
  uv_signal_start(&worker->sigterm_handler, worker_sigterm_handler, SIGTERM);

  log_append(worker->log, LOG_INFO, "Worker running...");

  int ret = uv_run(&worker->loop, UV_RUN_DEFAULT);

  log_append(worker->log, LOG_TRACE, "Worker no longer running...");

  return ret;
}

void worker_stop(struct worker_t * worker)
{
  log_append(worker->log, LOG_INFO, "Worker shutting down...");
  worker->stopping = true;

  uv_signal_stop(&worker->sigpipe_handler);
  uv_signal_stop(&worker->sigint_handler);
  uv_signal_stop(&worker->sigterm_handler);
  uv_close((uv_handle_t *) &worker->sigpipe_handler, handler_closed);
  uv_close((uv_handle_t *) &worker->sigint_handler, handler_closed);
  uv_close((uv_handle_t *) &worker->sigterm_handler, handler_closed);

  uv_read_stop((uv_stream_t *) &worker->queue);
  uv_close((uv_handle_t *) &worker->queue, worker_queue_closed);

  struct client_t * client = worker->open_clients;
  while (client) {
    http_connection_shutdown(client->connection);
    client = client->next;
  }

  worker_stop_continue(worker);
}

void worker_free(struct worker_t * worker)
{
  struct plugin_list_t * current = worker->plugins;
  while (current) {
    plugin_free(current->plugin);
    struct plugin_list_t * prev = current;
    current = current->next;
    free(prev);
  }

  if (worker->tls_ctx && worker_use_tls(worker->config)) {
    tls_server_free(worker->tls_ctx);
  }

  uv_loop_close(&worker->loop);
}

