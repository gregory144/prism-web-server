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

#include "worker.h"
#include "client.h"

#define MAX_CLIENTS 0x4000
#define LISTEN_BACKLOG 1024

static void alloc_pipe_read_buffer(uv_handle_t * handle, size_t suggested_size, uv_buf_t * buf)
{
  UNUSED(handle);

  buf->base = malloc(256);
  buf->len = 256;
}

static void alloc_buffer(uv_handle_t * handle, size_t suggested_size, uv_buf_t * buf)
{
  UNUSED(handle);

  /*buf->base = malloc(suggested_size);*/
  /*buf->len = suggested_size;*/
  buf->base = malloc(512);
  printf("Allocating buffer: %p\n", buf->base);
  buf->len = 512;
}

static void app_write_finished(uv_write_t * req, int status)
{
  if (status) {
    fprintf(stderr, "Write error %d, %s\n", getpid(), uv_err_name(status));
  }
  free(req);
}

static bool worker_write_to_network(void * data, uint8_t * buffer, size_t length)
{
  /*worker_buffer_t * worker_buffer = malloc(sizeof(worker_buffer_t));*/

  /*// copy bytes to write to new buffer*/
  /*worker_buffer->buffer = malloc(sizeof(uint8_t) * length);*/
  /*memcpy(worker_buffer->buffer, buffer, length);*/

  /*worker_buffer->length = length;*/
  /*worker_buffer->client = client;*/
  /*worker_buffer->eof = false;*/

  /*blocking_queue_push(client->write_queue, worker_buffer);*/
  /*uv_async_send(&client->write_handle);*/

  struct client_t * client = data;

  fprintf(stderr, "Writing: %d, %lu\n", getpid(), length);

  uv_write_t * req = (uv_write_t *) malloc(sizeof(uv_write_t));
  uv_buf_t wrbuf = uv_buf_init((char *) buffer, length);
  req->data = client;
  uv_write(req, (uv_stream_t *) &client->tcp, &wrbuf, 1, app_write_finished);

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

  if (worker->config->use_tls) {
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

  log_append(client->log, LOG_DEBUG,
      "Closing connection from uv callback: %zu", client->id);

  client_free(client);
}

static void uv_cb_shutdown(uv_shutdown_t * shutdown_req, int status)
{
  struct client_t * client = shutdown_req->data;

  if (status) {
    log_append(client->log, LOG_ERROR, "Shutdown error, client: %zu: %s", client->id, uv_strerror(status));
  }

  if (!client->closing) {
    client->closing = true;
    uv_close((uv_handle_t *) &client->tcp, app_close_finished);
  }

  free(shutdown_req);
}

static void worker_close(struct client_t * client)
{
  printf("Closing client\n");

  uv_shutdown_t * shutdown_req = malloc(sizeof(uv_shutdown_t));
  shutdown_req->data = client;
  uv_shutdown(shutdown_req, (uv_stream_t *) &client->tcp, uv_cb_shutdown);
}

static void app_close_cb(void * data)
{
  struct client_t * client = data;
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
      fprintf(stderr, "Read error %s\n", uv_err_name(nread));
    }
    client->eof = true;
    printf("EOF\n");
    worker_notify_eof(client);
    free(buf->base);

  } else if (worker->config->use_tls) {

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

static void worker_on_new_connection(uv_stream_t * pipe_s, ssize_t nread, const uv_buf_t * buf)
{
  UNUSED(buf);

  if (nread < 0) {
    if (nread != UV_EOF) {
      fprintf(stderr, "Read error %s\n", uv_err_name(nread));
    }
    uv_close((uv_handle_t *) pipe_s, NULL);
    return;
  }

  uv_pipe_t * pipe = (uv_pipe_t *) pipe_s;
  if (!uv_pipe_pending_count(pipe)) {
    fprintf(stderr, "No pending count\n");
    return;
  }

  uv_handle_type pending = uv_pipe_pending_type(pipe);
  assert(pending == UV_TCP);

  struct worker_t * worker = pipe->data;

  struct client_t * client = malloc(sizeof(struct client_t));
  if (!client || !client_init(client, worker)) {
    // TODO error handling
    abort();
  }

  char * scheme = worker->config->use_tls ? "https" : "http";
  char * hostname = worker->config->hostname;
  int port = worker->config->port;

  client->connection = http_connection_init(client, &worker->config->http_log, &worker->config->hpack_log,
                       scheme, hostname, port, client->plugin_invoker,
                       app_write_cb, app_close_cb);

  if (worker->config->use_tls) {
    client->tls_ctx = tls_client_init(worker->tls_ctx, client, worker_write_to_network,
                                      tls_cb_write_to_app);
  }


  uv_tcp_init(&worker->loop, &client->tcp);
  client->tcp.data = client;

  if (uv_accept(pipe_s, (uv_stream_t *) &client->tcp) == 0) {
    fprintf(stderr, "Worker %d: Accepted fd %d\n", getpid(), client->tcp.io_watcher.fd);
    uv_read_start((uv_stream_t *) &client->tcp, alloc_buffer, worker_read_from_network);
  } else {
    uv_close((uv_handle_t *) &client->tcp, NULL);
  }

  free(buf->base);
}

bool worker_init(struct worker_t * worker, struct server_config_t * config)
{

  if (config->use_tls) {
    tls_init();
  }

  worker->config = config;
  worker->plugins = NULL;

  struct plugin_config_t * plugin_config = config->plugin_configs;
  struct plugin_list_t * last = NULL;

  while (plugin_config) {
    printf("Setting up plugin: %p\n", plugin_config);
    fflush(stdout);
    struct plugin_list_t * current = malloc(sizeof(struct plugin_list_t));
    current->plugin = plugin_init(NULL, &config->plugin_log, plugin_config->filename,
                                  (struct worker_t *) worker);
    current->next = NULL;

    if (!current->plugin) {
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

  if (config->use_tls) {
    worker->tls_ctx = tls_server_init(&config->tls_log, config->private_key_file, config->cert_file);
    ASSERT_OR_RETURN_FALSE(worker->tls_ctx);
  }

  // TODO error handling
  uv_loop_init(&worker->loop);
  worker->loop.data = worker;

  uv_pipe_init(&worker->loop, &worker->queue, 1);
  uv_pipe_open(&worker->queue, 0);
  worker->queue.data = worker;
  uv_read_start((uv_stream_t *) &worker->queue, alloc_pipe_read_buffer, worker_on_new_connection);

  worker->assigned_reads = 0;

  worker->log = &config->server_log;
  worker->data_log = &config->data_log;
  worker->wire_log = &config->wire_log;

  return true;
}

/*static void worker_uv_async_cb_written(uv_async_t * async_handle)*/
/*{*/
  /*struct client_t * client = async_handle->data;*/

  /*if (blocking_queue_size(client->write_queue) == 0) {*/
    /*http_connection_t * connection = client->connection;*/
    /*http_finished_writes(connection);*/
  /*}*/
/*}*/

/*static void worker_queue(struct client_t * client, bool eof, uint8_t * buffer, size_t length)*/
/*{*/
  /*struct server_t * server = client->server;*/

  /*struct worker_buffer_t * worker_buffer = malloc(sizeof(struct worker_buffer_t));*/
  /*worker_buffer->buffer = buffer;*/
  /*worker_buffer->length = length;*/
  /*worker_buffer->client = client;*/
  /*worker_buffer->eof = eof;*/

  /*if (client->worker_index == SIZE_MAX) {*/
    /*size_t worker_index = SIZE_MAX;*/
    /*size_t min_assigned_reads = SIZE_MAX;*/

    /*size_t i;*/

    /*for (i = 0; i < server->config->num_workers; i++) {*/
      /*worker_t * worker = server->workers[i];*/

      /*if (worker->assigned_reads < min_assigned_reads) {*/
        /*min_assigned_reads = worker->assigned_reads;*/
        /*worker_index = i;*/
      /*}*/
    /*}*/

    /*client->worker_index = worker_index;*/

    /*// set up the written_handle async handle for ths worker*/
    /*struct worker_t * picked_worker = server->workers[worker_index];*/

    /*uv_async_init(&picked_worker->loop, &client->written_handle, worker_uv_async_cb_written);*/
    /*client->written_handle.data = client;*/

  /*}*/

  /*worker_t * worker = server->workers[client->worker_index];*/
  /*worker->assigned_reads++;*/

  /*client->reads_finished = false;*/
  /*atomic_int_increment(&client->read_counter);*/

  /*blocking_queue_push(worker->read_queue, worker_buffer);*/

  /*uv_async_send(&worker->async_handle);*/
  /*log_append(server->log, LOG_TRACE, "Assigning to worker: #%zu with %zu reads", client->worker_index,*/
             /*worker->assigned_reads);*/
/*}*/

/*static bool worker_write_to_network(void * data, uint8_t * buffer, size_t length)*/
/*{*/
  /*client_t * client = data;*/

  /*worker_buffer_t * worker_buffer = malloc(sizeof(worker_buffer_t));*/

  /*// copy bytes to write to new buffer*/
  /*worker_buffer->buffer = malloc(sizeof(uint8_t) * length);*/
  /*memcpy(worker_buffer->buffer, buffer, length);*/

  /*worker_buffer->length = length;*/
  /*worker_buffer->client = client;*/
  /*worker_buffer->eof = false;*/

  /*blocking_queue_push(client->write_queue, worker_buffer);*/
  /*uv_async_send(&client->write_handle);*/

  /*return true;*/
/*}*/

/*static void worker_uv_cb_written_handle_closed(uv_handle_t * handle)*/
/*{*/
  /*client_t * client = handle->data;*/
  /*log_append(client->log, LOG_DEBUG, "Closing client: %zu", client->id);*/

  /*uv_async_send(&client->close_handle);*/
/*}*/

/*static void worker_close(client_t * client)*/
/*{*/
  /*uv_close((uv_handle_t *) &client->written_handle, worker_uv_cb_written_handle_closed);*/
/*}*/

/*static void worker_http_cb_close_connection(void * data)*/
/*{*/
  /*client_t * client = data;*/

  /*worker_close(client);*/
/*}*/

/*static bool worker_http_cb_write(void * data, uint8_t * buffer, size_t length)*/
/*{*/
  /*client_t * client = data;*/
  /*server_t * server = client->server;*/

  /*if (client->eof) {*/
    /*return false;*/
  /*}*/

  /*client->octets_written += length;*/

  /*log_append(server->log, LOG_DEBUG, "Write client #%zu (%zu octets, %zu total)", client->id, length,*/
             /*client->octets_written);*/
  /*if (log_enabled(client->data_log)) {*/
    /*log_append(client->data_log, LOG_TRACE, "Writing data: (%zd octets)", length);*/
    /*log_buffer(client->data_log, LOG_TRACE, buffer, length);*/
  /*}*/

  /*if (server->config->use_tls) {*/
    /*log_append(server->log, LOG_TRACE, "Passing %zu octets of data from application to TLS handler", length);*/
    /*bool ret = tls_encrypt_data_and_pass_to_network(client->tls_ctx, buffer, length);*/
    /*log_append(server->log, LOG_TRACE, "Passed %zu octets of data from application to TLS handler", length);*/
    /*return ret;*/
  /*} else {*/
    /*return worker_write_to_network(client, buffer, length);*/
  /*}*/
/*}*/

/*static void worker_parse(struct client_t * client, uint8_t * buffer, size_t length)*/
/*{*/
  /*client->octets_read += length;*/

  /*if (log_enabled(client->data_log)) {*/
    /*log_append(client->data_log, LOG_TRACE, "Reading data: (%zd octets)", length);*/
    /*log_buffer(client->data_log, LOG_TRACE, buffer, length);*/
  /*}*/

  /*if (client->tls_ctx && client->tls_ctx->selected_tls_version) {*/
    /*http_connection_set_tls_details(client->connection, client->tls_ctx->selected_tls_version,*/
                                    /*client->tls_ctx->selected_cipher, client->tls_ctx->cipher_key_size_in_bits);*/
  /*}*/

  /*if (!client->selected_protocol && client->tls_ctx && client->tls_ctx->selected_protocol) {*/
    /*http_connection_set_protocol(client->connection, client->tls_ctx->selected_protocol);*/
    /*client->selected_protocol = true;*/
  /*}*/

  /*log_append(client->log, LOG_DEBUG, "Read client #%zu (%zu octets, %zu total)",*/
      /*client->id, length, client->octets_read);*/

  /*http_connection_t * connection = client->connection;*/
  /*http_connection_read(connection, buffer, length);*/
/*}*/

/*static void worker_notify_eof(struct client_t * client)*/
/*{*/
  /*http_connection_t * connection = client->connection;*/
  /*http_connection_eof(connection);*/
/*}*/

/*static void worker_handle(uv_async_t * async_handle)*/
/*{*/

  /*worker_t * worker = async_handle->data;*/
  /*worker_buffer_t * buffer = NULL;*/

  /*while (true) {*/

    /*buffer = blocking_queue_try_pop(worker->read_queue);*/

    /*if (!buffer) {*/
      /*break;*/
    /*}*/

    /*struct client_t * client = buffer->client;*/
    /*struct server_t * server = client->server;*/

    /*if (buffer->eof) {*/
      /*client->eof = true;*/
      /*worker_notify_eof(client);*/
    /*} else if (server->config->use_tls) {*/

      /*tls_client_ctx_t * tls_client_ctx = client->tls_ctx;*/

      /*log_append(server->log, LOG_TRACE, "Passing %zu octets of data from network to TLS handler", buffer->length);*/

      /*if (!tls_decrypt_data_and_pass_to_app(tls_client_ctx, buffer->buffer, buffer->length)) {*/
        /*worker_close(client);*/
      /*}*/

      /*log_append(server->log, LOG_TRACE, "Passed %zu octets of data from network to TLS handler", buffer->length);*/

    /*} else {*/
      /*worker_parse(client, buffer->buffer, buffer->length);*/
    /*}*/

    /*free(buffer);*/
    /*buffer = NULL;*/

    /*atomic_int_decrement(&client->read_counter);*/
    /*uv_async_send(&client->read_finished_handle);*/
  /*}*/

/*}*/

/*static void worker_stop(uv_async_t * async_handle)*/
/*{*/
  /*worker_t * worker = async_handle->data;*/

  /*uv_stop(&worker->loop);*/
/*}*/

/*static void uv_close_cb_worker_stop(uv_handle_t * handle)*/
/*{*/
  /*UNUSED(handle);*/
  /*// noop*/
/*}*/

/*static void worker_free(worker_t * worker)*/
/*{*/
  /*blocking_queue_free(worker->read_queue);*/

  /*uv_close((uv_handle_t *) &worker->stop_handle, uv_close_cb_worker_stop);*/
  /*uv_close((uv_handle_t *) &worker->async_handle, uv_close_cb_worker_stop);*/

  /*log_append(worker->log, LOG_DEBUG, "Closing worker loop");*/
  /*uv_loop_close(&worker->loop);*/

  /*while (server->plugins) {*/
    /*plugin_list_t * current = server->plugins;*/
    /*server->plugins = server->plugins->next;*/
    /*plugin_free(current->plugin);*/
    /*free(current);*/
  /*}*/

  /*if (server->tls_ctx) {*/
    /*tls_server_free(server->tls_ctx);*/
  /*}*/

  /*free(worker);*/
/*}*/

/*static void worker_work(void * arg)*/
/*{*/
  /*worker_t * worker = arg;*/

  /*uv_run(&worker->loop, UV_RUN_DEFAULT);*/
  /*log_append(worker->log, LOG_DEBUG, "Worker loop finished");*/
/*}*/

/*static void server_sigpipe_handler(uv_signal_t * sigpipe_handler, int signum)*/
/*{*/
  /*server_t * server = sigpipe_handler->data;*/
  /*log_append(server->log, LOG_WARN, "Caught SIGPIPE: %d", signum);*/
/*}*/

/*static void server_sigint_handler(uv_signal_t * sigint_handler, int signum)*/
/*{*/
  /*server_t * server = sigint_handler->data;*/
  /*log_append(server->log, LOG_INFO, "Caught SIGINT: %d", signum);*/

  /*if (!server->terminate) {*/
    /*server_stop(server);*/
    /*server->terminate = true;*/
  /*}*/
/*}*/

/*// TODO - rename all functions that start with uv_ - those should be reserved for libuv internal functions*/
/*static void uv_cb_write(uv_write_t * req, int status)*/
/*{*/
  /*if (req == NULL) {*/
    /*abort();*/
  /*}*/

  /*struct http_write_req_data_t * write_req_data = req->data;*/
  /*struct client_t * client = write_req_data->stream->data;*/

  /*if (status < 0) {*/
    /*log_append(client->log, LOG_ERROR,*/
               /*"Write error: %s, client #%zu", uv_strerror(status), client->id);*/
  /*}*/

  /*uv_async_send(&client->written_handle);*/

  /*free(write_req_data->buf.base);*/
  /*free(write_req_data);*/
/*}*/

/*static void server_uv_async_cb_write(uv_async_t * async_handle)*/
/*{*/
  /*struct client_t * client = async_handle->data;*/

  /*while (true) {*/
    /*struct worker_buffer_t * worker_buffer = blocking_queue_try_pop(client->write_queue);*/

    /*if (!worker_buffer) {*/
      /*break;*/
    /*}*/

    /*uv_tcp_t * stream = &client->tcp;*/

    /*if (uv_is_active((uv_handle_t *) stream) && !client->eof) {*/

      /*struct http_write_req_data_t * write_req_data = malloc(sizeof(struct http_write_req_data_t));*/
      /*write_req_data->stream = (uv_stream_t *) stream;*/
      /*write_req_data->req.data = write_req_data;*/

      /*write_req_data->buf.base = (char *) worker_buffer->buffer;*/
      /*write_req_data->buf.len = worker_buffer->length;*/

      /*log_append(client->log, LOG_DEBUG, "Writing for client: #%zu", client->id);*/
      /*if (log_enabled(client->wire_log)) {*/
        /*log_append(client->wire_log, LOG_TRACE, "Writing to wire: (%zu octets)", worker_buffer->length);*/
        /*log_buffer(client->wire_log, LOG_TRACE, worker_buffer->buffer, worker_buffer->length);*/
      /*}*/

      /*uv_write(&write_req_data->req, (uv_stream_t *) stream, &write_req_data->buf, 1, uv_cb_write);*/

    /*} else {*/

      /*free(worker_buffer->buffer);*/
      /*uv_async_send(&client->written_handle);*/

    /*}*/

    /*free(worker_buffer);*/
  /*}*/

/*}*/

/*static void client_free_close_cb(uv_handle_t * handle)*/
/*{*/
  /*struct client_t * client = handle->data;*/

  /*client->closed_async_handle_count++;*/

  /*// we need the count to be 2 to continue - to make sure both*/
  /*// the client's write_handle and close_handle have been closed*/
  /*if (client->closed_async_handle_count == 3) {*/

    /*open_clients--;*/
    /*log_append(client->log, LOG_DEBUG, "Freed client %zu (%d/%d left)", client->id, open_clients, total_clients);*/
    /*free(client);*/

  /*}*/
/*}*/

/*static void client_free(struct client_t * client)*/
/*{*/

  /*if (!client->http_closed) {*/
    /*log_append(client->log, LOG_TRACE, "Freeing client but http not finished: %zu", client->id);*/
  /*}*/

  /*if (!client->uv_closed) {*/
    /*log_append(client->log, LOG_TRACE, "Freeing client but uv not finished: %zu", client->id);*/
  /*}*/

  /*if (!client->reads_finished) {*/
    /*log_append(client->log, LOG_TRACE, "Freeing client but reads not finished: %zu", client->id);*/
  /*}*/

  /*// wait until all threads have finished with it*/
  /*if (client->uv_closed && client->http_closed && client->reads_finished) {*/

    /*if (client->tls_ctx) {*/
      /*tls_client_free(client->tls_ctx);*/
    /*}*/

    /*http_connection_free(client->connection);*/

    /*atomic_int_free(&client->read_counter);*/
    /*blocking_queue_free(client->write_queue);*/

    /*uv_close((uv_handle_t *) &client->write_handle, client_free_close_cb);*/
    /*uv_close((uv_handle_t *) &client->close_handle, client_free_close_cb);*/
    /*uv_close((uv_handle_t *) &client->read_finished_handle, client_free_close_cb);*/

  /*}*/

/*}*/

/*static void uv_cb_close_connection(uv_handle_t * handle)*/
/*{*/

  /*struct client_t * client = handle->data;*/

  /*log_append(client->log, LOG_DEBUG,*/
      /*"Closing connection from uv callback: %zu, reads = %zu octets, writes = %zu octets",*/
      /*client->id, client->octets_read, client->octets_written);*/

  /*client->uv_closed = true;*/

  /*client_free(client);*/

/*}*/

/*static void uv_cb_shutdown(uv_shutdown_t * shutdown_req, int status)*/
/*{*/
  /*struct client_t * client = shutdown_req->data;*/

  /*if (status) {*/
    /*log_append(client->log, LOG_ERROR, "Shutdown error, client: %zu: %s", client->id, uv_strerror(status));*/
  /*}*/

  /*if (!client->closing) {*/
    /*client->closing = true;*/
    /*uv_close((uv_handle_t *) &client->tcp, uv_cb_close_connection);*/
  /*}*/

  /*free(shutdown_req);*/
/*}*/

/*static void uv_cb_read(uv_stream_t * stream, ssize_t nread, const uv_buf_t * buf)*/
/*{*/

  /*struct client_t * client = stream->data;*/

  /*if (client->closing) {*/
    /*free(buf->base);*/
    /*return;*/
  /*}*/

  /*if (nread == UV_EOF) {*/
    /*free(buf->base);*/

    /*log_append(client->log, LOG_DEBUG, "EOF, client: %zu", client->id);*/

    /*client->eof = true;*/
    /*worker_queue(client, true, NULL, 0);*/

    /*return;*/
  /*} else if (nread < 0) {*/
    /*free(buf->base);*/

    /*log_append(client->log, LOG_ERROR, "Read error, client: %zu: %s", client->id, uv_strerror(nread));*/

    /*client->eof = true;*/
    /*worker_queue(client, true, NULL, 0);*/

    /*client->closing = true;*/
    /*uv_close((uv_handle_t *) &client->tcp, uv_cb_close_connection);*/

    /*return;*/
  /*}*/

  /*log_append(client->log, LOG_DEBUG, "Queueing from client: #%zu", client->id);*/
  /*if (log_enabled(client->wire_log)) {*/
    /*log_append(client->wire_log, LOG_TRACE, "Reading from wire: (%zd octets)", nread);*/
    /*log_buffer(client->wire_log, LOG_TRACE, (uint8_t *) buf->base, nread);*/
  /*}*/
  /*worker_queue(client, false, (uint8_t *) buf->base, nread);*/

/*}*/

/*static void server_uv_async_cb_read_finished(uv_async_t * async_handle)*/
/*{*/
  /*client_t * client = async_handle->data;*/
  /*log_append(client->log, LOG_DEBUG, "Read finished async callback: %zu", client->id);*/

  /*if (atomic_int_value(&client->read_counter) == 0) {*/
    /*client->reads_finished = true;*/

    /*client_free(client);*/
  /*}*/

/*}*/

/*static void server_uv_async_cb_close(uv_async_t * async_handle)*/
/*{*/
  /*client_t * client = async_handle->data;*/
  /*log_append(client->log, LOG_DEBUG, "Closing connection from async callback: %zu", client->id);*/

  /*client->http_closed = true;*/

  /*// if the connection has already been closed (due to a read error)*/
  /*// don't try to shutdown - just free it*/
  /*if (client->uv_closed) {*/
    /*client_free(client);*/
    /*return;*/
  /*}*/

  /*if (client->closing) {*/
    /*return;*/
  /*}*/

  /*uv_shutdown_t * shutdown_req = malloc(sizeof(uv_shutdown_t));*/
  /*shutdown_req->data = client;*/
  /*uv_shutdown(shutdown_req, (uv_stream_t *) &client->tcp, uv_cb_shutdown);*/
/*}*/

/*// pass the decrypted data on to the application*/
/*static bool tls_cb_write_to_app(void * data, uint8_t * buf, size_t length)*/
/*{*/
  /*client_t * client = data;*/

  /*log_append(client->log, LOG_TRACE, "Passing %zu octets of data from TLS handler to application", length);*/
  /*worker_parse(client, (uint8_t *)buf, length);*/
  /*log_append(client->log, LOG_TRACE, "Passed %zu octets of data from TLS handler to application", length);*/

  /*return true;*/
/*}*/

/*static void uv_cb_listen(uv_stream_t * tcp_server, int status)*/
/*{*/
  /*server_t * server = tcp_server->data;*/

  /*if (status == -1) {*/
    /*log_append(server->log, LOG_ERROR, "Listen failed: %d", status);*/
    /*// error!*/
    /*return;*/
  /*}*/

  /*open_clients++;*/
  /*total_clients++;*/
  /*client_t * client = malloc(sizeof(client_t));*/
  /*client->id = server->client_ids++;*/
  /*log_append(server->log, LOG_DEBUG, "Initializing client %zu (%d)", client->id, total_clients);*/
  /*client->log = server->log;*/
  /*client->data_log = server->data_log;*/
  /*client->wire_log = server->wire_log;*/
  /*client->selected_protocol = false;*/
  /*client->closing = false;*/
  /*client->closed = false;*/
  /*client->uv_closed = false;*/
  /*client->http_closed = false;*/
  /*client->reads_finished = true;*/
  /*client->eof = false;*/
  /*client->tls_ctx = NULL;*/
  /*client->octets_written = 0;*/
  /*client->octets_read = 0;*/
  /*client->worker_index = SIZE_MAX;*/
  /*client->plugin_invoker.plugins = server->plugins;*/
  /*client->plugin_invoker.client = client;*/

  /*if (atomic_int_init(&client->read_counter) == NULL) {*/
    /*free(client);*/
    /*return;*/
  /*}*/

  /*client->write_queue = blocking_queue_init();*/

  /*uv_async_init(&server->loop, &client->write_handle, server_uv_async_cb_write);*/
  /*client->write_handle.data = client;*/

  /*uv_async_init(&server->loop, &client->close_handle, server_uv_async_cb_close);*/
  /*client->close_handle.data = client;*/

  /*uv_async_init(&server->loop, &client->read_finished_handle, server_uv_async_cb_read_finished);*/
  /*client->read_finished_handle.data = client;*/

  /*client->closed_async_handle_count = 0;*/

  /*client->server = server;*/

  /*char * scheme = server->config->use_tls ? "https" : "http";*/
  /*char * hostname = server->config->hostname;*/
  /*int port = server->config->port;*/

  /*client->connection = http_connection_init(client, &server->config->http_log, &server->config->hpack_log,*/
                       /*scheme, hostname, port, (struct plugin_invoker_t *)&client->plugin_invoker, worker_http_cb_write,*/
                       /*worker_http_cb_close_connection);*/

  /*uv_tcp_init(&server->loop, &client->tcp);*/
  /*client->tcp.data = client;*/

  /*if (uv_accept(tcp_server, (uv_stream_t *) &client->tcp) == 0) {*/

    /*if (server->config->use_tls) {*/
      /*client->tls_ctx = tls_client_init(server->tls_ctx, client, worker_write_to_network,*/
                                        /*tls_cb_write_to_app);*/
    /*}*/

    /*int err = uv_read_start((uv_stream_t *) &client->tcp, uv_cb_alloc_buffer, uv_cb_read);*/

    /*if (err < 0) {*/
      /*log_append(server->log, LOG_ERROR, "Read error: %s", uv_strerror(err));*/
    /*}*/
  /*} else {*/
    /*// according to libuv docs - this should never fail as long as we're only calling uv_accept*/
    /*// once per listen callback*/
    /*log_append(server->log, LOG_FATAL, "Accepting the connection failed");*/
    /*abort();*/
  /*}*/
/*}*/

/*struct worker_t * worker_init(server_config_t * config)*/
/*{*/

  /*if (config->use_tls) {*/
    /*tls_init();*/
  /*}*/

  /*server_t * server = malloc(sizeof(server_t));*/
  /*ASSERT_OR_RETURN_NULL(server);*/
  /*server->tls_ctx = NULL;*/
  /*server->config = config;*/
  /*server->plugins = NULL;*/
  /*server->client_ids = 0;*/
  /*server->log = &config->server_log;*/
  /*server->data_log = &config->data_log;*/
  /*server->wire_log = &config->wire_log;*/

  /*server->terminate = false;*/

  /*plugin_config_t * plugin_config = server->config->plugin_configs;*/
  /*plugin_list_t * last = NULL;*/

  /*while (plugin_config) {*/
    /*plugin_list_t * current = malloc(sizeof(plugin_list_t));*/
    /*current->plugin = plugin_init(NULL, &server->config->plugin_log, plugin_config->filename,*/
                                  /*(struct server_t *) server);*/
    /*current->next = NULL;*/

    /*if (!current->plugin) {*/
      /*free(server);*/
      /*return NULL;*/
    /*}*/

    /*if (!server->plugins) {*/
      /*server->plugins = current;*/
    /*} else {*/
      /*last->next = current;*/
    /*}*/

    /*last = current;*/

    /*plugin_config = plugin_config->next;*/
  /*}*/

  /*if (config->use_tls) {*/
    /*server->tls_ctx = tls_server_init(&server->config->tls_log, config->private_key_file, config->cert_file);*/

    /*if (!server->tls_ctx) {*/
      /*free(server);*/
      /*return NULL;*/
    /*}*/
  /*}*/

  /*uv_loop_init(&server->loop);*/

  /*uv_signal_init(&server->loop, &server->sigpipe_handler);*/
  /*server->sigpipe_handler.data = server;*/
  /*uv_signal_init(&server->loop, &server->sigint_handler);*/
  /*server->sigint_handler.data = server;*/

  /*return server;*/

/*}*/

/*static void null_close_cb(uv_handle_t * handle)*/
/*{*/
  /*UNUSED(handle);*/

  /*// noop*/
/*}*/

/*static void worker_free(struct worker_t * worker)*/
/*{*/
  /*while (worker->plugins) {*/
    /*struct plugin_list_t * current = worker->plugins;*/
    /*worker->plugins = worker->plugins->next;*/
    /*plugin_free(current->plugin);*/
    /*free(current);*/
  /*}*/

  /*if (worker->tls_ctx) {*/
    /*tls_server_free(worker->tls_ctx);*/
  /*}*/

  /*[>uv_signal_stop(&server->sigint_handler);<]*/
  /*[>uv_signal_stop(&server->sigpipe_handler);<]*/

  /*[>uv_close((uv_handle_t *) &server->sigint_handler, null_close_cb);<]*/
  /*[>uv_close((uv_handle_t *) &server->sigpipe_handler, null_close_cb);<]*/
  /*[>uv_close((uv_handle_t *) &server->tcp_handler, null_close_cb);<]*/

  /*uv_loop_close(&worker->loop);*/

  /*free(worker);*/
/*}*/

int worker_run(struct worker_t * worker)
{

  struct plugin_list_t * current = worker->plugins;

  while (current != NULL) {
    plugin_start(current->plugin);
    current = current->next;
  }

  /*uv_signal_start(&worker->sigpipe_handler, server_sigpipe_handler, SIGPIPE);*/
  /*uv_signal_start(&worker->sigint_handler, server_sigint_handler, SIGINT);*/

  int ret = uv_run(&worker->loop, UV_RUN_DEFAULT);

  /*worker_free(worker);*/

  return ret;
}

void worker_stop(struct worker_t * worker)
{
  log_append(worker->log, LOG_INFO, "Worker shutting down...");

  struct plugin_list_t * current = worker->plugins;

  while (current) {
    plugin_stop(current->plugin);
    current = current->next;
  }

  uv_stop(&worker->loop);
}
