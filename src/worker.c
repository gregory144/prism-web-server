#include <stdlib.h>

#include "util/util.h"
#include "server.h"

static void worker_handle(uv_async_t * async_handle);

static void worker_stop(uv_async_t * async_handle);

static worker_t * worker_init(log_context_t * log)
{
  worker_t * worker = malloc(sizeof(worker_t));

  worker->read_queue = blocking_queue_init();
  worker->assigned_reads = 0;

  uv_loop_init(&worker->loop);

  uv_async_init(&worker->loop, &worker->async_handle, worker_handle);
  worker->async_handle.data = worker;

  uv_async_init(&worker->loop, &worker->stop_handle, worker_stop);
  worker->stop_handle.data = worker;

  worker->log = log;

  return worker;
}

static void worker_uv_async_cb_written(uv_async_t * async_handle)
{
  client_t * client = async_handle->data;

  if (blocking_queue_size(client->write_queue) == 0) {
    http_connection_t * connection = client->connection;
    http_finished_writes(connection);
  }
}

static void worker_queue(client_t * client, bool eof, uint8_t * buffer, size_t length)
{
  server_t * server = client->server;

  worker_buffer_t * worker_buffer = malloc(sizeof(worker_buffer_t));
  worker_buffer->buffer = buffer;
  worker_buffer->length = length;
  worker_buffer->client = client;
  worker_buffer->eof = eof;

  if (client->worker_index == SIZE_MAX) {
    size_t worker_index = SIZE_MAX;
    size_t min_assigned_reads = SIZE_MAX;

    size_t i;

    for (i = 0; i < server->config->num_workers; i++) {
      worker_t * worker = server->workers[i];

      if (worker->assigned_reads < min_assigned_reads) {
        min_assigned_reads = worker->assigned_reads;
        worker_index = i;
      }
    }

    client->worker_index = worker_index;

    // set up the written_handle async handle for ths worker
    worker_t * picked_worker = server->workers[worker_index];

    uv_async_init(&picked_worker->loop, &client->written_handle, worker_uv_async_cb_written);
    client->written_handle.data = client;

  }

  worker_t * worker = server->workers[client->worker_index];
  worker->assigned_reads++;

  client->reads_finished = false;
  atomic_int_increment(&client->read_counter);

  blocking_queue_push(worker->read_queue, worker_buffer);

  uv_async_send(&worker->async_handle);
  log_append(server->log, LOG_TRACE, "Assigning to worker: #%ld with %ld reads", client->worker_index, worker->assigned_reads);
}

static bool worker_write_to_network(void * data, uint8_t * buffer, size_t length)
{
  client_t * client = data;

  worker_buffer_t * worker_buffer = malloc(sizeof(worker_buffer_t));

  // copy bytes to write to new buffer
  worker_buffer->buffer = malloc(sizeof(uint8_t) * length);
  memcpy(worker_buffer->buffer, buffer, length);

  worker_buffer->length = length;
  worker_buffer->client = client;
  worker_buffer->eof = false;

  blocking_queue_push(client->write_queue, worker_buffer);
  uv_async_send(&client->write_handle);

  return true;
}

static void worker_uv_cb_written_handle_closed(uv_handle_t * handle)
{
  client_t * client = handle->data;
  log_append(client->log, LOG_DEBUG, "Closing client: %ld", client->id);

  uv_async_send(&client->close_handle);
}

static void worker_close(client_t * client)
{
  uv_close((uv_handle_t *) &client->written_handle, worker_uv_cb_written_handle_closed);
}

static void worker_http_cb_close_connection(void * data)
{
  client_t * client = data;

  worker_close(client);
}

static bool worker_http_cb_write(void * data, uint8_t * buf, size_t length)
{
  client_t * client = data;
  server_t * server = client->server;

  if (client->eof) {
    return false;
  }

  client->octets_written += length;

  log_append(server->log, LOG_DEBUG, "Write client #%ld (%ld octets, %ld total)", client->id, length, client->octets_written);

  if (server->config->use_tls) {
  log_append(server->log, LOG_TRACE, "Passing %ld octets of data from application to TLS handler", length);
    bool ret = tls_encrypt_data_and_pass_to_network(client->tls_ctx, buf, length);
    log_append(server->log, LOG_TRACE, "Passed %ld octets of data from application to TLS handler", length);
    return ret;
  } else {
    return worker_write_to_network(client, buf, length);
  }
}

static void worker_parse(client_t * client, uint8_t * buffer, size_t length)
{
  client->octets_read += length;

  if (client->tls_ctx && client->tls_ctx->selected_tls_version) {
    http_connection_set_tls_details(client->connection, client->tls_ctx->selected_tls_version,
                                    client->tls_ctx->selected_cipher, client->tls_ctx->cipher_key_size_in_bits);
  }

  if (!client->selected_protocol && client->tls_ctx && client->tls_ctx->selected_protocol) {
    http_connection_set_protocol(client->connection, client->tls_ctx->selected_protocol);
    client->selected_protocol = true;
  }

  log_append(client->log, LOG_DEBUG, "Read client #%ld (%ld octets, %ld total)", client->id, length, client->octets_read);

  http_connection_t * connection = client->connection;
  http_connection_read(connection, buffer, length);
}

static void worker_notify_eof(client_t * client)
{
  http_connection_t * connection = client->connection;
  http_connection_eof(connection);
}

static void worker_handle(uv_async_t * async_handle)
{

  worker_t * worker = async_handle->data;
  worker_buffer_t * buffer = NULL;

  while (true) {

    buffer = blocking_queue_try_pop(worker->read_queue);

    if (!buffer) {
      break;
    }

    client_t * client = buffer->client;
    server_t * server = client->server;

    if (buffer->eof) {
      client->eof = true;
      worker_notify_eof(client);
    } else if (server->config->use_tls) {

      tls_client_ctx_t * tls_client_ctx = client->tls_ctx;

      log_append(server->log, LOG_TRACE, "Passing %ld octets of data from network to TLS handler", buffer->length);

      if (!tls_decrypt_data_and_pass_to_app(tls_client_ctx, buffer->buffer, buffer->length)) {
        worker_close(client);
      }

      log_append(server->log, LOG_TRACE, "Passed %ld octets of data from network to TLS handler", buffer->length);

    } else {
      worker_parse(client, buffer->buffer, buffer->length);
    }

    free(buffer);
    buffer = NULL;

    atomic_int_decrement(&client->read_counter);
    uv_async_send(&client->read_finished_handle);
  }

}

static void worker_stop(uv_async_t * async_handle)
{
  worker_t * worker = async_handle->data;

  uv_stop(&worker->loop);
}

static void uv_close_cb_worker_stop(uv_handle_t * handle)
{
  UNUSED(handle);
  // noop
}

static void worker_free(worker_t * worker)
{
  blocking_queue_free(worker->read_queue);

  uv_close((uv_handle_t *) &worker->stop_handle, uv_close_cb_worker_stop);
  uv_close((uv_handle_t *) &worker->async_handle, uv_close_cb_worker_stop);

  log_append(worker->log, LOG_DEBUG, "Closing worker loop");
  uv_loop_close(&worker->loop);

  free(worker);
}

static void worker_work(void * arg)
{
  worker_t * worker = arg;

  uv_run(&worker->loop, UV_RUN_DEFAULT);
  log_append(worker->log, LOG_DEBUG, "Worker loop finished");
}

